/**
 * SAML SSO Flow Executor
 *
 * Implements SAML 2.0 Single Sign-On flows:
 * - SP-Initiated SSO (SAML 2.0 Profiles Section 4.1)
 * - IdP-Initiated SSO (SAML 2.0 Profiles Section 4.1.5)
 *
 * The backend's SP builds and signs the <AuthnRequest>; the backend's IdP
 * verifies it against the SP's metadata, authenticates the principal, and
 * signs the <Response>; the SP verifies that Response against the IdP's
 * metadata. Every validation result shown here is one the backend ran.
 */

import {
  FlowExecutorBase,
  type FlowExecutorConfig,
  generateSecureRandom,
} from './base'

export interface SAMLSSOConfig extends FlowExecutorConfig {
  /** Whether this is SP-initiated (true) or IdP-initiated (false) */
  spInitiated: boolean
  /** SAML binding for the AuthnRequest: 'post' or 'redirect' */
  binding: 'post' | 'redirect'
  /** RelayState to pass through the flow (at most 80 bytes) */
  relayState?: string
}

interface ValidationCheck {
  name: string
  passed: boolean
  detail: string
  reference: string
}

interface ValidationReport {
  signed: boolean
  signature?: {
    signatureMethod: string
    digestMethod: string
    canonicalization: string
    referenceUri: string
  }
  checks: ValidationCheck[]
}

interface AuthnRequestResult {
  success: boolean
  error?: string
  binding: string
  requestId: string
  issueInstant: string
  issuer: string
  destination: string
  acsUrl: string
  protocolBinding: string
  rawXml: string
  base64Encoded?: string
  redirectUrl?: string
  relayState: string
  signed: boolean
  signatureAlgorithm: string
}

interface SSOResult {
  success: boolean
  error?: string
  responseId?: string
  inResponseTo?: string
  issueInstant?: string
  issuer?: string
  destination?: string
  statusCode?: string
  relayState?: string
  rawResponseXml?: string
  base64Encoded?: string
  unsolicited?: boolean
  idpValidation?: ValidationReport
  validation?: ValidationReport
  assertion?: {
    assertionId: string
    issueInstant: string
    issuer: string
    nameId: string
    nameIdFormat: string
    notBefore: string
    notOnOrAfter: string
    audience: string[]
    authnInstant: string
    sessionIndex: string
    authnContextClass: string
    attributes: Record<string, string[]>
    rawXml: string
  }
  session?: {
    sessionId: string
    nameId: string
    sessionIndex: string
    attributes?: Record<string, string[]>
  }
}

function firstFailure(report?: ValidationReport): string | undefined {
  const failed = report?.checks.find((check) => !check.passed)
  return failed ? `${failed.name}: ${failed.detail} (${failed.reference})` : undefined
}

export class SAMLSSOExecutor extends FlowExecutorBase {
  readonly flowType: string = 'saml_sso'
  readonly flowName: string = 'SAML Single Sign-On'
  readonly rfcReference: string = 'SAML 2.0 Profiles Section 4.1'

  protected flowConfig: SAMLSSOConfig

  constructor(config: SAMLSSOConfig) {
    super(config)
    this.flowConfig = config
  }

  async execute(): Promise<void> {
    this.abortController = new AbortController()

    const flowTypeDesc = this.flowConfig.spInitiated ? 'SP-Initiated' : 'IdP-Initiated'

    this.updateState({
      ...this.createInitialState(),
      status: 'executing',
      currentStep: `Initiating ${flowTypeDesc} SSO`,
    })

    try {
      const form = new URLSearchParams()
      if (this.flowConfig.spInitiated) {
        await this.createAuthnRequest(form)
      } else {
        this.addEvent({
          type: 'rfc',
          title: 'Unsolicited Response',
          description: 'IdP-initiated SSO: the IdP sends a <Response> without a preceding <AuthnRequest>, so it carries no InResponseTo.',
          rfcReference: 'SAML 2.0 Profiles Section 4.1.5',
        })
      }

      await this.authenticateAndConsume(form)

      this.updateState({ status: 'completed', currentStep: 'SSO completed successfully' })
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      this.updateState({
        status: 'error',
        currentStep: 'SSO failed',
        error: { code: 'saml_error', description: message },
      })
      this.addEvent({ type: 'error', title: 'SAML SSO Failed', description: message })
    }
  }

  /** The SP builds and signs an AuthnRequest addressed to the IdP's SingleSignOnService. */
  private async createAuthnRequest(form: URLSearchParams): Promise<void> {
    const relayState = this.flowConfig.relayState || generateSecureRandom(16)
    this.updateState({
      currentStep: 'SP creates AuthnRequest',
      securityParams: { ...this.state.securityParams, state: relayState },
    })

    const url = `${this.config.baseUrl}/looking-glass/authn-request?binding=${this.flowConfig.binding}&relay_state=${encodeURIComponent(relayState)}`
    const response = await fetch(this.withCaptureQuery(url), { headers: this.withCaptureHeaders() })
    const request = await response.json() as AuthnRequestResult
    if (!response.ok || !request.success) {
      throw new Error(request.error || `AuthnRequest creation failed (HTTP ${response.status})`)
    }

    this.addEvent({
      type: 'request',
      title: 'AuthnRequest',
      description: request.binding.endsWith('HTTP-Redirect')
        ? 'HTTP-Redirect binding: DEFLATE + base64 in the query string, with the signature over the query string itself'
        : 'HTTP-POST binding: base64 in a form field, with an enveloped XML signature',
      rfcReference: request.binding.endsWith('HTTP-Redirect') ? 'SAML 2.0 Bindings Section 3.4.4.1' : 'SAML 2.0 Bindings Section 3.5.4',
      data: {
        requestId: request.requestId,
        issueInstant: request.issueInstant,
        issuer: request.issuer,
        destination: request.destination,
        acsUrl: request.acsUrl,
        protocolBinding: request.protocolBinding,
        signatureAlgorithm: request.signatureAlgorithm,
        relayState: request.relayState,
        redirectUrl: request.redirectUrl,
        rawXml: request.rawXml,
        base64Encoded: request.base64Encoded,
      },
    })

    if (request.redirectUrl) {
      form.set('redirect_url', request.redirectUrl)
    } else if (request.base64Encoded) {
      form.set('SAMLRequest', request.base64Encoded)
      form.set('RelayState', request.relayState)
    }
  }

  /** The IdP authenticates the principal and issues a Response; the SP validates it. */
  private async authenticateAndConsume(form: URLSearchParams): Promise<void> {
    this.updateState({ currentStep: 'User authenticates at IdP' })

    const usersResponse = await fetch(`${this.config.baseUrl}/demo/users`, { headers: this.withCaptureHeaders() })
    if (!usersResponse.ok) {
      throw new Error('Failed to fetch demo users from IdP')
    }
    const usersData = await usersResponse.json() as {
      users: Array<{ id: string; name: string; credentials?: { email: string; password: string } }>
    }
    const selectedUser = usersData.users[0]
    const email = selectedUser?.credentials?.email
    const password = selectedUser?.credentials?.password
    if (!email || !password) {
      throw new Error('Demo user credentials unavailable')
    }
    this.addEvent({
      type: 'user_action',
      title: 'User Authentication',
      description: `Authenticating at the IdP as ${selectedUser.name} (${email})`,
      data: { user: { id: selectedUser.id, name: selectedUser.name, email } },
    })

    form.set('username', email)
    form.set('password', password)

    this.updateState({ currentStep: 'IdP issues Response; SP validates it' })
    const response = await fetch(`${this.config.baseUrl}/looking-glass/authenticate`, {
      method: 'POST',
      headers: this.withCaptureHeaders({ 'Content-Type': 'application/x-www-form-urlencoded' }),
      body: form.toString(),
    })
    const result = await response.json() as SSOResult

    if (result.idpValidation) {
      this.addEvent({
        type: 'security',
        title: 'IdP checks on the AuthnRequest',
        description: result.idpValidation.checks.every((c) => c.passed) ? 'All checks passed' : 'The IdP refused the AuthnRequest',
        rfcReference: 'SAML 2.0 Profiles Section 4.1.4.1',
        data: { ...result.idpValidation },
      })
    }

    if (result.rawResponseXml) {
      this.addEvent({
        type: 'response',
        title: 'SAML Response',
        description: `Status ${result.statusCode ?? 'unknown'}, delivered with the HTTP-POST binding`,
        rfcReference: 'SAML 2.0 Profiles Section 4.1.4.2',
        data: {
          responseId: result.responseId,
          inResponseTo: result.inResponseTo,
          issuer: result.issuer,
          destination: result.destination,
          statusCode: result.statusCode,
          relayState: result.relayState,
          rawXml: result.rawResponseXml,
          base64Encoded: result.base64Encoded,
        },
      })
    }

    if (result.validation) {
      this.addEvent({
        type: 'security',
        title: 'SP checks on the Response',
        description: result.success ? 'All checks passed' : firstFailure(result.validation) ?? 'Response rejected',
        rfcReference: 'SAML 2.0 Profiles Section 4.1.4.3',
        data: { ...result.validation },
      })
    }

    if (!response.ok || !result.success) {
      throw new Error(result.error || `SSO failed (HTTP ${response.status})`)
    }

    if (result.assertion) {
      this.addEvent({
        type: 'token',
        title: 'SAML Assertion',
        description: `Assertion for ${result.assertion.nameId}`,
        rfcReference: 'SAML 2.0 Core Section 2.3',
        data: { ...result.assertion },
      })
    }

    if (result.session) {
      this.addEvent({
        type: 'info',
        title: 'SP Session Created',
        description: result.unsolicited
          ? 'The SP accepted an unsolicited Response and created a session'
          : 'The SP created a session from the validated assertion',
        data: { ...result.session },
      })
    }
  }
}

/**
 * SP-Initiated SSO Executor (convenience class)
 */
export class SPInitiatedSSOExecutor extends SAMLSSOExecutor {
  override readonly flowType: string = 'saml_sp_sso'
  override readonly flowName: string = 'SP-Initiated SAML SSO'
  override readonly rfcReference: string = 'SAML 2.0 Profiles Section 4.1.3'

  constructor(config: Omit<SAMLSSOConfig, 'spInitiated'>) {
    super({ ...config, spInitiated: true })
  }
}

/**
 * IdP-Initiated SSO Executor (convenience class)
 */
export class IdPInitiatedSSOExecutor extends SAMLSSOExecutor {
  override readonly flowType: string = 'saml_idp_sso'
  override readonly flowName: string = 'IdP-Initiated SAML SSO'
  override readonly rfcReference: string = 'SAML 2.0 Profiles Section 4.1.5'

  constructor(config: Omit<SAMLSSOConfig, 'spInitiated'>) {
    super({ ...config, spInitiated: false })
  }
}
