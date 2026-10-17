/**
 * SAML Single Logout (SLO) Flow Executor
 *
 * SP-initiated Single Logout (SAML 2.0 Profiles Section 4.4): the backend's SP
 * ends its session and signs a <LogoutRequest>; the backend's IdP verifies it
 * against the SP's metadata, ends its session, and signs a <LogoutResponse>;
 * the SP matches that response to its request. Every validation result shown
 * here is one the backend ran.
 */

import {
  FlowExecutorBase,
  type FlowExecutorConfig,
  generateSecureRandom,
} from './base'

export interface SAMLLogoutConfig extends FlowExecutorConfig {
  /** SAML binding to use: 'post' or 'redirect' */
  binding: 'post' | 'redirect'
}

interface ValidationReport {
  signed: boolean
  checks: Array<{ name: string; passed: boolean; detail: string; reference: string }>
}

interface SessionInfo {
  sessionId: string
  peerEntityId: string
  nameId: string
  sessionIndex: string
}

interface LogoutRequestResult {
  success: boolean
  error?: string
  binding: string
  requestId: string
  issueInstant: string
  issuer: string
  destination: string
  nameId: string
  nameIdFormat: string
  sessionIndexes?: string[]
  rawXml: string
  base64Encoded?: string
  redirectUrl?: string
  signed: boolean
  relayState: string
}

interface LogoutResult {
  success: boolean
  error?: string
  binding?: string
  responseId?: string
  inResponseTo?: string
  issuer?: string
  statusCode?: string
  rawXml?: string
  redirectUrl?: string
  relayState?: string
  sessionsCleared?: number
  responderValidation?: ValidationReport
  requesterValidation?: ValidationReport
}

export class SAMLLogoutExecutor extends FlowExecutorBase {
  readonly flowType: string = 'saml_logout'
  readonly flowName: string = 'SAML Single Logout'
  readonly rfcReference: string = 'SAML 2.0 Profiles Section 4.4'

  protected flowConfig: SAMLLogoutConfig

  constructor(config: SAMLLogoutConfig) {
    super(config)
    this.flowConfig = config
  }

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({
      ...this.createInitialState(),
      status: 'executing',
      currentStep: 'Initiating SP-initiated Single Logout',
    })

    try {
      const sessionsResponse = await fetch(`${this.config.baseUrl}/demo/sessions`, {
        headers: this.withCaptureHeaders(),
      })
      const sessions = await sessionsResponse.json() as { sp: SessionInfo[]; idp: SessionInfo[] }
      const session = sessions.sp[0]
      if (!session) {
        throw new Error('No active SAML session at the SP. Run an SSO flow first.')
      }
      this.addEvent({
        type: 'info',
        title: 'SP Session',
        description: `Logging out ${session.nameId}`,
        data: { ...session },
      })

      await this.logout(session)

      this.updateState({ status: 'completed', currentStep: 'Single Logout completed' })
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      this.updateState({
        status: 'error',
        currentStep: 'Logout failed',
        error: { code: 'logout_error', description: message },
      })
      this.addEvent({ type: 'error', title: 'Single Logout Failed', description: message })
    }
  }

  private async logout(session: SessionInfo): Promise<void> {
    const relayState = generateSecureRandom(16)
    this.updateState({
      currentStep: 'SP creates LogoutRequest',
      securityParams: { ...this.state.securityParams, state: relayState },
    })

    const requestUrl = new URL(`${window.location.origin}${this.config.baseUrl}/looking-glass/logout-request`)
    requestUrl.searchParams.set('initiator', 'sp')
    requestUrl.searchParams.set('session_id', session.sessionId)
    requestUrl.searchParams.set('binding', this.flowConfig.binding)
    requestUrl.searchParams.set('relay_state', relayState)
    const requestResponse = await fetch(this.withCaptureQuery(requestUrl.toString()), {
      headers: this.withCaptureHeaders(),
    })
    const request = await requestResponse.json() as LogoutRequestResult
    if (!requestResponse.ok || !request.success) {
      throw new Error(request.error || `LogoutRequest creation failed (HTTP ${requestResponse.status})`)
    }

    this.addEvent({
      type: 'request',
      title: 'LogoutRequest',
      description: `Signed LogoutRequest for ${request.nameId} to ${request.destination}`,
      rfcReference: 'SAML 2.0 Profiles Section 4.4.3.1',
      data: { ...request },
    })

    this.updateState({ currentStep: 'IdP processes LogoutRequest' })
    const form = new URLSearchParams()
    if (request.redirectUrl) {
      form.set('redirect_url', request.redirectUrl)
    } else if (request.base64Encoded) {
      form.set('SAMLRequest', request.base64Encoded)
      form.set('RelayState', request.relayState)
    }
    const logoutResponse = await fetch(`${this.config.baseUrl}/looking-glass/logout`, {
      method: 'POST',
      headers: this.withCaptureHeaders({ 'Content-Type': 'application/x-www-form-urlencoded' }),
      body: form.toString(),
    })
    const result = await logoutResponse.json() as LogoutResult

    if (result.responderValidation) {
      this.addEvent({
        type: 'security',
        title: 'IdP checks on the LogoutRequest',
        description: result.responderValidation.checks.every((c) => c.passed) ? 'All checks passed' : 'The IdP refused the LogoutRequest',
        rfcReference: 'SAML 2.0 Core Section 3.7.3.2',
        data: { ...result.responderValidation },
      })
    }
    if (result.rawXml) {
      this.addEvent({
        type: 'response',
        title: 'LogoutResponse',
        description: `Status ${result.statusCode ?? 'unknown'}; ${result.sessionsCleared ?? 0} IdP session(s) ended`,
        rfcReference: 'SAML 2.0 Profiles Section 4.4.3.5',
        data: {
          responseId: result.responseId,
          inResponseTo: result.inResponseTo,
          issuer: result.issuer,
          statusCode: result.statusCode,
          relayState: result.relayState,
          redirectUrl: result.redirectUrl,
          rawXml: result.rawXml,
        },
      })
    }
    if (result.requesterValidation) {
      this.addEvent({
        type: 'security',
        title: 'SP checks on the LogoutResponse',
        description: result.success ? 'All checks passed' : result.error ?? 'LogoutResponse rejected',
        rfcReference: 'SAML 2.0 Profiles Section 4.4.4.2',
        data: { ...result.requesterValidation },
      })
    }

    if (!logoutResponse.ok || !result.success) {
      throw new Error(result.error || `Logout failed (HTTP ${logoutResponse.status})`)
    }
  }
}
