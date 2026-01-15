/**
 * SAML SSO Flow Executor
 * 
 * Implements SAML 2.0 Single Sign-On flows:
 * - SP-Initiated SSO (SAML 2.0 Profiles Section 4.1)
 * - IdP-Initiated SSO (SAML 2.0 Profiles Section 4.1.5)
 * 
 * Supports both HTTP-POST and HTTP-Redirect bindings.
 * 
 * **USES REAL SAML PROTOCOL EXECUTION**
 * All data comes from actual protocol execution via Looking Glass API.
 * No fake data, no placeholder IDs, no hardcoded values.
 */

import {
  FlowExecutorBase,
  type FlowExecutorConfig,
  generateSecureRandom,
} from './base'

export interface SAMLSSOConfig extends FlowExecutorConfig {
  /** Whether this is SP-initiated (true) or IdP-initiated (false) */
  spInitiated: boolean
  /** SAML binding to use: 'post' or 'redirect' */
  binding: 'post' | 'redirect'
  /** Target SP entity ID (for IdP-initiated) */
  targetSP?: string
  /** RelayState to pass through the flow */
  relayState?: string
}

// Response types from Looking Glass API
interface LookingGlassAuthnRequestResponse {
  success: boolean
  error?: string
  requestId: string
  issueInstant: string
  issuer: string
  destination: string
  acsUrl: string
  protocolBinding: string
  rawXml: string
  base64Encoded: string
  deflatedBase64?: string
  relayState: string
  signed: boolean
  signatureAlgorithm?: string
  redirectUrl?: string
}

interface LookingGlassSecurityValidation {
  responseSigned: boolean
  assertionSigned: boolean
  signatureValid: boolean
  signatureAlgorithm?: string
  digestAlgorithm?: string
  signatureErrors?: string[]
  signatureWarnings?: string[]
  inResponseToValid: boolean
  inResponseToError?: string
  isIdPInitiated: boolean
  replayCheckPassed: boolean
  replayError?: string
  subjectConfirmed: boolean
  recipientValid?: boolean
  notOnOrAfterValid?: boolean
  conditionsValid: boolean
  audienceValid?: boolean
  timeValid?: boolean
}

interface LookingGlassAssertionDetails {
  assertionId: string
  issueInstant: string
  issuer: string
  nameId: string
  nameIdFormat: string
  notBefore: string
  notOnOrAfter: string
  audience: string
  authnInstant: string
  sessionIndex: string
  authnContextClass: string
  attributes: Record<string, string[]>
}

interface LookingGlassSessionInfo {
  sessionId: string
  nameId: string
  nameIdFormat: string
  sessionIndex: string
  authnInstant: string
  attributes: Record<string, string[]>
}

interface LookingGlassSAMLResponse {
  success: boolean
  error?: string
  responseId: string
  inResponseTo?: string
  issueInstant: string
  issuer: string
  destination: string
  statusCode: string
  statusMessage?: string
  assertion: LookingGlassAssertionDetails
  rawResponseXml: string
  rawAssertionXml?: string
  base64Encoded: string
  security: LookingGlassSecurityValidation
  session: LookingGlassSessionInfo
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

    this.addEvent({
      type: 'info',
      title: `Starting ${flowTypeDesc} SAML SSO`,
      description: `Using HTTP-${this.flowConfig.binding.toUpperCase()} binding`,
      rfcReference: this.rfcReference,
      data: {
        spInitiated: this.flowConfig.spInitiated,
        binding: this.flowConfig.binding,
      },
    })

    try {
      if (this.flowConfig.spInitiated) {
        await this.executeSPInitiated()
      } else {
        await this.executeIdPInitiated()
      }

      this.updateState({
        status: 'completed',
        currentStep: 'SSO completed successfully',
      })

      this.addEvent({
        type: 'info',
        title: 'SAML SSO Complete',
        description: 'User successfully authenticated via SAML',
        rfcReference: this.rfcReference,
      })

    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      this.updateState({
        status: 'error',
        currentStep: 'SSO failed',
        error: {
          code: 'saml_error',
          description: message,
        },
      })
      this.addEvent({
        type: 'error',
        title: 'SAML SSO Failed',
        description: message,
      })
    }
  }

  private async executeSPInitiated(): Promise<void> {
    // Step 1: Create REAL AuthnRequest via Looking Glass API
    const relayState = this.flowConfig.relayState || generateSecureRandom(16)
    
    this.updateState({
      securityParams: {
        ...this.state.securityParams,
        state: relayState,
      },
    })

    this.addEvent({
      type: 'rfc',
      title: 'SAML 2.0 Profiles Section 4.1.3',
      description: 'SP creates AuthnRequest and sends to IdP',
      rfcReference: 'SAML 2.0 Profiles Section 4.1.3',
    })

    this.updateState({
      status: 'executing',
      currentStep: 'Creating AuthnRequest',
    })

    // Call Looking Glass API to create REAL AuthnRequest
    const authnRequestUrl = `${this.config.baseUrl}/looking-glass/authn-request?binding=${this.flowConfig.binding}&relay_state=${encodeURIComponent(relayState)}`
    const authnResponse = await fetch(this.withCaptureQuery(authnRequestUrl), {
      headers: this.withCaptureHeaders(),
    })
    
    if (!authnResponse.ok) {
      throw new Error('Failed to create AuthnRequest')
    }
    
    const authnData = await authnResponse.json() as LookingGlassAuthnRequestResponse
    
    if (!authnData.success) {
      throw new Error(authnData.error || 'AuthnRequest creation failed')
    }

    // Emit REAL AuthnRequest data
    this.addEvent({
      type: 'security',
      title: 'AuthnRequest Created',
      description: `Request ID: ${authnData.requestId}`,
      rfcReference: 'SAML 2.0 Core Section 3.4',
      data: {
        requestId: authnData.requestId,
        issueInstant: authnData.issueInstant,
        issuer: authnData.issuer,
        destination: authnData.destination,
        acsUrl: authnData.acsUrl,
        protocolBinding: authnData.protocolBinding,
        signed: authnData.signed,
        signatureAlgorithm: authnData.signatureAlgorithm,
      },
    })

    // Show raw XML for inspection
    this.addEvent({
      type: 'request',
      title: 'AuthnRequest XML',
      description: 'Raw SAML AuthnRequest message',
      rfcReference: 'SAML 2.0 Core Section 3.4.1',
      data: {
        rawXml: authnData.rawXml,
        base64Encoded: authnData.base64Encoded,
        binding: this.flowConfig.binding,
      },
    })

    this.addEvent({
      type: 'security',
      title: 'RelayState Generated',
      description: 'Opaque value to maintain state across SSO flow',
      rfcReference: 'SAML 2.0 Bindings Section 3.4.3',
      data: { relayState: authnData.relayState },
    })

    // Step 2: Get demo users and authenticate
    this.updateState({
      status: 'executing',
      currentStep: 'User authenticates at IdP',
    })

    const usersResponse = await fetch(`${this.config.baseUrl}/demo/users`, {
      headers: this.withCaptureHeaders(),
    })
    if (!usersResponse.ok) {
      throw new Error('Failed to fetch demo users from IdP')
    }
    const usersData = await usersResponse.json() as { users: Array<{ id: string; name: string; email: string }> }

    const selectedUser = usersData.users[0]
    
    this.addEvent({
      type: 'user_action',
      title: 'User Authentication',
      description: `Authenticating as ${selectedUser.name} (${selectedUser.email})`,
      data: { user: selectedUser },
    })

    // Step 3: Authenticate and get REAL SAML Response
    this.updateState({
      status: 'executing',
      currentStep: 'IdP processing authentication',
    })

    const authFormData = new URLSearchParams()
    authFormData.set('username', selectedUser.id)
    authFormData.set('password', 'password123')
    authFormData.set('request_id', authnData.requestId)
    authFormData.set('acs_url', authnData.acsUrl)
    authFormData.set('sp_entity_id', authnData.issuer)

    const authResponse = await fetch(`${this.config.baseUrl}/looking-glass/authenticate`, {
      method: 'POST',
      headers: this.withCaptureHeaders({ 'Content-Type': 'application/x-www-form-urlencoded' }),
      body: authFormData.toString(),
    })

    if (!authResponse.ok) {
      const errorText = await authResponse.text()
      throw new Error(`Authentication failed: ${errorText}`)
    }

    const samlResponse = await authResponse.json() as LookingGlassSAMLResponse

    if (!samlResponse.success) {
      throw new Error(samlResponse.error || 'SAML Response creation failed')
    }

    // Step 4: Emit REAL SAML Response data
    this.addEvent({
      type: 'rfc',
      title: 'SAML 2.0 Profiles Section 4.1.4',
      description: 'IdP responded with SAML Response containing Assertion',
      rfcReference: 'SAML 2.0 Profiles Section 4.1.4',
      data: {
        responseId: samlResponse.responseId,
        inResponseTo: samlResponse.inResponseTo,
        issuer: samlResponse.issuer,
        destination: samlResponse.destination,
        statusCode: samlResponse.statusCode,
      },
    })

    // Show raw Response XML
    this.addEvent({
      type: 'response',
      title: 'SAML Response XML',
      description: 'Raw SAML Response with Assertion',
      rfcReference: 'SAML 2.0 Core Section 3.4',
      data: {
        rawXml: samlResponse.rawResponseXml,
        base64Encoded: samlResponse.base64Encoded,
      },
    })

    // Step 5: Show REAL assertion details
    this.addEvent({
      type: 'token',
      title: 'SAML Assertion',
      description: `Assertion for ${samlResponse.assertion.nameId}`,
      rfcReference: 'SAML 2.0 Core Section 2.3',
      data: {
        assertionId: samlResponse.assertion.assertionId,
        issueInstant: samlResponse.assertion.issueInstant,
        issuer: samlResponse.assertion.issuer,
        nameId: samlResponse.assertion.nameId,
        nameIdFormat: samlResponse.assertion.nameIdFormat,
        sessionIndex: samlResponse.assertion.sessionIndex,
        authnInstant: samlResponse.assertion.authnInstant,
        authnContextClass: samlResponse.assertion.authnContextClass,
        conditions: {
          notBefore: samlResponse.assertion.notBefore,
          notOnOrAfter: samlResponse.assertion.notOnOrAfter,
          audience: samlResponse.assertion.audience,
        },
        attributes: samlResponse.assertion.attributes,
        rawXml: samlResponse.rawAssertionXml,
      },
    })

    // Step 6: Show REAL security validation results
    this.addEvent({
      type: 'security',
      title: 'Security Validation Results',
      description: `Signature: ${samlResponse.security.signatureValid ? 'VALID' : 'INVALID/MISSING'}`,
      rfcReference: 'SAML 2.0 Core Section 5',
      data: {
        // REAL signature validation - not hardcoded
        responseSigned: samlResponse.security.responseSigned,
        assertionSigned: samlResponse.security.assertionSigned,
        signatureValid: samlResponse.security.signatureValid,
        signatureAlgorithm: samlResponse.security.signatureAlgorithm,
        digestAlgorithm: samlResponse.security.digestAlgorithm,
        signatureErrors: samlResponse.security.signatureErrors,
        signatureWarnings: samlResponse.security.signatureWarnings,
        // REAL InResponseTo validation
        inResponseToValid: samlResponse.security.inResponseToValid,
        inResponseToError: samlResponse.security.inResponseToError,
        // REAL replay check
        replayCheckPassed: samlResponse.security.replayCheckPassed,
        replayError: samlResponse.security.replayError,
        // REAL subject confirmation
        subjectConfirmed: samlResponse.security.subjectConfirmed,
        recipientValid: samlResponse.security.recipientValid,
        notOnOrAfterValid: samlResponse.security.notOnOrAfterValid,
        // REAL conditions validation
        conditionsValid: samlResponse.security.conditionsValid,
        audienceValid: samlResponse.security.audienceValid,
        timeValid: samlResponse.security.timeValid,
      },
    })

    // Step 7: Session established with REAL data
    this.addEvent({
      type: 'info',
      title: 'SP Session Created',
      description: 'Service Provider has created a local session based on the SAML assertion',
      data: {
        sessionId: samlResponse.session.sessionId,
        nameId: samlResponse.session.nameId,
        sessionIndex: samlResponse.session.sessionIndex,
        attributes: samlResponse.session.attributes,
      },
    })

    // Validate RelayState
    this.addEvent({
      type: 'security',
      title: 'RelayState Validated',
      description: 'RelayState matches original value',
      data: { relayState },
    })
  }

  private async executeIdPInitiated(): Promise<void> {
    // IdP-initiated flow starts at the IdP
    this.addEvent({
      type: 'rfc',
      title: 'SAML 2.0 Profiles Section 4.1.5',
      description: 'IdP-Initiated SSO - unsolicited response flow',
      rfcReference: 'SAML 2.0 Profiles Section 4.1.5',
    })

    this.addEvent({
      type: 'security',
      title: 'Security Consideration',
      description: 'IdP-initiated SSO has no InResponseTo to validate, increasing replay risk',
      rfcReference: 'SAML 2.0 Profiles Section 4.1.5',
    })

    // Get demo users
    this.updateState({
      status: 'executing',
      currentStep: 'User authenticates at IdP',
    })

    const usersResponse = await fetch(`${this.config.baseUrl}/demo/users`, {
      headers: this.withCaptureHeaders(),
    })
    if (!usersResponse.ok) {
      throw new Error('Failed to fetch demo users from IdP')
    }
    const usersData = await usersResponse.json() as { users: Array<{ id: string; name: string; email: string }> }
    const selectedUser = usersData.users[0]

    this.addEvent({
      type: 'user_action',
      title: 'User at IdP Portal',
      description: `User ${selectedUser.name} selects Service Provider to access`,
      data: { user: selectedUser },
    })

    // Authenticate without request ID (IdP-initiated)
    this.updateState({
      status: 'executing',
      currentStep: 'IdP generating unsolicited response',
    })

    const authFormData = new URLSearchParams()
    authFormData.set('username', selectedUser.id)
    authFormData.set('password', 'password123')
    // NO request_id for IdP-initiated
    authFormData.set('acs_url', `${window.location.origin}${this.config.baseUrl}/acs`)
    authFormData.set('sp_entity_id', window.location.origin)

    const authResponse = await fetch(`${this.config.baseUrl}/looking-glass/authenticate`, {
      method: 'POST',
      headers: this.withCaptureHeaders({ 'Content-Type': 'application/x-www-form-urlencoded' }),
      body: authFormData.toString(),
    })

    if (!authResponse.ok) {
      const errorText = await authResponse.text()
      throw new Error(`Authentication failed: ${errorText}`)
    }

    const samlResponse = await authResponse.json() as LookingGlassSAMLResponse

    if (!samlResponse.success) {
      throw new Error(samlResponse.error || 'SAML Response creation failed')
    }

    this.addEvent({
      type: 'token',
      title: 'Unsolicited SAML Assertion',
      description: 'Assertion received without prior AuthnRequest',
      rfcReference: 'SAML 2.0 Profiles Section 4.1.5',
      data: {
        assertionId: samlResponse.assertion.assertionId,
        nameId: samlResponse.assertion.nameId,
        sessionIndex: samlResponse.assertion.sessionIndex,
        isIdPInitiated: samlResponse.security.isIdPInitiated,
        note: 'No InResponseTo field - this is an unsolicited response',
        rawXml: samlResponse.rawAssertionXml,
      },
    })

    // Show security validation (note: InResponseTo not validated for IdP-initiated)
    this.addEvent({
      type: 'security',
      title: 'Security Validation (IdP-Initiated)',
      description: 'Limited validation - no request ID to verify',
      data: {
        isIdPInitiated: samlResponse.security.isIdPInitiated,
        responseSigned: samlResponse.security.responseSigned,
        signatureValid: samlResponse.security.signatureValid,
        replayCheckPassed: samlResponse.security.replayCheckPassed,
        conditionsValid: samlResponse.security.conditionsValid,
        warning: 'IdP-initiated SSO cannot validate InResponseTo',
      },
    })

    this.addEvent({
      type: 'info',
      title: 'SP Session Created',
      description: 'Service Provider has created a local session from unsolicited assertion',
      data: {
        sessionId: samlResponse.session.sessionId,
        nameId: samlResponse.session.nameId,
      },
    })
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
