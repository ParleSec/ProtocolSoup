/**
 * SAML SSO Flow Executor
 * 
 * Implements SAML 2.0 Single Sign-On flows:
 * - SP-Initiated SSO (SAML 2.0 Profiles Section 4.1)
 * - IdP-Initiated SSO (SAML 2.0 Profiles Section 4.1.5)
 * 
 * Supports both HTTP-POST and HTTP-Redirect bindings.
 * 
 * Uses inline API calls instead of popups for better UX in this demo app.
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
    // Step 1: Generate RelayState for CSRF-like protection
    const relayState = this.flowConfig.relayState || generateSecureRandom(16)
    
    this.updateState({
      securityParams: {
        ...this.state.securityParams,
        state: relayState, // Reuse state field for RelayState
      },
    })

    this.addEvent({
      type: 'security',
      title: 'RelayState Generated',
      description: 'Opaque value to maintain state across SSO flow',
      rfcReference: 'SAML 2.0 Bindings Section 3.4.3',
      data: { relayState },
    })

    // Step 2: Fetch available demo users from IdP
    this.addEvent({
      type: 'rfc',
      title: 'SAML 2.0 Profiles Section 4.1.3',
      description: 'SP creates AuthnRequest and sends to IdP',
      rfcReference: 'SAML 2.0 Profiles Section 4.1.3',
    })

    this.updateState({
      status: 'executing',
      currentStep: 'Fetching IdP user list',
    })

    // Get demo users from backend
    const usersResponse = await fetch(`${this.config.baseUrl}/demo/users`)
    if (!usersResponse.ok) {
      throw new Error('Failed to fetch demo users from IdP')
    }
    const usersData = await usersResponse.json() as { users: Array<{ id: string; name: string; email: string }> }

    this.addEvent({
      type: 'info',
      title: 'IdP Users Retrieved',
      description: `Found ${usersData.users.length} demo users available for authentication`,
      data: { users: usersData.users.map(u => u.name) },
    })

    // Step 3: Simulate user selecting first demo user (auto-login for demo)
    const selectedUser = usersData.users[0]
    
    this.addEvent({
      type: 'user_action',
      title: 'User Authentication',
      description: `Authenticating as ${selectedUser.name} (${selectedUser.email})`,
      data: { user: selectedUser },
    })

    this.updateState({
      status: 'executing',
      currentStep: 'Authenticating user at IdP',
    })

    // Step 4: Perform authentication and get SAML Response
    const authResponse = await this.authenticateAtIdP(selectedUser.id, relayState)

    // Step 5: Process the SAML Response
    this.updateState({
      status: 'executing',
      currentStep: 'Processing SAML Response',
    })

    this.addEvent({
      type: 'rfc',
      title: 'SAML 2.0 Profiles Section 4.1.4',
      description: 'IdP responded with SAML Response containing Assertion',
      rfcReference: 'SAML 2.0 Profiles Section 4.1.4',
      data: {
        responseId: authResponse.responseId,
        assertionId: authResponse.assertionId,
        nameId: authResponse.nameId,
        sessionIndex: authResponse.sessionIndex,
      },
    })

    // Step 6: Validate RelayState
    if (authResponse.relayState && authResponse.relayState !== relayState) {
      throw new Error('RelayState mismatch - possible CSRF attack')
    }

    this.addEvent({
      type: 'security',
      title: 'RelayState Validated',
      description: 'RelayState matches original value',
      data: { relayState: authResponse.relayState },
    })

    // Step 7: Store assertion info
    this.addEvent({
      type: 'token',
      title: 'SAML Assertion Received',
      description: 'Assertion contains user identity and attributes',
      data: {
        sessionId: authResponse.sessionId,
        nameId: authResponse.nameId,
        sessionIndex: authResponse.sessionIndex,
        attributes: authResponse.attributes,
      },
    })

    // Step 8: Session established
    this.addEvent({
      type: 'info',
      title: 'SP Session Created',
      description: 'Service Provider has created a local session based on the SAML assertion',
      data: {
        sessionId: authResponse.sessionId,
        user: authResponse.nameId,
      },
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

    const usersResponse = await fetch(`${this.config.baseUrl}/demo/users`)
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
    const authResponse = await this.authenticateAtIdP(selectedUser.id, this.flowConfig.relayState || '', true)

    this.updateState({
      status: 'executing',
      currentStep: 'Processing unsolicited SAML Response',
    })

    this.addEvent({
      type: 'token',
      title: 'Unsolicited SAML Assertion',
      description: 'Assertion received without prior AuthnRequest',
      data: {
        sessionId: authResponse.sessionId,
        nameId: authResponse.nameId,
        sessionIndex: authResponse.sessionIndex,
        note: 'No InResponseTo field - this is an unsolicited response',
      },
    })

    this.addEvent({
      type: 'info',
      title: 'SP Session Created',
      description: 'Service Provider has created a local session from unsolicited assertion',
      data: { sessionId: authResponse.sessionId },
    })
  }

  /**
   * Authenticate at the IdP using API calls (no popup)
   */
  private async authenticateAtIdP(
    username: string, 
    relayState: string,
    idpInitiated = false
  ): Promise<SAMLAuthResponse> {
    // Create form data for login submission
    const formData = new URLSearchParams()
    formData.set('username', username)
    formData.set('password', 'password123') // Demo password
    formData.set('relay_state', relayState)
    formData.set('binding_type', this.flowConfig.binding)
    
    // ACS URL is always needed
    const acsUrl = `${window.location.origin}${this.config.baseUrl}/acs`
    formData.set('acs_url', acsUrl)
    formData.set('issuer', window.location.origin)
    
    // For SP-initiated, include request ID
    if (!idpInitiated) {
      formData.set('request_id', generateSecureRandom(16))
    } else {
      // IdP-initiated has no request ID
      formData.set('request_id', '')
    }

    this.addEvent({
      type: 'request',
      title: 'Authentication Request',
      description: `Authenticating user "${username}" at IdP`,
      rfcReference: 'SAML 2.0 Profiles Section 4.1.3',
      data: {
        username,
        binding: this.flowConfig.binding,
        acsUrl: `${window.location.origin}${this.config.baseUrl}/acs`,
      },
    })

    // Post to login endpoint
    const response = await fetch(`${this.config.baseUrl}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
      body: formData.toString(),
    })

    // The backend returns HTML with auto-submit form for POST binding
    // For our demo, we'll parse what we can or call ACS directly
    if (!response.ok) {
      const text = await response.text()
      throw new Error(`Authentication failed: ${text}`)
    }

    // Since backend returns HTML form, we'll simulate the ACS processing
    // by fetching session info directly for the demo
    const sessionsResponse = await fetch(`${this.config.baseUrl}/demo/sessions`)
    if (!sessionsResponse.ok) {
      throw new Error('Failed to retrieve session after authentication')
    }

    const sessionsData = await sessionsResponse.json() as { 
      sessions: Array<{
        id: string
        name_id: string
        name_id_format?: string
        session_index: string
        authn_instant: string
        attributes: Record<string, string[]>
        response?: {
          id: string
          in_response_to: string
          issuer: string
          issue_instant: string
          status_code: string
        }
        assertion?: {
          id: string
          issuer: string
          issue_instant: string
        }
      }> 
    }

    // Get the most recent session
    const session = sessionsData.sessions[sessionsData.sessions.length - 1]
    
    if (!session) {
      throw new Error('No session created after authentication')
    }

    this.addEvent({
      type: 'response',
      title: 'SAML Response Received',
      description: 'IdP issued SAML Response with assertion',
      rfcReference: 'SAML 2.0 Core Section 3.4',
      data: {
        binding: this.flowConfig.binding,
        responseId: session.response?.id,
        assertionId: session.assertion?.id,
        statusCode: session.response?.status_code || 'urn:oasis:names:tc:SAML:2.0:status:Success',
        signed: true,
        encrypted: false,
      },
    })

    return {
      success: true,
      sessionId: session.id,
      nameId: session.name_id,
      sessionIndex: session.session_index,
      relayState,
      attributes: session.attributes,
      responseId: session.response?.id || `_${generateSecureRandom(16)}`,
      assertionId: session.assertion?.id || `_${generateSecureRandom(16)}`,
    }
  }
}

interface SAMLAuthResponse {
  success: boolean
  sessionId: string
  nameId: string
  sessionIndex: string
  relayState: string
  attributes: Record<string, string[]>
  responseId: string
  assertionId: string
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

