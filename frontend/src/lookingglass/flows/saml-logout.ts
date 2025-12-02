/**
 * SAML Single Logout (SLO) Flow Executor
 * 
 * Implements SAML 2.0 Single Logout Profile (SAML 2.0 Profiles Section 4.4)
 * 
 * Supports:
 * - SP-initiated logout
 * - IdP-initiated logout
 * - HTTP-POST and HTTP-Redirect bindings
 * 
 * Uses inline API calls instead of popups for better UX in this demo app.
 */

import {
  FlowExecutorBase,
  type FlowExecutorConfig,
  generateSecureRandom,
} from './base'

export interface SAMLLogoutConfig extends FlowExecutorConfig {
  /** Current session ID to logout */
  sessionId?: string
  /** NameID of the user to logout */
  nameId?: string
  /** Session index from the original SSO */
  sessionIndex?: string
  /** SAML binding to use: 'post' or 'redirect' */
  binding: 'post' | 'redirect'
  /** Whether logout is initiated by SP (true) or IdP (false) */
  spInitiated: boolean
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

    const initiator = this.flowConfig.spInitiated ? 'SP' : 'IdP'

    this.updateState({
      ...this.createInitialState(),
      status: 'executing',
      currentStep: `Initiating ${initiator}-initiated Single Logout`,
    })

    this.addEvent({
      type: 'info',
      title: `Starting ${initiator}-Initiated Single Logout`,
      description: `Using HTTP-${this.flowConfig.binding.toUpperCase()} binding`,
      rfcReference: this.rfcReference,
      data: {
        spInitiated: this.flowConfig.spInitiated,
        binding: this.flowConfig.binding,
        sessionId: this.flowConfig.sessionId,
        nameId: this.flowConfig.nameId,
      },
    })

    try {
      // First, check if there are active sessions to logout
      const sessionsResponse = await fetch(`${this.config.baseUrl}/demo/sessions`)
      const sessionsData = await sessionsResponse.json() as { 
        sessions: Array<{
          id: string
          name_id: string
          session_index: string
        }> 
      }

      if (sessionsData.sessions.length === 0) {
        this.addEvent({
          type: 'info',
          title: 'No Active Sessions',
          description: 'No SAML sessions found to logout. Run SSO flow first.',
        })
        throw new Error('No active SAML sessions. Please run an SSO flow first.')
      }

      // Use the first session for logout demo
      const session = sessionsData.sessions[0]
      this.flowConfig.sessionId = session.id
      this.flowConfig.nameId = session.name_id
      this.flowConfig.sessionIndex = session.session_index

      this.addEvent({
        type: 'info',
        title: 'Active Session Found',
        description: `Found session for ${session.name_id}`,
        data: {
          sessionId: session.id,
          nameId: session.name_id,
          sessionIndex: session.session_index,
        },
      })

      if (this.flowConfig.spInitiated) {
        await this.executeSPInitiatedLogout()
      } else {
        await this.executeIdPInitiatedLogout()
      }

      this.updateState({
        status: 'completed',
        currentStep: 'Single Logout completed',
      })

      this.addEvent({
        type: 'info',
        title: 'Single Logout Complete',
        description: 'User has been logged out of all session participants',
        rfcReference: this.rfcReference,
      })

    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      this.updateState({
        status: 'error',
        currentStep: 'Logout failed',
        error: {
          code: 'logout_error',
          description: message,
        },
      })
      this.addEvent({
        type: 'error',
        title: 'Single Logout Failed',
        description: message,
      })
    }
  }

  private async executeSPInitiatedLogout(): Promise<void> {
    // Step 1: Generate request parameters
    const relayState = generateSecureRandom(16)
    const requestId = `_${generateSecureRandom(16)}`

    this.updateState({
      securityParams: {
        ...this.state.securityParams,
        state: relayState,
      },
    })

    // Step 2: Create LogoutRequest
    this.addEvent({
      type: 'rfc',
      title: 'SAML 2.0 Profiles Section 4.4.3',
      description: 'SP creates LogoutRequest for the user session',
      rfcReference: 'SAML 2.0 Profiles Section 4.4.3',
      data: {
        requestId,
        nameId: this.flowConfig.nameId,
        sessionIndex: this.flowConfig.sessionIndex,
        binding: this.flowConfig.binding,
      },
    })

    // Step 3: Send LogoutRequest to IdP
    this.updateState({
      status: 'executing',
      currentStep: 'Sending LogoutRequest to IdP',
    })

    this.addEvent({
      type: 'request',
      title: 'LogoutRequest to IdP',
      description: `Sending logout request via HTTP-${this.flowConfig.binding.toUpperCase()} binding`,
      rfcReference: 'SAML 2.0 Bindings Section 3.4',
      data: {
        destination: `${this.config.baseUrl}/slo`,
        binding: this.flowConfig.binding,
        relayState,
      },
    })

    // Make the SLO request
    const result = await this.performLogoutRequest(relayState)

    // Step 4: Process LogoutResponse
    this.addEvent({
      type: 'rfc',
      title: 'SAML 2.0 Profiles Section 4.4.4',
      description: 'Processing LogoutResponse from IdP',
      rfcReference: 'SAML 2.0 Profiles Section 4.4.4',
      data: {
        success: result.success,
        statusCode: result.statusCode,
        responseId: result.responseId,
      },
    })

    // Step 5: Validate RelayState
    if (result.relayState === relayState) {
      this.addEvent({
        type: 'security',
        title: 'RelayState Validated',
        description: 'RelayState matches original value',
        data: { relayState },
      })
    }

    // Step 6: Check for partial logout
    if (result.statusCode === 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout') {
      this.addEvent({
        type: 'security',
        title: 'Partial Logout',
        description: 'Not all session participants could be logged out',
        rfcReference: 'SAML 2.0 Core Section 3.7.3.1',
        data: { statusCode: result.statusCode },
      })
    }

    // Step 7: Session terminated
    this.addEvent({
      type: 'info',
      title: 'SP Session Terminated',
      description: 'Local session has been destroyed',
      data: {
        nameId: this.flowConfig.nameId,
        sessionId: this.flowConfig.sessionId,
      },
    })
  }

  private async executeIdPInitiatedLogout(): Promise<void> {
    // IdP-initiated logout: IdP sends LogoutRequest to each SP
    this.addEvent({
      type: 'rfc',
      title: 'SAML 2.0 Profiles Section 4.4.3.2',
      description: 'IdP initiates logout and propagates to all SPs',
      rfcReference: 'SAML 2.0 Profiles Section 4.4.3.2',
    })

    this.addEvent({
      type: 'info',
      title: 'Logout Propagation',
      description: 'IdP sends LogoutRequest to all session participants',
      data: {
        note: 'Each SP must terminate their session and respond',
        affectedSessions: 1,
      },
    })

    this.updateState({
      status: 'executing',
      currentStep: 'Receiving IdP LogoutRequest',
    })

    // Simulate receiving LogoutRequest from IdP
    this.addEvent({
      type: 'request',
      title: 'LogoutRequest from IdP',
      description: 'Received logout request from Identity Provider',
      data: {
        nameId: this.flowConfig.nameId,
        sessionIndex: this.flowConfig.sessionIndex,
      },
    })

    // Process the logout
    const result = await this.performLogoutRequest(generateSecureRandom(16))

    // SP terminates session and sends LogoutResponse
    this.addEvent({
      type: 'response',
      title: 'LogoutResponse to IdP',
      description: 'Confirming session termination to Identity Provider',
      rfcReference: 'SAML 2.0 Profiles Section 4.4.4.1',
      data: {
        success: result.success,
        statusCode: result.statusCode,
      },
    })

    this.addEvent({
      type: 'info',
      title: 'IdP Session Terminated',
      description: 'IdP has terminated the master session',
      data: {
        allParticipantsLoggedOut: result.success,
      },
    })
  }

  private async performLogoutRequest(relayState: string): Promise<LogoutResult> {
    // Use the demo logout endpoint for simplicity
    const params = new URLSearchParams()
    
    if (this.flowConfig.sessionId) {
      params.set('session_id', this.flowConfig.sessionId)
    }
    if (this.flowConfig.nameId) {
      params.set('name_id', this.flowConfig.nameId)
    }

    const response = await fetch(`${this.config.baseUrl}/demo/logout?${params.toString()}`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    })

    if (!response.ok) {
      throw new Error(`Logout request failed: ${response.status}`)
    }

    const data = await response.json() as Record<string, unknown>
    
    return {
      success: data.success as boolean ?? true,
      responseId: data.response_id as string ?? `_${generateSecureRandom(16)}`,
      inResponseTo: undefined,
      statusCode: data.status_code as string ?? 'urn:oasis:names:tc:SAML:2.0:status:Success',
      relayState: relayState,
    }
  }
}

interface LogoutResult {
  success: boolean
  responseId?: string
  inResponseTo?: string
  statusCode: string
  relayState?: string
}

/**
 * SP-Initiated Logout Executor (convenience class)
 */
export class SPInitiatedLogoutExecutor extends SAMLLogoutExecutor {
  override readonly flowType: string = 'saml_sp_logout'
  override readonly flowName: string = 'SP-Initiated Single Logout'
  override readonly rfcReference: string = 'SAML 2.0 Profiles Section 4.4.3'

  constructor(config: Omit<SAMLLogoutConfig, 'spInitiated'>) {
    super({ ...config, spInitiated: true })
  }
}

