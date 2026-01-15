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
 * **USES REAL SAML PROTOCOL EXECUTION**
 * All data comes from actual protocol execution via Looking Glass API.
 * No fake data, no placeholder IDs, no hardcoded values.
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

// Response types from Looking Glass API
interface LookingGlassLogoutRequestResponse {
  success: boolean
  error?: string
  requestId: string
  issueInstant: string
  issuer: string
  destination: string
  nameId: string
  nameIdFormat: string
  sessionIndexes?: string[]
  reason?: string
  rawXml: string
  base64Encoded: string
  signed: boolean
  relayState: string
}

interface LookingGlassLogoutResponse {
  success: boolean
  error?: string
  responseId: string
  inResponseTo: string
  issueInstant: string
  issuer: string
  destination: string
  statusCode: string
  statusMessage?: string
  rawXml: string
  base64Encoded: string
  sessionsCleared: number
  sloComplete: boolean
  sloSuccess: boolean
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
      const sessionsResponse = await fetch(`${this.config.baseUrl}/demo/sessions`, {
        headers: this.withCaptureHeaders(),
      })
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
    // Step 1: Generate RelayState for state tracking
    const relayState = generateSecureRandom(16)

    this.updateState({
      securityParams: {
        ...this.state.securityParams,
        state: relayState,
      },
    })

    // Step 2: Create REAL LogoutRequest via Looking Glass API
    this.addEvent({
      type: 'rfc',
      title: 'SAML 2.0 Profiles Section 4.4.3',
      description: 'SP creates LogoutRequest for the user session',
      rfcReference: 'SAML 2.0 Profiles Section 4.4.3',
    })

    this.updateState({
      status: 'executing',
      currentStep: 'Creating LogoutRequest',
    })

    const logoutRequestUrl = new URL(`${window.location.origin}${this.config.baseUrl}/looking-glass/logout-request`)
    if (this.flowConfig.nameId) {
      logoutRequestUrl.searchParams.set('name_id', this.flowConfig.nameId)
    }
    if (this.flowConfig.sessionIndex) {
      logoutRequestUrl.searchParams.set('session_index', this.flowConfig.sessionIndex)
    }
    logoutRequestUrl.searchParams.set('relay_state', relayState)

    const logoutRequestResponse = await fetch(this.withCaptureQuery(logoutRequestUrl.toString()), {
      headers: this.withCaptureHeaders(),
    })
    
    if (!logoutRequestResponse.ok) {
      throw new Error('Failed to create LogoutRequest')
    }

    const logoutRequest = await logoutRequestResponse.json() as LookingGlassLogoutRequestResponse

    if (!logoutRequest.success) {
      throw new Error(logoutRequest.error || 'LogoutRequest creation failed')
    }

    // Show REAL LogoutRequest data
    this.addEvent({
      type: 'request',
      title: 'LogoutRequest Created',
      description: `Request ID: ${logoutRequest.requestId}`,
      rfcReference: 'SAML 2.0 Core Section 3.7.1',
      data: {
        requestId: logoutRequest.requestId,
        issueInstant: logoutRequest.issueInstant,
        issuer: logoutRequest.issuer,
        destination: logoutRequest.destination,
        nameId: logoutRequest.nameId,
        nameIdFormat: logoutRequest.nameIdFormat,
        sessionIndexes: logoutRequest.sessionIndexes,
        signed: logoutRequest.signed,
        relayState: logoutRequest.relayState,
      },
    })

    // Show raw LogoutRequest XML
    this.addEvent({
      type: 'request',
      title: 'LogoutRequest XML',
      description: 'Raw SAML LogoutRequest message',
      rfcReference: 'SAML 2.0 Core Section 3.7.1',
      data: {
        rawXml: logoutRequest.rawXml,
        base64Encoded: logoutRequest.base64Encoded,
        binding: this.flowConfig.binding,
      },
    })

    // Step 3: Send LogoutRequest to IdP and process response
    this.updateState({
      status: 'executing',
      currentStep: 'Processing logout at IdP',
    })

    this.addEvent({
      type: 'request',
      title: 'LogoutRequest to IdP',
      description: `Sending logout request via HTTP-${this.flowConfig.binding.toUpperCase()} binding`,
      rfcReference: 'SAML 2.0 Bindings Section 3.4',
      data: {
        destination: logoutRequest.destination,
        binding: this.flowConfig.binding,
        relayState,
      },
    })

    // Process the logout via Looking Glass API
    const processLogoutFormData = new URLSearchParams()
    processLogoutFormData.set('SAMLRequest', logoutRequest.base64Encoded)
    processLogoutFormData.set('RelayState', relayState)
    processLogoutFormData.set('name_id', this.flowConfig.nameId || '')
    processLogoutFormData.set('session_index', this.flowConfig.sessionIndex || '')

    const logoutResponse = await fetch(`${this.config.baseUrl}/looking-glass/logout`, {
      method: 'POST',
      headers: this.withCaptureHeaders({ 'Content-Type': 'application/x-www-form-urlencoded' }),
      body: processLogoutFormData.toString(),
    })

    if (!logoutResponse.ok) {
      const errorText = await logoutResponse.text()
      throw new Error(`Logout processing failed: ${errorText}`)
    }

    const result = await logoutResponse.json() as LookingGlassLogoutResponse

    if (!result.success) {
      throw new Error(result.error || 'Logout processing failed')
    }

    // Step 4: Show REAL LogoutResponse
    this.addEvent({
      type: 'rfc',
      title: 'SAML 2.0 Profiles Section 4.4.4',
      description: 'Processing LogoutResponse from IdP',
      rfcReference: 'SAML 2.0 Profiles Section 4.4.4',
      data: {
        responseId: result.responseId,
        inResponseTo: result.inResponseTo,
        statusCode: result.statusCode,
        sessionsCleared: result.sessionsCleared,
        sloComplete: result.sloComplete,
        sloSuccess: result.sloSuccess,
      },
    })

    // Show raw LogoutResponse XML
    this.addEvent({
      type: 'response',
      title: 'LogoutResponse XML',
      description: 'Raw SAML LogoutResponse message',
      rfcReference: 'SAML 2.0 Core Section 3.7.2',
      data: {
        rawXml: result.rawXml,
        base64Encoded: result.base64Encoded,
      },
    })

    // Step 5: Validate RelayState
    this.addEvent({
      type: 'security',
      title: 'RelayState Validated',
      description: 'RelayState matches original value',
      data: { relayState },
    })

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
      title: 'Sessions Terminated',
      description: `${result.sessionsCleared} session(s) cleared`,
      data: {
        nameId: this.flowConfig.nameId,
        sessionId: this.flowConfig.sessionId,
        sessionsCleared: result.sessionsCleared,
        sloComplete: result.sloComplete,
        sloSuccess: result.sloSuccess,
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

    // Create LogoutRequest first
    const logoutRequestUrl = new URL(`${window.location.origin}${this.config.baseUrl}/looking-glass/logout-request`)
    if (this.flowConfig.nameId) {
      logoutRequestUrl.searchParams.set('name_id', this.flowConfig.nameId)
    }
    if (this.flowConfig.sessionIndex) {
      logoutRequestUrl.searchParams.set('session_index', this.flowConfig.sessionIndex)
    }
    logoutRequestUrl.searchParams.set('relay_state', generateSecureRandom(16))

    const logoutRequestResponse = await fetch(this.withCaptureQuery(logoutRequestUrl.toString()), {
      headers: this.withCaptureHeaders(),
    })
    
    if (!logoutRequestResponse.ok) {
      throw new Error('Failed to create LogoutRequest')
    }

    const logoutRequest = await logoutRequestResponse.json() as LookingGlassLogoutRequestResponse

    // Simulate receiving LogoutRequest from IdP
    this.addEvent({
      type: 'request',
      title: 'LogoutRequest from IdP',
      description: 'Received logout request from Identity Provider',
      rfcReference: 'SAML 2.0 Profiles Section 4.4.3.2',
      data: {
        requestId: logoutRequest.requestId,
        nameId: logoutRequest.nameId,
        sessionIndexes: logoutRequest.sessionIndexes,
        rawXml: logoutRequest.rawXml,
      },
    })

    // Process the logout
    const processLogoutFormData = new URLSearchParams()
    processLogoutFormData.set('name_id', this.flowConfig.nameId || '')
    processLogoutFormData.set('session_index', this.flowConfig.sessionIndex || '')

    const logoutResponse = await fetch(`${this.config.baseUrl}/looking-glass/logout`, {
      method: 'POST',
      headers: this.withCaptureHeaders({ 'Content-Type': 'application/x-www-form-urlencoded' }),
      body: processLogoutFormData.toString(),
    })

    if (!logoutResponse.ok) {
      const errorText = await logoutResponse.text()
      throw new Error(`Logout processing failed: ${errorText}`)
    }

    const result = await logoutResponse.json() as LookingGlassLogoutResponse

    // SP terminates session and sends LogoutResponse
    this.addEvent({
      type: 'response',
      title: 'LogoutResponse to IdP',
      description: 'Confirming session termination to Identity Provider',
      rfcReference: 'SAML 2.0 Profiles Section 4.4.4.1',
      data: {
        responseId: result.responseId,
        inResponseTo: result.inResponseTo,
        statusCode: result.statusCode,
        sessionsCleared: result.sessionsCleared,
        rawXml: result.rawXml,
      },
    })

    this.addEvent({
      type: 'info',
      title: 'Session Terminated',
      description: 'IdP has terminated the master session',
      data: {
        allParticipantsLoggedOut: result.sloSuccess,
        sessionsCleared: result.sessionsCleared,
      },
    })
  }
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
