/**
 * SAML Single Logout (SLO) Flow Executor
 *
 * Implements the SAML 2.0 Single Logout Profile (SAML 2.0 Profiles Section
 * 4.4) over the front-channel bindings:
 * - SP-initiated: the SP's /saml/sp/logout sends a signed <LogoutRequest> to
 *   the IdP (Section 4.4.3.1)
 * - IdP-initiated: the IdP's /saml/idp/logout sends a signed <LogoutRequest>
 *   to the SP (Section 4.4.3.3)
 *
 * The recipient ends its sessions and returns a signed <LogoutResponse>; the
 * initiator's SingleLogoutService outcome page reports what it received and
 * every check it ran.
 */

import { type FlowExecutorConfig, generateSecureRandom } from './base'
import { SAMLBrowserExecutor, type SAMLSessionInfo } from './saml-browser'

export interface SAMLLogoutConfig extends FlowExecutorConfig {
  /** SAML binding to use: 'post' or 'redirect' */
  binding: 'post' | 'redirect'
  /** Whether logout is initiated by the SP (true) or the IdP (false) */
  spInitiated: boolean
}

export class SAMLLogoutExecutor extends SAMLBrowserExecutor {
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

    try {
      await this.loadSPMetadata()

      const sessionsResponse = await fetch(this.withCaptureQuery(`${this.config.baseUrl}/demo/sessions`), {
        headers: this.withCaptureHeaders(),
      })
      if (!sessionsResponse.ok) {
        throw new Error(`Session list: HTTP ${sessionsResponse.status}`)
      }
      const sessions = await sessionsResponse.json() as { sp: SAMLSessionInfo[]; idp: SAMLSessionInfo[] }
      const session = this.flowConfig.spInitiated ? sessions.sp[0] : sessions.idp[0]
      if (!session) {
        throw new Error(`No active SAML session at the ${initiator}. Run an SSO flow first.`)
      }
      this.addEvent({
        type: 'info',
        title: `${initiator} Session`,
        description: `Logging out ${session.nameId} (SessionIndex ${session.sessionIndex})`,
        data: { ...session },
      })

      // RelayState MUST NOT exceed 80 bytes (SAML Bindings Section 3.4.3).
      const relayState = generateSecureRandom(16)
      this.updateState({ securityParams: { ...this.state.securityParams, state: relayState } })
      const query = `binding=${this.flowConfig.binding}&session_id=${encodeURIComponent(session.sessionId)}&RelayState=${encodeURIComponent(relayState)}`
      const path = this.flowConfig.spInitiated ? `/sp/logout?${query}` : `/idp/logout?${query}`
      this.addEvent({
        type: 'rfc',
        title: `${initiator}-Initiated Single Logout`,
        description: `The ${initiator} sends a signed <LogoutRequest> over HTTP-${this.flowConfig.binding === 'redirect' ? 'Redirect' : 'POST'}`,
        rfcReference: this.flowConfig.spInitiated ? 'SAML 2.0 Profiles Section 4.4.3.1' : 'SAML 2.0 Profiles Section 4.4.3.3',
        data: { binding: this.flowConfig.binding, relayState },
      })

      const outcome = await this.runInPopup(path, 'The browser carries the LogoutRequest and LogoutResponse between the SP and the IdP')
      this.reportOutcome(outcome)
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
}
