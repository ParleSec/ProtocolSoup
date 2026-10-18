/**
 * SAML SSO Flow Executor
 *
 * Implements SAML 2.0 Web Browser SSO:
 * - SP-initiated SSO (SAML 2.0 Profiles Section 4.1.3), starting at the SP's
 *   /saml/sp/login, which sends a signed <AuthnRequest> over HTTP-Redirect or
 *   HTTP-POST
 * - IdP-initiated SSO (SAML 2.0 Profiles Section 4.1.5), starting at the IdP's
 *   /saml/idp/initiate
 *
 * The user signs in at the IdP in a popup; the IdP posts the signed <Response>
 * to the SP's assertion consumer service, whose outcome page reports what it
 * received and every check it ran.
 */

import { type FlowExecutorConfig, generateSecureRandom } from './base'
import { SAMLBrowserExecutor, type SAMLSessionInfo } from './saml-browser'

export interface SAMLSSOConfig extends FlowExecutorConfig {
  /** Whether this is SP-initiated (true) or IdP-initiated (false) */
  spInitiated: boolean
  /** SAML binding for the AuthnRequest: 'post' or 'redirect' */
  binding: 'post' | 'redirect'
}

export class SAMLSSOExecutor extends SAMLBrowserExecutor {
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
      await this.loadSPMetadata()

      let path: string
      if (this.flowConfig.spInitiated) {
        // RelayState MUST NOT exceed 80 bytes (SAML Bindings Section 3.4.3).
        const relayState = generateSecureRandom(16)
        this.updateState({ securityParams: { ...this.state.securityParams, state: relayState } })
        path = `/sp/login?binding=${this.flowConfig.binding}&RelayState=${encodeURIComponent(relayState)}`
        this.addEvent({
          type: 'rfc',
          title: 'SP-Initiated SSO',
          description: `The SP sends a signed <AuthnRequest> over HTTP-${this.flowConfig.binding === 'redirect' ? 'Redirect' : 'POST'}; the IdP answers with a <Response> over HTTP-POST`,
          rfcReference: 'SAML 2.0 Profiles Section 4.1.3',
          data: { binding: this.flowConfig.binding, relayState },
        })
      } else {
        path = '/idp/initiate'
        this.addEvent({
          type: 'rfc',
          title: 'Unsolicited Response',
          description: 'The IdP sends a <Response> without a preceding <AuthnRequest>, so it carries no InResponseTo',
          rfcReference: 'SAML 2.0 Profiles Section 4.1.5',
        })
      }

      const outcome = await this.runInPopup(path, 'Sign in at the IdP once; later SSO runs reuse the IdP session without asking again')
      this.reportOutcome(outcome)

      const session = outcome.details?.session as SAMLSessionInfo | undefined
      if (session) {
        this.addEvent({
          type: 'info',
          title: 'SP Session Created',
          description: `Session ${session.sessionId} for ${session.nameId}`,
          data: { ...session },
        })
      }
      this.updateState({ status: 'completed', currentStep: 'SSO completed' })
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
