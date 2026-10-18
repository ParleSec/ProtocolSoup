/**
 * Shared base for the SAML flow executors.
 *
 * SAML's front-channel bindings run through the user agent, so these
 * executors open a popup at the real SP or IdP endpoint and let the browser
 * follow the HTTP-Redirect and HTTP-POST hops itself (SAML Bindings Sections
 * 3.4 and 3.5). Every hop carries lg_session, so the backend's capture
 * middleware and the SAML roles record the real exchanges in this Looking
 * Glass session. The entity that receives the last message answers with an
 * outcome page, which hands the executor what it actually received and every
 * check it ran.
 */

import { FlowExecutorBase } from './base'

export interface SAMLValidationCheck {
  name: string
  passed: boolean
  detail: string
  reference: string
}

export interface SAMLValidationReport {
  signed: boolean
  signature?: {
    signatureMethod: string
    digestMethod: string
    canonicalization: string
    referenceUri: string
  }
  checks: SAMLValidationCheck[]
}

/** The outcome an ACS or SingleLogoutService page reports (binding.Outcome). */
export interface SAMLOutcome {
  flow: 'sso' | 'slo'
  entity: string
  title: string
  success: boolean
  error?: string
  binding: string
  param: string
  relayState?: string
  receivedXml: string
  validation?: SAMLValidationReport
  reference: string
  details?: Record<string, unknown>
}

export interface SAMLSessionInfo {
  sessionId: string
  peerEntityId: string
  nameId: string
  nameIdFormat: string
  sessionIndex: string
}

export abstract class SAMLBrowserExecutor extends FlowExecutorBase {
  /** Origins the SAML outcome pages are served from. */
  private samlOrigins = new Set<string>([window.location.origin])

  /**
   * Fetches the SP's metadata (SAML Metadata Section 4.1.1: published at its
   * entityID) and trusts outcome messages from the entityID's origin.
   */
  protected async loadSPMetadata(): Promise<void> {
    const response = await fetch(this.withCaptureQuery(`${this.config.baseUrl}/sp/metadata`), {
      headers: this.withCaptureHeaders(),
    })
    const xml = await response.text()
    if (!response.ok) {
      throw new Error(`SP metadata: HTTP ${response.status}: ${xml}`)
    }
    const entityID = new DOMParser().parseFromString(xml, 'application/xml').documentElement.getAttribute('entityID') ?? ''
    this.samlOrigins.add(new URL(entityID, window.location.origin).origin)
    this.addEvent({
      type: 'info',
      title: 'SP Metadata',
      description: `EntityDescriptor for ${entityID}, served as ${response.headers.get('Content-Type') ?? 'unknown content type'}`,
      rfcReference: 'SAML Metadata Section 4.1.1',
      data: { entityID, rawXml: xml },
    })
  }

  /**
   * Opens the SAML endpoint at path (relative to the protocol base URL) in a
   * popup and resolves with the outcome page's report.
   */
  protected runInPopup(path: string, description: string): Promise<SAMLOutcome> {
    return new Promise((resolve, reject) => {
      const url = this.withCaptureQuery(`${window.location.origin}${this.config.baseUrl}${path}`)
      const isMobile = window.innerWidth < 640
      const width = isMobile ? window.screen.width : 720
      const height = isMobile ? window.screen.height : 800
      const left = isMobile ? 0 : window.screenX + (window.outerWidth - width) / 2
      const top = isMobile ? 0 : window.screenY + (window.outerHeight - height) / 2
      const popup = window.open(url, 'saml_browser', `width=${width},height=${height},left=${left},top=${top},scrollbars=yes,resizable=yes`)
      if (!popup) {
        reject(new Error('Popup blocked - please allow popups for this site'))
        return
      }

      this.updateState({ status: 'awaiting_user', currentStep: description })
      this.addEvent({
        type: 'user_action',
        title: 'SAML Window Opened',
        description,
        data: { url },
      })

      const cleanup = () => {
        clearInterval(pollTimer)
        window.removeEventListener('message', handleMessage)
      }
      const handleMessage = (event: MessageEvent) => {
        if (event.source !== popup || !this.samlOrigins.has(event.origin)) return
        if (event.data?.type !== 'saml_outcome') return
        cleanup()
        popup.close()
        this.updateState({ status: 'executing' })
        resolve(event.data.outcome as SAMLOutcome)
      }
      window.addEventListener('message', handleMessage)

      const pollTimer = setInterval(() => {
        if (popup.closed) {
          cleanup()
          reject(new Error('The SAML window was closed before the exchange finished'))
        }
      }, 500)

      this.abortController?.signal.addEventListener('abort', () => {
        cleanup()
        popup.close()
      })
    })
  }

  /** Adds the received message and the receiving entity's checks as events. */
  protected reportOutcome(outcome: SAMLOutcome): void {
    this.addEvent({
      type: 'response',
      title: `${outcome.param} received`,
      description: `Delivered to ${outcome.entity} over ${outcome.binding}`,
      rfcReference: outcome.reference,
      data: {
        binding: outcome.binding,
        relayState: outcome.relayState,
        rawXml: outcome.receivedXml,
      },
    })
    if (outcome.validation) {
      const failed = outcome.validation.checks.find((check) => !check.passed)
      this.addEvent({
        type: outcome.success ? 'security' : 'error',
        title: outcome.title,
        description: failed ? `${failed.name}: ${failed.detail} (${failed.reference})` : 'Every check passed',
        rfcReference: outcome.reference,
        data: { ...outcome.validation },
      })
    }
    if (!outcome.success) {
      throw new Error(outcome.error || `${outcome.title}: rejected`)
    }
  }
}
