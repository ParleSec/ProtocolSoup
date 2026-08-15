/**
 * OID4VCI Issuer-Initiated Credential Offer
 *
 * Builds a real OpenID4VCI 1.0 Section 4.1 Credential Offer for the
 * authorization_code grant (with a server-generated issuer_state) and either
 * an openid-credential-offer:// invocation URI or an HTTPS delivery URL for
 * an explicitly supplied external Credential Offer Endpoint.
 *
 * Looking Glass never impersonates the wallet for this flow. After creating
 * (and optionally delivering) the offer, a real wallet — the hosted wallet
 * harness or another OID4VCI wallet — must complete PAR, authorization_code
 * redemption, token exchange, and credential issuance. Looking Glass only
 * observes issuer-side status via status_uri using the same awaiting_user /
 * "Check Result" chrome as OID4VP wallet-callback flows (no browser-side
 * token/proof client).
 */

import { FlowExecutorBase, type FlowExecutorConfig } from './base'

export interface OID4VCIIssuerInitiatedConfig extends FlowExecutorConfig {
  credentialConfigurationID?: string
  /**
   * Absolute URL of the external wallet's OID4VCI 1.0 §4.1 Credential
   * Offer Endpoint (e.g. a test wallet module's exposed
   * `credential_offer_endpoint`). When absent, the executor produces the
   * standard openid-credential-offer:// invocation form for QR/deep-link use.
   */
  walletOfferEndpoint?: string
}

export class OID4VCIIssuerInitiatedExecutor extends FlowExecutorBase {
  readonly flowType = 'oid4vci_issuer_initiated'
  readonly flowName = 'OID4VCI Issuer-Initiated Offer'
  readonly rfcReference = 'OpenID4VCI 1.0 Section 4.1'

  private flowConfig: OID4VCIIssuerInitiatedConfig

  constructor(config: OID4VCIIssuerInitiatedConfig) {
    super(config)
    this.flowConfig = config
  }

  async execute(): Promise<void> {
    if (this.state.status === 'executing') {
      return
    }

    if (this.state.status === 'awaiting_user') {
      const statusURI = String(this.state.securityParams.statusUri || '').trim()
      const deadline = Number(this.state.securityParams.statusDeadline)
      if (!statusURI || !Number.isFinite(deadline)) {
        this.updateState({
          status: 'error',
          currentStep: 'OID4VCI flow failed',
          error: { code: 'oid4vci_flow_failed', description: 'Missing status_uri for issuer-initiated status check' },
        })
        return
      }

      this.abortController = new AbortController()
      this.updateState({ status: 'executing', currentStep: 'Checking issuer-initiated issuance status' })
      try {
        const outcome = await this.checkIssuanceStatus(statusURI, deadline)
        if (outcome === 'pending') {
          this.updateState({
            status: 'awaiting_user',
            currentStep: 'Waiting for wallet response callback',
          })
          this.addEvent({
            type: 'info',
            title: 'Still Waiting for Wallet Callback',
            description: `${this.describeStatus(this.lastKnownIssuanceStatus())} Complete wallet handoff, then check again.`,
          })
        }
      } catch (error) {
        if (error instanceof DOMException && error.name === 'AbortError') {
          return
        }
        const description = error instanceof Error ? error.message : 'Issuer-initiated status check failed'
        this.updateState({
          status: 'error',
          currentStep: 'OID4VCI flow failed',
          error: { code: 'oid4vci_flow_failed', description },
        })
        this.addEvent({ type: 'error', title: 'OID4VCI Execution Failed', description })
      }
      return
    }

    this.abortController = new AbortController()
    this.updateState({
      ...this.createInitialState(),
      status: 'executing',
      currentStep: 'Creating issuer-initiated credential offer',
    })

    try {
      const offerData = await this.createOffer()
      const offer = offerData.credential_offer as Record<string, unknown> | undefined
      if (!offer || typeof offer !== 'object') {
        throw new Error('Offer response missing credential_offer')
      }
      const issuerState = String(offerData.issuer_state || '').trim()
      const statusURI = String(offerData.status_uri || '').trim()
      const expiresIn = Number(offerData.expires_in)
      if (!issuerState || !statusURI || !Number.isFinite(expiresIn) || expiresIn <= 0) {
        throw new Error('Offer response missing issuer_state, status_uri, or expires_in')
      }
      const credentialConfigurationIds = Array.isArray(offerData.credential_configuration_ids)
        ? offerData.credential_configuration_ids.map((id) => String(id))
        : []

      this.addVCArtifact({
        type: 'credential_offer',
        title: 'Issuer-Initiated Credential Offer',
        format: 'openid4vci-offer',
        rfcReference: 'OpenID4VCI 1.0 Section 4.1',
        raw: JSON.stringify(offer, null, 2),
        metadata: {
          credentialIssuer: offerData.credential_issuer,
          credentialConfigurationIds,
          issuerState,
          grantType: 'authorization_code',
        },
      })

      const configuredWalletEndpoint = String(this.flowConfig.walletOfferEndpoint || '').trim()
      const delivered = offerData.credential_offer_delivered === true
      const deliveryURL = String(
        offerData.credential_offer_delivery_url
          || (configuredWalletEndpoint ? this.buildDeliveryURL(configuredWalletEndpoint, offer) : this.buildWalletInvocationURI(offer)),
      ).trim()
      this.addVCArtifact({
        type: 'wallet_handoff',
        title: delivered ? 'Credential Offer Delivered' : (configuredWalletEndpoint ? 'Deliver Offer to External Wallet' : 'Invoke Compatible Wallet'),
        format: 'openid4vci-offer-delivery',
        rfcReference: 'OpenID4VCI 1.0 Section 4.1.2',
        raw: deliveryURL,
        metadata: {
          walletOfferEndpoint: configuredWalletEndpoint || undefined,
          issuerState,
          credentialConfigurationIds,
          transport: configuredWalletEndpoint ? 'https' : 'openid-credential-offer',
          delivered,
          deliveryStatus: offerData.credential_offer_delivery_status,
          qrPayload: deliveryURL,
        },
      })
      this.addEvent({
        type: 'user_action',
        title: delivered ? 'Wallet Handoff Delivered' : 'Wallet Handoff Ready',
        description: delivered
          ? 'The issuer delivered the Credential Offer to the wallet credential_offer_endpoint. Click "Check Result" once the wallet has completed PAR, token exchange, and credential issuance.'
          : 'Share deep link or QR payload with a real wallet and wait for the issuer-observed authorization_code lifecycle',
        rfcReference: 'OpenID4VCI 1.0 Section 4.1.2',
        data: {
          walletOfferEndpoint: configuredWalletEndpoint || undefined,
          transport: configuredWalletEndpoint ? 'https' : 'openid-credential-offer',
          delivered,
          deliveryStatus: offerData.credential_offer_delivery_status,
          qr_payload: deliveryURL,
        },
      })

      const deadline = Date.now() + expiresIn * 1000
      const outcome = await this.checkIssuanceStatus(statusURI, deadline)
      if (outcome === 'pending') {
        this.updateState({
          status: 'awaiting_user',
          currentStep: 'Waiting for wallet response callback',
          securityParams: {
            ...this.state.securityParams,
            statusUri: statusURI,
            statusDeadline: String(deadline),
          },
        })
      }
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        return
      }
      const description = error instanceof Error ? error.message : 'Unknown OID4VCI flow error'
      this.updateState({
        status: 'error',
        currentStep: 'OID4VCI flow failed',
        error: { code: 'oid4vci_flow_failed', description },
      })
      this.addEvent({
        type: 'error',
        title: 'OID4VCI Execution Failed',
        description,
      })
    }
  }

  private async createOffer(): Promise<Record<string, unknown>> {
    this.updateState({ currentStep: 'Creating issuer-initiated credential offer' })

    const walletOfferEndpoint = String(this.flowConfig.walletOfferEndpoint || '').trim()
    const requestBody: Record<string, unknown> = {
      credential_configuration_ids: [this.selectedCredentialConfigurationID()],
    }
    if (walletOfferEndpoint) {
      requestBody.credential_offer_endpoint = walletOfferEndpoint
    }

    const { response, data } = await this.makeRequest('POST', `${this.config.baseUrl}/offers/authorization-code`, {
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
      step: walletOfferEndpoint
        ? 'Create and deliver authorization_code credential offer'
        : 'Create authorization_code credential offer',
      rfcReference: 'OpenID4VCI 1.0 Sections 4.1 and 4.1.2',
    })

    if (!response.ok) {
      const errorData = data as Record<string, unknown>
      throw new Error(String(errorData.error_description || errorData.error || `Offer creation failed (${response.status})`))
    }

    const offerData = data as Record<string, unknown>
    this.addEvent({
      type: 'info',
      title: offerData.credential_offer_delivered === true ? 'Offer Created and Delivered' : 'Offer Created',
      description: offerData.credential_offer_delivered === true
        ? `issuer_state: ${String(offerData.issuer_state || 'unknown')}; delivered to wallet credential_offer_endpoint (HTTP ${String(offerData.credential_offer_delivery_status || '')})`
        : `issuer_state: ${String(offerData.issuer_state || 'unknown')}`,
      data: {
        credentialConfigurationIds: offerData.credential_configuration_ids,
        issuerState: offerData.issuer_state,
        credentialOfferEndpoint: offerData.credential_offer_endpoint,
        delivered: offerData.credential_offer_delivered === true,
        deliveryStatus: offerData.credential_offer_delivery_status,
      },
    })
    return offerData
  }

  private buildDeliveryURL(walletOfferEndpoint: string, offer: Record<string, unknown>): string {
    let target: URL
    try {
      target = new URL(walletOfferEndpoint)
    } catch {
      throw new Error(`Wallet credential_offer_endpoint is not a valid absolute URL: ${walletOfferEndpoint}`)
    }
    if (target.protocol !== 'https:') {
      throw new Error('Wallet credential_offer_endpoint must use https:// (OID4VCI 1.0 Section 4.1)')
    }
    target.searchParams.set('credential_offer', JSON.stringify(offer))
    return target.toString()
  }

  private buildWalletInvocationURI(offer: Record<string, unknown>): string {
    const target = new URL('openid-credential-offer://')
    target.searchParams.set('credential_offer', JSON.stringify(offer))
    return target.toString()
  }

  /**
   * Performs a single check of the issuer-observed lifecycle status_uri and
   * returns whether the wallet's conversation with the issuer has finished.
   * Called once from the initial run and again each time the operator clicks
   * "Check Result" -- mirroring the OID4VP wallet-callback awaiting_user
   * chrome, rather than polling on an internal timer.
   */
  private async checkIssuanceStatus(statusURI: string, deadline: number): Promise<'pending' | 'completed'> {
    if (Date.now() >= deadline) {
      throw new Error('Issuer-initiated offer expired before credential issuance completed')
    }

    const fetchURL = this.sameOriginURL(statusURI)
    const { response, data } = await this.makeRequest('GET', fetchURL, {
      headers: { Accept: 'application/json' },
      step: 'Check issuer-initiated issuance status',
      rfcReference: 'OpenID4VCI 1.0 Sections 4.1 and 5.1.3',
    })
    if (!response.ok) {
      const errorData = data as Record<string, unknown>
      throw new Error(String(errorData.error_description || errorData.error || `Status request failed (${response.status})`))
    }

    const payload = data as Record<string, unknown>
    const status = String(payload.status || '').trim()
    if (!status) {
      throw new Error('Issuer-initiated status response missing status')
    }

    if (status !== this.lastKnownIssuanceStatus()) {
      this.addVCArtifact({
        type: 'wallet_lifecycle',
        title: this.describeStatusTitle(status),
        format: 'oid4vci-issuer-initiated-status',
        rfcReference: 'OpenID4VCI 1.0 Sections 4.1 and 5.1.3',
        json: payload,
        metadata: { status },
      })
      this.addEvent({
        type: status === 'expired' ? 'error' : 'info',
        title: this.describeStatusTitle(status),
        description: this.describeStatus(status),
        data: { status },
      })
    }

    if (status === 'credential_issued') {
      this.updateState({
        status: 'completed',
        currentStep: 'Issuer-initiated credential issuance completed',
      })
      return 'completed'
    }
    if (status === 'expired' || payload.terminal === true) {
      throw new Error('Issuer-initiated offer expired before credential issuance completed')
    }
    return 'pending'
  }

  /** Reads the most recently observed lifecycle status from captured artifacts. */
  private lastKnownIssuanceStatus(): string {
    const artifacts = this.state.vcArtifacts
    for (let i = artifacts.length - 1; i >= 0; i -= 1) {
      if (artifacts[i].type === 'wallet_lifecycle') {
        return String((artifacts[i].metadata as Record<string, unknown> | undefined)?.status || '')
      }
    }
    return ''
  }

  private sameOriginURL(statusURI: string): string {
    const parsed = new URL(statusURI, window.location.origin)
    return parsed.origin === window.location.origin
      ? parsed.toString()
      : `${parsed.pathname}${parsed.search}`
  }

  private describeStatusTitle(status: string): string {
    switch (status) {
      case 'waiting_for_wallet':
        return 'Waiting for Wallet'
      case 'authorization_request_received':
        return 'Authorization Request Received'
      case 'token_issued':
        return 'Access Token Issued'
      case 'credential_issued':
        return 'Credential Issued'
      case 'expired':
        return 'Credential Offer Expired'
      default:
        return `Issuer Status: ${status}`
    }
  }

  private describeStatus(status: string): string {
    switch (status) {
      case 'waiting_for_wallet':
        return 'The issuer-created context is live. Open the handoff URL or scan the QR code to send the Credential Offer to a wallet.'
      case 'authorization_request_received':
        return 'The wallet returned the exact issuer_state in a validated pushed Authorization Request.'
      case 'token_issued':
        return 'The wallet redeemed its authorization code and received a sender-constrained access token.'
      case 'credential_issued':
        return 'The wallet submitted a valid nonce-bound proof and the issuer issued the requested credential.'
      case 'expired':
        return 'The issuer-created processing context expired before issuance completed.'
      default:
        return `The issuer reported lifecycle status ${status}.`
    }
  }

  private selectedCredentialConfigurationID(): string {
    const configured = String(this.flowConfig.credentialConfigurationID || '').trim()
    // Default: the HAIP mDL configuration that issuer-initiated
    // authorization_code offers are most commonly built for.
    return configured || 'MobileDrivingLicenceMsoMdocHAIP'
  }
}
