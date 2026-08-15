/**
 * OID4VCI Pre-Authorized Code Flow Executor
 *
 * Looking Glass is a glass box over the real OID4VCI stages:
 * 1. Create Credential Offer (issuer)
 * 2. Wallet→issuer hops returned as `_protocol_exchanges`:
 *    metadata, token, nonce, proof JWT, credential (and deferred/notification)
 *
 * The hosted wallet performs wallet-role crypto; Looking Glass does not invent
 * those hops — it surfaces the real request/response transcript the wallet recorded.
 */

import { FlowExecutorBase, type FlowExecutorConfig, type CredentialInspectionMetadata } from './base'
import { decodeJWTWithoutValidation } from '../../utils/crypto'
import { api } from '../../utils/api'
import {
  walletImportOffer,
  WalletAPIRequestError,
  type WalletImportResponse,
  type WalletProtocolExchange,
} from '../wallet-client'

export interface OID4VCIPreAuthorizedConfig extends FlowExecutorConfig {
  txCodeRequired?: boolean
  deferred?: boolean
  credentialConfigurationID?: string
  credentialFormat?: string
}

export class OID4VCIPreAuthorizedExecutor extends FlowExecutorBase {
  readonly flowType = 'oid4vci_pre_authorized'
  readonly flowName = 'OID4VCI Pre-Authorized Code'
  readonly rfcReference = 'OpenID4VCI 1.0'

  private flowConfig: OID4VCIPreAuthorizedConfig

  constructor(config: OID4VCIPreAuthorizedConfig) {
    super(config)
    this.flowConfig = config
  }

  async execute(): Promise<void> {
    if (this.state.status === 'executing') {
      return
    }

    if (this.state.status === 'awaiting_user') {
      // Authorization-code continuation: the wallet completes PAR/auth in its
      // own UI. Re-check only emits guidance; the issuer wire stream carries
      // the real protocol exchanges once the wallet resumes.
      this.updateState({
        status: 'awaiting_user',
        currentStep: 'Waiting for wallet authorization continuation',
      })
      this.addEvent({
        type: 'info',
        title: 'Still Waiting for Wallet Authorization',
        description:
          'Complete authorization in the wallet harness (Continue to Issuer), then re-run this flow or refresh Looking Glass events. Looking Glass does not redeem authorization codes in-browser.',
      })
      return
    }

    this.abortController = new AbortController()
    this.updateState({
      ...this.createInitialState(),
      status: 'executing',
      currentStep: 'Starting OID4VCI pre-authorized flow',
    })

    try {
      const offerData = await this.createOffer()
      const offerInput = this.buildWalletOfferInput(offerData)
      const txCode = this.extractTxCodeFromOffer(offerData)

      this.updateState({ currentStep: 'Wallet redeeming offer with issuer' })
      this.addEvent({
        type: 'info',
        title: 'Offer Ready for Wallet Redemption',
        description:
          'Credential Offer created. Next Looking Glass steps are the real wallet→issuer protocol hops (metadata, token, nonce, proof, credential).',
        rfcReference: 'OpenID4VCI 1.0 Sections 4, 6–8',
        data: {
          txCodeProvided: Boolean(txCode),
          deferred: !!this.flowConfig.deferred,
          credentialConfigurationID: this.selectedCredentialConfigurationID(),
          credentialFormat: this.selectedCredentialFormat(),
        },
      })

      const walletResponse = await this.importOfferViaWallet(offerInput, txCode)
      this.surfaceWalletProtocolTranscript(walletResponse)

      if (walletResponse.authorization_required && walletResponse.authorization_url) {
        const authorizationURL = String(walletResponse.authorization_url).trim()
        this.addVCArtifact({
          type: 'wallet_handoff',
          title: 'Issuer Authorization Required',
          format: 'oid4vci-authorization-url',
          rfcReference: 'OpenID4VCI 1.0 Section 3.5',
          raw: authorizationURL,
          metadata: {
            credentialIssuer: walletResponse.credential_issuer,
            authorizationRequired: true,
          },
        })
        this.updateState({
          status: 'awaiting_user',
          currentStep: 'Waiting for authorization code at wallet',
          securityParams: {
            ...this.state.securityParams,
            authorizationUrl: authorizationURL,
            credentialIssuer: String(walletResponse.credential_issuer || ''),
          },
        })
        this.addEvent({
          type: 'user_action',
          title: 'Authorization Required',
          description:
            'Issuer requires the authorization_code grant. Complete authorization in the wallet, then refresh Looking Glass events to see PAR/token/credential hops.',
          rfcReference: 'OpenID4VCI 1.0 Section 3.5',
          data: {
            authorizationUrl: authorizationURL,
            credentialIssuer: walletResponse.credential_issuer,
          },
        })
        return
      }

      const credentialJWT = String(walletResponse.credential_jwt || '').trim()
      if (!credentialJWT) {
        throw new Error('Issuance completed without returning a credential')
      }

      if (this.flowConfig.deferred) {
        this.addVCArtifact({
          type: 'deferred_status',
          title: 'Deferred Credential Issued',
          format: 'oid4vci-deferred',
          rfcReference: 'OpenID4VCI 1.0 Section 9',
          metadata: {
            deferredFlow: true,
            deferredStatus: 'completed',
            credentialSource: walletResponse.credential_source,
          },
        })
        this.addEvent({
          type: 'info',
          title: 'Deferred Credential Ready',
          description:
            'Issuer returned transaction_id; wallet polled deferred_credential until credentials were available (OpenID4VCI 1.0 §9).',
          rfcReference: 'OpenID4VCI 1.0 Section 9',
          data: {
            credentialSource: walletResponse.credential_source,
            credentialId: walletResponse.credential_id,
          },
        })
      }

      await this.captureCredential(credentialJWT, {
        format: this.selectedCredentialFormat(walletResponse),
        credentialConfigurationID:
          String(walletResponse.credential_configuration_id || '').trim() ||
          this.selectedCredentialConfigurationID(),
        credentialSource: walletResponse.credential_source,
        credentialIssuer: walletResponse.credential_issuer,
        deferredFlow: !!this.flowConfig.deferred,
      })

      this.recordOfferArtifacts(walletResponse)

      this.updateState({
        status: 'completed',
        currentStep: 'Credential issued',
      })
    } catch (error) {
      const description = error instanceof Error ? error.message : 'Unknown OID4VCI flow error'
      this.updateState({
        status: 'error',
        currentStep: 'OID4VCI flow failed',
        error: {
          code: 'oid4vci_flow_failed',
          description,
        },
      })
      this.addEvent({
        type: 'error',
        title: 'OID4VCI Execution Failed',
        description,
      })
    }
  }

  private async createOffer(): Promise<Record<string, unknown>> {
    this.updateState({ currentStep: 'Creating credential offer' })

    const endpoint = this.flowConfig.deferred
      ? `${this.config.baseUrl}/offers/pre-authorized/deferred`
      : `${this.config.baseUrl}/offers/pre-authorized`

    const { response, data } = await this.makeRequest('POST', endpoint, {
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tx_code_required: !!this.flowConfig.txCodeRequired,
        credential_configuration_ids: [this.selectedCredentialConfigurationID()],
      }),
      step: 'Create pre-authorized credential offer',
      rfcReference: 'OpenID4VCI 1.0 Section 4',
    })

    if (!response.ok) {
      throw new Error(`Offer creation failed (${response.status})`)
    }

    const offerData = data as Record<string, unknown>
    const offerURI = typeof offerData.credential_offer_uri === 'string' ? offerData.credential_offer_uri : ''
    const txCodeOOBValue = this.extractTxCodeFromOffer(offerData)
    if (offerURI) {
      this.addVCArtifact({
        type: 'credential_offer_reference',
        title: 'Credential Offer URI',
        format: 'openid-credential-offer-uri',
        rfcReference: 'OpenID4VCI 1.0 Section 4.1',
        raw: offerURI,
        metadata: {
          offerId: offerData.offer_id,
          deferred: !!offerData.deferred,
          txCodeRequired: !!offerData.tx_code_required,
          txCodeOOBValue,
        },
      })
    }

    if (txCodeOOBValue) {
      this.addEvent({
        type: 'user_action',
        title: 'tx_code Received (Out-of-Band)',
        description: 'Issuer provided an out-of-band tx_code value for this pre-authorized offer',
        data: {
          offerId: offerData.offer_id,
          txCodeOOBValue,
        },
      })
    }

    this.addEvent({
      type: 'info',
      title: 'Offer Created',
      description: `Offer ID: ${String(offerData.offer_id || 'unknown')}`,
      data: {
        offerId: offerData.offer_id,
        byReference: typeof offerData.credential_offer_uri === 'string',
        txCodeRequired: !!offerData.tx_code_required,
        deferred: !!offerData.deferred,
      },
    })
    return offerData
  }

  private buildWalletOfferInput(offerData: Record<string, unknown>): string {
    // Prefer by-value so the wallet does not need a second fetch of the offer
    // URI (and so Looking Glass can keep the full offer payload in-session).
    const inlineOffer = offerData.credential_offer
    if (inlineOffer && typeof inlineOffer === 'object') {
      return JSON.stringify(inlineOffer)
    }
    const offerURI = String(offerData.credential_offer_uri || '').trim()
    if (offerURI) {
      return offerURI
    }
    // Fall back to reconstructing a minimal by-value offer from the create response.
    const credentialIssuer = String(offerData.credential_issuer || '').trim()
    const preAuthorizedCode = String(offerData.pre_authorized_code || '').trim()
    if (credentialIssuer && preAuthorizedCode) {
      const grant: Record<string, unknown> = {
        'pre-authorized_code': preAuthorizedCode,
      }
      if (offerData.tx_code_required) {
        grant.tx_code = {
          length: offerData.tx_code_length,
          input_mode: offerData.tx_code_input_mode,
          description: offerData.tx_code_description,
        }
      }
      return JSON.stringify({
        credential_issuer: credentialIssuer,
        credential_configuration_ids: [this.selectedCredentialConfigurationID()],
        grants: {
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': grant,
        },
      })
    }
    throw new Error('Offer response missing credential_offer_uri and credential_offer')
  }

  private async importOfferViaWallet(
    offerInput: string,
    txCode: string,
  ): Promise<WalletImportResponse> {
    this.addEvent({
      type: 'info',
      title: 'Wallet Begins Offer Redemption',
      description:
        'Wallet accepts the Credential Offer and starts the OID4VCI redemption sequence against the issuer.',
      rfcReference: 'OpenID4VCI 1.0 Sections 4, 6–8',
      data: {
        credentialConfigurationID: this.selectedCredentialConfigurationID(),
        credentialFormat: this.selectedCredentialFormat(),
        txCodeProvided: Boolean(txCode),
      },
    })

    try {
      return await walletImportOffer(
        {
          offer: offerInput,
          tx_code: txCode || undefined,
          credential_format: this.selectedCredentialFormat(),
          credential_configuration_id: this.selectedCredentialConfigurationID(),
          looking_glass_session_id: this.config.captureSessionId,
        },
        {
          signal: this.abortController?.signal,
          headers: this.config.captureSessionId
            ? { 'X-Looking-Glass-Session': this.config.captureSessionId }
            : undefined,
        },
      )
    } catch (error) {
      if (error instanceof WalletAPIRequestError && error.payload) {
        this.surfaceWalletProtocolTranscript(error.payload as WalletImportResponse)
      }
      throw error
    }
  }

  private surfaceWalletProtocolTranscript(response: WalletImportResponse): void {
    const hops = Array.isArray(response._protocol_exchanges) ? response._protocol_exchanges : []
    for (const hop of hops) {
      this.addProtocolHopExchange(hop)
    }

    const events = response._looking_glass_events
    if (Array.isArray(events)) {
      for (const event of events) {
        if (!event || typeof event !== 'object') continue
        const ev = event as Record<string, unknown>
        const eventType = String(ev.type || '')
        if (eventType === 'http_exchange') {
          continue
        }
        if (eventType === 'crypto') {
          this.addEvent({
            type: 'crypto',
            title: String(ev.title || 'Credential Proof JWT'),
            description:
              'Wallet built the openid4vci-proof+jwt bound to c_nonce and credential_issuer audience.',
            rfcReference: String(
              (ev.data as Record<string, unknown> | undefined)?.rfc_reference ||
                'OpenID4VCI 1.0 Section 8.2',
            ),
            data: (ev.data as Record<string, unknown>) || undefined,
          })
          const proof = (ev.data as Record<string, unknown> | undefined)?.proof
          if (proof && typeof proof === 'object') {
            this.addVCArtifact({
              type: 'proof_jwt',
              title: 'Credential Proof JWT',
              format: 'openid4vci-proof+jwt',
              rfcReference: 'OpenID4VCI 1.0 Section 8.2',
              json: proof as Record<string, unknown>,
            })
          }
          continue
        }
        this.addVCArtifact({
          type: 'wallet_lifecycle',
          title: String(ev.title || ev.type || 'Wallet Event'),
          format: String(ev.type || ''),
          json: (ev.data && typeof ev.data === 'object' ? ev.data : ev) as Record<string, unknown>,
        })
      }
    }

    if (hops.length === 0) {
      this.addEvent({
        type: 'info',
        title: 'No Protocol Hops Returned',
        description:
          'Wallet completed without _protocol_exchanges. Check issuer Wire captures for HTTP traffic tagged with this Looking Glass session.',
      })
    }
  }

  private addProtocolHopExchange(hop: WalletProtocolExchange): void {
    const step = String(hop.step || 'Issuer HTTP Exchange').trim() || 'Issuer HTTP Exchange'
    const method = String(hop.method || 'GET').trim() || 'GET'
    const url = String(hop.url || '').trim()
    const status = Number(hop.response_status || 0)
    const duration = Number(hop.duration_ms || 0)
    this.updateState({ currentStep: step })
    const exchange = this.addExchange({
      step,
      rfcReference: String(hop.rfc_reference || 'OpenID4VCI 1.0'),
      request: {
        method,
        url,
        headers: hop.request_headers || {},
        body:
          hop.request_body === undefined || hop.request_body === null
            ? undefined
            : typeof hop.request_body === 'string'
              ? hop.request_body
              : (hop.request_body as Record<string, string>),
      },
      response: {
        status,
        statusText: status ? String(status) : 'error',
        headers: hop.response_headers || {},
        body: hop.response_body ?? hop.extra ?? null,
        duration,
      },
    })
    this.addEvent({
      type: 'request',
      title: step,
      description: `${method} ${url}`,
      rfcReference: String(hop.rfc_reference || ''),
      data: {
        exchangeId: exchange.id,
        actor: hop.actor || 'wallet→issuer',
        responseStatus: status,
        durationMs: duration,
      },
    })
    this.addEvent({
      type: 'response',
      title: `${step} Response`,
      description: status ? `HTTP ${status}` : 'Request failed before a response',
      rfcReference: String(hop.rfc_reference || ''),
      data: {
        exchangeId: exchange.id,
        responseStatus: status,
      },
    })
  }

  private recordOfferArtifacts(walletResponse: WalletImportResponse): void {
    if (walletResponse.credential_offer && typeof walletResponse.credential_offer === 'object') {
      this.addVCArtifact({
        type: 'credential_offer',
        title: 'Wallet-Resolved Credential Offer',
        format: 'openid4vci-offer',
        rfcReference: 'OpenID4VCI 1.0 Section 4.1',
        json: walletResponse.credential_offer,
        metadata: {
          credentialOfferURI: walletResponse.credential_offer_uri,
          transport: walletResponse.credential_offer_transport,
          credentialIssuer: walletResponse.credential_issuer,
        },
      })
    }
    if (walletResponse.issuer_metadata && typeof walletResponse.issuer_metadata === 'object') {
      this.addVCArtifact({
        type: 'wallet_lifecycle',
        title: 'Credential Issuer Metadata',
        format: 'openid-credential-issuer',
        rfcReference: 'OpenID4VCI 1.0 Section 11',
        json: walletResponse.issuer_metadata,
        metadata: {
          credentialIssuer: walletResponse.credential_issuer,
          tokenEndpoint: walletResponse.token_endpoint,
          credentialEndpoint: walletResponse.credential_endpoint,
          nonceEndpoint: walletResponse.nonce_endpoint,
        },
      })
    }
  }

  private async captureCredential(
    rawCredential: string,
    additionalMetadata?: Record<string, unknown>,
  ): Promise<void> {
    const credentialFormat =
      String(additionalMetadata?.format || this.selectedCredentialFormat()).trim() || 'mso_mdoc'
    const isMdoc = credentialFormat === 'mso_mdoc'

    let decodedCredentialJWT: ReturnType<typeof decodeJWTWithoutValidation> = null
    if (!isMdoc) {
      const issuerJWT = this.extractIssuerJWT(rawCredential)
      const decoded = this.decodeJwt(issuerJWT, 'access_token')
      this.updateState({
        decodedTokens: [...this.state.decodedTokens, decoded],
      })
      decodedCredentialJWT = decodeJWTWithoutValidation(issuerJWT)
    }

    let credentialInspection: CredentialInspectionMetadata
    try {
      const inspection = await api.decodeCredential(rawCredential)
      credentialInspection = { status: 'decoded', evidence: inspection.evidence, assurance: inspection.assurance }
    } catch (error) {
      credentialInspection = {
        status: 'decode_failed',
        reason: error instanceof Error ? error.message : 'Unknown error decoding credential',
      }
    }

    this.addVCArtifact({
      type: 'credential',
      title: `Issued ${credentialFormat} Credential`,
      format: credentialFormat,
      rfcReference: isMdoc ? 'ISO/IEC 18013-5 IssuerSigned' : 'OpenID4VCI 1.0 Section 8',
      raw: rawCredential,
      json: decodedCredentialJWT
        ? { header: decodedCredentialJWT.header, payload: decodedCredentialJWT.payload }
        : {},
      metadata: {
        credentialInspection,
        ...(additionalMetadata || {}),
      },
    })
    this.addEvent({
      type: 'token',
      title: 'Credential Received',
      description: `Issued ${credentialFormat} credential from the Credential Endpoint`,
      data: {
        format: credentialFormat,
        ...(isMdoc ? {} : { hasDisclosures: rawCredential.includes('~') }),
      },
    })
  }

  private selectedCredentialConfigurationID(): string {
    const configured = String(this.flowConfig.credentialConfigurationID || '').trim()
    if (configured) {
      return configured
    }
    return 'MobileDrivingLicenceMsoMdoc'
  }

  private selectedCredentialFormat(responsePayload?: Record<string, unknown>): string {
    const responseFormat = responsePayload ? String(responsePayload.credential_format || responsePayload.format || '').trim() : ''
    if (responseFormat) {
      return responseFormat
    }
    const configured = String(this.flowConfig.credentialFormat || '').trim()
    if (configured) {
      return configured
    }
    return 'mso_mdoc'
  }

  private extractIssuerJWT(rawCredential: string): string {
    const segments = rawCredential.split('~')
    return segments[0] || rawCredential
  }

  private extractTxCodeFromOffer(offerData: Record<string, unknown>): string {
    const direct = String(offerData.tx_code_oob_value || '').trim()
    if (direct) {
      return direct
    }
    return String(offerData.tx_code_value || '').trim()
  }
}
