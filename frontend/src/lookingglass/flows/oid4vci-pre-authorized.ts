/**
 * OID4VCI Pre-Authorized Code Flow Executor
 *
 * Executes real OID4VCI calls:
 * - Create credential offer
 * - Exchange pre-authorized code for access token
 * - Build proof JWT bound to c_nonce
 * - Request credential
 * - Optionally poll deferred endpoint
 */

import { FlowExecutorBase, type FlowExecutorConfig } from './base'
import { decodeJWTWithoutValidation } from '../../utils/crypto'

export interface OID4VCIPreAuthorizedConfig extends FlowExecutorConfig {
  txCodeRequired?: boolean
  txCodeValue?: string
  deferred?: boolean
  credentialConfigurationID?: string
  credentialFormat?: string
}

export class OID4VCIPreAuthorizedExecutor extends FlowExecutorBase {
  readonly flowType = 'oid4vci_pre_authorized'
  readonly flowName = 'OID4VCI Pre-Authorized Code'
  readonly rfcReference = 'OpenID4VCI 1.0'

  private flowConfig: OID4VCIPreAuthorizedConfig
  private walletKeyPairPromise?: Promise<CryptoKeyPair>

  constructor(config: OID4VCIPreAuthorizedConfig) {
    super(config)
    this.flowConfig = config
  }

  async execute(): Promise<void> {
    if (this.state.status === 'executing') {
      return
    }

    if (this.state.status === 'awaiting_user') {
      const transactionId = String(this.state.securityParams.transactionId || '').trim()
      const accessToken = String(this.state.securityParams.deferredAccessToken || '').trim()
      if (!transactionId || !accessToken) {
        this.updateState({
          status: 'error',
          currentStep: 'OID4VCI flow failed',
          error: {
            code: 'oid4vci_flow_failed',
            description: 'Missing transaction_id or access_token for deferred check',
          },
        })
        return
      }
      this.abortController = new AbortController()
      this.updateState({
        status: 'executing',
        currentStep: 'Checking deferred credential status',
      })
      try {
        const ready = await this.checkDeferredCredential(accessToken, transactionId)
        if (!ready) {
          this.updateState({
            status: 'awaiting_user',
            currentStep: 'Deferred credential not ready -- check again when ready',
          })
          return
        }
        this.updateState({
          status: 'completed',
          currentStep: 'OID4VCI flow completed',
        })
      } catch (error) {
        const description = error instanceof Error ? error.message : 'Deferred credential check failed'
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
      currentStep: 'Starting OID4VCI pre-authorized flow',
    })

    try {
      const offerData = await this.createOffer()
      await this.resolveOfferReference(offerData)
      const tokenData = await this.exchangeToken(offerData)
      const walletSubject = typeof offerData.wallet_subject === 'string' ? offerData.wallet_subject : undefined
      const proofJWT = await this.createProof(tokenData.c_nonce, walletSubject)
      const credentialResponse = await this.requestCredential(tokenData.access_token, proofJWT)

      if (credentialResponse.transaction_id) {
        const transactionId = String(credentialResponse.transaction_id)
        this.updateState({
          status: 'awaiting_user',
          currentStep: 'Deferred credential issued -- click Check Status when ready',
          securityParams: {
            ...this.state.securityParams,
            transactionId,
            deferredAccessToken: tokenData.access_token,
          },
        })
        this.addEvent({
          type: 'user_action',
          title: 'Deferred Issuance -- Awaiting Manual Check',
          description: `Credential issuance is deferred (transaction_id: ${transactionId}). Click "Check Status" to poll the deferred endpoint.`,
          data: { transactionId },
        })
        return
      }

      if (typeof credentialResponse.credential === 'string') {
        this.captureCredential(credentialResponse.credential, {
          format: this.selectedCredentialFormat(credentialResponse),
          credentialConfigurationID: this.selectedCredentialConfigurationID(),
        })
      }

      this.updateState({
        status: 'completed',
        currentStep: 'OID4VCI flow completed',
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

  private async resolveOfferReference(offerData: Record<string, unknown>): Promise<void> {
    const offerURI = offerData.credential_offer_uri
    if (typeof offerURI !== 'string' || !offerURI) {
      return
    }

    this.updateState({ currentStep: 'Resolving credential_offer_uri' })
    const uri = new URL(offerURI, window.location.origin)
    const { response, data } = await this.makeRequest('GET', uri.toString(), {
      headers: { Accept: 'application/json' },
      step: 'Resolve credential offer reference',
      rfcReference: 'OpenID4VCI 1.0 Section 4.1',
    })

    if (!response.ok) {
      throw new Error(`Failed to resolve credential_offer_uri (${response.status})`)
    }

    this.addVCArtifact({
      type: 'credential_offer',
      title: 'Resolved Credential Offer',
      format: 'openid4vci-offer',
      rfcReference: 'OpenID4VCI 1.0 Section 4.1',
      json: (data as Record<string, unknown>),
      metadata: {
        byReference: true,
      },
    })
  }

  private async exchangeToken(offerData: Record<string, unknown>): Promise<Record<string, string>> {
    this.updateState({ currentStep: 'Exchanging pre-authorized code for access token' })

    const preAuthorizedCode = String(offerData.pre_authorized_code || '')
    if (!preAuthorizedCode) {
      throw new Error('Offer response missing pre_authorized_code')
    }

    const body: Record<string, string> = {
      grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': preAuthorizedCode,
    }
    if (this.flowConfig.txCodeRequired) {
      let txCode = String(this.flowConfig.txCodeValue || '').trim()
      if (!txCode) {
        txCode = this.extractTxCodeFromOffer(offerData)
      }
      if (!txCode) {
        throw new Error('Offer requires tx_code; provide txCodeValue from the out-of-band channel')
      }
      body.tx_code = txCode
    }

    const { response, data } = await this.makeRequest('POST', `${this.config.baseUrl}/token`, {
      body,
      step: 'Token request (pre-authorized_code)',
      rfcReference: 'OpenID4VCI 1.0 Section 6.1',
    })

    if (!response.ok) {
      const errorData = data as Record<string, unknown>
      throw new Error(String(errorData.error_description || errorData.error || `Token request failed (${response.status})`))
    }

    const tokenData = data as Record<string, string>
    this.processTokenResponse(tokenData as Record<string, unknown>)
    if (!tokenData.c_nonce) {
      throw new Error('Token response missing c_nonce')
    }
    return tokenData
  }

  private async createProof(cNonce: string, walletSubject?: string): Promise<string> {
    this.updateState({ currentStep: 'Creating nonce-bound proof JWT' })
    const normalizedSubject = walletSubject && walletSubject.trim().length > 0
      ? walletSubject.trim()
      : 'did:example:wallet:holder'
    const audience = `${window.location.origin}${this.config.baseUrl}`
    const now = Math.floor(Date.now() / 1000)
    const expiration = now + 180
    const { privateKey, publicJWK, kid } = await this.getWalletSigningMaterial()

    const proofJWT = await this.signRS256JWT(
      {
        alg: 'RS256',
        typ: 'openid4vci-proof+jwt',
        kid,
      },
      {
        iss: normalizedSubject,
        sub: normalizedSubject,
        aud: audience,
        nonce: cNonce,
        iat: now,
        exp: expiration,
        jti: this.randomValue(20),
        cnf: {
          jwk: publicJWK,
        },
      },
      privateKey,
    )
    const decodedProofJWT = decodeJWTWithoutValidation(proofJWT)

    this.addVCArtifact({
      type: 'proof_jwt',
      title: 'Credential Proof JWT',
      format: 'openid4vci-proof+jwt',
      rfcReference: 'OpenID4VCI 1.0 Section 8.2',
      raw: proofJWT,
      json: decodedProofJWT
        ? { header: decodedProofJWT.header, payload: decodedProofJWT.payload }
        : {},
      metadata: {
        nonceBound: true,
        walletSubject: normalizedSubject,
        generatedClientSide: true,
      },
    })
    return proofJWT
  }

  private async requestCredential(accessToken: string, proofJWT: string): Promise<Record<string, unknown>> {
    this.updateState({ currentStep: 'Requesting credential from credential endpoint' })

    const { response, data } = await this.makeRequest('POST', `${this.config.baseUrl}/credential`, {
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({
        credential_configuration_id: this.selectedCredentialConfigurationID(),
        format: this.selectedCredentialFormat(),
        proofs: [
          {
            proof_type: 'jwt',
            jwt: proofJWT,
          },
        ],
      }),
      step: 'Credential request',
      rfcReference: 'OpenID4VCI 1.0 Section 8',
    })

    if (!response.ok) {
      const errorData = data as Record<string, unknown>
      throw new Error(String(errorData.error_description || errorData.error || `Credential request failed (${response.status})`))
    }

    const credentialData = data as Record<string, unknown>
    if (credentialData.transaction_id) {
      const transactionID = String(credentialData.transaction_id)
      this.addVCArtifact({
        type: 'deferred_status',
        title: 'Deferred Issuance Transaction',
        format: 'oid4vci-deferred',
        rfcReference: 'OpenID4VCI 1.0 Deferred Credential Endpoint',
        metadata: {
          deferredFlow: true,
          deferredStatus: 'transaction_created',
          transactionId: transactionID,
          deferred: true,
        },
      })
      this.addEvent({
        type: 'info',
        title: 'Deferred Issuance Started',
        description: `transaction_id: ${transactionID}`,
        data: { transactionId: transactionID },
      })
    }
    return credentialData
  }

  private async checkDeferredCredential(accessToken: string, transactionId: string): Promise<boolean> {
    this.updateState({ currentStep: 'Checking deferred_credential endpoint' })

    const { response, data } = await this.makeRequest('POST', `${this.config.baseUrl}/deferred_credential`, {
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({ transaction_id: transactionId }),
      step: 'Deferred credential check',
      rfcReference: 'OpenID4VCI 1.0 Deferred Credential Endpoint',
    })

    const payload = data as Record<string, unknown>

    if (response.status === 202) {
      const retryAfterHeader = response.headers.get('Retry-After')
      const retryHint = retryAfterHeader ? ` (retry-after: ${retryAfterHeader}s)` : ''
      this.addVCArtifact({
        type: 'deferred_status',
        title: 'Deferred Issuance Pending',
        format: 'oid4vci-deferred',
        rfcReference: 'OpenID4VCI 1.0 Deferred Credential Endpoint',
        metadata: {
          deferredFlow: true,
          deferredStatus: 'pending',
          transactionId,
          retryAfterHeader: retryAfterHeader || undefined,
        },
      })
      this.addEvent({
        type: 'info',
        title: 'Deferred Issuance Still Pending',
        description: `Issuer returned issuance_pending${retryHint}. Click "Check Status" to try again.`,
        data: { transactionId, retryAfter: retryAfterHeader },
      })
      return false
    }

    if (response.ok && typeof payload.credential === 'string') {
      this.addVCArtifact({
        type: 'deferred_status',
        title: 'Deferred Issuance Completed',
        format: 'oid4vci-deferred',
        rfcReference: 'OpenID4VCI 1.0 Deferred Credential Endpoint',
        metadata: {
          deferredFlow: true,
          deferredStatus: 'completed',
          transactionId,
        },
      })
      this.captureCredential(payload.credential, {
        format: this.selectedCredentialFormat(payload),
        credentialConfigurationID: this.selectedCredentialConfigurationID(),
        deferredFlow: true,
        deferredStatus: 'completed',
        deferredTransactionId: transactionId,
      })
      this.addEvent({
        type: 'info',
        title: 'Deferred Issuance Completed',
        description: `Deferred credential issued for transaction_id: ${transactionId}`,
        data: { transactionId },
      })
      return true
    }

    if (!response.ok) {
      const errorCode = String(payload.error || '')
      if (errorCode === 'issuance_pending') {
        this.addEvent({
          type: 'info',
          title: 'Deferred Issuance Still Pending',
          description: 'Issuer returned issuance_pending. Click "Check Status" to try again.',
          data: { transactionId },
        })
        return false
      }
      throw new Error(String(payload.error_description || errorCode || `Deferred check failed (${response.status})`))
    }

    throw new Error('Deferred credential response missing credential')
  }

  private captureCredential(rawCredential: string, additionalMetadata?: Record<string, unknown>): void {
    const issuerJWT = this.extractIssuerJWT(rawCredential)
    const decodedCredentialJWT = decodeJWTWithoutValidation(issuerJWT)
    const credentialFormat = String(additionalMetadata?.format || this.selectedCredentialFormat()).trim() || 'dc+sd-jwt'
    const decoded = this.decodeJwt(issuerJWT, 'access_token')
    this.updateState({
      decodedTokens: [...this.state.decodedTokens, decoded],
    })
    const disclosureCount = rawCredential.split('~').filter(Boolean).length - 1
    this.addVCArtifact({
      type: 'credential',
      title: `Issued ${credentialFormat} Credential`,
      format: credentialFormat,
      rfcReference: 'OpenID4VCI 1.0 Section 8',
      raw: rawCredential,
      json: decodedCredentialJWT
        ? { header: decodedCredentialJWT.header, payload: decodedCredentialJWT.payload }
        : {},
      metadata: {
        hasDisclosures: rawCredential.includes('~'),
        disclosureCount: disclosureCount > 0 ? disclosureCount : 0,
        ...(additionalMetadata || {}),
      },
    })
    this.addEvent({
      type: 'token',
      title: 'Credential Received',
      description: `Issued ${credentialFormat} credential captured from credential endpoint`,
      data: {
        format: credentialFormat,
        hasDisclosures: rawCredential.includes('~'),
      },
    })
  }

  private selectedCredentialConfigurationID(): string {
    const configured = String(this.flowConfig.credentialConfigurationID || '').trim()
    if (configured) {
      return configured
    }
    return 'UniversityDegreeCredential'
  }

  private selectedCredentialFormat(responsePayload?: Record<string, unknown>): string {
    const responseFormat = responsePayload ? String(responsePayload.format || '').trim() : ''
    if (responseFormat) {
      return responseFormat
    }
    const configured = String(this.flowConfig.credentialFormat || '').trim()
    if (configured) {
      return configured
    }
    return 'dc+sd-jwt'
  }

  private extractIssuerJWT(rawCredential: string): string {
    const segments = rawCredential.split('~')
    return segments[0] || rawCredential
  }

  private async getWalletSigningMaterial(): Promise<{ privateKey: CryptoKey; publicJWK: Record<string, unknown>; kid: string }> {
    if (!this.walletKeyPairPromise) {
      this.walletKeyPairPromise = window.crypto.subtle.generateKey(
        {
          name: 'RSASSA-PKCS1-v1_5',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true,
        ['sign', 'verify'],
      ) as Promise<CryptoKeyPair>
    }
    const keyPair = await this.walletKeyPairPromise
    const exported = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey)
    const publicJWK: Record<string, unknown> = {
      kty: exported.kty,
      n: exported.n,
      e: exported.e,
      alg: 'RS256',
      use: 'sig',
    }
    const exportedKid = (exported as Record<string, unknown>).kid
    const kid = typeof exportedKid === 'string' && exportedKid.length > 0
      ? exportedKid
      : `wallet-${(exported.n || '').slice(0, 12)}`
    publicJWK.kid = kid
    return {
      privateKey: keyPair.privateKey,
      publicJWK,
      kid,
    }
  }

  private async signRS256JWT(
    header: Record<string, unknown>,
    payload: Record<string, unknown>,
    privateKey: CryptoKey,
  ): Promise<string> {
    const encodedHeader = this.base64UrlEncodeString(JSON.stringify(header))
    const encodedPayload = this.base64UrlEncodeString(JSON.stringify(payload))
    const signingInput = `${encodedHeader}.${encodedPayload}`
    const signature = await window.crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      privateKey,
      new TextEncoder().encode(signingInput),
    )
    const encodedSignature = this.base64UrlEncodeBytes(new Uint8Array(signature))
    return `${signingInput}.${encodedSignature}`
  }

  private base64UrlEncodeString(value: string): string {
    return this.base64UrlEncodeBytes(new TextEncoder().encode(value))
  }

  private base64UrlEncodeBytes(bytes: Uint8Array): string {
    let binary = ''
    bytes.forEach(byte => {
      binary += String.fromCharCode(byte)
    })
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
  }

  private randomValue(length: number): string {
    const size = length > 0 ? length : 24
    const bytes = new Uint8Array(size)
    window.crypto.getRandomValues(bytes)
    return this.base64UrlEncodeBytes(bytes).slice(0, size)
  }

  private extractTxCodeFromOffer(offerData: Record<string, unknown>): string {
    const direct = String(offerData.tx_code_oob_value || '').trim()
    if (direct) {
      return direct
    }
    const fallbackTxCode = String(offerData.tx_code_value || '').trim()
    return fallbackTxCode
  }
}
