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

export interface OID4VCIPreAuthorizedConfig extends FlowExecutorConfig {
  txCodeRequired?: boolean
  txCodeValue?: string
  deferred?: boolean
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
        await this.pollDeferredCredential(tokenData.access_token, credentialResponse.transaction_id)
      } else if (typeof credentialResponse.credential === 'string') {
        this.captureCredential(credentialResponse.credential)
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

    this.addVCArtifact({
      type: 'proof_jwt',
      title: 'Credential Proof JWT',
      format: 'openid4vci-proof+jwt',
      rfcReference: 'OpenID4VCI 1.0 Section 8.2',
      raw: proofJWT,
      json: this.decodeJWTWithoutValidation(proofJWT),
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
        credential_configuration_id: 'UniversityDegreeCredential',
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
      this.addVCArtifact({
        type: 'verification_result',
        title: 'Deferred Issuance Transaction',
        format: 'oid4vci-deferred',
        rfcReference: 'OpenID4VCI 1.0 Deferred Credential Endpoint',
        metadata: {
          transactionId: String(credentialData.transaction_id),
          deferred: true,
        },
      })
      this.addEvent({
        type: 'info',
        title: 'Deferred Issuance Started',
        description: `transaction_id: ${String(credentialData.transaction_id)}`,
        data: credentialData,
      })
    }
    return credentialData
  }

  private async pollDeferredCredential(accessToken: string, transactionID: unknown): Promise<void> {
    const transaction = String(transactionID || '')
    if (!transaction) {
      throw new Error('Deferred issuance returned empty transaction_id')
    }

    this.updateState({ currentStep: 'Polling deferred_credential endpoint' })

    let attempts = 0
    while (attempts < 5) {
      attempts += 1
      const { response, data } = await this.makeRequest('POST', `${this.config.baseUrl}/deferred_credential`, {
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          transaction_id: transaction,
        }),
        step: `Deferred credential poll #${attempts}`,
        rfcReference: 'OpenID4VCI 1.0 Deferred Credential Endpoint',
      })

      if (response.ok) {
        const payload = data as Record<string, unknown>
        if (typeof payload.credential === 'string') {
          this.captureCredential(payload.credential)
          return
        }
      } else {
        const errorData = data as Record<string, unknown>
        const errorCode = String(errorData.error || '')
        if (errorCode !== 'issuance_pending') {
          throw new Error(String(errorData.error_description || errorCode || `Deferred polling failed (${response.status})`))
        }
      }

      await new Promise(resolve => setTimeout(resolve, 1000))
    }

    throw new Error('Deferred credential was not ready within retry window')
  }

  private captureCredential(rawCredential: string): void {
    const issuerJWT = this.extractIssuerJWT(rawCredential)
    const decoded = this.decodeJwt(issuerJWT, 'access_token')
    this.updateState({
      decodedTokens: [...this.state.decodedTokens, decoded],
    })
    const disclosureCount = rawCredential.split('~').filter(Boolean).length - 1
    this.addVCArtifact({
      type: 'credential',
      title: 'Issued SD-JWT VC',
      format: 'dc+sd-jwt',
      rfcReference: 'OpenID4VCI 1.0 Section 8',
      raw: rawCredential,
      json: this.decodeJWTWithoutValidation(issuerJWT),
      metadata: {
        hasDisclosures: rawCredential.includes('~'),
        disclosureCount: disclosureCount > 0 ? disclosureCount : 0,
      },
    })
    this.addEvent({
      type: 'token',
      title: 'Credential Received',
      description: 'Issued SD-JWT VC captured from credential endpoint',
      data: {
        format: 'dc+sd-jwt',
        hasDisclosures: rawCredential.includes('~'),
      },
    })
  }

  private extractIssuerJWT(rawCredential: string): string {
    const segments = rawCredential.split('~')
    return segments[0] || rawCredential
  }

  private decodeJWTWithoutValidation(token: string): Record<string, unknown> {
    try {
      const [headerB64, payloadB64] = token.split('.')
      if (!headerB64 || !payloadB64) {
        return {}
      }
      const parsePart = (value: string): Record<string, unknown> => {
        const base64 = value.replace(/-/g, '+').replace(/_/g, '/')
        const padding = '='.repeat((4 - (base64.length % 4)) % 4)
        return JSON.parse(atob(base64 + padding)) as Record<string, unknown>
      }
      return {
        header: parsePart(headerB64),
        payload: parsePart(payloadB64),
      }
    } catch {
      return {}
    }
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
    const legacy = String(offerData.tx_code_value || '').trim()
    return legacy
  }
}
