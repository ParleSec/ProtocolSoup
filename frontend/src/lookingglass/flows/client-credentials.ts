/**
 * Client Credentials Flow Executor
 * 
 * Implements RFC 6749 Section 4.4 - Client Credentials Grant
 * 
 * Used for machine-to-machine authentication where the client
 * is acting on its own behalf, not on behalf of a user.
 * 
 * Flow:
 * 1. Client authenticates directly with token endpoint
 * 2. Token endpoint returns access token
 * 
 * NO user interaction required.
 */

import { FlowExecutorBase, type DecodedToken, type FlowExecutorConfig } from './base'
import {
  generateRS256SigningMaterial,
  signRS256JWT,
  generateES256SigningMaterial,
  generateDPoPProof,
  type RS256SigningMaterial,
  type ES256SigningMaterial,
} from '../../utils/crypto'

export type ClientCredentialsAuthMethod = 'client_secret_basic' | 'private_key_jwt'
export type ClientCredentialsAccessTokenMode = 'bearer' | 'dpop'

export interface ClientCredentialsConfig extends FlowExecutorConfig {
  clientSecret?: string
  clientAuthMethod?: ClientCredentialsAuthMethod
  /** Canonical absolute AS token endpoint used for DPoP htu binding. */
  tokenEndpoint?: string
  /**
   * Bind the issued access token to a client-held ES256 key via a DPoP
   * proof (RFC 9449), instead of leaving it an unconstrained Bearer token.
   * Orthogonal to clientAuthMethod: DPoP proves possession of a key bound
   * to the *token*, client_secret_basic/private_key_jwt authenticate the
   * *client* -- both can be used together on the same request.
   */
  accessTokenMode?: ClientCredentialsAccessTokenMode
}

interface PrivateKeyJWTRegistration {
  clientId: string
  tokenEndpoint: string
}

export class ClientCredentialsExecutor extends FlowExecutorBase {
  readonly flowType = 'client_credentials'
  readonly flowName: string
  readonly rfcReference: string

  private flowConfig: ClientCredentialsConfig
  private signingMaterialPromise?: Promise<RS256SigningMaterial>
  private dpopSigningMaterialPromise?: Promise<ES256SigningMaterial>

  constructor(config: ClientCredentialsConfig) {
    super(config)
    this.flowConfig = config
    const usesDPoP = config.accessTokenMode === 'dpop'
    this.flowName = usesDPoP
      ? 'Client Credentials Grant with DPoP'
      : 'Client Credentials Grant'
    this.rfcReference = usesDPoP
      ? 'RFC 6749 Section 4.4 + RFC 9449'
      : 'RFC 6749 Section 4.4'
  }

  async execute(): Promise<void> {
    const authMethod = this.flowConfig.clientAuthMethod || 'client_secret_basic'
    const accessTokenMode = this.flowConfig.accessTokenMode || 'bearer'
    if (authMethod === 'client_secret_basic' && !this.flowConfig.clientSecret) {
      this.updateState({
        status: 'error',
        currentStep: 'Configuration Error',
        error: {
          code: 'missing_client_secret',
          description: 'client_secret_basic requires a client_secret.',
        },
      })
      this.addEvent({
        type: 'error',
        title: 'Missing Client Secret',
        description: 'The selected client_secret_basic method requires a client_secret',
        rfcReference: 'RFC 6749 Section 4.4.2',
      })
      return
    }

    this.abortController = new AbortController()
    this.updateState({
      ...this.createInitialState(),
      status: 'executing',
      currentStep: 'Initiating Client Credentials Flow',
    })

    this.addEvent({
      type: 'info',
      title: 'Starting Client Credentials Flow',
      description: 'Machine-to-machine authentication without user interaction',
      rfcReference: this.rfcReference,
      data: {
        clientId: authMethod === 'private_key_jwt'
          ? 'Assigned by the owned session registration'
          : this.config.clientId,
        scopes: this.config.scopes,
        clientAuthenticationMethod: authMethod,
        accessTokenMode,
        note: 'This flow is for confidential clients only',
      },
    })

    this.addEvent({
      type: 'rfc',
      title: 'RFC 6749 Section 4.4',
      description: 'Client Credentials Grant - Client authenticates directly with authorization server',
      rfcReference: this.rfcReference,
      data: {
        useCase: 'Machine-to-machine, backend services, APIs',
        noUserInvolved: true,
        clientAuthenticationMethod: authMethod,
        accessTokenMode,
      },
    })

    try {
      await this.requestToken()

      this.updateState({
        status: 'completed',
        currentStep: 'Flow completed successfully',
      })

      this.addEvent({
        type: 'info',
        title: 'Client Credentials Flow Complete',
        description: 'Access token obtained for client application',
        rfcReference: this.rfcReference,
      })

    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      this.updateState({
        status: 'error',
        currentStep: 'Flow failed',
        error: {
          code: 'execution_error',
          description: message,
        },
      })
      this.addEvent({
        type: 'error',
        title: 'Flow Execution Failed',
        description: message,
      })
    }
  }

  private async requestToken(): Promise<void> {
    const authMethod = this.flowConfig.clientAuthMethod || 'client_secret_basic'
    const accessTokenMode = this.flowConfig.accessTokenMode || 'bearer'
    this.addEvent({
      type: 'rfc',
      title: 'RFC 6749 Section 4.4.2',
      description: 'Access Token Request - Client authenticates and requests token',
      rfcReference: 'RFC 6749 Section 4.4.2',
      data: {
        grant_type: 'client_credentials',
        authentication: authMethod,
        accessTokenMode,
      },
    })

    this.updateState({
      currentStep: 'Requesting access token',
    })

    const body: Record<string, string> = {
      grant_type: 'client_credentials',
    }

    // Add scope if specified
    if (this.config.scopes.length > 0) {
      body.scope = this.config.scopes.join(' ')
    }

    const headers: Record<string, string> = {}
    let tokenRequestReference = 'RFC 6749 Section 4.4.2'
    let acceptedAssertion: {
      raw: string
      decoded: DecodedToken
      claims: Record<string, unknown>
      privateKeyExtractable: boolean
      algorithm: string
      kid: string
      clientId: string
      tokenEndpoint: string
    } | undefined
    if (authMethod === 'private_key_jwt') {
      const signingMaterial = await this.getSigningMaterial()
      const registration = await this.registerPublicKey(signingMaterial.publicJWK)
      const now = Math.floor(Date.now() / 1000)
      const claims = {
        iss: registration.clientId,
        sub: registration.clientId,
        aud: registration.tokenEndpoint,
        iat: now,
        exp: now + 300,
        jti: crypto.randomUUID(),
      }
      const assertion = await signRS256JWT(
        { alg: 'RS256', typ: 'JWT', kid: signingMaterial.kid },
        claims,
        signingMaterial.privateKey,
      )
      body.client_id = registration.clientId
      body.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      body.client_assertion = assertion
      tokenRequestReference = 'RFC 7523 Section 2.2'

      const decodedAssertion = this.decodeJwt(assertion, 'client_assertion')
      acceptedAssertion = {
        raw: assertion,
        decoded: decodedAssertion,
        claims,
        privateKeyExtractable: signingMaterial.privateKey.extractable,
        algorithm: signingMaterial.alg,
        kid: signingMaterial.kid,
        clientId: registration.clientId,
        tokenEndpoint: registration.tokenEndpoint,
      }
    } else {
      // RFC 6749 Section 2.3.1: clients with a password can authenticate with
      // HTTP Basic; request-body password authentication is NOT RECOMMENDED.
      headers.Authorization = `Basic ${btoa(`${this.config.clientId}:${this.flowConfig.clientSecret}`)}`
      this.addEvent({
        type: 'security',
        title: 'Client Authentication',
        description: 'Sending client credentials via HTTP Basic Authentication',
        rfcReference: 'RFC 6749 Section 2.3.1',
        data: {
          method: 'client_secret_basic',
          note: 'POST body credentials are NOT RECOMMENDED per RFC 6749 Section 2.3.1',
        },
      })
    }

    const tokenRequestURL = `${this.config.baseUrl}/token`
    let dpopProof: string | undefined
    if (accessTokenMode === 'dpop') {
      // RFC 9449 Section 4.2 requires htu to be an absolute URI. The
      // browser sends the HTTP request through the same-origin Next.js
      // proxy, but the proof binds to the authorization server's canonical
      // endpoint returned by the backend. For private_key_jwt, registration
      // returns that same endpoint as the assertion audience.
      const proofTarget = acceptedAssertion?.tokenEndpoint || this.flowConfig.tokenEndpoint
      if (!proofTarget) {
        throw new Error('DPoP requires the authorization server canonical token endpoint')
      }
      dpopProof = await this.attachDpopProof(headers, proofTarget)
    }

    let { response, data } = await this.makeRequest(
      'POST',
      tokenRequestURL,
      {
        headers,
        body,
        step: 'Token Request (Client Credentials)',
        rfcReference: tokenRequestReference,
      }
    )

    // RFC 9449 Section 8: the authorization server may reject an otherwise
    // valid proof for lacking its current server-provided nonce, returning
    // use_dpop_nonce plus a DPoP-Nonce header. This is the protocol's
    // defined recovery path -- retry exactly once with a fresh proof that
    // echoes the supplied nonce, not a generic retry loop.
    if (!response.ok && dpopProof) {
      const challengeBody = data as Record<string, unknown>
      const serverNonce = response.headers.get('DPoP-Nonce')
      if (challengeBody.error === 'use_dpop_nonce' && serverNonce) {
        this.addEvent({
          type: 'security',
          title: 'DPoP Nonce Challenge (RFC 9449 Section 8)',
          description: 'The authorization server rejected the proof for lacking its current server-provided nonce and returned a fresh one via the DPoP-Nonce header. Retrying once with the nonce echoed into a new proof.',
          rfcReference: 'RFC 9449 Section 8',
          data: {
            from: 'Authorization Server',
            to: 'Client',
            error: challengeBody.error,
            nonce: serverNonce,
          },
        })
        const proofTarget = acceptedAssertion?.tokenEndpoint || this.flowConfig.tokenEndpoint
        if (!proofTarget) {
          throw new Error('DPoP nonce retry requires the authorization server canonical token endpoint')
        }
        dpopProof = await this.attachDpopProof(headers, proofTarget, serverNonce)
        ;({ response, data } = await this.makeRequest(
          'POST',
          tokenRequestURL,
          {
            headers,
            body,
            step: 'Token Request (Client Credentials, DPoP-Nonce Retry)',
            rfcReference: 'RFC 9449 Section 8',
          }
        ))
      }
    }

    if (!response.ok) {
      const errorData = data as Record<string, unknown>
      
      this.addEvent({
        type: 'rfc',
        title: 'RFC 6749 Section 5.2',
        description: 'Error Response - Token request failed',
        rfcReference: 'RFC 6749 Section 5.2',
        data: errorData,
      })

      throw new Error(
        (errorData.error_description as string) || 
        (errorData.error as string) || 
        'Token request failed'
      )
    }

    if (authMethod === 'private_key_jwt') {
      if (!acceptedAssertion) {
        throw new Error('The accepted client assertion is unavailable')
      }
      this.updateState({
        tokens: { ...this.state.tokens, clientAssertion: acceptedAssertion.raw },
        decodedTokens: [...this.state.decodedTokens, acceptedAssertion.decoded],
      })
      this.addEvent({
        type: 'crypto',
        title: 'Client Assertion Signed and Accepted',
        description: 'The client assertion is published after the authorization server atomically accepted its single-use jti',
        rfcReference: 'RFC 7523 Section 3',
        data: {
          from: 'Client',
          to: 'Authorization Server',
          client_assertion: acceptedAssertion.raw,
          header: acceptedAssertion.decoded.header,
          claims: acceptedAssertion.claims,
          privateKeyExtractable: acceptedAssertion.privateKeyExtractable,
          algorithm: acceptedAssertion.algorithm,
        },
      })
      this.addEvent({
        type: 'security',
        title: 'private_key_jwt Client Authentication',
        description: 'Only the signed assertion crossed the client boundary; the private key remained in WebCrypto',
        rfcReference: 'RFC 7523 Section 2.2',
        data: {
          from: 'Client',
          to: 'Authorization Server',
          method: 'private_key_jwt',
          clientId: acceptedAssertion.clientId,
          kid: acceptedAssertion.kid,
          tokenEndpointAudience: acceptedAssertion.tokenEndpoint,
        },
      })
      this.addEvent({
        type: 'crypto',
        title: 'Client Assertion Verified',
        description: 'The authorization server accepted the registered key, assertion claims, signature, and single-use jti before issuing the token',
        rfcReference: 'RFC 7523 Section 3',
        data: {
          from: 'Authorization Server',
          to: 'Client',
          client_authentication_method: 'private_key_jwt',
          client_authentication_methods: ['private_key_jwt'],
          adjudicatedByTokenEndpoint: true,
        },
      })
    }

    this.addEvent({
      type: 'rfc',
      title: 'RFC 6749 Section 4.4.3',
      description: 'Access Token Response - Token received',
      rfcReference: 'RFC 6749 Section 4.4.3',
      data: {
        note: 'No refresh_token in Client Credentials (RFC 6749 Section 4.4.3)',
      },
    })

    const responseBody = data as Record<string, unknown>
    if (dpopProof && responseBody.token_type !== 'DPoP') {
      this.addEvent({
        type: 'error',
        title: 'DPoP Protection Not Granted',
        description: 'The client explicitly requested DPoP protection, but the authorization server did not return token_type=DPoP. The response is discarded rather than treating the access token as a Bearer token.',
        rfcReference: 'RFC 9449 Section 5',
        data: {
          from: 'Authorization Server',
          to: 'Client',
          token_type: responseBody.token_type,
          discarded: true,
        },
      })
      throw new Error('Authorization server did not return the requested DPoP-bound access token')
    }

    this.processTokenResponse(responseBody)

    if (dpopProof) {
      this.addEvent({
        type: 'security',
        title: 'Access Token Sender-Constrained (DPoP)',
        description: 'The authorization server bound the access token to this proof\'s key via cnf.jkt and returned token_type=DPoP. Presenting this token without a matching proof will be rejected.',
        rfcReference: 'RFC 9449 Sections 5 and 7',
        data: {
          from: 'Authorization Server',
          to: 'Client',
          token_type: responseBody.token_type,
          dpopBound: true,
        },
      })
    }
  }

  /**
   * Generates a client-held ES256 key (once per execution) and a DPoP proof
   * (RFC 9449 Section 4.2) over the given endpoint, then attaches it to the
   * outgoing request via the `DPoP` header. The proof itself is published
   * as a Looking Glass event/token so it can be inspected -- only the
   * public JWK ever leaves the browser; the private key stays in WebCrypto.
   */
  private async attachDpopProof(headers: Record<string, string>, endpoint: string, nonce?: string): Promise<string> {
    if (!this.dpopSigningMaterialPromise) {
      this.dpopSigningMaterialPromise = generateES256SigningMaterial('dpop-client')
    }
    const signingMaterial = await this.dpopSigningMaterialPromise
    this.addEvent({
      type: 'crypto',
      title: 'DPoP Key Pair Generated (RFC 9449)',
      description: 'A fresh ES256 key pair is generated in WebCrypto for this execution. Only the public JWK is ever transmitted.',
      rfcReference: 'RFC 9449 Section 4.2',
      data: {
        kty: signingMaterial.publicJWK.kty,
        crv: signingMaterial.publicJWK.crv,
        privateKeyExtractable: signingMaterial.privateKey.extractable,
      },
    })

    const proof = await generateDPoPProof(signingMaterial, { htm: 'POST', htu: endpoint, nonce })
    headers.DPoP = proof
    const decodedProof = this.decodeJwt(proof, 'dpop_proof')
    this.updateState({
      tokens: { ...this.state.tokens, dpopProof: proof },
      decodedTokens: [...this.state.decodedTokens, decodedProof],
    })
    this.addEvent({
      type: 'crypto',
      title: 'DPoP Proof Generated',
      description: 'A fresh proof-of-possession JWT is minted for this specific request: bound to the HTTP method and URI (htm/htu), with a single-use jti.',
      rfcReference: 'RFC 9449 Section 4.2',
      data: {
        from: 'Client',
        to: 'Authorization Server',
        header: decodedProof.header,
        claims: decodedProof.payload,
      },
    })
    return proof
  }

  private getSigningMaterial(): Promise<RS256SigningMaterial> {
    if (!this.signingMaterialPromise) {
      this.signingMaterialPromise = generateRS256SigningMaterial('machine-client')
    }
    return this.signingMaterialPromise
  }

  private async registerPublicKey(
    publicJWK: RS256SigningMaterial['publicJWK'],
  ): Promise<PrivateKeyJWTRegistration> {
    if (!this.config.captureSessionId || !this.config.captureSessionToken) {
      throw new Error('private_key_jwt registration requires an owned Looking Glass session')
    }
    const url = `${this.config.baseUrl}/demo/clients/machine-client-pkjwt/jwks`
    const headers = this.withCaptureHeaders({ 'Content-Type': 'application/json' })
    const requestHeaders = {
      ...headers,
      'X-Looking-Glass-Session-Token': this.config.captureSessionToken,
    }
    const body = JSON.stringify({ keys: [publicJWK] })
    const exchange = this.addExchange({
      step: 'Register Client Public JWK',
      rfcReference: 'RFC 7517 Section 5',
      request: { method: 'POST', url, headers, body },
    })
    this.addEvent({
      type: 'crypto',
      title: 'Registering Client Public Key',
      description: 'The client sends only its public JWK to the authorization server',
      rfcReference: 'RFC 7517 Section 5',
      data: {
        from: 'Client',
        to: 'Authorization Server',
        kid: publicJWK.kid,
        kty: publicJWK.kty,
        privateKeyTransmitted: false,
        exchangeId: exchange.id,
      },
    })

    const startedAt = Date.now()
    const response = await fetch(url, {
      method: 'POST',
      headers: requestHeaders,
      body,
      signal: this.abortController?.signal,
    })
    const duration = Date.now() - startedAt
    const responseBody = await response.json().catch(() => ({}))
    exchange.response = {
      status: response.status,
      statusText: response.statusText,
      headers: Object.fromEntries(response.headers.entries()),
      body: responseBody,
      duration,
    }
    this.updateState({
      exchanges: this.state.exchanges.map(item => item.id === exchange.id ? exchange : item),
    })
    if (!response.ok) {
      throw new Error('The authorization server rejected the client public key registration')
    }
    const registration = responseBody as Record<string, unknown>
    if (typeof registration.client_id !== 'string' || registration.client_id.length === 0 ||
        typeof registration.token_endpoint !== 'string' || registration.token_endpoint.length === 0) {
      throw new Error('The authorization server returned an invalid private_key_jwt client registration')
    }
    const tokenEndpoint = new URL(registration.token_endpoint)
    const loopbackHTTP = tokenEndpoint.protocol === 'http:' &&
      ['localhost', '127.0.0.1', '[::1]'].includes(tokenEndpoint.hostname)
    if (tokenEndpoint.protocol !== 'https:' && !loopbackHTTP) {
      throw new Error('The private_key_jwt token endpoint must use HTTPS outside loopback development')
    }
    return {
      clientId: registration.client_id,
      tokenEndpoint: tokenEndpoint.toString(),
    }
  }
}

