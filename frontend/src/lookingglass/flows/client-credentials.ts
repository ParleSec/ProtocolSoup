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
  type RS256SigningMaterial,
} from '../../utils/crypto'

export type ClientCredentialsAuthMethod = 'client_secret_basic' | 'private_key_jwt'

export interface ClientCredentialsConfig extends FlowExecutorConfig {
  clientSecret?: string
  clientAuthMethod?: ClientCredentialsAuthMethod
}

interface PrivateKeyJWTRegistration {
  clientId: string
  tokenEndpoint: string
}

export class ClientCredentialsExecutor extends FlowExecutorBase {
  readonly flowType = 'client_credentials'
  readonly flowName = 'Client Credentials Grant'
  readonly rfcReference = 'RFC 6749 Section 4.4'

  private flowConfig: ClientCredentialsConfig
  private signingMaterialPromise?: Promise<RS256SigningMaterial>

  constructor(config: ClientCredentialsConfig) {
    super(config)
    this.flowConfig = config

  }

  async execute(): Promise<void> {
    const authMethod = this.flowConfig.clientAuthMethod || 'client_secret_basic'
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
    this.addEvent({
      type: 'rfc',
      title: 'RFC 6749 Section 4.4.2',
      description: 'Access Token Request - Client authenticates and requests token',
      rfcReference: 'RFC 6749 Section 4.4.2',
      data: {
        grant_type: 'client_credentials',
        authentication: authMethod,
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

    const { response, data } = await this.makeRequest(
      'POST',
      `${this.config.baseUrl}/token`,
      {
        headers,
        body,
        step: 'Token Request (Client Credentials)',
        rfcReference: tokenRequestReference,
      }
    )

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

    this.processTokenResponse(data as Record<string, unknown>)
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

