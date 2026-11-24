/**
 * Token Revocation Flow Executor
 * 
 * Implements RFC 7009 - OAuth 2.0 Token Revocation
 * 
 * Makes live requests to the revocation endpoint and captures responses.
 */

import { FlowExecutorBase, type FlowExecutorConfig } from './base'
import { getRegisteredPrivateKeyJWTClient } from './client-credentials'
import { signRS256JWT } from '../../utils/crypto'

export interface TokenRevocationConfig extends FlowExecutorConfig {
  /** The token to revoke */
  token: string
  /** Hint about the token type (access_token or refresh_token) */
  tokenTypeHint?: 'access_token' | 'refresh_token'
  /** Client secret for authentication */
  clientSecret?: string
}

export class TokenRevocationExecutor extends FlowExecutorBase {
  readonly flowType = 'token_revocation'
  readonly flowName = 'Token Revocation'
  readonly rfcReference = 'RFC 7009'

  private flowConfig: TokenRevocationConfig

  constructor(config: TokenRevocationConfig) {
    super(config)
    this.flowConfig = config
    // Token validation happens at execute() time, not constructor
  }

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({
      ...this.createInitialState(),
      status: 'executing',
      currentStep: 'Initiating Token Revocation',
    })

    // Validate token is provided
    if (!this.flowConfig.token) {
      this.updateState({
        status: 'error',
        currentStep: 'Missing required token',
        error: {
          code: 'missing_token',
          description: 'Token Revocation requires a token to revoke. First obtain a token using Authorization Code or Client Credentials flow.',
        },
      })
      this.addEvent({
        type: 'error',
        title: 'Missing Token',
        description: 'Provide a token to revoke (run an authorization flow first)',
      })
      return
    }

    this.addEvent({
      type: 'info',
      title: 'Starting Token Revocation',
      description: `POST ${this.config.baseUrl}/revoke`,
      rfcReference: this.rfcReference,
    })

    try {
      await this.revokeToken()

      this.updateState({
        status: 'completed',
        currentStep: 'Revocation request accepted',
      })

    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      this.updateState({
        status: 'error',
        currentStep: 'Revocation failed',
        error: {
          code: 'revocation_error',
          description: message,
        },
      })
      this.addEvent({
        type: 'error',
        title: 'Request Failed',
        description: message,
      })
    }
  }

  private async revokeToken(): Promise<void> {
    this.updateState({
      currentStep: 'Sending revocation request',
    })

    // Build the actual request body
    const body: Record<string, string> = {
      token: this.flowConfig.token,
    }

    if (this.flowConfig.tokenTypeHint) {
      body.token_type_hint = this.flowConfig.tokenTypeHint
    }

    // RFC 7009 Section 2.1: "The client also includes its authentication
    // credentials as described in Section 2.3. of [RFC6749]", and the server
    // revokes only a token that was issued to the client making the request.
    // A confidential client authenticates with HTTP Basic (RFC 6749 Section
    // 2.3.1) or, when it registered a key, with a signed JWT (RFC 7523
    // Section 2.2); a public client has no credentials and names itself with
    // client_id. No configured client_id means the private_key_jwt client
    // this page registered in the Client Credentials flow.
    const headers: Record<string, string> = {}
    let signedAssertion: { raw: string; claims: Record<string, unknown>; clientId: string; kid: string } | undefined
    if (!this.config.clientId) {
      const registered = getRegisteredPrivateKeyJWTClient()
      if (!registered) {
        throw new Error('No private_key_jwt client is registered in this page. Run Client Credentials with private_key_jwt first.')
      }
      // RFC 7523 Section 3: aud identifies the authorization server, and its
      // token endpoint URL may be used for that. Each assertion is single-use,
      // so this is a new one with its own jti.
      const now = Math.floor(Date.now() / 1000)
      const claims = {
        iss: registered.clientId,
        sub: registered.clientId,
        aud: registered.tokenEndpoint,
        iat: now,
        exp: now + 300,
        jti: crypto.randomUUID(),
      }
      const assertion = await signRS256JWT(
        { alg: 'RS256', typ: 'JWT', kid: registered.signingMaterial.kid },
        claims,
        registered.signingMaterial.privateKey,
      )
      body.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      body.client_assertion = assertion
      signedAssertion = { raw: assertion, claims, clientId: registered.clientId, kid: registered.signingMaterial.kid }
    } else if (this.flowConfig.clientSecret) {
      headers.Authorization = `Basic ${btoa(`${this.config.clientId}:${this.flowConfig.clientSecret}`)}`
      this.addEvent({
        type: 'security',
        title: 'Client Authentication',
        description: `Authenticating as ${this.config.clientId} via HTTP Basic Authentication`,
        rfcReference: 'RFC 6749 Section 2.3.1',
        data: {
          clientId: this.config.clientId,
          authMethod: 'client_secret_basic',
        },
      })
    } else {
      body.client_id = this.config.clientId
      this.addEvent({
        type: 'security',
        title: 'Client Identification',
        description: `Revoking as ${this.config.clientId}, which sends client_id and no client credentials`,
        rfcReference: 'RFC 7009 Section 2.1',
        data: {
          clientId: this.config.clientId,
          authMethod: 'none',
        },
      })
    }

    // Make the request and capture traffic
    const { response, data } = await this.makeRequest(
      'POST',
      `${this.config.baseUrl}/revoke`,
      {
        headers,
        body,
        step: 'Token Revocation Request',
        rfcReference: 'RFC 7009 Section 2.1',
      }
    )

    // Published after the request, when the server has consumed its jti.
    if (signedAssertion) {
      this.addEvent({
        type: 'crypto',
        title: 'Client Assertion Signed',
        description: `Authenticated as ${signedAssertion.clientId} with a new assertion signed by the key that client registered`,
        rfcReference: 'RFC 7523 Section 2.2',
        data: {
          method: 'private_key_jwt',
          clientId: signedAssertion.clientId,
          kid: signedAssertion.kid,
          client_assertion: signedAssertion.raw,
          claims: signedAssertion.claims,
        },
      })
    }

    // RFC 7009 Section 2.2: 200 for a revoked token and for an invalid one.
    // A token issued to another client is refused with an error instead.
    if (!response.ok) {
      const errorData = data as Record<string, unknown>
      throw new Error(
        (errorData.error_description as string) ||
        (errorData.error as string) ||
        `Revocation failed with status ${response.status}`
      )
    }

    // Log the actual outcome. A 200 does not say which of the two cases
    // applied, so the event does not claim one.
    this.addEvent({
      type: 'security',
      title: 'Revocation Request Accepted',
      description: `Server returned ${response.status}: the token was revoked, or it was already invalid. The client must not use it again.`,
      rfcReference: 'RFC 7009 Section 2.2',
      data: {
        status: response.status,
      },
    })
  }
}
