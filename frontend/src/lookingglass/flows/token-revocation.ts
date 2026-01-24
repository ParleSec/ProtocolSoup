/**
 * Token Revocation Flow Executor
 * 
 * Implements RFC 7009 - OAuth 2.0 Token Revocation
 * 
 * Makes live requests to the revocation endpoint and captures responses.
 */

import { FlowExecutorBase, type FlowExecutorConfig } from './base'

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
        currentStep: 'Token revoked successfully',
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
      client_id: this.config.clientId,
    }

    if (this.flowConfig.tokenTypeHint) {
      body.token_type_hint = this.flowConfig.tokenTypeHint
    }

    if (this.flowConfig.clientSecret) {
      body.client_secret = this.flowConfig.clientSecret
    }

    // Make the request and capture traffic
    const { response, data } = await this.makeRequest(
      'POST',
      `${this.config.baseUrl}/revoke`,
      {
        body,
        step: 'Token Revocation Request',
        rfcReference: 'RFC 7009 Section 2.1',
      }
    )

    // Per RFC 7009, server returns 200 OK even for invalid tokens
    if (!response.ok) {
      const errorData = data as Record<string, unknown>
      throw new Error(
        (errorData.error_description as string) ||
        (errorData.error as string) ||
        `Revocation failed with status ${response.status}`
      )
    }

    // Log the actual outcome
    this.addEvent({
      type: 'security',
      title: 'Token Revoked',
      description: `Server returned ${response.status} - token is now invalid`,
      data: {
        status: response.status,
        tokenRevoked: true,
        // Note: Per RFC 7009, 200 OK is returned even if token was already invalid
      },
    })
  }
}
