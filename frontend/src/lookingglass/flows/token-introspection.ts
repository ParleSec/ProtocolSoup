/**
 * Token Introspection Flow Executor
 * 
 * Implements RFC 7662 - OAuth 2.0 Token Introspection
 * 
 * Makes REAL requests to the introspection endpoint and captures actual responses.
 */

import { FlowExecutorBase, type FlowExecutorConfig } from './base'

export interface TokenIntrospectionConfig extends FlowExecutorConfig {
  /** The token to introspect */
  token: string
  /** Hint about the token type (access_token or refresh_token) */
  tokenTypeHint?: 'access_token' | 'refresh_token'
  /** Client secret for authentication */
  clientSecret?: string
}

export class TokenIntrospectionExecutor extends FlowExecutorBase {
  readonly flowType = 'token_introspection'
  readonly flowName = 'Token Introspection'
  readonly rfcReference = 'RFC 7662'

  private flowConfig: TokenIntrospectionConfig

  constructor(config: TokenIntrospectionConfig) {
    super(config)
    this.flowConfig = config
    // Token validation happens at execute() time, not constructor
    // This allows the executor to be created and show flow info in UI
  }

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({
      ...this.createInitialState(),
      status: 'executing',
      currentStep: 'Initiating Token Introspection',
    })

    // Validate token is provided
    if (!this.flowConfig.token) {
      this.updateState({
        status: 'error',
        currentStep: 'Missing required token',
        error: {
          code: 'missing_token',
          description: 'Token Introspection requires an access token. First obtain a token using Authorization Code or Client Credentials flow.',
        },
      })
      this.addEvent({
        type: 'error',
        title: 'Missing Token',
        description: 'Provide an access token to introspect (run an authorization flow first)',
      })
      return
    }

    this.addEvent({
      type: 'info',
      title: 'Starting Token Introspection',
      description: `POST ${this.config.baseUrl}/introspect`,
      rfcReference: this.rfcReference,
    })

    try {
      await this.introspectToken()

      this.updateState({
        status: 'completed',
        currentStep: 'Introspection completed',
      })

    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      this.updateState({
        status: 'error',
        currentStep: 'Introspection failed',
        error: {
          code: 'introspection_error',
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

  private async introspectToken(): Promise<void> {
    this.updateState({
      currentStep: 'Sending introspection request',
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

    // Make the REAL request and capture traffic
    const { response, data } = await this.makeRequest(
      'POST',
      `${this.config.baseUrl}/introspect`,
      {
        body,
        step: 'Token Introspection Request',
        rfcReference: 'RFC 7662 Section 2.1',
      }
    )

    if (!response.ok) {
      const errorData = data as Record<string, unknown>
      throw new Error(
        (errorData.error_description as string) ||
        (errorData.error as string) ||
        `Introspection failed with status ${response.status}`
      )
    }

    // Log the ACTUAL response data
    const introspectionResponse = data as Record<string, unknown>

    if (introspectionResponse.active) {
      this.addEvent({
        type: 'security',
        title: 'Token Status: ACTIVE',
        description: `Token is valid. Subject: ${introspectionResponse.sub || 'N/A'}, Scope: ${introspectionResponse.scope || 'N/A'}`,
        data: introspectionResponse, // Include the REAL response data
      })
    } else {
      this.addEvent({
        type: 'security',
        title: 'Token Status: INACTIVE',
        description: 'Token is invalid, expired, or revoked',
        data: introspectionResponse,
      })
    }
  }
}
