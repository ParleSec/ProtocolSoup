/**
 * Refresh Token Flow Executor
 * 
 * Implements RFC 6749 Section 6 - Refreshing an Access Token
 * 
 * Used to obtain a new access token using a refresh token,
 * without requiring the user to re-authenticate.
 * 
 * Flow:
 * 1. Client sends refresh token to token endpoint
 * 2. Token endpoint validates and returns new access token
 *    (optionally with a new refresh token)
 */

import { FlowExecutorBase, type FlowExecutorConfig } from './base'

export interface RefreshTokenConfig extends FlowExecutorConfig {
  /** The refresh token to use */
  refreshToken: string
  /** Client secret (for confidential clients) */
  clientSecret?: string
}

export class RefreshTokenExecutor extends FlowExecutorBase {
  readonly flowType = 'refresh_token'
  readonly flowName = 'Refresh Token Grant'
  readonly rfcReference = 'RFC 6749 Section 6'

  private flowConfig: RefreshTokenConfig

  constructor(config: RefreshTokenConfig) {
    super(config)
    this.flowConfig = config

    if (!config.refreshToken) {
      throw new Error('Refresh Token flow requires a refresh_token')
    }
  }

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({
      ...this.createInitialState(),
      status: 'executing',
      currentStep: 'Initiating Refresh Token Flow',
    })

    this.addEvent({
      type: 'info',
      title: 'Starting Refresh Token Flow',
      description: 'Obtaining new access token using refresh token',
      rfcReference: this.rfcReference,
      data: {
        clientId: this.config.clientId,
        hasRefreshToken: true,
        requestedScopes: this.config.scopes,
      },
    })

    this.addEvent({
      type: 'rfc',
      title: 'RFC 6749 Section 6',
      description: 'Refresh tokens allow obtaining new access tokens without user interaction',
      rfcReference: this.rfcReference,
      data: {
        purpose: 'Extend session without re-authentication',
        security: 'Refresh tokens are long-lived and must be stored securely',
      },
    })

    try {
      await this.refreshAccessToken()

      this.updateState({
        status: 'completed',
        currentStep: 'Flow completed successfully',
      })

      this.addEvent({
        type: 'info',
        title: 'Refresh Token Flow Complete',
        description: 'New access token obtained',
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

  private async refreshAccessToken(): Promise<void> {
    this.updateState({
      currentStep: 'Requesting new access token',
    })

    const body: Record<string, string> = {
      grant_type: 'refresh_token',
      refresh_token: this.flowConfig.refreshToken,
      client_id: this.config.clientId,
    }

    // Add scope if requesting different/reduced scope
    if (this.config.scopes.length > 0) {
      body.scope = this.config.scopes.join(' ')

      this.addEvent({
        type: 'rfc',
        title: 'RFC 6749 Section 6 - Scope',
        description: 'Requesting specific scopes (must be subset of original)',
        rfcReference: 'RFC 6749 Section 6',
        data: {
          requestedScope: body.scope,
          note: 'Scope must be equal to or narrower than original grant',
        },
      })
    }

    // Add client secret for confidential clients
    if (this.flowConfig.clientSecret) {
      body.client_secret = this.flowConfig.clientSecret

      this.addEvent({
        type: 'security',
        title: 'Client Authentication',
        description: 'Including client_secret for confidential client',
        rfcReference: 'RFC 6749 Section 2.3',
      })
    }

    const { response, data } = await this.makeRequest(
      'POST',
      `${this.config.baseUrl}/token`,
      {
        body,
        step: 'Token Refresh Request',
        rfcReference: 'RFC 6749 Section 6',
      }
    )

    if (!response.ok) {
      const errorData = data as Record<string, unknown>
      
      // Check for specific refresh token errors
      if (errorData.error === 'invalid_grant') {
        this.addEvent({
          type: 'security',
          title: 'Refresh Token Invalid or Expired',
          description: 'The refresh token is no longer valid - user must re-authenticate',
          rfcReference: 'RFC 6749 Section 5.2',
          data: errorData,
        })
      }

      throw new Error(
        (errorData.error_description as string) || 
        (errorData.error as string) || 
        'Token refresh failed'
      )
    }

    const responseData = data as Record<string, unknown>

    // Check if a new refresh token was issued (rotation)
    if (responseData.refresh_token) {
      this.addEvent({
        type: 'security',
        title: 'Refresh Token Rotation',
        description: 'New refresh token issued - old token should be discarded',
        rfcReference: 'RFC 6749 Section 6',
        data: {
          note: 'Refresh token rotation is a security best practice',
          warning: 'Previous refresh token is now invalid',
        },
      })
    }

    this.processTokenResponse(responseData)
  }
}

