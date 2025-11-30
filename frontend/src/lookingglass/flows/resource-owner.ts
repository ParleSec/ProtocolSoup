/**
 * Resource Owner Password Credentials Flow Executor
 * 
 * Implements RFC 6749 Section 4.3 - Resource Owner Password Credentials Grant
 * 
 * ⚠️ LEGACY FLOW - NOT RECOMMENDED
 * Only use when there is a high degree of trust between the resource owner
 * and the client (e.g., the client is part of the device operating system).
 * 
 * Flow:
 * 1. Client collects username and password directly
 * 2. Client sends credentials to token endpoint
 * 3. Token endpoint validates and returns tokens
 * 
 * Security Issues:
 * - Client has access to user's credentials
 * - No way for user to authorize specific scopes
 * - No MFA support without protocol extensions
 */

import { FlowExecutorBase, type FlowExecutorConfig } from './base'

export interface ResourceOwnerConfig extends FlowExecutorConfig {
  /** Resource owner's username */
  username: string
  /** Resource owner's password */
  password: string
  /** Client secret (optional, for confidential clients) */
  clientSecret?: string
}

export class ResourceOwnerExecutor extends FlowExecutorBase {
  readonly flowType = 'password'
  readonly flowName = 'Resource Owner Password Credentials Grant (Legacy)'
  readonly rfcReference = 'RFC 6749 Section 4.3'

  private flowConfig: ResourceOwnerConfig

  constructor(config: ResourceOwnerConfig) {
    super(config)
    this.flowConfig = config

    if (!config.username || !config.password) {
      throw new Error('Username and password are required')
    }
  }

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({
      ...this.createInitialState(),
      status: 'executing',
      currentStep: 'Initiating Resource Owner Password Flow',
    })

    this.addEvent({
      type: 'info',
      title: 'Starting Resource Owner Password Credentials Flow',
      description: '⚠️ Legacy flow - shown for educational purposes',
      rfcReference: this.rfcReference,
      data: {
        clientId: this.config.clientId,
        scopes: this.config.scopes,
        username: this.flowConfig.username,
      },
    })

    this.addEvent({
      type: 'security',
      title: '⚠️ Security Warning: ROPC Flow Deprecated',
      description: 'This flow exposes user credentials to the client application',
      rfcReference: 'OAuth 2.0 Security BCP',
      data: {
        risks: [
          'Client has direct access to user credentials',
          'No user consent screen for scope authorization',
          'No support for MFA/2FA without extensions',
          'Credentials could be logged or stored insecurely',
          'Cannot be used with federated identity providers',
        ],
        recommendation: 'Use Authorization Code flow with PKCE',
        legitimateUseCase: 'First-party apps on trusted OS with no browser',
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
        title: 'Resource Owner Password Flow Complete',
        description: 'Tokens obtained using direct credentials',
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
    this.addEvent({
      type: 'rfc',
      title: 'RFC 6749 Section 4.3.2',
      description: 'Access Token Request - Sending user credentials directly',
      rfcReference: 'RFC 6749 Section 4.3.2',
      data: {
        grant_type: 'password',
        note: 'User credentials sent in clear text (over TLS)',
      },
    })

    this.updateState({
      currentStep: 'Requesting access token with credentials',
    })

    const body: Record<string, string> = {
      grant_type: 'password',
      username: this.flowConfig.username,
      password: this.flowConfig.password,
      client_id: this.config.clientId,
    }

    if (this.config.scopes.length > 0) {
      body.scope = this.config.scopes.join(' ')
    }

    if (this.flowConfig.clientSecret) {
      body.client_secret = this.flowConfig.clientSecret
    }

    this.addEvent({
      type: 'security',
      title: 'Credentials in Request',
      description: 'Username and password being sent to token endpoint',
      rfcReference: 'RFC 6749 Section 4.3.2',
      data: {
        warning: 'This is why ROPC is not recommended',
        username: this.flowConfig.username,
        passwordSent: true,
      },
    })

    const { response, data } = await this.makeRequest(
      'POST',
      `${this.config.baseUrl}/token`,
      {
        body,
        step: 'Token Request (Password Grant)',
        rfcReference: 'RFC 6749 Section 4.3.2',
      }
    )

    if (!response.ok) {
      const errorData = data as Record<string, unknown>
      
      if (errorData.error === 'invalid_grant') {
        this.addEvent({
          type: 'error',
          title: 'Invalid Credentials',
          description: 'Username or password is incorrect',
          rfcReference: 'RFC 6749 Section 5.2',
        })
      }

      throw new Error(
        (errorData.error_description as string) || 
        (errorData.error as string) || 
        'Token request failed'
      )
    }

    this.addEvent({
      type: 'rfc',
      title: 'RFC 6749 Section 4.3.3',
      description: 'Access Token Response - Tokens received',
      rfcReference: 'RFC 6749 Section 4.3.3',
    })

    this.processTokenResponse(data as Record<string, unknown>)
  }
}

