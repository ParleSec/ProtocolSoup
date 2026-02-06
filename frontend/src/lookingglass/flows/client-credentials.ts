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

import { FlowExecutorBase, type FlowExecutorConfig } from './base'

export interface ClientCredentialsConfig extends FlowExecutorConfig {
  /** Client secret is REQUIRED for this flow */
  clientSecret: string
}

export class ClientCredentialsExecutor extends FlowExecutorBase {
  readonly flowType = 'client_credentials'
  readonly flowName = 'Client Credentials Grant'
  readonly rfcReference = 'RFC 6749 Section 4.4'

  private flowConfig: ClientCredentialsConfig

  constructor(config: ClientCredentialsConfig) {
    super(config)
    this.flowConfig = config

    // Note: clientSecret validation happens when execute() is called
    // This allows the UI to show the executor is available, but execution will fail
  }

  async execute(): Promise<void> {
    // Validate client secret is present
    if (!this.flowConfig.clientSecret) {
      this.updateState({
        status: 'error',
        currentStep: 'Configuration Error',
        error: {
          code: 'missing_client_secret',
          description: 'Client Credentials flow requires a client_secret. Use a confidential client.',
        },
      })
      this.addEvent({
        type: 'error',
        title: 'Missing Client Secret',
        description: 'Client Credentials flow requires a confidential client with a client_secret',
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
        clientId: this.config.clientId,
        scopes: this.config.scopes,
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
    this.addEvent({
      type: 'rfc',
      title: 'RFC 6749 Section 4.4.2',
      description: 'Access Token Request - Client authenticates and requests token',
      rfcReference: 'RFC 6749 Section 4.4.2',
      data: {
        grant_type: 'client_credentials',
        authentication: 'HTTP Basic (client_id:client_secret)',
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

    // RFC 6749 Section 2.3.1: "Clients in possession of a client password MAY use the
    // HTTP Basic authentication scheme." POST body credentials "is NOT RECOMMENDED and
    // SHOULD be limited to clients unable to directly utilize the HTTP Basic
    // authentication scheme."
    this.addEvent({
      type: 'security',
      title: 'Client Authentication',
      description: 'Sending client credentials via HTTP Basic Authentication (RECOMMENDED per RFC 6749 Section 2.3.1)',
      rfcReference: 'RFC 6749 Section 2.3.1',
      data: {
        method: 'HTTP Basic (Authorization header)',
        note: 'POST body credentials are NOT RECOMMENDED per RFC 6749 Section 2.3.1',
      },
    })

    const { response, data } = await this.makeRequest(
      'POST',
      `${this.config.baseUrl}/token`,
      {
        headers: {
          'Authorization': `Basic ${btoa(`${this.config.clientId}:${this.flowConfig.clientSecret}`)}`,
        },
        body,
        step: 'Token Request (Client Credentials)',
        rfcReference: 'RFC 6749 Section 4.4.2',
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
}

