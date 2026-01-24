/**
 * OIDC UserInfo Flow Executor
 * 
 * Implements OIDC Core 1.0 Section 5.3 - UserInfo Endpoint
 * 
 * Makes live requests to the UserInfo endpoint and captures user claims.
 */

import { FlowExecutorBase, type FlowExecutorConfig } from './base'

export interface OIDCUserInfoConfig extends FlowExecutorConfig {
  /** Access token with openid scope */
  accessToken: string
}

export class OIDCUserInfoExecutor extends FlowExecutorBase {
  readonly flowType = 'oidc_userinfo'
  readonly flowName = 'OIDC UserInfo Endpoint'
  readonly rfcReference = 'OIDC Core 1.0 Section 5.3'

  private flowConfig: OIDCUserInfoConfig

  constructor(config: OIDCUserInfoConfig) {
    super(config)
    this.flowConfig = config
    // Token validation happens at execute() time, not constructor
  }

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({
      ...this.createInitialState(),
      status: 'executing',
      currentStep: 'Initiating UserInfo Request',
    })

    // Validate access token is provided
    if (!this.flowConfig.accessToken) {
      this.updateState({
        status: 'error',
        currentStep: 'Missing required access token',
        error: {
          code: 'missing_token',
          description: 'UserInfo endpoint requires an access token with openid scope. First complete an OIDC Authorization Code flow.',
        },
      })
      this.addEvent({
        type: 'error',
        title: 'Missing Access Token',
        description: 'Provide an access token with openid scope (run OIDC authorization flow first)',
      })
      return
    }

    this.addEvent({
      type: 'info',
      title: 'Starting UserInfo Request',
      description: `GET ${this.config.baseUrl}/userinfo`,
      rfcReference: this.rfcReference,
    })

    try {
      await this.fetchUserInfo()

      this.updateState({
        status: 'completed',
        currentStep: 'UserInfo retrieved successfully',
      })

    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      this.updateState({
        status: 'error',
        currentStep: 'UserInfo request failed',
        error: {
          code: 'userinfo_error',
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

  private async fetchUserInfo(): Promise<void> {
    this.updateState({
      currentStep: 'Sending UserInfo request',
    })

    // Make the request with Bearer token
    const { response, data } = await this.makeRequest(
      'GET',
      `${this.config.baseUrl}/userinfo`,
      {
        headers: {
          'Authorization': `Bearer ${this.flowConfig.accessToken}`,
          'Accept': 'application/json',
        },
        step: 'UserInfo Request',
        rfcReference: 'OIDC Core 1.0 Section 5.3.1',
      }
    )

    if (!response.ok) {
      const errorData = data as Record<string, unknown>
      throw new Error(
        (errorData.error_description as string) ||
        (errorData.error as string) ||
        `UserInfo request failed with status ${response.status}`
      )
    }

    // Log the ACTUAL user claims received
    const userInfo = data as Record<string, unknown>

    this.addEvent({
      type: 'token',
      title: 'User Claims Received',
      description: `Subject: ${userInfo.sub}`,
      data: userInfo, // Include ALL actual claims from the response
    })

    // Log which claim categories were returned
    const claimCategories: string[] = []
    if (userInfo.name || userInfo.given_name || userInfo.family_name) claimCategories.push('profile')
    if (userInfo.email) claimCategories.push('email')
    if (userInfo.phone_number) claimCategories.push('phone')
    if (userInfo.address) claimCategories.push('address')

    if (claimCategories.length > 0) {
      this.addEvent({
        type: 'info',
        title: 'Claims Retrieved',
        description: `Scopes with data: ${claimCategories.join(', ')}`,
        data: {
          sub: userInfo.sub,
          claimCount: Object.keys(userInfo).length,
          categories: claimCategories,
        },
      })
    }
  }
}
