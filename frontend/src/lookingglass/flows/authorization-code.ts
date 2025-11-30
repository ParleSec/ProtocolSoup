/**
 * Authorization Code Flow Executor
 * 
 * Implements RFC 6749 Section 4.1 - Authorization Code Grant
 * With optional PKCE extension (RFC 7636)
 * 
 * Flow:
 * 1. Client redirects user to authorization endpoint
 * 2. User authenticates and authorizes
 * 3. Authorization server redirects back with code
 * 4. Client exchanges code for tokens at token endpoint
 */

import {
  FlowExecutorBase,
  type FlowExecutorConfig,
  generateSecureRandom,
  generateCodeVerifier,
  generateCodeChallenge,
} from './base'

export interface AuthorizationCodeConfig extends FlowExecutorConfig {
  /** Use PKCE (RFC 7636) - required for public clients */
  usePkce: boolean
  /** Include nonce for OIDC */
  includeNonce?: boolean
}

export class AuthorizationCodeExecutor extends FlowExecutorBase {
  readonly flowType = 'authorization_code'
  readonly flowName = 'Authorization Code Grant'
  readonly rfcReference = 'RFC 6749 Section 4.1'

  private flowConfig: AuthorizationCodeConfig

  constructor(config: AuthorizationCodeConfig) {
    super(config)
    this.flowConfig = config
  }

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({
      ...this.createInitialState(),
      status: 'executing',
      currentStep: 'Initiating Authorization Code Flow',
    })

    this.addEvent({
      type: 'info',
      title: 'Starting Authorization Code Flow',
      description: `Per ${this.rfcReference}${this.flowConfig.usePkce ? ' with PKCE (RFC 7636)' : ''}`,
      rfcReference: this.rfcReference,
      data: {
        clientId: this.config.clientId,
        scopes: this.config.scopes,
        usePkce: this.flowConfig.usePkce,
      },
    })

    try {
      // Step 1: Generate security parameters
      await this.generateSecurityParams()

      // Step 2: Build authorization URL and redirect user
      const authUrl = this.buildAuthorizationUrl()
      
      this.addEvent({
        type: 'rfc',
        title: 'RFC 6749 Section 4.1.1',
        description: 'Authorization Request - Client constructs authorization URL',
        rfcReference: 'RFC 6749 Section 4.1.1',
        data: {
          response_type: 'code',
          client_id: this.config.clientId,
          redirect_uri: this.config.redirectUri,
          scope: this.config.scopes.join(' '),
          state: this.state.securityParams.state,
        },
      })

      // Step 3: Open authorization in popup and wait for callback
      this.updateState({ 
        status: 'awaiting_user',
        currentStep: 'Awaiting user authorization',
      })
      
      const { code, state } = await this.openAuthorizationPopup(authUrl)

      // Step 4: Validate state (CSRF protection)
      if (state !== this.state.securityParams.state) {
        throw new Error('State mismatch - possible CSRF attack')
      }

      this.addEvent({
        type: 'security',
        title: 'State Parameter Validated',
        description: 'CSRF protection - state matches original value',
        rfcReference: 'RFC 6749 Section 10.12',
        data: { state },
      })

      this.addEvent({
        type: 'rfc',
        title: 'RFC 6749 Section 4.1.2',
        description: 'Authorization Response - Received authorization code',
        rfcReference: 'RFC 6749 Section 4.1.2',
        data: {
          code: `${code.substring(0, 10)}...`,
          state,
        },
      })

      // Step 5: Exchange code for tokens
      this.updateState({
        status: 'executing',
        currentStep: 'Exchanging code for tokens',
      })

      await this.exchangeCodeForTokens(code)

      this.updateState({
        status: 'completed',
        currentStep: 'Flow completed successfully',
      })

      this.addEvent({
        type: 'info',
        title: 'Authorization Code Flow Complete',
        description: `Successfully obtained ${Object.keys(this.state.tokens).filter(k => this.state.tokens[k as keyof typeof this.state.tokens]).length} token(s)`,
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

  private async generateSecurityParams(): Promise<void> {
    // Generate state parameter (CSRF protection)
    const state = generateSecureRandom(16)
    
    this.updateState({
      securityParams: {
        ...this.state.securityParams,
        state,
      },
    })

    this.addEvent({
      type: 'security',
      title: 'State Parameter Generated',
      description: 'Random value for CSRF protection per RFC 6749 Section 10.12',
      rfcReference: 'RFC 6749 Section 10.12',
      data: { state },
    })

    // Generate PKCE parameters if enabled
    if (this.flowConfig.usePkce) {
      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)

      this.updateState({
        securityParams: {
          ...this.state.securityParams,
          codeVerifier,
          codeChallenge,
        },
      })

      this.addEvent({
        type: 'crypto',
        title: 'PKCE Parameters Generated (RFC 7636)',
        description: 'code_verifier (secret) and code_challenge (public hash)',
        rfcReference: 'RFC 7636 Section 4.1-4.2',
        data: {
          codeVerifier: `${codeVerifier.substring(0, 8)}...${codeVerifier.substring(codeVerifier.length - 8)}`,
          codeVerifierLength: codeVerifier.length,
          codeChallenge,
          codeChallengeMethod: 'S256',
        },
      })
    }

    // Generate nonce for OIDC
    if (this.flowConfig.includeNonce) {
      const nonce = generateSecureRandom(16)
      
      this.updateState({
        securityParams: {
          ...this.state.securityParams,
          nonce,
        },
      })

      this.addEvent({
        type: 'security',
        title: 'Nonce Generated (OIDC)',
        description: 'Random value to prevent replay attacks',
        rfcReference: 'OIDC Core 1.0 Section 3.1.2.1',
        data: { nonce },
      })
    }
  }

  private buildAuthorizationUrl(): string {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      scope: this.config.scopes.join(' '),
      state: this.state.securityParams.state!,
    })

    if (this.config.redirectUri) {
      params.set('redirect_uri', this.config.redirectUri)
    }

    if (this.flowConfig.usePkce && this.state.securityParams.codeChallenge) {
      params.set('code_challenge', this.state.securityParams.codeChallenge)
      params.set('code_challenge_method', 'S256')
    }

    if (this.state.securityParams.nonce) {
      params.set('nonce', this.state.securityParams.nonce)
    }

    // Add any extra parameters
    if (this.config.extraParams) {
      for (const [key, value] of Object.entries(this.config.extraParams)) {
        params.set(key, value)
      }
    }

    return `${this.config.baseUrl}/authorize?${params.toString()}`
  }

  private openAuthorizationPopup(authUrl: string): Promise<{ code: string; state: string }> {
    return new Promise((resolve, reject) => {
      const width = 600
      const height = 700
      const left = window.screenX + (window.outerWidth - width) / 2
      const top = window.screenY + (window.outerHeight - height) / 2

      const popup = window.open(
        authUrl,
        'oauth_authorization',
        `width=${width},height=${height},left=${left},top=${top},scrollbars=yes`
      )

      if (!popup) {
        reject(new Error('Popup blocked - please allow popups for this site'))
        return
      }

      this.addEvent({
        type: 'user_action',
        title: 'Authorization Window Opened',
        description: 'User must authenticate and authorize the application',
        data: { url: authUrl },
      })

      const handleMessage = (event: MessageEvent) => {
        if (event.origin !== window.location.origin) return

        if (event.data?.type === 'oauth_callback') {
          window.removeEventListener('message', handleMessage)
          clearInterval(pollTimer)
          popup.close()

          const { code, state, error, error_description } = event.data

          if (error) {
            this.addEvent({
              type: 'error',
              title: 'Authorization Denied',
              description: error_description || error,
              rfcReference: 'RFC 6749 Section 4.1.2.1',
              data: { error, error_description },
            })
            reject(new Error(error_description || error))
            return
          }

          resolve({ code, state })
        }
      }

      window.addEventListener('message', handleMessage)

      const pollTimer = setInterval(() => {
        if (popup.closed) {
          clearInterval(pollTimer)
          window.removeEventListener('message', handleMessage)
          
          if (this.state.status === 'awaiting_user') {
            reject(new Error('User closed authorization window'))
          }
        }
      }, 500)
    })
  }

  private async exchangeCodeForTokens(code: string): Promise<void> {
    this.addEvent({
      type: 'rfc',
      title: 'RFC 6749 Section 4.1.3',
      description: 'Access Token Request - Exchanging authorization code for tokens',
      rfcReference: 'RFC 6749 Section 4.1.3',
    })

    const body: Record<string, string> = {
      grant_type: 'authorization_code',
      code,
      client_id: this.config.clientId,
    }

    if (this.config.redirectUri) {
      body.redirect_uri = this.config.redirectUri
    }

    // Add PKCE code_verifier
    if (this.flowConfig.usePkce && this.state.securityParams.codeVerifier) {
      body.code_verifier = this.state.securityParams.codeVerifier

      this.addEvent({
        type: 'crypto',
        title: 'PKCE Verification (RFC 7636)',
        description: 'Sending code_verifier for server-side validation',
        rfcReference: 'RFC 7636 Section 4.5',
        data: {
          note: 'Server will hash this and compare with code_challenge',
        },
      })
    }

    // Add client secret for confidential clients
    if (this.config.clientSecret) {
      body.client_secret = this.config.clientSecret
    }

    const { response, data } = await this.makeRequest(
      'POST',
      `${this.config.baseUrl}/token`,
      {
        body,
        step: 'Token Exchange Request',
        rfcReference: 'RFC 6749 Section 4.1.3',
      }
    )

    if (!response.ok) {
      const errorData = data as Record<string, unknown>
      throw new Error(
        (errorData.error_description as string) || 
        (errorData.error as string) || 
        'Token exchange failed'
      )
    }

    this.addEvent({
      type: 'rfc',
      title: 'RFC 6749 Section 4.1.4',
      description: 'Access Token Response - Tokens received from authorization server',
      rfcReference: 'RFC 6749 Section 4.1.4',
    })

    this.processTokenResponse(data as Record<string, unknown>)
  }
}

