/**
 * Implicit Flow Executor
 * 
 * Implements RFC 6749 Section 4.2 - Implicit Grant
 * 
 * ⚠️ LEGACY FLOW - NOT RECOMMENDED FOR NEW APPLICATIONS
 * Use Authorization Code with PKCE instead.
 * 
 * Included for educational purposes to understand OAuth history
 * and why PKCE was developed.
 * 
 * Flow:
 * 1. Client redirects user to authorization endpoint with response_type=token
 * 2. User authenticates and authorizes
 * 3. Authorization server redirects back with token in URL FRAGMENT
 *    (NOT query parameter - fragment is not sent to server)
 * 
 * Security Issues:
 * - Token exposed in browser history
 * - Token exposed in referrer header
 * - No client authentication
 * - Vulnerable to token substitution attacks
 */

import { FlowExecutorBase, type FlowExecutorConfig, generateSecureRandom } from './base'

export interface ImplicitConfig extends FlowExecutorConfig {
  /** Include nonce for OIDC implicit flow */
  includeNonce?: boolean
  /** response_type: 'token' (OAuth) or 'id_token token' (OIDC) */
  responseType?: 'token' | 'id_token' | 'id_token token'
}

export class ImplicitExecutor extends FlowExecutorBase {
  readonly flowType = 'implicit'
  readonly flowName = 'Implicit Grant (Legacy)'
  readonly rfcReference = 'RFC 6749 Section 4.2'

  private flowConfig: ImplicitConfig

  constructor(config: ImplicitConfig) {
    super(config)
    this.flowConfig = {
      ...config,
      responseType: config.responseType || 'token',
    }
  }

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({
      ...this.createInitialState(),
      status: 'executing',
      currentStep: 'Initiating Implicit Flow',
    })

    this.addEvent({
      type: 'info',
      title: 'Starting Implicit Flow',
      description: '⚠️ Legacy flow - shown for educational purposes',
      rfcReference: this.rfcReference,
      data: {
        clientId: this.config.clientId,
        scopes: this.config.scopes,
        responseType: this.flowConfig.responseType,
      },
    })

    this.addEvent({
      type: 'security',
      title: '⚠️ Security Warning: Implicit Flow Deprecated',
      description: 'This flow is NOT recommended. Use Authorization Code + PKCE instead.',
      rfcReference: 'OAuth 2.0 Security BCP',
      data: {
        risks: [
          'Access token exposed in URL fragment',
          'Token visible in browser history',
          'Token may leak via referrer header',
          'No client authentication possible',
          'Vulnerable to token injection attacks',
        ],
        recommendation: 'Use Authorization Code flow with PKCE (RFC 7636)',
      },
    })

    try {
      // Generate security parameters
      await this.generateSecurityParams()

      // Build authorization URL
      const authUrl = this.buildAuthorizationUrl()

      this.addEvent({
        type: 'rfc',
        title: 'RFC 6749 Section 4.2.1',
        description: 'Authorization Request - response_type=token returns token directly',
        rfcReference: 'RFC 6749 Section 4.2.1',
        data: {
          response_type: this.flowConfig.responseType,
          note: 'Token will be returned in URL fragment, not query string',
        },
      })

      // Open authorization popup
      this.updateState({
        status: 'awaiting_user',
        currentStep: 'Awaiting user authorization',
      })

      const tokens = await this.openAuthorizationPopup(authUrl)

      // Validate state
      if (tokens.state !== this.state.securityParams.state) {
        throw new Error('State mismatch - possible CSRF attack')
      }

      this.addEvent({
        type: 'security',
        title: 'State Parameter Validated',
        description: 'CSRF protection - state matches original value',
        rfcReference: 'RFC 6749 Section 10.12',
      })

      // Process tokens from fragment
      this.processImplicitTokens(tokens)

      this.updateState({
        status: 'completed',
        currentStep: 'Flow completed',
      })

      this.addEvent({
        type: 'info',
        title: 'Implicit Flow Complete',
        description: 'Token(s) received directly from authorization endpoint',
        rfcReference: 'RFC 6749 Section 4.2.2',
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
      description: 'Random value for CSRF protection',
      rfcReference: 'RFC 6749 Section 10.12',
      data: { state },
    })

    // Generate nonce for OIDC
    if (this.flowConfig.includeNonce || 
        this.flowConfig.responseType?.includes('id_token')) {
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
        description: 'Required when requesting id_token to prevent replay attacks',
        rfcReference: 'OIDC Core 1.0 Section 3.2.2.1',
        data: { nonce },
      })
    }
  }

  private buildAuthorizationUrl(): string {
    const params = new URLSearchParams({
      response_type: this.flowConfig.responseType!,
      client_id: this.config.clientId,
      scope: this.config.scopes.join(' '),
      state: this.state.securityParams.state!,
    })

    if (this.config.redirectUri) {
      params.set('redirect_uri', this.config.redirectUri)
    }

    if (this.state.securityParams.nonce) {
      params.set('nonce', this.state.securityParams.nonce)
    }

    if (this.config.extraParams) {
      for (const [key, value] of Object.entries(this.config.extraParams)) {
        params.set(key, value)
      }
    }

    return this.withCaptureQuery(`${this.config.baseUrl}/authorize?${params.toString()}`)
  }

  private openAuthorizationPopup(authUrl: string): Promise<{
    access_token?: string
    id_token?: string
    token_type?: string
    expires_in?: number
    state: string
  }> {
    return new Promise((resolve, reject) => {
      // Use full screen on mobile devices
      const isMobile = window.innerWidth < 640
      const width = isMobile ? window.screen.width : 600
      const height = isMobile ? window.screen.height : 700
      const left = isMobile ? 0 : window.screenX + (window.outerWidth - width) / 2
      const top = isMobile ? 0 : window.screenY + (window.outerHeight - height) / 2

      const popup = window.open(
        authUrl,
        'oauth_implicit',
        `width=${width},height=${height},left=${left},top=${top},scrollbars=yes,resizable=yes`
      )

      if (!popup) {
        reject(new Error('Popup blocked'))
        return
      }

      this.addEvent({
        type: 'user_action',
        title: 'Authorization Window Opened',
        description: 'User must authenticate and authorize',
      })

      const handleMessage = (event: MessageEvent) => {
        if (event.origin !== window.location.origin) return

        if (event.data?.type === 'oauth_implicit_callback') {
          window.removeEventListener('message', handleMessage)
          clearInterval(pollTimer)
          popup.close()

          const { error, error_description, ...tokens } = event.data

          if (error) {
            this.addEvent({
              type: 'error',
              title: 'Authorization Denied',
              description: error_description || error,
              rfcReference: 'RFC 6749 Section 4.2.2.1',
            })
            reject(new Error(error_description || error))
            return
          }

          this.addEvent({
            type: 'rfc',
            title: 'RFC 6749 Section 4.2.2',
            description: 'Access Token Response - Token received in URL fragment',
            rfcReference: 'RFC 6749 Section 4.2.2',
            data: {
              location: 'URL fragment (after #)',
              note: 'Fragment is NOT sent to server - only accessible to browser',
            },
          })

          resolve(tokens)
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

  private processImplicitTokens(tokens: {
    access_token?: string
    id_token?: string
    token_type?: string
    expires_in?: number
  }): void {
    const stateTokens: typeof this.state.tokens = {}
    const decodedTokens = []

    if (tokens.access_token) {
      stateTokens.accessToken = tokens.access_token
      const decoded = this.decodeJwt(tokens.access_token, 'access_token')
      decodedTokens.push(decoded)

      this.addEvent({
        type: 'token',
        title: 'Access Token Received',
        description: 'Token received directly in redirect (no code exchange)',
        data: {
          tokenType: tokens.token_type,
          expiresIn: tokens.expires_in,
        },
      })
    }

    if (tokens.id_token) {
      stateTokens.idToken = tokens.id_token
      const decoded = this.decodeJwt(tokens.id_token, 'id_token')
      decodedTokens.push(decoded)

      this.addEvent({
        type: 'token',
        title: 'ID Token Received (OIDC)',
        description: decoded.isValid ? 'ID token validated' : 'ID token has validation errors',
        rfcReference: 'OIDC Core 1.0 Section 3.2.2.5',
        data: {
          isValid: decoded.isValid,
          validationErrors: decoded.validationErrors,
        },
      })
    }

    stateTokens.tokenType = tokens.token_type
    stateTokens.expiresIn = tokens.expires_in

    this.updateState({
      tokens: stateTokens,
      decodedTokens,
    })

    // Note about refresh tokens
    this.addEvent({
      type: 'rfc',
      title: 'No Refresh Token in Implicit Flow',
      description: 'RFC 6749 Section 4.2.2 explicitly prohibits refresh tokens in implicit flow',
      rfcReference: 'RFC 6749 Section 4.2.2',
      data: {
        reason: 'Public clients cannot securely store refresh tokens',
        workaround: 'Use silent renewal with prompt=none or hidden iframe',
      },
    })
  }
}


