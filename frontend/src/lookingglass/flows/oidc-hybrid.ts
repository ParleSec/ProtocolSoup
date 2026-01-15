/**
 * OIDC Hybrid Flow Executor
 * 
 * Implements OpenID Connect Core 1.0 Section 3.3 - Hybrid Flow
 * 
 * Combines aspects of Authorization Code and Implicit flows.
 * Some tokens returned from authorization endpoint, some from token endpoint.
 * 
 * response_type combinations:
 * - "code id_token" - ID token from authz endpoint, access token from token endpoint
 * - "code token" - Access token from authz endpoint, can get more tokens from token endpoint
 * - "code id_token token" - Both tokens from authz endpoint, can get more from token endpoint
 * 
 * Use case: When you need ID token immediately for front-end but want
 * access token handled securely by backend.
 */

import {
  FlowExecutorBase,
  type FlowExecutorConfig,
  generateSecureRandom,
  generateCodeVerifier,
  generateCodeChallenge,
} from './base'

export type HybridResponseType = 'code id_token' | 'code token' | 'code id_token token'

export interface OIDCHybridConfig extends FlowExecutorConfig {
  /** Which tokens to return from authorization endpoint */
  responseType: HybridResponseType
  /** Use PKCE (recommended) */
  usePkce?: boolean
}

export class OIDCHybridExecutor extends FlowExecutorBase {
  readonly flowType = 'oidc_hybrid'
  readonly flowName = 'OIDC Hybrid Flow'
  readonly rfcReference = 'OIDC Core 1.0 Section 3.3'

  private flowConfig: OIDCHybridConfig

  constructor(config: OIDCHybridConfig) {
    super(config)
    this.flowConfig = {
      ...config,
      usePkce: config.usePkce ?? true,
    }

    // Ensure openid scope is included
    if (!this.config.scopes.includes('openid')) {
      this.config.scopes = ['openid', ...this.config.scopes]
    }
  }

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({
      ...this.createInitialState(),
      status: 'executing',
      currentStep: 'Initiating OIDC Hybrid Flow',
    })

    this.addEvent({
      type: 'info',
      title: 'Starting OIDC Hybrid Flow',
      description: 'Combining Authorization Code and Implicit flows',
      rfcReference: this.rfcReference,
      data: {
        responseType: this.flowConfig.responseType,
        scopes: this.config.scopes,
        clientId: this.config.clientId,
      },
    })

    this.addEvent({
      type: 'rfc',
      title: 'OIDC Core 1.0 Section 3.3',
      description: 'Hybrid Flow - Returns some tokens from authz endpoint, some from token endpoint',
      rfcReference: this.rfcReference,
      data: {
        responseType: this.flowConfig.responseType,
        tokensFromAuthzEndpoint: this.getTokensFromAuthzEndpoint(),
        tokensFromTokenEndpoint: ['access_token', 'refresh_token'],
      },
    })

    try {
      // Generate security parameters
      await this.generateSecurityParams()

      // Build authorization URL
      const authUrl = this.buildAuthorizationUrl()

      // Open authorization popup
      this.updateState({
        status: 'awaiting_user',
        currentStep: 'Awaiting user authorization',
      })

      const authzResponse = await this.openAuthorizationPopup(authUrl)

      // Validate state
      if (authzResponse.state !== this.state.securityParams.state) {
        throw new Error('State mismatch - possible CSRF attack')
      }

      // Validate c_hash if id_token present with code
      if (authzResponse.id_token && authzResponse.code) {
        await this.validateCHash(authzResponse.id_token, authzResponse.code)
      }

      // Validate at_hash if id_token present with access_token
      if (authzResponse.id_token && authzResponse.access_token) {
        await this.validateAtHash(authzResponse.id_token, authzResponse.access_token)
      }

      // Process tokens from authorization endpoint
      this.processAuthorizationResponse(authzResponse)

      // Exchange code for additional tokens
      if (authzResponse.code) {
        this.updateState({
          status: 'executing',
          currentStep: 'Exchanging code for tokens',
        })

        await this.exchangeCodeForTokens(authzResponse.code)
      }

      this.updateState({
        status: 'completed',
        currentStep: 'Flow completed successfully',
      })

      this.addEvent({
        type: 'info',
        title: 'OIDC Hybrid Flow Complete',
        description: 'Tokens received from both endpoints',
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

  private getTokensFromAuthzEndpoint(): string[] {
    const tokens: string[] = ['code']
    if (this.flowConfig.responseType.includes('id_token')) {
      tokens.push('id_token')
    }
    if (this.flowConfig.responseType.includes('token')) {
      tokens.push('access_token')
    }
    return tokens
  }

  private async generateSecurityParams(): Promise<void> {
    // State for CSRF protection
    const state = generateSecureRandom(16)
    
    // Nonce is REQUIRED in hybrid flow when id_token is requested
    const nonce = generateSecureRandom(16)
    
    this.updateState({
      securityParams: {
        state,
        nonce,
      },
    })

    this.addEvent({
      type: 'security',
      title: 'Security Parameters Generated',
      description: 'State and nonce for CSRF and replay protection',
      data: { state, nonce },
    })

    // PKCE if enabled
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
        title: 'PKCE Parameters Generated',
        description: 'Additional security for code exchange',
        rfcReference: 'RFC 7636',
        data: { codeChallenge },
      })
    }
  }

  private buildAuthorizationUrl(): string {
    const params = new URLSearchParams({
      response_type: this.flowConfig.responseType,
      client_id: this.config.clientId,
      scope: this.config.scopes.join(' '),
      state: this.state.securityParams.state!,
      nonce: this.state.securityParams.nonce!,
      response_mode: 'fragment', // Hybrid flow returns in fragment
    })

    if (this.config.redirectUri) {
      params.set('redirect_uri', this.config.redirectUri)
    }

    if (this.flowConfig.usePkce && this.state.securityParams.codeChallenge) {
      params.set('code_challenge', this.state.securityParams.codeChallenge)
      params.set('code_challenge_method', 'S256')
    }

    return this.withCaptureQuery(`${this.config.baseUrl}/authorize?${params.toString()}`)
  }

  private openAuthorizationPopup(authUrl: string): Promise<{
    code?: string
    access_token?: string
    id_token?: string
    token_type?: string
    expires_in?: number
    state: string
  }> {
    return new Promise((resolve, reject) => {
      const width = 600
      const height = 700
      const left = window.screenX + (window.outerWidth - width) / 2
      const top = window.screenY + (window.outerHeight - height) / 2

      const popup = window.open(
        authUrl,
        'oidc_hybrid',
        `width=${width},height=${height},left=${left},top=${top},scrollbars=yes`
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

        if (event.data?.type === 'oidc_hybrid_callback') {
          window.removeEventListener('message', handleMessage)
          clearInterval(pollTimer)
          popup.close()

          const { error, error_description, ...tokens } = event.data

          if (error) {
            reject(new Error(error_description || error))
            return
          }

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

  private async validateCHash(idToken: string, code: string): Promise<void> {
    // c_hash validation per OIDC Core 1.0 Section 3.3.2.11
    const decoded = this.decodeJwt(idToken, 'id_token')
    if (!decoded.payload) return

    const cHash = decoded.payload.c_hash as string
    if (!cHash) {
      this.addEvent({
        type: 'security',
        title: 'c_hash Missing',
        description: 'ID token should contain c_hash when code is present',
        rfcReference: 'OIDC Core 1.0 Section 3.3.2.11',
      })
      return
    }

    // Compute expected c_hash
    const encoder = new TextEncoder()
    const hash = await crypto.subtle.digest('SHA-256', encoder.encode(code))
    const halfHash = new Uint8Array(hash.slice(0, hash.byteLength / 2))
    const expectedCHash = btoa(String.fromCharCode(...halfHash))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '')

    if (cHash === expectedCHash) {
      this.addEvent({
        type: 'security',
        title: 'c_hash Validated',
        description: 'Authorization code hash matches',
        rfcReference: 'OIDC Core 1.0 Section 3.3.2.11',
      })
    } else {
      this.addEvent({
        type: 'error',
        title: 'c_hash Mismatch',
        description: 'Authorization code may have been tampered with',
        rfcReference: 'OIDC Core 1.0 Section 3.3.2.11',
      })
    }
  }

  private async validateAtHash(idToken: string, accessToken: string): Promise<void> {
    // at_hash validation per OIDC Core 1.0 Section 3.3.2.11
    const decoded = this.decodeJwt(idToken, 'id_token')
    if (!decoded.payload) return

    const atHash = decoded.payload.at_hash as string
    if (!atHash) {
      this.addEvent({
        type: 'security',
        title: 'at_hash Missing',
        description: 'ID token should contain at_hash when access_token is present',
        rfcReference: 'OIDC Core 1.0 Section 3.3.2.11',
      })
      return
    }

    // Compute expected at_hash
    const encoder = new TextEncoder()
    const hash = await crypto.subtle.digest('SHA-256', encoder.encode(accessToken))
    const halfHash = new Uint8Array(hash.slice(0, hash.byteLength / 2))
    const expectedAtHash = btoa(String.fromCharCode(...halfHash))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '')

    if (atHash === expectedAtHash) {
      this.addEvent({
        type: 'security',
        title: 'at_hash Validated',
        description: 'Access token hash matches',
        rfcReference: 'OIDC Core 1.0 Section 3.3.2.11',
      })
    } else {
      this.addEvent({
        type: 'error',
        title: 'at_hash Mismatch',
        description: 'Access token may have been tampered with',
      })
    }
  }

  private processAuthorizationResponse(response: {
    access_token?: string
    id_token?: string
    token_type?: string
    expires_in?: number
  }): void {
    const tokens = { ...this.state.tokens }
    const decodedTokens = [...this.state.decodedTokens]

    if (response.id_token) {
      tokens.idToken = response.id_token
      const decoded = this.decodeJwt(response.id_token, 'id_token')
      decodedTokens.push(decoded)

      this.addEvent({
        type: 'token',
        title: 'ID Token from Authorization Endpoint',
        description: 'Received before token exchange',
        rfcReference: 'OIDC Core 1.0 Section 3.3.2.11',
      })
    }

    if (response.access_token) {
      tokens.accessToken = response.access_token
      const decoded = this.decodeJwt(response.access_token, 'access_token')
      decodedTokens.push(decoded)

      this.addEvent({
        type: 'token',
        title: 'Access Token from Authorization Endpoint',
        description: 'Received in fragment (similar to implicit flow)',
        rfcReference: 'OIDC Core 1.0 Section 3.3.2.5',
      })
    }

    this.updateState({ tokens, decodedTokens })
  }

  private async exchangeCodeForTokens(code: string): Promise<void> {
    this.addEvent({
      type: 'rfc',
      title: 'OIDC Core 1.0 Section 3.3.3',
      description: 'Token Request - Exchanging code for additional tokens',
      rfcReference: 'OIDC Core 1.0 Section 3.3.3',
    })

    const body: Record<string, string> = {
      grant_type: 'authorization_code',
      code,
      client_id: this.config.clientId,
    }

    if (this.config.redirectUri) {
      body.redirect_uri = this.config.redirectUri
    }

    if (this.flowConfig.usePkce && this.state.securityParams.codeVerifier) {
      body.code_verifier = this.state.securityParams.codeVerifier
    }

    if (this.config.clientSecret) {
      body.client_secret = this.config.clientSecret
    }

    const { response, data } = await this.makeRequest(
      'POST',
      `${this.config.baseUrl}/token`,
      {
        body,
        step: 'Token Exchange (Hybrid Flow)',
        rfcReference: 'OIDC Core 1.0 Section 3.3.3',
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
      title: 'OIDC Core 1.0 Section 3.3.3.3',
      description: 'Token Response - Additional tokens from token endpoint',
      rfcReference: 'OIDC Core 1.0 Section 3.3.3.3',
    })

    this.processTokenResponse(data as Record<string, unknown>)
  }
}


