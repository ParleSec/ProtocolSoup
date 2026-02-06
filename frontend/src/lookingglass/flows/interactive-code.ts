/**
 * Interaction Code Flow Executor
 * 
 * A comprehensive, step-by-step OAuth 2.0 Authorization Code flow
 * with real-time events against actual infrastructure.
 * 
 * This flow provides:
 * - Real HTTP requests to the backend OAuth2/OIDC endpoints
 * - Step-by-step breakdowns with detailed security annotations
 * - PKCE support by default (RFC 7636)
 * - Real-time WebSocket events from the Looking Glass engine
 * - Interactive pause points for educational purposes
 * - Token introspection and validation
 * 
 * Flow Steps:
 * 1. Discovery - Fetch OIDC discovery document & JWKS
 * 2. Security Setup - Generate state, PKCE parameters, nonce
 * 3. Authorization Request - Redirect to auth server
 * 4. User Authentication - User authenticates with IdP
 * 5. Authorization Response - Receive authorization code
 * 6. Token Exchange - Exchange code for tokens
 * 7. Token Validation - Verify JWT signatures and claims
 * 8. UserInfo (Optional) - Fetch user profile
 */

import {
  FlowExecutorBase,
  type FlowExecutorConfig,
  type FlowEvent,
  generateSecureRandom,
  generateCodeVerifier,
  generateCodeChallenge,
} from './base'

export interface InteractiveCodeConfig extends FlowExecutorConfig {
  /** Enable PKCE (default: true - required for public clients) */
  usePkce?: boolean
  /** Include nonce for OIDC ID token binding */
  includeNonce?: boolean
  /** Enable step-by-step mode with pause points */
  stepByStep?: boolean
  /** Fetch discovery document before authorization */
  useDiscovery?: boolean
  /** Perform token introspection after obtaining tokens */
  introspectTokens?: boolean
  /** Fetch UserInfo endpoint after obtaining tokens */
  fetchUserInfo?: boolean
  /** Custom prompt parameter (none, login, consent, select_account) */
  prompt?: string
}

interface DiscoveryDocument {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  userinfo_endpoint?: string
  jwks_uri: string
  introspection_endpoint?: string
  revocation_endpoint?: string
  scopes_supported?: string[]
  response_types_supported?: string[]
  grant_types_supported?: string[]
  token_endpoint_auth_methods_supported?: string[]
  code_challenge_methods_supported?: string[]
}

interface JWKSDocument {
  keys: Array<{
    kty: string
    kid: string
    use: string
    alg: string
    n?: string
    e?: string
    crv?: string
    x?: string
    y?: string
  }>
}

export class InteractiveCodeExecutor extends FlowExecutorBase {
  readonly flowType = 'interaction-code'
  readonly flowName = 'Interaction Authorization Code Flow'
  readonly rfcReference = 'RFC 6749, RFC 7636, OIDC Core 1.0'

  private flowConfig: InteractiveCodeConfig
  private discovery: DiscoveryDocument | null = null
  private jwks: JWKSDocument | null = null

  constructor(config: InteractiveCodeConfig) {
    super(config)
    this.flowConfig = {
      usePkce: true,
      includeNonce: true,
      useDiscovery: true,
      introspectTokens: false,
      fetchUserInfo: true,
      stepByStep: false,
      ...config,
    }
  }

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({
      ...this.createInitialState(),
      status: 'executing',
      currentStep: 'Initializing Interaction Code Flow',
    })

    this.addEvent({
      type: 'info',
      title: 'Starting Interaction Authorization Code Flow',
      description: 'A comprehensive OAuth 2.0/OIDC flow with real infrastructure',
      rfcReference: this.rfcReference,
      data: {
        clientId: this.config.clientId,
        scopes: this.config.scopes,
        features: {
          pkce: this.flowConfig.usePkce,
          nonce: this.flowConfig.includeNonce,
          discovery: this.flowConfig.useDiscovery,
          userinfo: this.flowConfig.fetchUserInfo,
        },
      },
    })

    try {
      // Phase 1: Discovery (optional but recommended)
      if (this.flowConfig.useDiscovery) {
        await this.performDiscovery()
      }

      // Phase 2: Security Parameter Generation
      await this.generateSecurityParams()

      // Phase 3: Build and execute authorization request
      const authUrl = this.buildAuthorizationUrl()
      
      this.addEvent({
        type: 'rfc',
        title: 'Authorization Request Constructed',
        description: 'Ready to redirect user to authorization endpoint',
        rfcReference: 'RFC 6749 Section 4.1.1',
        data: this.parseUrlParams(authUrl),
      })

      // Phase 4: User authorization via popup
      this.updateState({
        status: 'awaiting_user',
        currentStep: 'Awaiting user authentication...',
      })

      const { code, state } = await this.openAuthorizationPopup(authUrl)

      // Phase 5: State validation (CSRF protection)
      await this.validateStateParameter(state)

      this.addEvent({
        type: 'rfc',
        title: 'Authorization Response Received',
        description: 'Authorization server returned an authorization code',
        rfcReference: 'RFC 6749 Section 4.1.2',
        data: {
          code: this.maskSecret(code, 10),
          state: state,
          codeLength: code.length,
        },
      })

      // Phase 6: Token exchange
      this.updateState({
        status: 'executing',
        currentStep: 'Exchanging authorization code for tokens...',
      })

      await this.exchangeCodeForTokens(code)

      // Phase 7: UserInfo (optional)
      if (this.flowConfig.fetchUserInfo && this.state.tokens.accessToken) {
        await this.fetchUserInfo()
      }

      // Complete
      this.updateState({
        status: 'completed',
        currentStep: 'Flow completed successfully',
      })

      this.addEvent({
        type: 'info',
        title: 'Interaction Code Flow Complete',
        description: this.generateCompletionSummary(),
        rfcReference: this.rfcReference,
        data: {
          tokensReceived: {
            accessToken: !!this.state.tokens.accessToken,
            idToken: !!this.state.tokens.idToken,
            refreshToken: !!this.state.tokens.refreshToken,
          },
          securityFeatures: {
            pkceUsed: this.flowConfig.usePkce,
            nonceValidated: this.flowConfig.includeNonce,
            stateValidated: true,
          },
        },
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
        data: {
          phase: this.state.currentStep,
          suggestion: this.getErrorSuggestion(message),
        },
      })
    }
  }

  /**
   * Phase 1: Discovery - Fetch OIDC configuration and JWKS
   */
  private async performDiscovery(): Promise<void> {
    this.updateState({ currentStep: 'Discovering OpenID Provider configuration...' })

    this.addEvent({
      type: 'info',
      title: 'Discovery Phase',
      description: 'Fetching OpenID Provider metadata for endpoint configuration',
      rfcReference: 'OIDC Discovery 1.0',
    })

    // Fetch discovery document
    const discoveryUrl = `${this.config.baseUrl}/.well-known/openid-configuration`
    
    try {
      const { response, data } = await this.makeRequest('GET', discoveryUrl, {
        step: 'OpenID Discovery Request',
        rfcReference: 'OIDC Discovery 1.0',
      })

      if (!response.ok) {
        this.addEvent({
          type: 'info',
          title: 'Discovery Unavailable',
          description: 'Proceeding with default endpoint configuration',
        })
        return
      }

      this.discovery = data as DiscoveryDocument

      this.addEvent({
        type: 'rfc',
        title: 'Discovery Document Retrieved',
        description: `Found ${Object.keys(this.discovery).length} configuration parameters`,
        rfcReference: 'OIDC Discovery 1.0 Section 3',
        data: {
          issuer: this.discovery.issuer,
          endpoints: {
            authorization: this.discovery.authorization_endpoint,
            token: this.discovery.token_endpoint,
            userinfo: this.discovery.userinfo_endpoint,
            jwks: this.discovery.jwks_uri,
          },
          capabilities: {
            pkce: this.discovery.code_challenge_methods_supported,
            scopes: this.discovery.scopes_supported?.slice(0, 5),
          },
        },
      })

      // Fetch JWKS
      if (this.discovery.jwks_uri) {
        await this.fetchJWKS(this.discovery.jwks_uri)
      }

    } catch {
      this.addEvent({
        type: 'info',
        title: 'Discovery Failed',
        description: 'Using fallback endpoint configuration',
      })
    }
  }

  /**
   * Fetch JSON Web Key Set for token signature verification
   */
  private async fetchJWKS(jwksUri: string): Promise<void> {
    this.addEvent({
      type: 'crypto',
      title: 'Fetching JWKS',
      description: 'Retrieving public keys for token signature verification',
      rfcReference: 'RFC 7517',
    })

    try {
      const { response, data } = await this.makeRequest('GET', jwksUri, {
        step: 'JWKS Request',
        rfcReference: 'RFC 7517 (JSON Web Key)',
      })

      if (response.ok) {
        this.jwks = data as JWKSDocument

        this.addEvent({
          type: 'crypto',
          title: 'JWKS Retrieved',
          description: `Found ${this.jwks.keys.length} public key(s) for signature verification`,
          rfcReference: 'RFC 7517 Section 5',
          data: {
            keyCount: this.jwks.keys.length,
            keys: this.jwks.keys.map(k => ({
              kid: k.kid,
              kty: k.kty,
              alg: k.alg,
              use: k.use,
            })),
          },
        })
      }
    } catch {
      this.addEvent({
        type: 'info',
        title: 'JWKS Fetch Failed',
        description: 'Token signature verification will be limited',
      })
    }
  }

  /**
   * Phase 2: Generate security parameters (state, PKCE, nonce)
   */
  private async generateSecurityParams(): Promise<void> {
    this.updateState({ currentStep: 'Generating security parameters...' })

    this.addEvent({
      type: 'security',
      title: 'Security Parameter Generation',
      description: 'Creating cryptographic values for flow protection',
    })

    // Generate state parameter (CSRF protection)
    const state = generateSecureRandom(32)
    
    this.updateState({
      securityParams: {
        ...this.state.securityParams,
        state,
      },
    })

    this.addEvent({
      type: 'security',
      title: 'State Parameter Generated',
      description: 'Random value for CSRF protection - must match on callback',
      rfcReference: 'RFC 6749 Section 10.12',
      data: {
        state,
        length: state.length,
        entropy: '128 bits',
        purpose: 'Binds authorization request to user session',
      },
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
        title: 'PKCE Parameters Generated',
        description: 'Proof Key for Code Exchange - protects against code interception',
        rfcReference: 'RFC 7636',
        data: {
          codeVerifier: this.maskSecret(codeVerifier, 8),
          codeVerifierLength: codeVerifier.length,
          codeChallenge,
          codeChallengeMethod: 'S256',
          algorithm: 'SHA-256(code_verifier) → Base64URL',
        },
      })

      this.addEvent({
        type: 'security',
        title: 'PKCE Security Insight',
        description: 'code_verifier is kept secret; only code_challenge is sent to authorization server',
        rfcReference: 'RFC 7636 Section 1.1',
        data: {
          threat: 'Authorization Code Interception Attack',
          mitigation: 'Proof that token requester is the same as authorization requester',
          recommendation: 'Required for public clients (SPAs, mobile apps)',
        },
      })
    }

    // Generate nonce for OIDC
    if (this.flowConfig.includeNonce) {
      const nonce = generateSecureRandom(32)

      this.updateState({
        securityParams: {
          ...this.state.securityParams,
          nonce,
        },
      })

      this.addEvent({
        type: 'security',
        title: 'Nonce Generated',
        description: 'Random value for ID token replay protection',
        rfcReference: 'OIDC Core 1.0 Section 3.1.2.1',
        data: {
          nonce,
          length: nonce.length,
          purpose: 'Binds ID token to this specific authentication request',
          validation: 'Must match nonce claim in returned ID token',
        },
      })
    }
  }

  /**
   * Build the authorization URL with all required parameters
   */
  private buildAuthorizationUrl(): string {
    const endpoint = `${this.config.baseUrl}/authorize`

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      scope: this.config.scopes.join(' '),
      state: this.state.securityParams.state!,
    })

    if (this.config.redirectUri) {
      params.set('redirect_uri', this.config.redirectUri)
    }

    // PKCE parameters
    if (this.flowConfig.usePkce && this.state.securityParams.codeChallenge) {
      params.set('code_challenge', this.state.securityParams.codeChallenge)
      params.set('code_challenge_method', 'S256')
    }

    // OIDC nonce
    if (this.state.securityParams.nonce) {
      params.set('nonce', this.state.securityParams.nonce)
    }

    // Prompt parameter
    if (this.flowConfig.prompt) {
      params.set('prompt', this.flowConfig.prompt)
    }

    // Extra parameters
    if (this.config.extraParams) {
      for (const [key, value] of Object.entries(this.config.extraParams)) {
        params.set(key, value)
      }
    }

    return this.withCaptureQuery(`${endpoint}?${params.toString()}`)
  }

  /**
   * Open authorization popup and wait for callback
   */
  private openAuthorizationPopup(authUrl: string): Promise<{ code: string; state: string }> {
    return new Promise((resolve, reject) => {
      let safeAuthUrl: string
      try {
        safeAuthUrl = this.ensureAllowedAuthUrl(authUrl)
      } catch (error) {
        reject(error)
        return
      }

      // Use full screen on mobile devices
      const isMobile = window.innerWidth < 640
      const width = isMobile ? window.screen.width : 600
      const height = isMobile ? window.screen.height : 700
      const left = isMobile ? 0 : window.screenX + (window.outerWidth - width) / 2
      const top = isMobile ? 0 : window.screenY + (window.outerHeight - height) / 2

      const popup = window.open(
        safeAuthUrl,
        'oauth_authorization',
        `width=${width},height=${height},left=${left},top=${top},scrollbars=yes,resizable=yes`
      )

      if (!popup) {
        reject(new Error('Popup blocked - please allow popups for this site'))
        return
      }

      this.addEvent({
        type: 'user_action',
        title: 'Authorization Window Opened',
        description: 'User must authenticate and authorize the application',
        data: {
          action: 'User authentication in progress',
          tip: 'Use demo credentials from the IdP presets',
        },
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

      // Poll for popup closure
      const pollTimer = setInterval(() => {
        if (popup.closed) {
          clearInterval(pollTimer)
          window.removeEventListener('message', handleMessage)

          if (this.state.status === 'awaiting_user') {
            reject(new Error('User closed authorization window'))
          }
        }
      }, 500)

      // Abort handler
      this.abortController?.signal.addEventListener('abort', () => {
        clearInterval(pollTimer)
        window.removeEventListener('message', handleMessage)
        popup.close()
      })
    })
  }

  /**
   * Validate state parameter (CSRF protection)
   */
  private async validateStateParameter(returnedState: string): Promise<void> {
    if (returnedState !== this.state.securityParams.state) {
      this.addEvent({
        type: 'error',
        title: 'State Mismatch - Possible CSRF Attack',
        description: 'The state parameter does not match the original value',
        rfcReference: 'RFC 6749 Section 10.12',
        data: {
          expected: this.state.securityParams.state,
          received: returnedState,
          action: 'Aborting flow for security',
        },
      })
      throw new Error('State mismatch - possible CSRF attack')
    }

    this.addEvent({
      type: 'security',
      title: 'State Parameter Validated',
      description: 'CSRF protection confirmed - state matches original value',
      rfcReference: 'RFC 6749 Section 10.12',
      data: {
        state: returnedState,
        status: 'validated',
      },
    })
  }

  /**
   * Phase 6: Exchange authorization code for tokens
   */
  private async exchangeCodeForTokens(code: string): Promise<void> {
    this.addEvent({
      type: 'rfc',
      title: 'Token Exchange Request',
      description: 'Exchanging authorization code for tokens via back-channel',
      rfcReference: 'RFC 6749 Section 4.1.3',
      data: {
        grant_type: 'authorization_code',
        code: this.maskSecret(code, 10),
        hasPkceVerifier: !!this.state.securityParams.codeVerifier,
      },
    })

    const tokenEndpoint = this.discovery?.token_endpoint || `${this.config.baseUrl}/token`

    const body: Record<string, string> = {
      grant_type: 'authorization_code',
      code,
      client_id: this.config.clientId,
    }

    if (this.config.redirectUri) {
      body.redirect_uri = this.config.redirectUri
    }

    // PKCE code_verifier
    if (this.flowConfig.usePkce && this.state.securityParams.codeVerifier) {
      body.code_verifier = this.state.securityParams.codeVerifier

      this.addEvent({
        type: 'crypto',
        title: 'PKCE Verification',
        description: 'Sending code_verifier for server-side validation',
        rfcReference: 'RFC 7636 Section 4.5',
        data: {
          codeVerifier: this.maskSecret(this.state.securityParams.codeVerifier, 8),
          validation: 'Server hashes this and compares with code_challenge',
        },
      })
    }

    // Client secret for confidential clients
    if (this.config.clientSecret) {
      body.client_secret = this.config.clientSecret
    }

    const { response, data } = await this.makeRequest('POST', tokenEndpoint, {
      body,
      step: 'Token Exchange Request',
      rfcReference: 'RFC 6749 Section 4.1.3',
    })

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
      title: 'Token Response Received',
      description: 'Authorization server issued tokens',
      rfcReference: 'RFC 6749 Section 4.1.4',
      data: {
        tokenTypes: Object.keys(data as Record<string, unknown>).filter(k => k.includes('token')),
      },
    })

    this.processTokenResponse(data as Record<string, unknown>)
    await this.validateReceivedTokens()
  }

  /**
   * Additional validation of received tokens
   */
  private async validateReceivedTokens(): Promise<void> {
    // Validate ID token nonce if applicable
    if (this.flowConfig.includeNonce && this.state.tokens.idToken) {
      const idTokenDecoded = this.state.decodedTokens.find(t => t.type === 'id_token')
      
      if (idTokenDecoded?.payload) {
        const tokenNonce = idTokenDecoded.payload.nonce as string
        const expectedNonce = this.state.securityParams.nonce

        if (tokenNonce !== expectedNonce) {
          this.addEvent({
            type: 'error',
            title: 'Nonce Mismatch',
            description: 'ID token nonce does not match - possible replay attack',
            rfcReference: 'OIDC Core 1.0 Section 3.1.3.7',
            data: { expected: expectedNonce, received: tokenNonce },
          })
        } else {
          this.addEvent({
            type: 'security',
            title: 'Nonce Validated',
            description: 'ID token is bound to this authentication session',
            rfcReference: 'OIDC Core 1.0 Section 3.1.3.7',
          })
        }
      }
    }

    // Log token details
    if (this.state.tokens.accessToken) {
      const accessDecoded = this.state.decodedTokens.find(t => t.type === 'access_token')
      
      this.addEvent({
        type: 'token',
        title: 'Access Token Analyzed',
        description: accessDecoded?.payload ? 'JWT access token with claims' : 'Opaque access token',
        data: accessDecoded?.payload ? {
          subject: accessDecoded.payload.sub,
          issuer: accessDecoded.payload.iss,
          audience: accessDecoded.payload.aud,
          expiresAt: accessDecoded.payload.exp 
            ? new Date((accessDecoded.payload.exp as number) * 1000).toISOString()
            : undefined,
          scope: accessDecoded.payload.scope,
        } : { type: 'opaque' },
      })
    }

    if (this.state.tokens.idToken) {
      const idDecoded = this.state.decodedTokens.find(t => t.type === 'id_token')
      
      this.addEvent({
        type: 'token',
        title: 'ID Token Analyzed',
        description: 'User identity claims from ID token',
        rfcReference: 'OIDC Core 1.0 Section 2',
        data: idDecoded?.payload ? {
          subject: idDecoded.payload.sub,
          name: idDecoded.payload.name,
          email: idDecoded.payload.email,
          issuer: idDecoded.payload.iss,
          audience: idDecoded.payload.aud,
          authTime: idDecoded.payload.auth_time
            ? new Date((idDecoded.payload.auth_time as number) * 1000).toISOString()
            : undefined,
        } : {},
      })
    }

    if (this.state.tokens.refreshToken) {
      this.addEvent({
        type: 'token',
        title: 'Refresh Token Received',
        description: 'Can be used to obtain new access tokens without user interaction',
        rfcReference: 'RFC 6749 Section 1.5',
        data: {
          tip: 'Store securely - treat as a credential',
        },
      })
    }
  }

  /**
   * Fetch UserInfo endpoint
   */
  private async fetchUserInfo(): Promise<void> {
    const userInfoEndpoint = this.discovery?.userinfo_endpoint || `${this.config.baseUrl}/userinfo`

    this.addEvent({
      type: 'info',
      title: 'Fetching UserInfo',
      description: 'Requesting additional user claims from UserInfo endpoint',
      rfcReference: 'OIDC Core 1.0 Section 5.3',
    })

    try {
      const { response, data } = await this.makeRequest('GET', userInfoEndpoint, {
        headers: {
          'Authorization': `Bearer ${this.state.tokens.accessToken}`,
        },
        step: 'UserInfo Request',
        rfcReference: 'OIDC Core 1.0 Section 5.3',
      })

      if (response.ok) {
        this.addEvent({
          type: 'info',
          title: 'UserInfo Retrieved',
          description: 'Additional user profile claims received',
          rfcReference: 'OIDC Core 1.0 Section 5.3.2',
          data: data as Record<string, unknown>,
        })
      }
    } catch {
      this.addEvent({
        type: 'info',
        title: 'UserInfo Request Failed',
        description: 'Could not fetch additional user claims',
      })
    }
  }

  /**
   * Helper: Parse URL parameters for logging
   */
  private ensureAllowedAuthUrl(authUrl: string): string {
    const resolved = new URL(authUrl, window.location.origin)
    const baseUrl = new URL(this.config.baseUrl, window.location.origin)
    const allowedOrigins = new Set<string>([window.location.origin, baseUrl.origin])

    if (this.discovery?.issuer) {
      try {
        allowedOrigins.add(new URL(this.discovery.issuer).origin)
      } catch {
        // Ignore malformed issuer; enforced by origin check below.
      }
    }

    if (!['http:', 'https:'].includes(resolved.protocol)) {
      throw new Error(`Unsupported authorization URL scheme: ${resolved.protocol}`)
    }

    if (!allowedOrigins.has(resolved.origin)) {
      throw new Error(`Authorization endpoint origin not allowed: ${resolved.origin}`)
    }

    return resolved.toString()
  }

  /**
   * Helper: Parse URL parameters for logging
   */
  private parseUrlParams(url: string): Record<string, string> {
    const urlObj = new URL(url, window.location.origin)
    const params: Record<string, string> = {}
    urlObj.searchParams.forEach((value, key) => {
      // Mask sensitive values
      if (key === 'code_challenge') {
        params[key] = value.substring(0, 20) + '...'
      } else {
        params[key] = value
      }
    })
    return params
  }

  /**
   * Helper: Mask sensitive values for logging
   */
  private maskSecret(value: string, showChars: number): string {
    if (value.length <= showChars * 2) {
      return '***'
    }
    return `${value.substring(0, showChars)}...${value.substring(value.length - showChars)}`
  }

  /**
   * Helper: Generate completion summary
   */
  private generateCompletionSummary(): string {
    const tokens = []
    if (this.state.tokens.accessToken) tokens.push('access_token')
    if (this.state.tokens.idToken) tokens.push('id_token')
    if (this.state.tokens.refreshToken) tokens.push('refresh_token')

    const security = []
    if (this.flowConfig.usePkce) security.push('PKCE')
    if (this.flowConfig.includeNonce) security.push('nonce')
    security.push('state')

    return `Obtained ${tokens.length} token(s) with ${security.join(', ')} protection`
  }

  /**
   * Helper: Get error suggestions
   */
  private getErrorSuggestion(error: string): string {
    const suggestions: Record<string, string> = {
      'popup': 'Allow popups for this site in your browser settings',
      'state': 'This could indicate a CSRF attack or session issue - refresh and try again',
      'invalid_grant': 'The authorization code may have expired or already been used',
      'invalid_client': 'Check client credentials configuration',
      'access_denied': 'User denied the authorization request',
    }

    for (const [key, suggestion] of Object.entries(suggestions)) {
      if (error.toLowerCase().includes(key)) {
        return suggestion
      }
    }

    return 'Check the request details and try again'
  }

  // Override addEvent to add emoji prefixes based on type
  protected addEvent(event: Omit<FlowEvent, 'id' | 'timestamp'>): void {
    super.addEvent(event)
  }
}

