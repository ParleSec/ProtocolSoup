/**
 * Live Flow Executor
 * 
 * Executes protocol flows against the MockIdP, capturing
 * requests, responses, tokens, and cryptographic operations.
 * 
 * This is NOT a simulation - it runs real OAuth 2.0 and OIDC flows.
 */

import { generateCodeVerifier, generateCodeChallenge, generateState, generateNonce } from '../utils/crypto'

// ============================================================================
// Types
// ============================================================================

export interface FlowExecutionConfig {
  /** Base URL for the authorization server (MockIdP) */
  authServerUrl: string
  /** Client ID for the demo application */
  clientId: string
  /** Redirect URI for callbacks */
  redirectUri: string
  /** Scopes to request */
  scopes: string[]
  /** Whether to use PKCE */
  usePkce: boolean
  /** Whether this is an OIDC flow (includes nonce) */
  isOidc: boolean
}

export interface FlowExecutionState {
  /** Unique execution ID */
  executionId: string
  /** Current state of the flow */
  status: 'idle' | 'started' | 'authorizing' | 'exchanging' | 'completed' | 'error'
  /** PKCE code verifier (kept secret) */
  codeVerifier?: string
  /** PKCE code challenge (sent to server) */
  codeChallenge?: string
  /** State parameter for CSRF protection */
  state?: string
  /** Nonce for OIDC replay protection */
  nonce?: string
  /** Authorization code received */
  authorizationCode?: string
  /** Access token received */
  accessToken?: string
  /** ID token received (OIDC) */
  idToken?: string
  /** Refresh token received */
  refreshToken?: string
  /** Token expiration */
  expiresIn?: number
  /** Error if any */
  error?: string
  /** Captured requests */
  requests: CapturedRequest[]
  /** Captured responses */
  responses: CapturedResponse[]
  /** Decoded tokens */
  decodedTokens: DecodedToken[]
  /** Timeline of events */
  events: ExecutionEvent[]
}

export interface CapturedRequest {
  id: string
  timestamp: Date
  method: string
  url: string
  headers: Record<string, string>
  body?: string | Record<string, string>
  description: string
}

export interface CapturedResponse {
  id: string
  requestId: string
  timestamp: Date
  status: number
  statusText: string
  headers: Record<string, string>
  body?: unknown
  duration: number
  description: string
}

export interface DecodedToken {
  id: string
  type: 'access_token' | 'id_token' | 'refresh_token'
  raw: string
  header?: Record<string, unknown>
  payload?: Record<string, unknown>
  signature?: string
  isValid?: boolean
  validationErrors?: string[]
}

export interface ExecutionEvent {
  id: string
  timestamp: Date
  type: 'info' | 'request' | 'response' | 'token' | 'crypto' | 'security' | 'error'
  title: string
  description: string
  data?: Record<string, unknown>
}

export type FlowExecutionListener = (state: FlowExecutionState) => void

// ============================================================================
// Flow Executor Class
// ============================================================================

export class FlowExecutor {
  private config: FlowExecutionConfig
  private state: FlowExecutionState
  private listeners: Set<FlowExecutionListener> = new Set()
  private abortController: AbortController | null = null

  constructor(config: FlowExecutionConfig) {
    this.config = config
    this.state = this.createInitialState()
  }

  private createInitialState(): FlowExecutionState {
    return {
      executionId: crypto.randomUUID(),
      status: 'idle',
      requests: [],
      responses: [],
      decodedTokens: [],
      events: [],
    }
  }

  // Subscribe to state changes
  subscribe(listener: FlowExecutionListener): () => void {
    this.listeners.add(listener)
    listener(this.state) // Immediately call with current state
    return () => this.listeners.delete(listener)
  }

  private updateState(updates: Partial<FlowExecutionState>): void {
    this.state = { ...this.state, ...updates }
    this.listeners.forEach(listener => listener(this.state))
  }

  private addEvent(event: Omit<ExecutionEvent, 'id' | 'timestamp'>): void {
    const fullEvent: ExecutionEvent = {
      ...event,
      id: crypto.randomUUID(),
      timestamp: new Date(),
    }
    this.updateState({
      events: [...this.state.events, fullEvent],
    })
  }

  private addRequest(request: Omit<CapturedRequest, 'id' | 'timestamp'>): string {
    const id = crypto.randomUUID()
    const fullRequest: CapturedRequest = {
      ...request,
      id,
      timestamp: new Date(),
    }
    this.updateState({
      requests: [...this.state.requests, fullRequest],
    })
    return id
  }

  private addResponse(response: Omit<CapturedResponse, 'id' | 'timestamp'>): void {
    const fullResponse: CapturedResponse = {
      ...response,
      id: crypto.randomUUID(),
      timestamp: new Date(),
    }
    this.updateState({
      responses: [...this.state.responses, fullResponse],
    })
  }

  private decodeJwt(token: string, type: DecodedToken['type']): DecodedToken {
    const decoded: DecodedToken = {
      id: crypto.randomUUID(),
      type,
      raw: token,
    }

    try {
      const parts = token.split('.')
      if (parts.length === 3) {
        decoded.header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')))
        decoded.payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')))
        decoded.signature = parts[2]

        // Basic validation
        const validationErrors: string[] = []
        const payload = decoded.payload as Record<string, unknown>

        // Check expiration
        if (payload.exp && typeof payload.exp === 'number') {
          if (payload.exp * 1000 < Date.now()) {
            validationErrors.push('Token is expired')
          }
        }

        // Check issued at
        if (payload.iat && typeof payload.iat === 'number') {
          if (payload.iat * 1000 > Date.now() + 60000) {
            validationErrors.push('Token issued in the future')
          }
        }

        // Check nonce for ID tokens
        if (type === 'id_token' && this.state.nonce) {
          if (payload.nonce !== this.state.nonce) {
            validationErrors.push(`Nonce mismatch: expected ${this.state.nonce}, got ${payload.nonce}`)
          }
        }

        decoded.isValid = validationErrors.length === 0
        decoded.validationErrors = validationErrors
      } else {
        decoded.isValid = false
        decoded.validationErrors = ['Invalid JWT format - expected 3 parts']
      }
    } catch (e) {
      decoded.isValid = false
      decoded.validationErrors = [`Failed to decode: ${e instanceof Error ? e.message : 'Unknown error'}`]
    }

    return decoded
  }

  // ============================================================================
  // Authorization Code Flow
  // ============================================================================

  async executeAuthorizationCodeFlow(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({
      ...this.createInitialState(),
      status: 'started',
    })

    this.addEvent({
      type: 'info',
      title: 'Starting Authorization Code Flow',
      description: `Initiating OAuth 2.0 Authorization Code flow${this.config.usePkce ? ' with PKCE' : ''}`,
      data: {
        clientId: this.config.clientId,
        scopes: this.config.scopes,
        usePkce: this.config.usePkce,
        isOidc: this.config.isOidc,
      },
    })

    try {
      // Step 1: Generate PKCE parameters if enabled
      if (this.config.usePkce) {
        await this.generatePkceParameters()
      }

      // Step 2: Generate state and nonce
      await this.generateSecurityParameters()

      // Step 3: Build and navigate to authorization URL
      const authUrl = this.buildAuthorizationUrl()
      
      this.addEvent({
        type: 'request',
        title: 'Authorization Request',
        description: 'Redirecting user to authorization endpoint',
        data: {
          url: authUrl,
          method: 'GET (Browser Redirect)',
        },
      })

      // Open authorization in a popup or redirect
      this.updateState({ status: 'authorizing' })
      
      // Return the auth URL for the UI to handle
      return this.openAuthorizationPopup(authUrl)
      
    } catch (error) {
      this.handleError(error)
    }
  }

  private async generatePkceParameters(): Promise<void> {
    this.addEvent({
      type: 'crypto',
      title: 'Generating PKCE Parameters',
      description: 'Creating code verifier and code challenge for PKCE',
    })

    const codeVerifier = generateCodeVerifier()
    const codeChallenge = await generateCodeChallenge(codeVerifier)

    this.updateState({
      codeVerifier,
      codeChallenge,
    })

    this.addEvent({
      type: 'crypto',
      title: 'PKCE Parameters Generated',
      description: 'Code verifier (secret) and challenge (public) created',
      data: {
        codeVerifier: `${codeVerifier.substring(0, 10)}...${codeVerifier.substring(codeVerifier.length - 10)}`,
        codeVerifierLength: codeVerifier.length,
        codeChallenge,
        codeChallengeMethod: 'S256',
      },
    })
  }

  private async generateSecurityParameters(): Promise<void> {
    const state = generateState()
    let nonce: string | undefined

    this.updateState({ state })

    this.addEvent({
      type: 'security',
      title: 'State Parameter Generated',
      description: 'Random state for CSRF protection',
      data: { state },
    })

    if (this.config.isOidc) {
      nonce = generateNonce()
      this.updateState({ nonce })

      this.addEvent({
        type: 'security',
        title: 'Nonce Generated',
        description: 'Random nonce for replay attack protection (OIDC)',
        data: { nonce },
      })
    }
  }

  private buildAuthorizationUrl(): string {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: this.config.scopes.join(' '),
      state: this.state.state!,
    })

    if (this.config.usePkce && this.state.codeChallenge) {
      params.set('code_challenge', this.state.codeChallenge)
      params.set('code_challenge_method', 'S256')
    }

    if (this.config.isOidc && this.state.nonce) {
      params.set('nonce', this.state.nonce)
    }

    return `${this.config.authServerUrl}/authorize?${params.toString()}`
  }

  private openAuthorizationPopup(authUrl: string): Promise<void> {
    return new Promise((resolve, reject) => {
      // Calculate popup position
      const width = 600
      const height = 700
      const left = window.screenX + (window.outerWidth - width) / 2
      const top = window.screenY + (window.outerHeight - height) / 2

      const popup = window.open(
        authUrl,
        'oauth_popup',
        `width=${width},height=${height},left=${left},top=${top},scrollbars=yes`
      )

      if (!popup) {
        this.addEvent({
          type: 'error',
          title: 'Popup Blocked',
          description: 'Browser blocked the authorization popup. Please allow popups for this site.',
        })
        reject(new Error('Popup blocked'))
        return
      }

      // Listen for the callback
      const handleMessage = async (event: MessageEvent) => {
        // Verify origin
        if (event.origin !== window.location.origin) return

        if (event.data?.type === 'oauth_callback') {
          window.removeEventListener('message', handleMessage)
          clearInterval(pollTimer)
          popup.close()

          const { code, state, error, error_description } = event.data

          if (error) {
            this.addEvent({
              type: 'error',
              title: 'Authorization Error',
              description: error_description || error,
              data: { error, error_description },
            })
            this.updateState({ status: 'error', error: error_description || error })
            reject(new Error(error_description || error))
            return
          }

          // Validate state
          if (state !== this.state.state) {
            this.addEvent({
              type: 'security',
              title: 'State Mismatch - CSRF Attack Prevented!',
              description: `Expected: ${this.state.state}, Received: ${state}`,
              data: { expected: this.state.state, received: state },
            })
            this.updateState({ status: 'error', error: 'State mismatch - possible CSRF attack' })
            reject(new Error('State mismatch'))
            return
          }

          this.addEvent({
            type: 'security',
            title: 'State Validated',
            description: 'State parameter matches - no CSRF attack detected',
            data: { state },
          })

          this.updateState({ authorizationCode: code })

          this.addEvent({
            type: 'response',
            title: 'Authorization Code Received',
            description: 'Successfully received authorization code from IdP',
            data: {
              code: `${code.substring(0, 10)}...`,
              codeLength: code.length,
            },
          })

          // Exchange code for tokens
          try {
            await this.exchangeCodeForTokens(code)
            resolve()
          } catch (e) {
            reject(e)
          }
        }
      }

      window.addEventListener('message', handleMessage)

      // Poll to check if popup was closed without completing
      const pollTimer = setInterval(() => {
        if (popup.closed) {
          clearInterval(pollTimer)
          window.removeEventListener('message', handleMessage)
          
          if (this.state.status === 'authorizing') {
            this.addEvent({
              type: 'info',
              title: 'Authorization Cancelled',
              description: 'User closed the authorization window',
            })
            this.updateState({ status: 'idle' })
            reject(new Error('User cancelled authorization'))
          }
        }
      }, 500)
    })
  }

  private async exchangeCodeForTokens(code: string): Promise<void> {
    this.updateState({ status: 'exchanging' })

    this.addEvent({
      type: 'info',
      title: 'Token Exchange Started',
      description: 'Exchanging authorization code for tokens',
    })

    const tokenUrl = `${this.config.authServerUrl}/token`
    
    const body: Record<string, string> = {
      grant_type: 'authorization_code',
      code,
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
    }

    // Add PKCE code verifier
    if (this.config.usePkce && this.state.codeVerifier) {
      body.code_verifier = this.state.codeVerifier

      this.addEvent({
        type: 'crypto',
        title: 'PKCE Verification',
        description: 'Sending code verifier for server-side PKCE validation',
        data: {
          codeVerifier: `${this.state.codeVerifier.substring(0, 10)}...`,
          note: 'Server will hash this and compare with code_challenge',
        },
      })
    }

    const requestId = this.addRequest({
      method: 'POST',
      url: tokenUrl,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body,
      description: 'Token Exchange Request',
    })

    this.addEvent({
      type: 'request',
      title: 'Token Request Sent',
      description: 'POST request to token endpoint',
      data: {
        url: tokenUrl,
        grantType: 'authorization_code',
        hasCodeVerifier: !!this.state.codeVerifier,
      },
    })

    const startTime = Date.now()

    try {
      const response = await fetch(tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams(body),
        signal: this.abortController?.signal,
      })

      const duration = Date.now() - startTime
      const responseData = await response.json()

      this.addResponse({
        requestId,
        status: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries(response.headers.entries()),
        body: responseData,
        duration,
        description: 'Token Endpoint Response',
      })

      if (!response.ok) {
        this.addEvent({
          type: 'error',
          title: 'Token Exchange Failed',
          description: responseData.error_description || responseData.error || 'Unknown error',
          data: responseData,
        })
        this.updateState({ 
          status: 'error', 
          error: responseData.error_description || responseData.error 
        })
        throw new Error(responseData.error_description || responseData.error)
      }

      // Extract and decode tokens
      await this.processTokenResponse(responseData)

    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        this.addEvent({
          type: 'info',
          title: 'Request Aborted',
          description: 'Token exchange was cancelled',
        })
      } else {
        throw error
      }
    }
  }

  private async processTokenResponse(data: Record<string, unknown>): Promise<void> {
    this.addEvent({
      type: 'response',
      title: 'Tokens Received',
      description: 'Successfully received tokens from authorization server',
      data: {
        hasAccessToken: !!data.access_token,
        hasIdToken: !!data.id_token,
        hasRefreshToken: !!data.refresh_token,
        expiresIn: data.expires_in,
        tokenType: data.token_type,
        scope: data.scope,
      },
    })

    const decodedTokens: DecodedToken[] = []

    // Process access token
    if (typeof data.access_token === 'string') {
      this.updateState({ accessToken: data.access_token })
      
      const decoded = this.decodeJwt(data.access_token, 'access_token')
      decodedTokens.push(decoded)

      this.addEvent({
        type: 'token',
        title: 'Access Token Decoded',
        description: decoded.isValid ? 'Token structure is valid' : 'Token has validation issues',
        data: {
          header: decoded.header,
          payload: decoded.payload,
          isValid: decoded.isValid,
          validationErrors: decoded.validationErrors,
        },
      })
    }

    // Process ID token (OIDC)
    if (typeof data.id_token === 'string') {
      this.updateState({ idToken: data.id_token })
      
      const decoded = this.decodeJwt(data.id_token, 'id_token')
      decodedTokens.push(decoded)

      this.addEvent({
        type: 'token',
        title: 'ID Token Decoded (OIDC)',
        description: decoded.isValid ? 'Token structure is valid' : 'Token has validation issues',
        data: {
          header: decoded.header,
          payload: decoded.payload,
          isValid: decoded.isValid,
          validationErrors: decoded.validationErrors,
          nonceValidated: this.state.nonce ? decoded.payload?.nonce === this.state.nonce : 'N/A',
        },
      })
    }

    // Process refresh token
    if (typeof data.refresh_token === 'string') {
      this.updateState({ refreshToken: data.refresh_token })
      
      // Refresh tokens may not be JWTs
      const decoded = this.decodeJwt(data.refresh_token, 'refresh_token')
      decodedTokens.push(decoded)

      this.addEvent({
        type: 'token',
        title: 'Refresh Token Received',
        description: decoded.isValid ? 'Token decoded successfully' : 'Token may be opaque (not a JWT)',
        data: {
          isJwt: decoded.payload !== undefined,
          note: 'Refresh tokens are often opaque references, not JWTs',
        },
      })
    }

    // Update expiration
    if (typeof data.expires_in === 'number') {
      this.updateState({ expiresIn: data.expires_in })
    }

    this.updateState({ 
      status: 'completed',
      decodedTokens,
    })

    this.addEvent({
      type: 'info',
      title: 'Flow Completed Successfully',
      description: 'Authorization Code flow completed - tokens acquired and validated',
      data: {
        tokensReceived: decodedTokens.map(t => t.type),
        totalDuration: `${this.state.events.length} events captured`,
      },
    })
  }

  private handleError(error: unknown): void {
    const message = error instanceof Error ? error.message : 'Unknown error'
    
    this.addEvent({
      type: 'error',
      title: 'Flow Execution Error',
      description: message,
    })

    this.updateState({
      status: 'error',
      error: message,
    })
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  abort(): void {
    this.abortController?.abort()
    this.updateState({ status: 'idle' })
  }

  reset(): void {
    this.abort()
    this.state = this.createInitialState()
    this.listeners.forEach(listener => listener(this.state))
  }

  getState(): FlowExecutionState {
    return this.state
  }
}

// ============================================================================
// React Hook for Flow Execution
// ============================================================================

import { useState, useCallback, useRef, useEffect } from 'react'

export function useFlowExecutor(config: FlowExecutionConfig) {
  const executorRef = useRef<FlowExecutor | null>(null)
  const [state, setState] = useState<FlowExecutionState | null>(null)

  // Create executor on config change
  useEffect(() => {
    executorRef.current = new FlowExecutor(config)
    const unsubscribe = executorRef.current.subscribe(setState)
    return () => {
      unsubscribe()
      executorRef.current?.abort()
    }
  }, [config])

  const execute = useCallback(async () => {
    if (!executorRef.current) return
    await executorRef.current.executeAuthorizationCodeFlow()
  }, [])

  const abort = useCallback(() => {
    executorRef.current?.abort()
  }, [])

  const reset = useCallback(() => {
    executorRef.current?.reset()
  }, [])

  return {
    state,
    execute,
    abort,
    reset,
    isExecuting: state?.status === 'started' || state?.status === 'authorizing' || state?.status === 'exchanging',
  }
}

// Default configuration for demo
// Uses 'public-app' which is a public OAuth client (SPA) that uses PKCE
export const DEFAULT_EXECUTOR_CONFIG: FlowExecutionConfig = {
  authServerUrl: '/oauth2', // Routes are at root: /oauth2/..., /oidc/...
  clientId: 'public-app', // Public client - uses PKCE, no client secret
  redirectUri: `${window.location.origin}/callback`,
  scopes: ['openid', 'profile', 'email'],
  usePkce: true,
  isOidc: true,
}

