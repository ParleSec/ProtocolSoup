/**
 * Flow Executor Base
 * 
 * Base interface and utilities for all flow executors.
 * Each executor implements a specific OAuth 2.0 or OIDC flow per RFC.
 */

// ============================================================================
// Types
// ============================================================================

export interface FlowExecutorConfig {
  /** Base URL for protocol endpoints (e.g., /oauth2 or /oidc) */
  baseUrl: string
  /** Client identifier */
  clientId: string
  /** Client secret (for confidential clients) */
  clientSecret?: string
  /** Redirect URI for authorization flows */
  redirectUri?: string
  /** Requested scopes */
  scopes: string[]
  /** Additional parameters specific to the flow */
  extraParams?: Record<string, string>
  /** Looking Glass session ID for wire capture */
  captureSessionId?: string
}

export interface FlowExecutorState {
  /** Unique execution ID */
  executionId: string
  /** Flow type being executed */
  flowType: string
  /** Current status */
  status: 'idle' | 'executing' | 'awaiting_user' | 'completed' | 'error'
  /** Current step in the flow */
  currentStep: string
  /** All captured HTTP exchanges */
  exchanges: CapturedExchange[]
  /** Timeline of events */
  events: FlowEvent[]
  /** Tokens received */
  tokens: {
    accessToken?: string
    idToken?: string
    refreshToken?: string
    tokenType?: string
    expiresIn?: number
    scope?: string
  }
  /** Decoded token payloads */
  decodedTokens: DecodedToken[]
  /** Security parameters used */
  securityParams: {
    state?: string
    nonce?: string
    codeVerifier?: string
    codeChallenge?: string
    deviceCode?: string
  }
  /** Error details if any */
  error?: {
    code: string
    description: string
    uri?: string
  }
}

export interface CapturedExchange {
  id: string
  timestamp: Date
  /** RFC section reference */
  rfcReference?: string
  /** Step description */
  step: string
  request: {
    method: string
    url: string
    headers: Record<string, string>
    body?: Record<string, string> | string
  }
  response?: {
    status: number
    statusText: string
    headers: Record<string, string>
    body: unknown
    duration: number
  }
}

export interface FlowEvent {
  id: string
  timestamp: Date
  type: 'info' | 'request' | 'response' | 'token' | 'crypto' | 'security' | 'user_action' | 'error' | 'rfc'
  title: string
  description: string
  /** RFC section this event relates to */
  rfcReference?: string
  data?: Record<string, unknown>
}

export interface DecodedToken {
  type: 'access_token' | 'id_token' | 'refresh_token'
  raw: string
  header?: Record<string, unknown>
  payload?: Record<string, unknown>
  signature?: string
  isValid?: boolean
  validationErrors?: string[]
}

export type FlowStateListener = (state: FlowExecutorState) => void

// ============================================================================
// Base Executor Class
// ============================================================================

export abstract class FlowExecutorBase {
  protected config: FlowExecutorConfig
  protected state: FlowExecutorState
  protected listeners: Set<FlowStateListener> = new Set()
  protected abortController: AbortController | null = null

  /** Flow type identifier (e.g., 'authorization_code', 'client_credentials') */
  abstract readonly flowType: string
  /** Human readable name */
  abstract readonly flowName: string
  /** RFC reference */
  abstract readonly rfcReference: string

  constructor(config: FlowExecutorConfig) {
    this.config = config
    this.state = this.createInitialState()
  }

  protected createInitialState(): FlowExecutorState {
    return {
      executionId: crypto.randomUUID(),
      flowType: this.flowType,
      status: 'idle',
      currentStep: 'Initialized',
      exchanges: [],
      events: [],
      tokens: {},
      decodedTokens: [],
      securityParams: {},
    }
  }

  /** Subscribe to state changes */
  subscribe(listener: FlowStateListener): () => void {
    this.listeners.add(listener)
    listener(this.state)
    return () => this.listeners.delete(listener)
  }

  /** Update state and notify listeners */
  protected updateState(updates: Partial<FlowExecutorState>): void {
    this.state = { ...this.state, ...updates }
    this.listeners.forEach(listener => listener(this.state))
  }

  /** Add an event to the timeline */
  protected addEvent(event: Omit<FlowEvent, 'id' | 'timestamp'>): void {
    const fullEvent: FlowEvent = {
      ...event,
      id: crypto.randomUUID(),
      timestamp: new Date(),
    }
    this.updateState({
      events: [...this.state.events, fullEvent],
    })
  }

  /** Add a captured HTTP exchange */
  protected addExchange(exchange: Omit<CapturedExchange, 'id' | 'timestamp'>): CapturedExchange {
    const fullExchange: CapturedExchange = {
      ...exchange,
      id: crypto.randomUUID(),
      timestamp: new Date(),
    }
    this.updateState({
      exchanges: [...this.state.exchanges, fullExchange],
    })
    return fullExchange
  }

  protected withCaptureHeaders(headers?: Record<string, string>): Record<string, string> {
    const merged: Record<string, string> = {
      ...(headers || {}),
    }
    if (this.config.captureSessionId) {
      merged['X-Looking-Glass-Session'] = this.config.captureSessionId
    }
    return merged
  }

  protected withCaptureQuery(url: string): string {
    if (!this.config.captureSessionId) {
      return url
    }
    const [base, hash] = url.split('#')
    const parsed = new URL(base, window.location.origin)
    parsed.searchParams.set('lg_session', this.config.captureSessionId)
    return hash ? `${parsed.toString()}#${hash}` : parsed.toString()
  }

  /** Make an HTTP request and capture it */
  protected async makeRequest(
    method: string,
    url: string,
    options: {
      headers?: Record<string, string>
      body?: Record<string, string> | string
      step: string
      rfcReference?: string
    }
  ): Promise<{ response: Response; data: unknown; exchange: CapturedExchange }> {
    const headers = this.withCaptureHeaders(options.headers)

    let bodyStr: string | undefined
    if (options.body) {
      if (typeof options.body === 'object') {
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        bodyStr = new URLSearchParams(options.body).toString()
      } else {
        bodyStr = options.body
      }
    }

    // Create exchange record
    const exchange = this.addExchange({
      step: options.step,
      rfcReference: options.rfcReference,
      request: {
        method,
        url,
        headers,
        body: options.body,
      },
    })

    this.addEvent({
      type: 'request',
      title: `${method} ${new URL(url, window.location.origin).pathname}`,
      description: options.step,
      rfcReference: options.rfcReference,
      data: {
        method,
        url,
        hasBody: !!options.body,
      },
    })

    const startTime = Date.now()

    const response = await fetch(url, {
      method,
      headers,
      body: bodyStr,
      signal: this.abortController?.signal,
    })

    const duration = Date.now() - startTime
    let data: unknown

    const contentType = response.headers.get('content-type')
    if (contentType?.includes('application/json')) {
      data = await response.json()
    } else {
      data = await response.text()
    }

    // Update exchange with response
    exchange.response = {
      status: response.status,
      statusText: response.statusText,
      headers: Object.fromEntries(response.headers.entries()),
      body: data,
      duration,
    }

    // Update the exchange in state
    this.updateState({
      exchanges: this.state.exchanges.map(e => 
        e.id === exchange.id ? exchange : e
      ),
    })

    this.addEvent({
      type: 'response',
      title: `${response.status} ${response.statusText}`,
      description: `Response received in ${duration}ms`,
      data: {
        status: response.status,
        duration,
        hasBody: !!data,
      },
    })

    return { response, data, exchange }
  }

  /** Decode a JWT token */
  protected decodeJwt(token: string, type: DecodedToken['type']): DecodedToken {
    const decoded: DecodedToken = {
      type,
      raw: token,
    }

    try {
      const parts = token.split('.')
      if (parts.length === 3) {
        decoded.header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')))
        decoded.payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')))
        decoded.signature = parts[2]

        const validationErrors: string[] = []
        const payload = decoded.payload as Record<string, unknown>

        // Check expiration
        if (payload.exp && typeof payload.exp === 'number') {
          if (payload.exp * 1000 < Date.now()) {
            validationErrors.push('Token is expired')
          }
        }

        // Check nonce for ID tokens
        if (type === 'id_token' && this.state.securityParams.nonce) {
          if (payload.nonce !== this.state.securityParams.nonce) {
            validationErrors.push(`Nonce mismatch`)
          }
        }

        decoded.isValid = validationErrors.length === 0
        decoded.validationErrors = validationErrors
      } else {
        // Might be an opaque token
        decoded.isValid = true
      }
    } catch {
      decoded.isValid = false
      decoded.validationErrors = ['Failed to decode token']
    }

    return decoded
  }

  /** Process token response from token endpoint */
  protected processTokenResponse(data: Record<string, unknown>): void {
    const tokens: FlowExecutorState['tokens'] = {}
    const decodedTokens: DecodedToken[] = []

    if (typeof data.access_token === 'string') {
      tokens.accessToken = data.access_token
      const decoded = this.decodeJwt(data.access_token, 'access_token')
      decodedTokens.push(decoded)

      this.addEvent({
        type: 'token',
        title: 'Access Token Received',
        description: decoded.payload ? 'JWT access token decoded' : 'Opaque access token received',
        data: decoded.payload ? { claims: Object.keys(decoded.payload) } : undefined,
      })
    }

    if (typeof data.id_token === 'string') {
      tokens.idToken = data.id_token
      const decoded = this.decodeJwt(data.id_token, 'id_token')
      decodedTokens.push(decoded)

      this.addEvent({
        type: 'token',
        title: 'ID Token Received (OIDC)',
        description: decoded.isValid ? 'ID token validated' : 'ID token has validation errors',
        rfcReference: 'OIDC Core 1.0 Section 2',
        data: {
          claims: decoded.payload ? Object.keys(decoded.payload) : [],
          isValid: decoded.isValid,
        },
      })
    }

    if (typeof data.refresh_token === 'string') {
      tokens.refreshToken = data.refresh_token
      const decoded = this.decodeJwt(data.refresh_token, 'refresh_token')
      decodedTokens.push(decoded)

      this.addEvent({
        type: 'token',
        title: 'Refresh Token Received',
        description: 'Can be used to obtain new access tokens',
        rfcReference: 'RFC 6749 Section 1.5',
      })
    }

    if (typeof data.token_type === 'string') {
      tokens.tokenType = data.token_type
    }
    if (typeof data.expires_in === 'number') {
      tokens.expiresIn = data.expires_in
    }
    if (typeof data.scope === 'string') {
      tokens.scope = data.scope
    }

    this.updateState({ tokens, decodedTokens })
  }

  /** Abstract method - each flow implements its own execution */
  abstract execute(): Promise<void>

  /** Abort the current execution */
  abort(): void {
    this.abortController?.abort()
    this.updateState({ status: 'idle' })
  }

  /** Reset to initial state */
  reset(): void {
    this.abort()
    this.state = this.createInitialState()
    this.listeners.forEach(listener => listener(this.state))
  }

  /** Get current state */
  getState(): FlowExecutorState {
    return this.state
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/** Generate cryptographically secure random string */
export function generateSecureRandom(length: number): string {
  const array = new Uint8Array(length)
  crypto.getRandomValues(array)
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('')
}

/** Generate PKCE code verifier (RFC 7636) */
export function generateCodeVerifier(): string {
  const array = new Uint8Array(32)
  crypto.getRandomValues(array)
  return base64UrlEncode(array)
}

/** Generate PKCE code challenge from verifier (RFC 7636) */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return base64UrlEncode(new Uint8Array(hash))
}

/** Base64 URL encode */
function base64UrlEncode(buffer: Uint8Array): string {
  let binary = ''
  for (const byte of buffer) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}


