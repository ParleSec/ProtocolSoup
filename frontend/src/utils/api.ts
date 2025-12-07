/**
 * API utilities for Protocol Showcase
 * 
 * Provides typed API helpers with error handling for
 * communicating with the backend services.
 */

const API_BASE = '/api'

/**
 * API Error class with status code and body
 */
export class APIError extends Error {
  constructor(
    message: string,
    public status: number,
    public body?: Record<string, unknown>
  ) {
    super(message)
    this.name = 'APIError'
  }
}

/**
 * Generic fetch wrapper with error handling
 */
export async function apiFetch<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = endpoint.startsWith('/') ? `${API_BASE}${endpoint}` : endpoint
  
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  })

  // Handle error responses
  if (!response.ok) {
    let body: Record<string, unknown> | undefined
    try {
      body = await response.json()
    } catch {
      // Response may not be JSON
    }
    
    const message = body?.error_description || body?.error || response.statusText
    throw new APIError(String(message), response.status, body)
  }

  // Handle empty responses
  if (response.status === 204) {
    return undefined as T
  }

  return response.json()
}

/**
 * GET request helper
 */
export function apiGet<T>(endpoint: string): Promise<T> {
  return apiFetch<T>(endpoint, { method: 'GET' })
}

/**
 * POST request helper with JSON body
 */
export function apiPost<T>(endpoint: string, body?: unknown): Promise<T> {
  return apiFetch<T>(endpoint, {
    method: 'POST',
    body: body ? JSON.stringify(body) : undefined,
  })
}

/**
 * POST request helper with form data
 */
export async function apiPostForm<T>(
  endpoint: string,
  data: Record<string, string>
): Promise<T> {
  const url = endpoint.startsWith('/api') ? endpoint : 
              endpoint.startsWith('/') ? endpoint : `${API_BASE}/${endpoint}`
  
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams(data).toString(),
  })

  if (!response.ok) {
    let body: Record<string, unknown> | undefined
    try {
      body = await response.json()
    } catch {
      // Response may not be JSON
    }
    
    const message = body?.error_description || body?.error || response.statusText
    throw new APIError(String(message), response.status, body)
  }

  return response.json()
}

/**
 * Token response type
 */
export interface TokenResponse {
  access_token: string
  token_type: string
  expires_in: number
  refresh_token?: string
  id_token?: string
  scope?: string
}

/**
 * Protocol summary type
 */
export interface Protocol {
  id: string
  name: string
  version: string
  description: string
  tags: string[]
}

/**
 * Flow definition type
 */
export interface FlowDefinition {
  id: string
  name: string
  description: string
  steps: FlowStep[]
  executable: boolean
  category?: string // "workload-api", "admin", "infrastructure"
}

export interface FlowStep {
  order: number
  name: string
  description: string
  from: string
  to: string
  type: 'request' | 'response' | 'redirect' | 'internal'
  parameters?: Record<string, string>
  security?: string[]
}

/**
 * Demo session type
 */
export interface DemoSession {
  session_id: string
  protocol: string
  flow: string
  ws_endpoint: string
  scenario: {
    id: string
    name: string
    description: string
    steps: Array<{
      order: number
      name: string
      description: string
      auto: boolean
    }>
  }
}

/**
 * API endpoint functions
 */
export const api = {
  /**
   * Get list of available protocols
   */
  getProtocols(): Promise<{ protocols: Protocol[] }> {
    return apiGet('/protocols')
  },

  /**
   * Get a specific protocol
   */
  getProtocol(id: string): Promise<Protocol> {
    return apiGet(`/protocols/${id}`)
  },

  /**
   * Get flows for a protocol
   */
  getProtocolFlows(protocolId: string): Promise<{ flows: FlowDefinition[] }> {
    return apiGet(`/protocols/${protocolId}/flows`)
  },

  /**
   * Start a demo session
   */
  startDemo(protocolId: string, flowId: string): Promise<DemoSession> {
    return apiPost(`/protocols/${protocolId}/demo/${flowId}`)
  },

  /**
   * Decode a JWT token
   */
  decodeToken(token: string): Promise<{
    header: Record<string, unknown>
    payload: Record<string, unknown>
    signature: string
    valid: boolean
    errors?: string[]
  }> {
    return apiPost('/lookingglass/decode', { token })
  },

  /**
   * Get active looking glass sessions
   */
  getSessions(): Promise<{ sessions: Array<{
    id: string
    protocol_id: string
    flow_id: string
    state: string
    created_at: string
  }> }> {
    return apiGet('/lookingglass/sessions')
  },

  /**
   * Get a specific session
   */
  getSession(sessionId: string): Promise<{
    id: string
    protocol_id: string
    flow_id: string
    state: string
    events: Array<{
      type: string
      timestamp: string
      title: string
      data?: Record<string, unknown>
    }>
  }> {
    return apiGet(`/lookingglass/sessions/${sessionId}`)
  },

  /**
   * Exchange authorization code for tokens
   */
  exchangeCode(
    endpoint: string,
    code: string,
    redirectUri: string,
    clientId: string,
    codeVerifier?: string
  ): Promise<TokenResponse> {
    const data: Record<string, string> = {
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
    }
    
    if (codeVerifier) {
      data.code_verifier = codeVerifier
    }
    
    return apiPostForm(endpoint, data)
  },

  /**
   * Refresh access token
   */
  refreshToken(
    endpoint: string,
    refreshToken: string,
    clientId: string
  ): Promise<TokenResponse> {
    return apiPostForm(endpoint, {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: clientId,
    })
  },

  /**
   * Get health status
   */
  getHealth(): Promise<{
    status: string
    version: string
    protocols: string[]
  }> {
    return apiFetch('/health', { method: 'GET' })
  },
}

