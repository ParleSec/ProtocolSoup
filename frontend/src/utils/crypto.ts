/**
 * Cryptographic utilities for OAuth 2.0 / OIDC flows
 * 
 * Provides PKCE (Proof Key for Code Exchange) implementation
 * and other crypto helpers for secure authentication flows.
 */

/**
 * Generate a cryptographically secure random string
 * Used for code_verifier, state, and nonce parameters
 */
export function generateRandomString(length: number = 32): string {
  const array = new Uint8Array(length)
  crypto.getRandomValues(array)
  return base64URLEncode(array)
}

/**
 * Base64URL encode a Uint8Array
 * Per RFC 7636, uses URL-safe characters without padding
 */
export function base64URLEncode(buffer: Uint8Array): string {
  return btoa(String.fromCharCode(...buffer))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

/**
 * Base64URL decode a string to Uint8Array
 */
export function base64URLDecode(str: string): Uint8Array {
  // Add padding if needed
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/')
  const padding = '='.repeat((4 - (base64.length % 4)) % 4)
  const decoded = atob(base64 + padding)
  return Uint8Array.from(decoded, c => c.charCodeAt(0))
}

/**
 * Decode a base64url value into a UTF-8 string.
 */
export function decodeBase64URLToString(str: string): string | null {
  try {
    const decodedBytes = base64URLDecode(str)
    return new TextDecoder().decode(decodedBytes)
  } catch {
    return null
  }
}

/**
 * Decode a base64url value that contains JSON.
 */
export function decodeBase64URLJSON<T = unknown>(str: string): T | null {
  const decoded = decodeBase64URLToString(str)
  if (!decoded) {
    return null
  }
  try {
    return JSON.parse(decoded) as T
  } catch {
    return null
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

export interface DecodedJWT {
  header: Record<string, unknown>
  payload: Record<string, unknown>
  signature: string
}

/**
 * Decode JWT segments without validating the signature.
 */
export function decodeJWTWithoutValidation(token: string): DecodedJWT | null {
  const [headerSegment, payloadSegment, signature] = token.split('.')
  if (!headerSegment || !payloadSegment || signature === undefined) {
    return null
  }

  const header = decodeBase64URLJSON<unknown>(headerSegment)
  const payload = decodeBase64URLJSON<unknown>(payloadSegment)
  if (!isRecord(header) || !isRecord(payload)) {
    return null
  }

  return {
    header,
    payload,
    signature,
  }
}

/**
 * Generate a PKCE code verifier
 * A high-entropy cryptographic random string (43-128 chars)
 */
export function generateCodeVerifier(): string {
  // 32 bytes = 43 base64url characters after encoding
  return generateRandomString(32)
}

/**
 * Generate a PKCE code challenge from a verifier
 * Uses SHA-256 hash and base64url encoding
 */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return base64URLEncode(new Uint8Array(digest))
}

/**
 * Generate a state parameter for CSRF protection
 */
export function generateState(): string {
  return generateRandomString(16)
}

/**
 * Generate a nonce for OIDC replay protection
 */
export function generateNonce(): string {
  return generateRandomString(16)
}

/**
 * PKCE parameters for an OAuth flow
 */
export interface PKCEParams {
  codeVerifier: string
  codeChallenge: string
  codeChallengeMethod: 'S256'
}

/**
 * Generate complete PKCE parameters
 */
export async function generatePKCE(): Promise<PKCEParams> {
  const codeVerifier = generateCodeVerifier()
  const codeChallenge = await generateCodeChallenge(codeVerifier)
  
  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: 'S256',
  }
}

/**
 * OAuth state storage helpers
 * Store and retrieve OAuth parameters in sessionStorage
 */
export const oauthStorage = {
  /**
   * Store PKCE verifier for later retrieval
   */
  storeVerifier(verifier: string): void {
    sessionStorage.setItem('pkce_verifier', verifier)
  },

  /**
   * Retrieve and clear PKCE verifier
   */
  getVerifier(): string | null {
    const verifier = sessionStorage.getItem('pkce_verifier')
    sessionStorage.removeItem('pkce_verifier')
    return verifier
  },

  /**
   * Store OAuth state for CSRF validation
   */
  storeState(state: string): void {
    sessionStorage.setItem('oauth_state', state)
  },

  /**
   * Validate and clear OAuth state
   */
  validateState(receivedState: string): boolean {
    const storedState = sessionStorage.getItem('oauth_state')
    sessionStorage.removeItem('oauth_state')
    return storedState === receivedState
  },

  /**
   * Store OIDC nonce for validation
   */
  storeNonce(nonce: string): void {
    sessionStorage.setItem('oidc_nonce', nonce)
  },

  /**
   * Get and clear OIDC nonce
   */
  getNonce(): string | null {
    const nonce = sessionStorage.getItem('oidc_nonce')
    sessionStorage.removeItem('oidc_nonce')
    return nonce
  },

  /**
   * Store flow type (oauth2 or oidc)
   */
  storeFlowType(flowType: string): void {
    sessionStorage.setItem('oauth_flow_type', flowType)
  },

  /**
   * Get flow type
   */
  getFlowType(): string {
    return sessionStorage.getItem('oauth_flow_type') || 'oauth2'
  },

  /**
   * Clear all OAuth-related storage
   */
  clearAll(): void {
    sessionStorage.removeItem('pkce_verifier')
    sessionStorage.removeItem('oauth_state')
    sessionStorage.removeItem('oidc_nonce')
    sessionStorage.removeItem('oauth_flow_type')
  },
}


