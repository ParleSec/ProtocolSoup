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
 * Compute the RFC 7638 JWK SHA-256 thumbprint ("jkt") for the three key
 * types this codebase actually mints: RSA, EC, and OKP -- Ed25519 holder
 * keys reach this on the wallet's did:key path, so omitting OKP would
 * either throw or silently compute a wrong digest and render a false
 * mismatch against a correct jkt in the panel this exists to keep honest.
 *
 * Mirrors crypto.JWK.Thumbprint() in backend/internal/crypto/keys.go
 * exactly: same three kty branches, same canonical member ordering per
 * RFC 7638 Section 3.2 (crv,kty,x,y for EC; e,kty,n for RSA; crv,kty,x for
 * OKP -- each already alphabetical, which is what makes plain object
 * literal key order equivalent to Go's alphabetically-sorted map-key JSON
 * marshalling), and the same refusal for anything else: the Go function
 * returns "" for an unsupported kty rather than guessing, so this returns
 * null for the same case. "Cannot compute for this key type" must be
 * rendered as its own state wherever this is used, never as a mismatch --
 * an unknown future kty must not produce a false verdict.
 */
export async function jwkThumbprint(jwk: Record<string, unknown>): Promise<string | null> {
  const kty = typeof jwk.kty === 'string' ? jwk.kty : ''
  let canonical: Record<string, string>

  switch (kty) {
    case 'RSA': {
      const { e, n } = jwk
      if (typeof e !== 'string' || typeof n !== 'string') return null
      canonical = { e, kty, n }
      break
    }
    case 'EC': {
      const { crv, x, y } = jwk
      if (typeof crv !== 'string' || typeof x !== 'string' || typeof y !== 'string') return null
      canonical = { crv, kty, x, y }
      break
    }
    case 'OKP': {
      const { crv, x } = jwk
      if (typeof crv !== 'string' || typeof x !== 'string') return null
      canonical = { crv, kty, x }
      break
    }
    default:
      return null
  }

  const encoder = new TextEncoder()
  const data = encoder.encode(JSON.stringify(canonical))
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

export interface RS256SigningMaterial {
  privateKey: CryptoKey
  publicJWK: JsonWebKey & { alg: 'RS256'; use: 'sig'; kid: string }
  kid: string
  alg: 'RS256'
}

/**
 * Generate client-held RS256 signing material. The private CryptoKey is
 * non-extractable; only the public JWK can leave the browser.
 */
export async function generateRS256SigningMaterial(kidPrefix: string): Promise<RS256SigningMaterial> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    false,
    ['sign', 'verify'],
  ) as CryptoKeyPair
  const exported = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
  const exportedKid = (exported as JsonWebKey & { kid?: string }).kid
  const kid = typeof exportedKid === 'string' && exportedKid.length > 0
    ? exportedKid
    : `${kidPrefix}-${(exported.n || '').slice(0, 12)}`
  return {
    privateKey: keyPair.privateKey,
    publicJWK: {
      kty: exported.kty,
      n: exported.n,
      e: exported.e,
      alg: 'RS256',
      use: 'sig',
      key_ops: ['verify'],
      kid,
    },
    kid,
    alg: 'RS256',
  }
}

/** Sign a compact JWT with RSASSA-PKCS1-v1_5 and SHA-256 (RS256). */
export async function signRS256JWT(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  privateKey: CryptoKey,
): Promise<string> {
  const encodedHeader = base64URLEncode(new TextEncoder().encode(JSON.stringify(header)))
  const encodedPayload = base64URLEncode(new TextEncoder().encode(JSON.stringify(payload)))
  const signingInput = `${encodedHeader}.${encodedPayload}`
  const signature = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    privateKey,
    new TextEncoder().encode(signingInput),
  )
  return `${signingInput}.${base64URLEncode(new Uint8Array(signature))}`
}

export interface ES256SigningMaterial {
  privateKey: CryptoKey
  publicJWK: JsonWebKey & { alg: 'ES256'; use: 'sig'; kid: string }
  kid: string
  alg: 'ES256'
}

/**
 * Generate client-held ES256 (ECDSA P-256) signing material. The private
 * CryptoKey is non-extractable; only the public JWK can leave the browser.
 * This is the key material used for DPoP proofs (RFC 9449) -- a fresh key
 * pair per Looking Glass execution, never persisted or transmitted.
 */
export async function generateES256SigningMaterial(kidPrefix: string): Promise<ES256SigningMaterial> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign', 'verify'],
  ) as CryptoKeyPair
  const exported = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
  const kid = `${kidPrefix}-${(exported.x || '').slice(0, 12)}`
  return {
    privateKey: keyPair.privateKey,
    publicJWK: {
      kty: exported.kty,
      crv: exported.crv,
      x: exported.x,
      y: exported.y,
      alg: 'ES256',
      use: 'sig',
      key_ops: ['verify'],
      kid,
    },
    kid,
    alg: 'ES256',
  }
}

/**
 * Sign a compact JWT with ECDSA P-256 and SHA-256 (ES256). WebCrypto's
 * ECDSA signature is already the raw (r||s) concatenation JOSE expects --
 * no ASN.1 DER conversion is needed, unlike Node's crypto.sign default.
 */
export async function signES256JWT(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  privateKey: CryptoKey,
): Promise<string> {
  const encodedHeader = base64URLEncode(new TextEncoder().encode(JSON.stringify(header)))
  const encodedPayload = base64URLEncode(new TextEncoder().encode(JSON.stringify(payload)))
  const signingInput = `${encodedHeader}.${encodedPayload}`
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    privateKey,
    new TextEncoder().encode(signingInput),
  )
  return `${signingInput}.${base64URLEncode(new Uint8Array(signature))}`
}

/**
 * Build a DPoP proof JWT (RFC 9449 Section 4.2) bound to the given HTTP
 * method and target URI. When `accessToken` is supplied, the mandatory
 * `ath` claim (Section 4.3 step 11) is included so the same helper covers
 * both the token-endpoint proof (no access token yet) and a subsequent
 * resource-endpoint proof (access token already issued). When `nonce` is
 * supplied, it is echoed into the proof's `nonce` claim -- the server's
 * required response to an RFC 9449 Section 8 `use_dpop_nonce` challenge.
 */
export async function generateDPoPProof(
  signingMaterial: ES256SigningMaterial,
  options: { htm: string; htu: string; accessToken?: string; nonce?: string },
): Promise<string> {
  const header: Record<string, unknown> = {
    typ: 'dpop+jwt',
    alg: 'ES256',
    jwk: {
      kty: signingMaterial.publicJWK.kty,
      crv: signingMaterial.publicJWK.crv,
      x: signingMaterial.publicJWK.x,
      y: signingMaterial.publicJWK.y,
    },
  }
  const claims: Record<string, unknown> = {
    jti: crypto.randomUUID(),
    htm: options.htm,
    htu: options.htu,
    iat: Math.floor(Date.now() / 1000),
  }
  if (options.accessToken) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(options.accessToken))
    claims.ath = base64URLEncode(new Uint8Array(digest))
  }
  if (options.nonce) {
    claims.nonce = options.nonce
  }
  return signES256JWT(header, claims, signingMaterial.privateKey)
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


