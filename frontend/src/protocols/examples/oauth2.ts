import type { CodeExample } from './index'

export const OAUTH2_EXAMPLES: Record<string, CodeExample> = {
  /* ------------------------------------------------------------------ */
  authorization_code: {
    language: 'javascript',
    label: 'JavaScript (Browser + Server)',
    code: `// OAuth 2.0 Authorization Code Flow (RFC 6749 §4.1)
// Step 1: Build authorization URL and redirect the user
const state = crypto.randomUUID();                 // CSRF protection (§4.1.1)
sessionStorage.setItem('oauth_state', state);

const authUrl = new URL('/oauth2/authorize', window.location.origin);
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', CLIENT_ID);
authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
authUrl.searchParams.set('scope', 'openid profile email');
authUrl.searchParams.set('state', state);
window.location.href = authUrl.toString();

// Step 2: In your callback handler — validate state, exchange code
const params = new URLSearchParams(window.location.search);
if (params.get('state') !== sessionStorage.getItem('oauth_state')) {
  throw new Error('State mismatch — possible CSRF attack');
}

// Step 3: Exchange the authorization code for tokens (server-side)
const tokenResponse = await fetch('/oauth2/token', {
  method: 'POST',
  headers: {
    'Authorization': 'Basic ' + btoa(CLIENT_ID + ':' + CLIENT_SECRET),
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.get('code'),
    redirect_uri: REDIRECT_URI,
  }),
}).then(r => r.json());

// Token response (RFC 6749 §5.1)
// {
//   "access_token":  "eyJhbGciOiJSUzI1NiIs...",
//   "token_type":    "Bearer",
//   "expires_in":    3600,
//   "refresh_token": "dGhpcyBpcyBhIHJlZnJl...",
//   "scope":         "openid profile email"
// }`,
  },

  /* ------------------------------------------------------------------ */
  authorization_code_pkce: {
    language: 'javascript',
    label: 'JavaScript (Browser — Public Client)',
    code: `// OAuth 2.0 Authorization Code + PKCE (RFC 7636)
// PKCE is REQUIRED for public clients (no client_secret)

// Step 1: Generate cryptographic PKCE parameters
const codeVerifier = base64URLEncode(
  crypto.getRandomValues(new Uint8Array(32))          // 256-bit random
);
const codeChallenge = base64URLEncode(
  await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier))
);

// Step 2: Redirect to authorization endpoint with PKCE challenge
const state = crypto.randomUUID();
sessionStorage.setItem('oauth_state', state);
sessionStorage.setItem('pkce_verifier', codeVerifier);

const authUrl = new URL('/oauth2/authorize', window.location.origin);
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', CLIENT_ID);
authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
authUrl.searchParams.set('scope', 'openid profile email');
authUrl.searchParams.set('state', state);
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');     // §4.3
window.location.href = authUrl.toString();

// Step 3: In callback — exchange code with verifier (no client_secret needed)
const tokens = await fetch('/oauth2/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: authorizationCode,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    code_verifier: sessionStorage.getItem('pkce_verifier'),    // §4.5
  }),
}).then(r => r.json());

// Server computes SHA-256(code_verifier) and compares to stored code_challenge.
// If they don't match → 400 invalid_grant (§4.6)`,
  },

  /* ------------------------------------------------------------------ */
  client_credentials: {
    language: 'javascript',
    label: 'JavaScript (Server-to-Server)',
    code: `// OAuth 2.0 Client Credentials Grant (RFC 6749 §4.4)
// Used for machine-to-machine authentication — no user involved.

const tokenResponse = await fetch('/oauth2/token', {
  method: 'POST',
  headers: {
    // Client authenticates via HTTP Basic (RFC 6749 §2.3.1)
    // The server rejects requests that use BOTH Basic and body credentials.
    'Authorization': 'Basic ' + btoa(CLIENT_ID + ':' + CLIENT_SECRET),
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    grant_type: 'client_credentials',
    scope: 'api:read api:write',       // Optional — defaults to client's registered scopes
  }),
}).then(r => r.json());

// Response (RFC 6749 §4.4.3)
// {
//   "access_token": "eyJhbGciOiJSUzI1NiIs...",
//   "token_type":   "Bearer",
//   "expires_in":   3600,
//   "scope":        "api:read api:write"
// }
//
// NOTE: No refresh_token is issued for client_credentials grants.
// When the access token expires, the client re-authenticates.

// Use the token to call protected APIs
const data = await fetch('/api/resource', {
  headers: { 'Authorization': 'Bearer ' + tokenResponse.access_token },
}).then(r => r.json());`,
  },

  /* ------------------------------------------------------------------ */
  refresh_token: {
    language: 'javascript',
    label: 'JavaScript (Server-side)',
    code: `// OAuth 2.0 Refresh Token Grant (RFC 6749 §6)
// Obtain a new access token without requiring the user to re-authenticate.

const refreshResponse = await fetch('/oauth2/token', {
  method: 'POST',
  headers: {
    'Authorization': 'Basic ' + btoa(CLIENT_ID + ':' + CLIENT_SECRET),
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: storedRefreshToken,
    // scope is optional — omit to keep the original scope,
    // or provide a subset to downscope the new token.
  }),
}).then(r => r.json());

// Response includes a ROTATED refresh token (best practice)
// {
//   "access_token":  "eyJhbGciOiJSUzI1NiIs...",   ← new
//   "token_type":    "Bearer",
//   "expires_in":    3600,
//   "refresh_token": "cm90YXRlZCByZWZyZXNo...",   ← new (old one is now invalid)
//   "scope":         "openid profile email"
// }
//
// IMPORTANT: Refresh token rotation (RFC 6749 §6 + Security BCP §4.14.2)
// The server invalidates the old refresh token and issues a new one.
// If the old token is replayed, the server detects potential theft and
// revokes the entire token family.

// Always store the new refresh token, discarding the old one
storedRefreshToken = refreshResponse.refresh_token;`,
  },

  /* ------------------------------------------------------------------ */
  token_introspection: {
    language: 'javascript',
    label: 'JavaScript (Resource Server)',
    code: `// OAuth 2.0 Token Introspection (RFC 7662)
// Resource servers call this to validate opaque or JWT tokens.

const introspection = await fetch('/oauth2/introspect', {
  method: 'POST',
  headers: {
    // The resource server authenticates as an OAuth client
    'Authorization': 'Basic ' + btoa(CLIENT_ID + ':' + CLIENT_SECRET),
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    token: accessToken,
    token_type_hint: 'access_token',   // Optional hint (§2.1) — advisory only
  }),
}).then(r => r.json());

// Active token response (§2.2):
// {
//   "active":     true,
//   "token_type": "Bearer",
//   "scope":      "openid profile email",
//   "client_id":  "my-app",
//   "sub":        "user-uuid-1234",
//   "exp":        1740000000,
//   "iat":        1739996400,
//   "iss":        "https://auth.example.com",
//   "jti":        "token-uuid-5678"
// }
//
// Revoked or expired token:
// { "active": false }

if (introspection.active) {
  console.log('Token valid for:', introspection.scope);
  console.log('Expires:', new Date(introspection.exp * 1000));
} else {
  // Reject the request — token is expired, revoked, or unknown
  throw new Error('Token is not active');
}`,
  },

  /* ------------------------------------------------------------------ */
  token_revocation: {
    language: 'javascript',
    label: 'JavaScript (Client)',
    code: `// OAuth 2.0 Token Revocation (RFC 7009)
// Invalidate tokens when a user logs out or access is no longer needed.

// Revoke the refresh token (invalidates the entire token family)
await fetch('/oauth2/revoke', {
  method: 'POST',
  headers: {
    'Authorization': 'Basic ' + btoa(CLIENT_ID + ':' + CLIENT_SECRET),
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    token: refreshToken,
    token_type_hint: 'refresh_token',   // Advisory hint (§2.1)
  }),
});
// Server ALWAYS returns 200 OK regardless of whether the token existed,
// was already revoked, or was unknown. This prevents token-existence
// oracle attacks (RFC 7009 §2.2).

// Also revoke the access token for immediate effect
await fetch('/oauth2/revoke', {
  method: 'POST',
  headers: {
    'Authorization': 'Basic ' + btoa(CLIENT_ID + ':' + CLIENT_SECRET),
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    token: accessToken,
    token_type_hint: 'access_token',
  }),
});

// After revocation, introspection will return { "active": false }
// and the token will be rejected at protected endpoints.`,
  },
}
