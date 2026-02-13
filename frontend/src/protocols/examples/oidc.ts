import type { CodeExample } from './index'

export const OIDC_EXAMPLES: Record<string, CodeExample> = {
  /* ------------------------------------------------------------------ */
  oidc_authorization_code: {
    language: 'javascript',
    label: 'JavaScript (Browser + Server)',
    code: `// OpenID Connect Authorization Code Flow (OIDC Core §3.1)
// Extends OAuth 2.0 with identity — returns an ID Token alongside the access token.

// Step 1: Generate nonce for replay protection (§3.1.2.1)
const nonce = base64URLEncode(crypto.getRandomValues(new Uint8Array(32)));
const state = crypto.randomUUID();
sessionStorage.setItem('oidc_nonce', nonce);
sessionStorage.setItem('oidc_state', state);

// Step 2: Redirect to the OIDC authorization endpoint
const authUrl = new URL('/oidc/authorize', window.location.origin);
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', CLIENT_ID);
authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
authUrl.searchParams.set('scope', 'openid profile email');    // "openid" is REQUIRED
authUrl.searchParams.set('state', state);
authUrl.searchParams.set('nonce', nonce);                     // Bound into the ID Token
window.location.href = authUrl.toString();

// Step 3: In callback — exchange code for tokens
const tokens = await fetch('/oidc/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: authorizationCode,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
  }),
}).then(r => r.json());

// Response includes an ID Token (JWT):
// {
//   "access_token":  "eyJhbGciOiJSUzI1NiIs...",
//   "id_token":      "eyJhbGciOiJSUzI1NiIs...",   ← identity assertion
//   "token_type":    "Bearer",
//   "expires_in":    3600,
//   "scope":         "openid profile email"
// }

// Step 4: Validate the ID Token (§3.1.3.7) — do this server-side
// Required checks:
//  1. Verify JWT signature against JWKS from the discovery document
//  2. iss MUST match the expected issuer
//  3. aud MUST contain your client_id
//  4. nonce MUST match the value you stored in Step 1
//  5. exp MUST be in the future
//  6. iat should be reasonably recent`,
  },

  /* ------------------------------------------------------------------ */
  oidc_implicit: {
    language: 'javascript',
    label: 'JavaScript (Browser — Legacy)',
    code: `// OIDC Implicit Flow (OIDC Core §3.2)
// ⚠️  DEPRECATED — Use Authorization Code + PKCE instead (OAuth 2.1 §4.1)
// Tokens are returned in the URL fragment, exposing them to browser history
// and referrer headers.

// Step 1: Generate nonce — REQUIRED when id_token is in response_type (§3.2.2.1)
const nonce = base64URLEncode(crypto.getRandomValues(new Uint8Array(32)));
sessionStorage.setItem('oidc_nonce', nonce);

// Step 2: Redirect with response_type requesting id_token + access_token
const authUrl = new URL('/oidc/authorize', window.location.origin);
authUrl.searchParams.set('response_type', 'id_token token');  // §3.2.2.1
authUrl.searchParams.set('client_id', CLIENT_ID);
authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
authUrl.searchParams.set('scope', 'openid profile');
authUrl.searchParams.set('state', crypto.randomUUID());
authUrl.searchParams.set('nonce', nonce);
window.location.href = authUrl.toString();

// Step 3: Parse tokens from the URL fragment (NOT query string)
const fragment = new URLSearchParams(window.location.hash.substring(1));
const idToken = fragment.get('id_token');
const accessToken = fragment.get('access_token');
const tokenType = fragment.get('token_type');     // "Bearer"

// Step 4: Validate the ID Token (§3.2.2.11)
//  1. Verify JWT signature against JWKS
//  2. Validate nonce matches stored value (CRITICAL for replay protection)
//  3. Validate at_hash:
//     at_hash = BASE64URL(left-half(SHA-256(access_token)))
//     This binds the access_token to the id_token (§3.2.2.9)
//  4. Check iss, aud, exp as usual
//
// Security risks of Implicit Flow:
//  - Tokens visible in browser history and server logs
//  - No client authentication possible
//  - No refresh tokens issued
//  - Vulnerable to token injection attacks without at_hash validation`,
  },

  /* ------------------------------------------------------------------ */
  oidc_hybrid: {
    language: 'javascript',
    label: 'JavaScript (Browser + Server)',
    code: `// OIDC Hybrid Flow (OIDC Core §3.3)
// Returns an ID Token immediately (front-channel) AND a code for
// secure back-channel token exchange. Useful when you need identity
// information before the code exchange completes.

// Step 1: Generate nonce — REQUIRED for any response_type containing id_token
const nonce = base64URLEncode(crypto.getRandomValues(new Uint8Array(32)));
sessionStorage.setItem('oidc_nonce', nonce);

// Step 2: Redirect with hybrid response_type
const authUrl = new URL('/oidc/authorize', window.location.origin);
authUrl.searchParams.set('response_type', 'code id_token');   // §3.3.2.1
authUrl.searchParams.set('client_id', CLIENT_ID);
authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
authUrl.searchParams.set('scope', 'openid profile email');
authUrl.searchParams.set('state', crypto.randomUUID());
authUrl.searchParams.set('nonce', nonce);
window.location.href = authUrl.toString();

// Step 3: Parse the response — code in query, id_token in fragment
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');
const fragment = new URLSearchParams(window.location.hash.substring(1));
const idToken = fragment.get('id_token');

// Step 4: Validate the front-channel ID Token including c_hash (§3.3.2.11)
// c_hash = BASE64URL(left-half(SHA-256(code)))
// This cryptographically binds the authorization code to the ID Token,
// preventing code substitution attacks.
const codeBytes = new TextEncoder().encode(code);
const hashBuffer = await crypto.subtle.digest('SHA-256', codeBytes);
const leftHalf = new Uint8Array(hashBuffer.slice(0, hashBuffer.byteLength / 2));
const computedCHash = base64URLEncode(leftHalf);
// Compare computedCHash with the c_hash claim in the ID Token

// Step 5: Exchange the code for tokens via back-channel (same as Auth Code flow)
const tokens = await fetch('/oidc/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: REDIRECT_URI,
  }),
}).then(r => r.json());

// The back-channel token response includes a fresh ID Token — validate it too.`,
  },

  /* ------------------------------------------------------------------ */
  oidc_userinfo: {
    language: 'javascript',
    label: 'JavaScript (Client)',
    code: `// OIDC UserInfo Endpoint (OIDC Core §5.3)
// Returns claims about the authenticated user. The claims returned
// depend on the scopes requested during authorization.

const userInfo = await fetch('/oidc/userinfo', {
  headers: { 'Authorization': 'Bearer ' + accessToken },
}).then(r => r.json());

// Response — claims are determined by the granted scopes:
//
// scope "openid":   { "sub": "user-uuid-1234" }
// scope "profile":  + { "name", "family_name", "given_name", "picture", ... }
// scope "email":    + { "email", "email_verified" }
// scope "address":  + { "address": { "formatted", "street_address", ... } }
// scope "phone":    + { "phone_number", "phone_number_verified" }
//
// Example response with "openid profile email":
// {
//   "sub":            "user-uuid-1234",
//   "name":           "Jane Doe",
//   "given_name":     "Jane",
//   "family_name":    "Doe",
//   "email":          "jane.doe@corp.example",
//   "email_verified": true,
//   "picture":        "https://cdn.example/avatars/jane.jpg"
// }
//
// The "sub" claim MUST match the "sub" in the ID Token.
// If they differ, the response MUST be rejected (§5.3.4).`,
  },

  /* ------------------------------------------------------------------ */
  oidc_discovery: {
    language: 'javascript',
    label: 'JavaScript (Client)',
    code: `// OpenID Connect Discovery (OIDC Discovery 1.0 §4)
// Auto-configure your client by fetching the provider's metadata document.

// Step 1: Fetch the OpenID Provider Configuration
const config = await fetch('/.well-known/openid-configuration')
  .then(r => r.json());

// The discovery document contains all endpoints and capabilities:
// {
//   "issuer":                  "https://auth.example.com",
//   "authorization_endpoint":  "/oidc/authorize",
//   "token_endpoint":          "/oidc/token",
//   "userinfo_endpoint":       "/oidc/userinfo",
//   "jwks_uri":                "/oidc/jwks",
//   "scopes_supported":        ["openid", "profile", "email"],
//   "response_types_supported":["code", "id_token", "id_token token",
//                               "code id_token", "code token",
//                               "code id_token token"],
//   "id_token_signing_alg_values_supported": ["RS256"],
//   "subject_types_supported": ["public"],
//   "token_endpoint_auth_methods_supported": ["client_secret_basic",
//                                             "client_secret_post"]
// }

// Step 2: Fetch the JSON Web Key Set for signature verification
const jwks = await fetch(config.jwks_uri).then(r => r.json());
// { "keys": [{ "kty": "RSA", "kid": "...", "n": "...", "e": "AQAB", "use": "sig" }] }

// Step 3: Use discovered endpoints to configure your OIDC client
console.log('Authorization:', config.authorization_endpoint);
console.log('Token:',         config.token_endpoint);
console.log('UserInfo:',      config.userinfo_endpoint);
console.log('Scopes:',        config.scopes_supported);
console.log('Algorithms:',    config.id_token_signing_alg_values_supported);`,
  },
}
