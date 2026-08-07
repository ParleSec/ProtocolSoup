# OAuth 2.0 Protocol Implementation

A standards-compliant implementation of the [OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749) with PKCE (RFC 7636), `private_key_jwt` client authentication (RFC 7523 §2.2), Token Introspection (RFC 7662), and Token Revocation (RFC 7009).

## Overview

This implementation provides:

- **Authorization Code Grant**: Standard flow for web applications with PKCE support
- **Client Credentials Grant**: Machine-to-machine authentication
- **private_key_jwt**: RSA, P-256, or Ed25519 client assertions with registered JWKS/JWKS URI keys
- **Implicit Grant**: Legacy browser-based flow (deprecated, for reference)
- **Refresh Token Grant**: Token renewal without user interaction
- **Token Introspection**: RFC 7662 compliant active token validation
- **Token Revocation**: RFC 7009 compliant token invalidation
- **PKCE Support**: Proof Key for Code Exchange for public clients
- **Looking Glass Integration**: Real-time flow visualization

## Service Deployment

The OAuth 2.0 implementation is part of the **Federation Service** in the split backend architecture:

- **Behind the gateway** (recommended): `/oauth2/*` is proxied through the gateway
- **Standalone**: Run the federation service directly and access `/oauth2/*`

The OAuth 2.0 plugin serves as the foundation for the OIDC plugin. See the [OIDC README](../oidc/README.md) for identity-layer extensions.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      OAuth 2.0 Implementation                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Client Application                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Web App / Mobile App / CLI / Service                               │    │
│  │                                                                     │    │
│  │  Authorization Code + PKCE ──> For interactive user flows           │    │
│  │  Client Credentials ──────────> For service-to-service auth         │    │
│  │  Refresh Token ───────────────> For token renewal                   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                │                                            │
│                                │ HTTPS                                      │
│                                ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    OAuth 2.0 Plugin (plugin.go)                     │    │
│  │                                                                     │    │
│  │  ┌───────────────────┐  ┌───────────────────┐  ┌─────────────────┐  │    │
│  │  │  Authorization    │  │  Token Endpoint   │  │  Token Mgmt     │  │    │
│  │  │  (handlers.go)    │  │  (handlers.go)    │  │  (handlers.go)  │  │    │
│  │  │                   │  │                   │  │                 │  │    │
│  │  │ • /authorize      │  │ • /token          │  │ • /introspect   │  │    │
│  │  │ • Login form      │  │ • auth_code grant │  │ • /revoke       │  │    │
│  │  │ • PKCE challenge  │  │ • client_creds    │  │ • Token blacklist│ │    │
│  │  │ • State CSRF      │  │ • refresh_token   │  │ • ETag support  │  │    │
│  │  └───────────────────┘  └───────────────────┘  └─────────────────┘  │    │
│  │                                                                     │    │
│  │  ┌───────────────────┐  ┌───────────────────────────────────────┐   │    │
│  │  │  Login Request    │  │  Looking Glass Events                 │   │    │
│  │  │  Storage          │  │                                       │   │    │
│  │  │                   │  │  • Authorization Request Received     │   │    │
│  │  │ • CSRF protection │  │  • User Authentication Required       │   │    │
│  │  │ • 10 min TTL      │  │  • Authorization Code Issued          │   │    │
│  │  │ • Single use      │  │  • Token Exchange Request             │   │    │
│  │  └───────────────────┘  │  • Access Token Issued                │   │    │
│  │                         │  • PKCE Verification Successful       │   │    │
│  │                         │  • Token Introspection Result         │   │    │
│  │                         │  • Token Revoked                      │   │    │
│  │                         └───────────────────────────────────────┘   │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                │                                            │
│                                ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      Mock Identity Provider                         │    │
│  │                                                                     │    │
│  │  ┌───────────────┐ ┌───────────────┐ ┌────────────────────────────┐ │    │
│  │  │ Users         │ │ Clients       │ │ Authorization Codes        │ │    │
│  │  │               │ │               │ │                            │ │    │
│  │  │ alice@...     │ │ public-app    │ │ • code → client+user+scope │ │    │
│  │  │ bob@...       │ │ demo-app      │ │ • PKCE challenge bound     │ │    │
│  │  │ admin@...     │ │ machine-client│ │ • 10 minute TTL            │ │    │
│  │  └───────────────┘ └───────────────┘ │ • Single use + consumed    │ │    │
│  │                                      └────────────────────────────┘ │    │
│  │  ┌───────────────┐ ┌───────────────┐ ┌────────────────────────────┐ │    │
│  │  │ Refresh Tokens│ │ KeySet        │ │ Revoked Tokens             │ │    │
│  │  │               │ │               │ │                            │ │    │
│  │  │ • 7 day TTL   │ │ • RS256       │ │ • Token blacklist          │ │    │
│  │  │ • Rotation    │ │ • ES256       │ │ • Introspection: active=false│    │
│  │  │ • Client bound│ │ • JWK export  │ │ • RFC 7009 compliant       │ │    │
│  │  └───────────────┘ └───────────────┘ └────────────────────────────┘ │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## File Structure

| File | Purpose |
|------|---------|
| `plugin.go` | Main plugin implementing `ProtocolPlugin` interface, route registration, flow definitions |
| `handlers.go` | HTTP handlers for authorization, token, introspection, revocation, login request management |
| `clientauth_jwt.go` | RFC 7523 assertion validation, replay protection, and client JWKS resolution |

## API Endpoints

### Authorization Endpoint

| Method | Endpoint | Description | RFC Reference |
|--------|----------|-------------|---------------|
| GET | `/oauth2/authorize` | Display authorization/login page | RFC 6749 §3.1 |
| POST | `/oauth2/authorize` | Process login form submission | RFC 6749 §3.1 |

### Token Endpoint

| Method | Endpoint | Description | RFC Reference |
|--------|----------|-------------|---------------|
| POST | `/oauth2/token` | Exchange code/credentials for tokens | RFC 6749 §3.2 |
| GET | `/.well-known/oauth-authorization-server/oauth2` | OAuth authorization server metadata | RFC 8414 |

**Supported Grant Types:**
- `authorization_code` - Exchange authorization code for tokens
- `client_credentials` - Direct client authentication
- `refresh_token` - Obtain new tokens using refresh token

### Token Management

| Method | Endpoint | Description | RFC Reference |
|--------|----------|-------------|---------------|
| POST | `/oauth2/introspect` | Validate and inspect token | RFC 7662 §2 |
| POST | `/oauth2/revoke` | Invalidate token | RFC 7009 §2 |

### Demo Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/oauth2/demo/users` | List demo users with credentials |
| GET | `/oauth2/demo/clients` | List registered OAuth clients |
| POST | `/oauth2/demo/clients/machine-client-pkjwt/jwks` | Register the browser demo's public JWK Set |

## Grant Types

### Authorization Code Grant (RFC 6749 §4.1)

The standard flow for web applications:

```
┌──────┐          ┌──────────┐          ┌─────────────────────┐
│Client│          │   User   │          │ Authorization Server│
└──┬───┘          └────┬─────┘          └──────────┬──────────┘
   │                   │                           │
   │──1. Auth Request (response_type=code)────────>│
   │                   │                           │
   │                   │<──2. Login Page───────────│
   │                   │                           │
   │                   │──3. Credentials──────────>│
   │                   │                           │
   │<──4. Redirect with code + state───────────────│
   │                   │                           │
   │──5. Token Request (grant_type=authorization_code)──>│
   │                   │                           │
   │<──6. Access Token + Refresh Token─────────────│
```

**Authorization Request Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `response_type` | Yes | Must be `code` |
| `client_id` | Yes | Client identifier |
| `redirect_uri` | Yes | Callback URL |
| `scope` | No | Space-separated scopes |
| `state` | Recommended | CSRF protection token |
| `code_challenge` | PKCE | BASE64URL(SHA256(verifier)) |
| `code_challenge_method` | PKCE | `S256` or `plain` |

**Token Request Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `grant_type` | Yes | `authorization_code` |
| `code` | Yes | Authorization code |
| `redirect_uri` | Yes | Must match original |
| `client_id` | Yes | Client identifier |
| `client_secret` | Confidential | Client secret |
| `code_verifier` | PKCE | Original verifier |

### Client Credentials Grant (RFC 6749 §4.4)

For machine-to-machine authentication:

```
┌──────────┐                    ┌─────────────────────┐
│  Client  │                    │ Authorization Server│
└────┬─────┘                    └──────────┬──────────┘
     │                                     │
     │──Token Request (grant_type=client_credentials)──>│
     │  + client_secret_basic OR private_key_jwt        │
     │                                     │
     │<──Access Token (no refresh token)───│
```

**Token Request Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `grant_type` | Yes | `client_credentials` |
| `client_id` | Yes | Client identifier |
| `client_secret` | Basic/POST | Client secret |
| `client_assertion_type` | private_key_jwt | `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` |
| `client_assertion` | private_key_jwt | Single signed JWT (maximum 8KB) |
| `scope` | No | Requested scopes |

`private_key_jwt` is enabled only for `client_credentials`. ProtocolSoup
requires `iss` and `sub` to equal the request-body `client_id`, an exact
`aud` match to the configured token endpoint URL, fractional RFC 7519
NumericDate support for `iat`, `exp`, and optional `nbf`, and a single-use
`jti`. Assertions have a maximum 300-second lifetime and a 60-second
clock-skew tolerance. An atomic replay reservation remains through `exp` plus
that skew, covering the complete interval in which an assertion could be
accepted. Production uses shared Redis (`SET NX`) and fails closed with
`server_error` if the store is unavailable.
Supported algorithms are RS256, ES256 with P-256, and EdDSA with Ed25519; the
algorithm must match the registered key type and the client registration must
select `private_key_jwt`. RSA verification keys require an odd modulus of at
least 2048 bits and an odd exponent of at least 3.

Clients may register a static JWKS, a HTTPS `jwks_uri`, or both. Static keys
are checked first. The private JWK members `d`, `p`, `q`, `dp`, `dq`, `qi`,
`oth`, and `k` are rejected. Remote retrieval disables environment proxies,
blocks IPv4/IPv6 special-use addresses at resolution and dial time, uses one
3-second DNS-to-body deadline, rejects redirects, caps responses at 64KB,
coalesces concurrent fetches, caches for 10 minutes, and rate-limits refreshes
on `kid` miss. Unusable unrelated remote keys are ignored if a usable
verification key remains.

The browser demo uses the Looking Glass session owner capability to perform one
active-session-only public-key registration. That registration creates the
real distinct client ID (no `private_key_jwt` client is pre-seeded) and returns
the token endpoint used as the assertion audience. This preserves real
authorization-server state, prevents concurrent sessions from replacing one
shared key, and works when frontend and backend origins differ. Demo
registrations expire after 10 minutes and are pruned from the in-memory client
registry.

RFC 8414 metadata is emitted only when `SHOWCASE_BASE_URL` is a pathless HTTPS
origin. Production startup rejects HTTP, subpath, trailing-slash, query, and
fragment values. Local loopback HTTP remains usable for development flows but
is not published as standards-conformant authorization server metadata.

### Refresh Token Grant (RFC 6749 §6)

For obtaining new tokens:

```
┌──────────┐                    ┌─────────────────────┐
│  Client  │                    │ Authorization Server│
└────┬─────┘                    └──────────┬──────────┘
     │                                     │
     │──Token Request (grant_type=refresh_token)──────>│
     │  + refresh_token                                 │
     │                                     │
     │<──New Access Token + New Refresh Token──────────│
```

**Token Request Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `grant_type` | Yes | `refresh_token` |
| `refresh_token` | Yes | Valid refresh token |
| `client_id` | Yes | Original client |
| `scope` | No | Same or subset of original |

## PKCE Support (RFC 7636)

PKCE prevents authorization code interception for public clients:

### Code Verifier Requirements

- Length: 43-128 characters
- Characters: `[A-Za-z0-9-._~]`
- Cryptographically random

### Code Challenge Methods

| Method | Computation | Security |
|--------|-------------|----------|
| `S256` | `BASE64URL(SHA256(verifier))` | **Recommended** |
| `plain` | `verifier` | Fallback only |

### Verification Process

```
Authorization Request:
  code_challenge = BASE64URL(SHA256(code_verifier))
  code_challenge_method = S256

Token Request:
  code_verifier = original random string

Server Verification:
  BASE64URL(SHA256(code_verifier)) == code_challenge
```

## Token Introspection (RFC 7662)

Validate and inspect token metadata:

**Request:**
```http
POST /oauth2/introspect HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

token=ACCESS_TOKEN&token_type_hint=access_token
```

**Response (Active Token):**
```json
{
  "active": true,
  "scope": "read write",
  "client_id": "demo-app",
  "username": "alice@example.com",
  "token_type": "Bearer",
  "exp": 1704825600,
  "iat": 1704822000,
  "sub": "alice@example.com",
  "aud": "demo-app",
  "iss": "https://protocolsoup.com",
  "jti": "unique-token-id"
}
```

**Response (Inactive/Revoked Token):**
```json
{
  "active": false
}
```

## Token Revocation (RFC 7009)

Invalidate tokens when no longer needed:

**Request:**
```http
POST /oauth2/revoke HTTP/1.1
Content-Type: application/x-www-form-urlencoded

token=REFRESH_TOKEN&token_type_hint=refresh_token&client_id=public-app
```

**Response:**
```
HTTP/1.1 200 OK
```

Per RFC 7009 §2.2, the server always returns 200 OK regardless of whether the token was valid. This prevents attackers from using the endpoint to probe for valid tokens.

## Token Response Format

### Successful Token Response (RFC 6749 §5.1)

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "read write"
}
```

### Error Response (RFC 6749 §5.2)

```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code has expired",
  "error_uri": "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2"
}
```

### Error Codes

| Error | Description | HTTP Status |
|-------|-------------|-------------|
| `invalid_request` | Missing or invalid parameter | 400 |
| `invalid_client` | Client authentication failed | 401 |
| `invalid_grant` | Invalid code, token, or credentials | 400 |
| `unauthorized_client` | Client not authorized for grant | 400 |
| `unsupported_grant_type` | Grant type not supported | 400 |
| `invalid_scope` | Invalid or unknown scope | 400 |

## Looking Glass Events

The following events are emitted for real-time visualization:

| Event | Description |
|-------|-------------|
| `Authorization Request Received` | Initial auth request with parameters |
| `User Authentication Required` | Login form displayed |
| `User Credentials Submitted` | Login attempt (no password logged) |
| `User Authenticated Successfully` | Successful login |
| `Authorization Code Issued` | Code generated with PKCE binding |
| `Token Request Received` | Token endpoint called |
| `Token Exchange Request` | Code being exchanged |
| `PKCE Verification Successful` | Code verifier validated |
| `Client Authenticated` | Confidential client validated |
| `Access Token Issued` | Tokens generated |
| `Tokens Refreshed` | New tokens via refresh grant |
| `Token Introspection Result` | Introspection response |
| `Token Revoked` | Token invalidated |

## Looking Glass Flows

### Executable Flows

| Flow ID | Name | Description |
|---------|------|-------------|
| `authorization_code` | Authorization Code Flow | Standard web app flow with PKCE |
| `client_credentials` | Client Credentials | Machine-to-machine authentication; client auth (`client_secret_basic`/`private_key_jwt`) and access-token protection (Bearer/RFC 9449 DPoP) are independent selectors |
| `implicit` | Implicit Flow | Legacy browser flow (deprecated) |
| `refresh_token` | Refresh Token | Token renewal |
| `token_introspection` | Token Introspection | Validate active tokens |
| `token_revocation` | Token Revocation | Invalidate tokens |

### Reference-Only Flows

| Flow ID | Name | Why Not Executable |
|---------|------|-------------------|
| `device_code` | Device Authorization | Requires polling/user code display |
| `resource_owner` | Resource Owner Password | Exposes credentials (anti-pattern) |

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SHOWCASE_BASE_URL` | Public base URL | `http://localhost:8080` |
| `SHOWCASE_CORS_ORIGINS` | CORS allowed origins | `http://localhost:3000,http://localhost:5173` |
| `OAUTH2_REPLAY_REDIS_URL` | Shared replay Redis URL for `private_key_jwt` assertion replay; required in demo and reachable `rediss://` is required in production. Also backs this plugin's RFC 9449 DPoP proof `jti` replay store (separate key prefix/instance) | in-memory in development/tests |
| `SHOWCASE_DPOP_NONCE_REQUIRED` | Enables the RFC 9449 §8 nonce challenge at `/oauth2/token` | `false` |
| `MOCKIDP_DEMO_CLIENT_SECRET` | demo-app client secret | (auto-generated) |
| `MOCKIDP_MACHINE_CLIENT_SECRET` | machine-client secret | (auto-generated) |

### Registered Clients

| client_id | Type | Grant Types | Secret |
|-----------|------|-------------|--------|
| `public-app` | Public | authorization_code, refresh_token | - |
| `demo-app` | Confidential | authorization_code, refresh_token | (env or auto) |
| `machine-client` | Confidential | client_credentials | (env or auto) |

## Development

### Running Locally

```bash
# Start with Docker Compose
cd docker
docker compose up -d

# Authorization Code Flow (opens browser)
open "http://localhost:8080/oauth2/authorize?response_type=code&client_id=public-app&redirect_uri=http://localhost:3000/callback&scope=read%20write&state=xyz"

# Exchange code for tokens
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=http://localhost:3000/callback&client_id=public-app&code_verifier=VERIFIER"

# Client Credentials (get demo secret first)
SECRET=$(curl -s http://localhost:8080/oauth2/demo/clients | jq -r '.clients[] | select(.id=="machine-client") | .secret')
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=machine-client&client_secret=$SECRET&scope=read"

# Introspect token
curl -X POST http://localhost:8080/oauth2/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=ACCESS_TOKEN&client_id=demo-app&client_secret=$SECRET"

# Revoke token
curl -X POST http://localhost:8080/oauth2/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=REFRESH_TOKEN&client_id=public-app"
```

## RFC Compliance

| RFC | Title | Status |
|-----|-------|--------|
| RFC 6749 | OAuth 2.0 Authorization Framework | ✅ Compliant |
| RFC 7636 | PKCE | ✅ Compliant |
| RFC 7662 | Token Introspection | ✅ Compliant |
| RFC 7009 | Token Revocation | ✅ Compliant |
| RFC 7523 §2.2 | JWT client authentication | ✅ Implemented profile |
| RFC 8414 | Authorization Server Metadata | ✅ Implemented |
| RFC 9449 | DPoP | ✅ Implemented (opt-in per request) |

### Implemented Features

- ✅ Authorization Code Grant
- ✅ Client Credentials Grant
- ✅ Implicit Grant (legacy)
- ✅ Refresh Token Grant
- ✅ PKCE (S256, plain)
- ✅ Token Introspection
- ✅ Token Revocation
- ✅ State parameter CSRF protection
- ✅ Client authentication (Basic, POST, private_key_jwt for client_credentials)
- ✅ Sender-constrained access tokens (RFC 9449 DPoP), opt-in via a `DPoP` proof header at the token endpoint
- ✅ `private_key_jwt` client authentication (RFC 7523 §2.2 / OIDC Core §9)
- ✅ Client assertion replay protection (`jti`)
- ✅ Refresh token rotation

### Not Implemented

- ❌ Resource Owner Password Credentials (deprecated)
- ❌ Device Authorization Grant (RFC 8628)
- ❌ JWT Bearer Grant / assertion as authorization grant (RFC 7523 §2.1)
- ❌ SAML 2.0 Bearer Grant (RFC 7522)

## License

Part of the ProtocolSoup project.
