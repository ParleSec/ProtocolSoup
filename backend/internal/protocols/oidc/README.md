# OpenID Connect Protocol Implementation

A standards-compliant implementation of [OpenID Connect 1.0](https://openid.net/connect/) identity layer built on top of OAuth 2.0. This implementation provides real authentication flows against a Mock Identity Provider with full PKCE support, ID Token issuance, and UserInfo endpoint.

## Overview

This implementation provides:

- **Real OIDC Flows**: Authorization Code, Implicit, and Hybrid flows with actual token issuance
- **ID Token Issuance**: JWT ID Tokens with standard claims (sub, iss, aud, exp, iat, nonce, auth_time)
- **UserInfo Endpoint**: Claims retrieval based on requested scopes
- **Discovery Document**: OpenID Provider metadata at `.well-known/openid-configuration`
- **JWKS Endpoint**: Public keys for ID Token signature verification
- **PKCE Support**: Proof Key for Code Exchange (RFC 7636) for public clients
- **Nonce Validation**: Replay attack prevention with nonce binding
- **Looking Glass Integration**: Real-time flow visualization for educational purposes

## Service Deployment

The OIDC implementation is part of the **Federation Service** in the split backend architecture:

- **Behind the gateway** (recommended): `/oidc/*` is proxied through the gateway
- **Standalone**: Run the federation service directly and access `/oidc/*`

The OIDC plugin extends the OAuth 2.0 plugin, sharing the Mock IdP and key management infrastructure.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    OpenID Connect Implementation                            │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Relying Party (Client Application)                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                                                                     │    │
│  │  1. Discovery Fetch    2. Auth Request    6. Token Exchange         │    │
│  │  ─────────────────>    ─────────────────> ─────────────────>        │    │
│  │                                                                     │    │
│  │  7. ID Token Validation  8. UserInfo Request                        │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                │                                            │
│                                │ HTTPS                                      │
│                                ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     OIDC Plugin (plugin.go)                         │    │
│  │                                                                     │    │
│  │  ┌───────────────────┐  ┌───────────────────┐  ┌─────────────────┐  │    │
│  │  │  Discovery        │  │  Authorization    │  │  Token Endpoint │  │    │
│  │  │  (discovery.go)   │  │  (userinfo.go)    │  │  (userinfo.go)  │  │    │
│  │  │                   │  │                   │  │                 │  │    │
│  │  │ • /openid-config  │  │ • /authorize      │  │ • /token        │  │    │
│  │  │ • /jwks.json      │  │ • nonce binding   │  │ • ID Token gen  │  │    │
│  │  │ • Metadata        │  │ • scope: openid   │  │ • at_hash/c_hash│  │    │
│  │  └───────────────────┘  └───────────────────┘  └─────────────────┘  │    │
│  │                                                                     │    │
│  │  ┌───────────────────┐  ┌───────────────────┐  ┌─────────────────┐  │    │
│  │  │  UserInfo         │  │  Claims           │  │  Login Request  │  │    │
│  │  │  (claims.go)      │  │  (claims.go)      │  │  Storage        │  │    │
│  │  │                   │  │                   │  │                 │  │    │
│  │  │ • /userinfo       │  │ • Standard claims │  │ • CSRF protect  │  │    │
│  │  │ • Scope filtering │  │ • Scope mapping   │  │ • TTL cleanup   │  │    │
│  │  │ • Bearer token    │  │ • Profile/Email   │  │ • Session bind  │  │    │
│  │  └───────────────────┘  └───────────────────┘  └─────────────────┘  │    │
│  │                                                                     │    │
│  │  ┌───────────────────────────────────────────────────────────────┐  │    │
│  │  │                    OAuth 2.0 Plugin (shared)                  │  │    │
│  │  │                                                               │  │    │
│  │  │  /oauth2/authorize  /oauth2/token  /oauth2/introspect         │  │    │
│  │  │  /oauth2/revoke     /oauth2/demo/*                            │  │    │
│  │  └───────────────────────────────────────────────────────────────┘  │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                │                                            │
│                                ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         Mock Identity Provider                      │    │
│  │                                                                     │    │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │    │
│  │  │   Users Store   │  │  Clients Store  │  │  KeySet (RSA/EC)    │  │    │
│  │  │                 │  │                 │  │                     │  │    │
│  │  │ • alice@...     │  │ • public-app    │  │ • RS256 signing     │  │    │
│  │  │ • bob@...       │  │ • demo-app      │  │ • ES256 signing     │  │    │
│  │  │ • admin@...     │  │ • machine-client│  │ • JWKS generation   │  │    │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────────┘  │    │
│  │                                                                     │    │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │    │
│  │  │ Auth Codes      │  │ Refresh Tokens  │  │  Revoked Tokens     │  │    │
│  │  │ (10 min TTL)    │  │ (7 day TTL)     │  │  (blacklist)        │  │    │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────────┘  │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## File Structure

| File | Purpose |
|------|---------|
| `plugin.go` | Main plugin implementing `ProtocolPlugin` interface, route registration, flow definitions |
| `userinfo.go` | Authorization and token endpoints, login request handling, ID Token issuance |
| `claims.go` | UserInfo endpoint, standard OIDC claims definitions, scope-to-claims mapping |
| `discovery.go` | OpenID Provider discovery document and JWKS endpoint |

### OAuth 2.0 Plugin (Shared)

| File | Purpose |
|------|---------|
| `oauth2/plugin.go` | OAuth 2.0 plugin with authorization code, PKCE, client credentials flows |
| `oauth2/handlers.go` | Token endpoint, introspection (RFC 7662), revocation (RFC 7009), login handling |

## API Endpoints

### Discovery Endpoints (Public)

| Method | Endpoint | Description | Spec Reference |
|--------|----------|-------------|----------------|
| GET | `/oidc/.well-known/openid-configuration` | OpenID Provider metadata | OIDC Discovery §4 |
| GET | `/oidc/.well-known/jwks.json` | JSON Web Key Set | OIDC Core §10.1 |
| GET | `/oidc/jwks` | JWKS (alternate path) | OIDC Core §10.1 |

### Authentication Endpoints

| Method | Endpoint | Description | Spec Reference |
|--------|----------|-------------|----------------|
| GET | `/oidc/authorize` | Authorization endpoint (displays login) | OIDC Core §3.1.2 |
| POST | `/oidc/authorize` | Authorization form submission | OIDC Core §3.1.2 |
| POST | `/oidc/token` | Token endpoint (code exchange) | OIDC Core §3.1.3 |
| GET | `/oidc/userinfo` | UserInfo endpoint (Bearer token) | OIDC Core §5.3 |
| POST | `/oidc/userinfo` | UserInfo endpoint (POST variant) | OIDC Core §5.3 |

### OAuth 2.0 Endpoints

| Method | Endpoint | Description | RFC Reference |
|--------|----------|-------------|---------------|
| GET | `/oauth2/authorize` | OAuth 2.0 authorization | RFC 6749 §3.1 |
| POST | `/oauth2/authorize` | OAuth 2.0 form submission | RFC 6749 §3.1 |
| POST | `/oauth2/token` | OAuth 2.0 token endpoint | RFC 6749 §3.2 |
| POST | `/oauth2/introspect` | Token introspection | RFC 7662 §2 |
| POST | `/oauth2/revoke` | Token revocation | RFC 7009 §2 |

### Demo Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/oauth2/demo/users` | List demo users with credentials |
| GET | `/oauth2/demo/clients` | List registered clients |
| GET | `/saml/demo/users` | List SAML demo users |

## Supported Flows

### Authorization Code Flow (OIDC Core §3.1)

The most secure flow for server-side applications:

```
┌──────┐     ┌──────────┐     ┌──────────────────┐
│Client│     │  User    │     │  OpenID Provider │
└──┬───┘     └────┬─────┘     └────────┬─────────┘
   │              │                    │
   │──1. Auth Request (scope=openid)──>│
   │              │                    │
   │              │<──2. Login Form────│
   │              │                    │
   │              │──3. Credentials───>│
   │              │                    │
   │<──4. Authorization Code + state───│
   │              │                    │
   │──5. Token Exchange (code+verifier)────────────>│
   │              │                    │
   │<──6. ID Token + Access Token + Refresh Token──│
   │              │                    │
   │──7. UserInfo Request (Bearer)────────────────>│
   │              │                    │
   │<──8. User Claims─────────────────────────────│
```

### Implicit Flow (OIDC Core §3.2)

For browser-based applications (legacy, not recommended):

| response_type | Returns |
|---------------|---------|
| `id_token` | ID Token only (fragment) |
| `id_token token` | ID Token + Access Token (fragment) |
| `token` | Access Token only (OAuth 2.0 implicit) |

### Hybrid Flow (OIDC Core §3.3)

Combines Authorization Code and Implicit for advanced scenarios:

| response_type | Query Params | Fragment Params |
|---------------|--------------|-----------------|
| `code id_token` | code | id_token |
| `code token` | code | access_token |
| `code id_token token` | code | id_token, access_token |

## ID Token Structure

The ID Token is a JWT containing identity claims per OIDC Core §2:

```json
{
  "iss": "https://protocolsoup.com",
  "sub": "alice@example.com",
  "aud": "public-app",
  "exp": 1704825600,
  "iat": 1704822000,
  "auth_time": 1704822000,
  "nonce": "n-0S6_WzA2Mj",
  "at_hash": "77QmUPtjPfzWtF2AnpK9RQ",
  "c_hash": "LDktKdoQak3Pk0cnXxCltA",
  "name": "Alice Johnson",
  "email": "alice@example.com",
  "email_verified": true
}
```

### Required Claims

| Claim | Description | Reference |
|-------|-------------|-----------|
| `iss` | Issuer identifier (OP URL) | OIDC Core §2 |
| `sub` | Subject identifier (user) | OIDC Core §2 |
| `aud` | Audience (client_id) | OIDC Core §2 |
| `exp` | Expiration time | OIDC Core §2 |
| `iat` | Issued at time | OIDC Core §2 |

### Conditional Claims

| Claim | Condition | Reference |
|-------|-----------|-----------|
| `nonce` | If nonce in request | OIDC Core §3.1.2.1 |
| `auth_time` | If max_age or auth_time requested | OIDC Core §2 |
| `at_hash` | If access_token returned (Hybrid) | OIDC Core §3.3.2.11 |
| `c_hash` | If code returned (Hybrid) | OIDC Core §3.3.2.11 |

## Scopes and Claims

### Standard Scopes

| Scope | Claims Returned |
|-------|-----------------|
| `openid` | `sub` (REQUIRED for OIDC) |
| `profile` | `name`, `family_name`, `given_name`, `preferred_username`, `picture` |
| `email` | `email`, `email_verified` |
| `address` | `address` (structured) |
| `phone` | `phone_number`, `phone_number_verified` |

### Example UserInfo Response

```json
{
  "sub": "alice@example.com",
  "name": "Alice Johnson",
  "given_name": "Alice",
  "family_name": "Johnson",
  "preferred_username": "alice",
  "email": "alice@example.com",
  "email_verified": true
}
```

## PKCE Support (RFC 7636)

PKCE prevents authorization code interception attacks for public clients:

### Supported Methods

| Method | Description | Security |
|--------|-------------|----------|
| `S256` | SHA-256 hash of verifier | **Recommended** |
| `plain` | Verifier sent as-is | Fallback only |

### Flow with PKCE

```
1. Client generates code_verifier (43-128 chars, [A-Za-z0-9-._~])
2. Client computes code_challenge = BASE64URL(SHA256(code_verifier))
3. Authorization request includes code_challenge + code_challenge_method
4. Token request includes original code_verifier
5. Server verifies: BASE64URL(SHA256(code_verifier)) == code_challenge
```

### PKCE Parameters

| Parameter | Request | Required |
|-----------|---------|----------|
| `code_challenge` | Authorization | Yes (public clients) |
| `code_challenge_method` | Authorization | Yes (S256 or plain) |
| `code_verifier` | Token | Yes (if challenge sent) |

## Login Request Security

Authentication requests are protected against parameter tampering:

1. **Server-Side Storage**: Sensitive parameters (redirect_uri, state, nonce, PKCE) stored server-side
2. **Opaque Reference**: Login form only contains `login_request_id`
3. **TTL Cleanup**: Expired requests automatically purged (10 minute TTL)
4. **Single Use**: Request consumed after successful authentication

This prevents:
- Redirect URI manipulation
- State/nonce injection
- PKCE challenge substitution

## Token Response

### Authorization Code Grant

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "openid profile email"
}
```

### Token Introspection Response

```json
{
  "active": true,
  "scope": "openid profile email",
  "client_id": "public-app",
  "username": "alice@example.com",
  "token_type": "Bearer",
  "exp": 1704825600,
  "iat": 1704822000,
  "sub": "alice@example.com",
  "aud": "public-app",
  "iss": "https://protocolsoup.com"
}
```

## Looking Glass Flows

### Executable Flows

| Flow ID | Name | Description |
|---------|------|-------------|
| `oidc_authorization_code` | OIDC Authorization Code | Full OIDC flow with ID Token, PKCE, nonce |
| `oidc_implicit` | OIDC Implicit Flow | ID Token returned in fragment (legacy) |
| `oidc_hybrid` | OIDC Hybrid Flow | Code in query + tokens in fragment |
| `oidc_discovery` | OIDC Discovery | Fetch and inspect provider metadata |
| `authorization_code` | OAuth 2.0 Auth Code | Standard OAuth 2.0 with PKCE |
| `implicit` | OAuth 2.0 Implicit | Access token in fragment (legacy) |
| `client_credentials` | Client Credentials | Machine-to-machine authentication |
| `refresh_token` | Token Refresh | Obtain new tokens using refresh token |
| `token_introspection` | Token Introspection | Validate and inspect active tokens |
| `token_revocation` | Token Revocation | Invalidate tokens |

### Reference-Only Flows

| Flow ID | Name | Why Not Executable |
|---------|------|-------------------|
| `device_code` | Device Authorization | Requires polling and user code display |
| `resource_owner` | Resource Owner Password | Exposes credentials (not recommended) |

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SHOWCASE_BASE_URL` | Public base URL for issuer | `http://localhost:8080` |
| `SHOWCASE_CORS_ORIGINS` | Allowed CORS origins | `http://localhost:3000,http://localhost:5173` |
| `MOCKIDP_ALICE_PASSWORD` | Alice user password | (auto-generated) |
| `MOCKIDP_BOB_PASSWORD` | Bob user password | (auto-generated) |
| `MOCKIDP_ADMIN_PASSWORD` | Admin user password | (auto-generated) |
| `MOCKIDP_DEMO_CLIENT_SECRET` | demo-app client secret | (auto-generated) |
| `MOCKIDP_MACHINE_CLIENT_SECRET` | machine-client secret | (auto-generated) |

### Registered Clients

| client_id | Type | Grant Types |
|-----------|------|-------------|
| `public-app` | Public | authorization_code, refresh_token |
| `demo-app` | Confidential | authorization_code, refresh_token |
| `machine-client` | Confidential | client_credentials |

## Discovery Document

The OpenID Provider Configuration is available at `/.well-known/openid-configuration`:

```json
{
  "issuer": "https://protocolsoup.com",
  "authorization_endpoint": "https://protocolsoup.com/oidc/authorize",
  "token_endpoint": "https://protocolsoup.com/oidc/token",
  "userinfo_endpoint": "https://protocolsoup.com/oidc/userinfo",
  "jwks_uri": "https://protocolsoup.com/oidc/.well-known/jwks.json",
  "scopes_supported": ["openid", "profile", "email", "address", "phone"],
  "response_types_supported": ["code", "id_token", "token", "code id_token", "code token", "id_token token", "code id_token token"],
  "grant_types_supported": ["authorization_code", "implicit", "refresh_token", "client_credentials"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256", "ES256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "code_challenge_methods_supported": ["S256", "plain"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "email", "email_verified"]
}
```

## Error Responses

### OAuth 2.0 Errors (RFC 6749 §5.2)

```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code has expired",
  "error_uri": "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2"
}
```

### Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| `invalid_request` | Missing/invalid parameter | 400 |
| `invalid_client` | Client authentication failed | 401 |
| `invalid_grant` | Invalid authorization code/refresh token | 400 |
| `unauthorized_client` | Client not authorized for grant type | 400 |
| `unsupported_grant_type` | Grant type not supported | 400 |
| `invalid_scope` | Invalid scope requested | 400 |
| `invalid_token` | Token validation failed (UserInfo) | 401 |

## Development

### Running Locally

```bash
# Start with Docker Compose
cd docker
docker compose up -d

# Test discovery document
curl http://localhost:8080/oidc/.well-known/openid-configuration | jq

# Test authorization flow (opens browser)
open "http://localhost:8080/oidc/authorize?response_type=code&client_id=public-app&redirect_uri=http://localhost:3000/callback&scope=openid%20profile%20email&state=xyz&nonce=abc123"

# Exchange code for tokens
curl -X POST http://localhost:8080/oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=http://localhost:3000/callback&client_id=public-app&code_verifier=VERIFIER"

# Fetch UserInfo
curl http://localhost:8080/oidc/userinfo \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

### Token Validation

```bash
# Introspect a token
curl -X POST http://localhost:8080/oauth2/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=ACCESS_TOKEN&client_id=demo-app&client_secret=SECRET"

# Revoke a token
curl -X POST http://localhost:8080/oauth2/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=REFRESH_TOKEN&client_id=public-app"
```

## Specifications Compliance

| Specification | Status |
|---------------|--------|
| OpenID Connect Core 1.0 | ✅ Compliant |
| OpenID Connect Discovery 1.0 | ✅ Compliant |
| OAuth 2.0 (RFC 6749) | ✅ Compliant |
| PKCE (RFC 7636) | ✅ Compliant |
| Token Introspection (RFC 7662) | ✅ Compliant |
| Token Revocation (RFC 7009) | ✅ Compliant |
| JWT (RFC 7519) | ✅ Compliant |
| JWK (RFC 7517) | ✅ Compliant |

### Implemented Features

- ✅ Authorization Code Flow with PKCE
- ✅ Implicit Flow (id_token, token, id_token token)
- ✅ Hybrid Flow (code id_token, code token, code id_token token)
- ✅ Client Credentials Grant
- ✅ Refresh Token Grant
- ✅ Token Introspection
- ✅ Token Revocation
- ✅ Discovery Document
- ✅ JWKS Endpoint
- ✅ UserInfo Endpoint
- ✅ ID Token with standard claims
- ✅ at_hash and c_hash for Hybrid flows
- ✅ Nonce validation
- ✅ State parameter CSRF protection

### Not Implemented

- ❌ Dynamic Client Registration (RFC 7591)
- ❌ Session Management (OIDC Session Management)
- ❌ Front-Channel/Back-Channel Logout
- ❌ Pushed Authorization Requests (PAR)
- ❌ JWT-Secured Authorization Request (JAR)

## License

Part of the ProtocolSoup project.
