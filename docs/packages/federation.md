# protocolsoup-federation

**OAuth 2.0, OpenID Connect, and SAML 2.0 Identity Provider**

Complete federation server with built-in Mock IdP. Use for local development, testing, or learning authentication protocols.

## Quick Start

```bash
docker run -p 8080:8080 \
  -e SHOWCASE_BASE_URL=http://localhost:8080 \
  ghcr.io/parlesec/protocolsoup-federation
```

**Runs standalone** - no external dependencies.

## Endpoints

### OAuth 2.0
| Endpoint | Description |
|----------|-------------|
| `GET /oauth2/authorize` | Authorization endpoint |
| `POST /oauth2/authorize` | Authorization form submit |
| `POST /oauth2/token` | Token endpoint |
| `POST /oauth2/introspect` | Token introspection (RFC 7662) |
| `POST /oauth2/revoke` | Token revocation (RFC 7009) |

### OpenID Connect
| Endpoint | Description |
|----------|-------------|
| `GET /oidc/.well-known/openid-configuration` | Discovery document |
| `GET /oidc/.well-known/jwks.json` | JSON Web Key Set |
| `GET /oidc/authorize` | Authorization endpoint |
| `POST /oidc/token` | Token endpoint |
| `GET /oidc/userinfo` | UserInfo endpoint |

### SAML 2.0
| Endpoint | Description |
|----------|-------------|
| `GET /saml/metadata` | IdP Metadata (XML) |
| `GET /saml/sso` | SSO Service (Redirect binding) |
| `POST /saml/sso` | SSO Service (POST binding) |
| `POST /saml/acs` | Assertion Consumer Service |
| `GET /saml/slo` | Single Logout (Redirect) |
| `POST /saml/slo` | Single Logout (POST) |

### Demo
| Endpoint | Description |
|----------|-------------|
| `GET /oauth2/demo/users` | Demo user credentials |
| `GET /oauth2/demo/clients` | Demo client credentials |
| `GET /saml/demo/users` | SAML demo users |

## Demo Users

| Username | Description |
|----------|-------------|
| `alice@example.com` | Standard user |
| `bob@example.com` | Standard user |
| `admin@example.com` | Admin user |

Passwords are randomized at startup. Retrieve via `GET /oauth2/demo/users`.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SHOWCASE_BASE_URL` | `http://localhost:8080` | Issuer URL in tokens |
| `SHOWCASE_LISTEN_ADDR` | `:8080` | Listen address |
| `SHOWCASE_MOCK_IDP` | `true` | Enable Mock IdP |
| `MOCKIDP_ALICE_PASSWORD` | (random) | Alice's password |
| `MOCKIDP_BOB_PASSWORD` | (random) | Bob's password |
| `MOCKIDP_ADMIN_PASSWORD` | (random) | Admin's password |
| `MOCKIDP_DEMO_CLIENT_SECRET` | (random) | demo-app client secret |
| `MOCKIDP_MACHINE_CLIENT_SECRET` | (random) | machine-client secret |

## Supported OAuth 2.0 Flows

- Authorization Code (with PKCE)
- Client Credentials
- Implicit (legacy)
- Refresh Token

## Example: Get an Access Token

```bash
# Client Credentials flow
curl -X POST http://localhost:8080/oauth2/token \
  -d "grant_type=client_credentials" \
  -d "client_id=machine-client" \
  -d "client_secret=<from /oauth2/demo/clients>" \
  -d "scope=read write"
```
