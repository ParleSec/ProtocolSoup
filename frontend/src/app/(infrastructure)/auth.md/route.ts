import { AGENT_PATHS, API_REFERENCE_URL, protocolDocsUrl, siteUrl } from '@/lib/agent-discovery'
import { SITE_ORIGIN } from '@/lib/seo'

/**
 * Auth.md (https://github.com/workos/auth.md): a human- and agent-readable
 * description of how to authenticate against this deployment.
 *
 * Every endpoint named here is served by the agentic registration plugin in
 * `backend/internal/protocols/agentauth`. The machine-readable form of the same
 * information is the `agent_auth` block in the authorization server metadata.
 */

const AGENT_AUTH_ISSUER = `${SITE_ORIGIN}/agentauth`

export async function GET() {
  const body = `# auth.md

How autonomous agents register with and authenticate to Protocol Soup
(${SITE_ORIGIN}).

Machine-readable companions to this document:

- Authorization Server metadata, with the \`agent_auth\` block (RFC 8414): \`${AGENT_PATHS.authorizationServer}\`
- Agentic registration server metadata: \`${AGENT_PATHS.agentAuthServer}\`
- Protected Resource Metadata (RFC 9728): \`${AGENT_PATHS.protectedResource}\`
- OpenID Provider metadata: \`/.well-known/openid-configuration\`
- API catalog (RFC 9727): \`${AGENT_PATHS.apiCatalog}\`

## Audience

This document is for autonomous agents and API clients. Protocol Soup is an
educational sandbox for authentication and identity protocols: agents read the
protocol catalog, start real protocol flows, and decode the resulting tokens.

## Registration

Agents register themselves. There is no console, no waitlist, and no API key to
request.

Registration is anonymous. Post to the identity endpoint and you receive a
signed identity assertion describing an agent that exists but has no owner:

    curl -X POST ${AGENT_AUTH_ISSUER}/identity \\
      -H 'Content-Type: application/json' \\
      -d '{"type":"anonymous"}'

The response carries an \`identity_assertion\`, an \`agent_id\`, and a
\`claim_token\`. Keep the claim token: it is the only handle that lets a person
later take ownership of the agent, and it cannot be recovered from the
assertion.

**Identity types supported:** \`anonymous\` only. An ID-JAG
(\`urn:ietf:params:oauth:token-type:id-jag\`) minted by an external agent
provider is *not* accepted, because verifying one needs that provider's key set
and this deployment federates with none. Posting any type other than
\`anonymous\` returns \`unsupported_identity_type\`.

## Exchanging the assertion for an access token

The assertion is an authorization grant in the sense of RFC 7523 Section 2.1.
Present it at the agentic registration server's token endpoint:

    curl -X POST ${AGENT_AUTH_ISSUER}/token \\
      -d 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' \\
      --data-urlencode 'assertion=<identity_assertion>'

Before issuing anything the server checks the signature, that \`iss\` and
\`aud\` both name \`${AGENT_AUTH_ISSUER}\`, that \`exp\` has not passed and
\`nbf\` has, that the subject is still a registered agent, and that the
assertion's \`jti\` has not been seen before. **Assertions are single use.**
Every failure returns \`invalid_grant\` without saying which check failed.

An unclaimed agent receives the scope \`agent:read\`. Access tokens live one
hour.

## Claiming an agent

An agent bound to a person gets \`agent:read agent:write\`. Binding runs the
two-channel ceremony of RFC 8628, so the agent cannot approve itself.

1. The agent starts a claim with its \`claim_token\` and the person's email:

        curl -X POST ${AGENT_AUTH_ISSUER}/identity/claim \\
          -H 'Content-Type: application/json' \\
          -d '{"claim_token":"<claim_token>","email":"you@example.com"}'

   The response holds a \`user_code\`, a \`verification_uri\`, an
   \`expires_in\` of 600 seconds, and an \`interval\` of 5 seconds.

2. The agent shows the person the code and the URI. It must not open the URI
   itself.

3. The person visits \`${AGENT_AUTH_ISSUER}/claim\`, enters the code, and
   approves.

4. Meanwhile the agent polls the token endpoint:

        curl -X POST ${AGENT_AUTH_ISSUER}/token \\
          -d 'grant_type=urn:workos:agent-auth:grant-type:claim' \\
          -d 'claim_token=<claim_token>'

   Until approval lands this returns \`authorization_pending\`. Polling faster
   than the interval returns \`slow_down\`. A lapsed code returns
   \`expired_token\`, and a fresh one can be requested from step 1. On success
   the agent receives an access token scoped \`agent:read agent:write\` and a
   replacement identity assertion carrying \`claimed: true\`.

## Revocation

    curl -X POST ${AGENT_AUTH_ISSUER}/revoke -d 'token=<claim_token>'

Following RFC 7009 Section 2.2 this answers \`200\` whether or not the token
was recognised. Revocation stops further assertions being redeemed; access
tokens already issued stay valid until they expire, which is why their lifetime
is short. The corresponding event identifier is
\`https://schemas.workos.com/events/agent/auth/identity/assertion/revoked\`.

## Most of this site needs no credentials at all

The read APIs are open. Registration is only needed for the agent-scoped
surface described above:

| Endpoint | Purpose |
| --- | --- |
| \`GET /api\` | Service index and endpoint map |
| \`GET /api/protocols\` | Protocol catalog |
| \`GET /api/protocols/{id}\` | A single protocol |
| \`GET /api/protocols/{id}/flows\` | Flows available for a protocol |
| \`POST /api/protocols/{id}/demo/{flow}\` | Start a real protocol flow |
| \`POST /api/lookingglass/decode\` | Decode a JWT and explain its claims |
| \`POST /api/lookingglass/decode/credential\` | Decode a verifiable credential |
| \`GET /health\` | Runtime health |

These endpoints are rate limited to 100 requests per minute per client IP.
Exceeding the limit returns \`429 Too Many Requests\`.

Full request and response schemas are published in the OpenAPI contracts linked
from the [API catalog](${siteUrl(AGENT_PATHS.apiCatalog)}) and rendered at
[the API reference](${API_REFERENCE_URL}).

## The OAuth-protected resource

\`GET /oidc/userinfo\` is the only endpoint guarded by the OpenID Provider
(OpenID Connect Core 1.0 Section 5.3). It requires a bearer access token
(RFC 6750) issued by that provider, not by the agentic registration server, and
describes itself at:

    ${siteUrl(`${AGENT_PATHS.protectedResource}/oidc/userinfo`)}

A request without a usable token is rejected with \`401\` and a challenge
pointing back at that document, as RFC 9728 Section 5.1 recommends:

    WWW-Authenticate: Bearer error="invalid_token",
      error_description="No access token presented (RFC 6750 Section 2)",
      resource_metadata="${siteUrl(`${AGENT_PATHS.protectedResource}/oidc/userinfo`)}"

Tokens are accepted in the \`Authorization\` header (RFC 6750 Section 2.1) or as
an \`access_token\` parameter in a form-encoded body (Section 2.2). The URI query
parameter form of Section 2.3 is not accepted.

## Authorization servers

| Issuer | Metadata | Role |
| --- | --- | --- |
| \`${SITE_ORIGIN}\` | \`${AGENT_PATHS.authorizationServer}\` | OpenID Provider; also published as \`/.well-known/openid-configuration\` |
| \`${SITE_ORIGIN}/oauth2\` | \`/.well-known/oauth-authorization-server/oauth2\` | OAuth 2.0 authorization server |
| \`${AGENT_AUTH_ISSUER}\` | \`${AGENT_PATHS.agentAuthServer}\` | Agentic registration; issues agent access tokens |

## Human client credentials

**There is no dynamic client registration.** Neither the OpenID Provider nor
the OAuth 2.0 authorization server implements RFC 7591. Agent registration
described above is a different mechanism and does not produce an OAuth client.

For the human-facing OAuth and OIDC flows this sandbox ships pre-registered
demo clients and demo users, both readable without credentials:

- \`GET /oauth2/demo/clients\` — client IDs, secrets, redirect URIs, and the
  authentication method each client is registered for.
- \`GET /oauth2/demo/users\` — the resource owners you can authenticate as.

Because those credentials are published, treat every token minted here as
public.

Client authentication at the OAuth 2.0 token endpoint supports
\`client_secret_basic\`, \`client_secret_post\`, and \`private_key_jwt\`
(RS256, ES256, EdDSA). Grant types are \`authorization_code\`,
\`refresh_token\`, and \`client_credentials\`. PKCE is supported with \`S256\`
and required for public clients.

The token endpoint also accepts an optional \`DPoP\` proof header (RFC 9449).
When present and valid, the issued access token is bound to the proof's key
via a \`cnf.jkt\` claim and \`token_type\` becomes \`DPoP\` instead of
\`Bearer\`; a public client's refresh token issued alongside it is bound the
same way. Absent that header, every flow behaves exactly as if DPoP did not
exist. The OID4VCI token endpoint (\`/oid4vci/token\`) accepts the same
header and binds its own issued access token identically, though it never
issues a refresh token.

## Sandbox notice

Every token, credential, and user record here is issued by a mock identity
provider for teaching purposes. Nothing on this origin guards real data, and no
credential issued here is valid anywhere else.

One deviation is worth stating plainly: the claim verification page does **not**
authenticate the person approving an agent. A production deployment MUST sign
the person in first and bind the agent to that account rather than to an email
the agent supplied. Treat every \`user_code\` issued here as public.

Protocol behaviour is otherwise real. Assertions are genuinely signed and
genuinely verified, replay is genuinely refused, and the polling errors are the
ones the specifications define, so an agent can exercise a real client
implementation against this deployment end to end.

Protocol-by-protocol documentation: ${protocolDocsUrl('oauth2')}
`

  return new Response(body, {
    headers: {
      'Content-Type': 'text/markdown; charset=utf-8',
      'Cache-Control': 'public, max-age=3600, s-maxage=3600',
    },
  })
}
