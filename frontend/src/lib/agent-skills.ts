import { AGENT_PATHS, API_REFERENCE_URL, siteUrl } from '@/lib/agent-discovery'
import { SITE_ORIGIN, WALLET_ORIGIN } from '@/lib/seo'

/**
 * Skills published under the Agent Skills Discovery RFC v0.2.0
 * (https://github.com/cloudflare/agent-skills-discovery-rfc).
 *
 * Each skill drives endpoints this deployment actually serves. The index and
 * the artifact route both render through `renderSkill`, so the sha256 digest
 * published in the index is always the digest of the bytes an agent receives.
 */

export interface AgentSkill {
  name: string
  description: string
  body: string
}

const LOOKING_GLASS_TOKEN_HEADER = 'X-Looking-Glass-Session-Token'

const SKILLS: AgentSkill[] = [
  {
    name: 'browse-protocol-catalog',
    description:
      'Discover which authentication and identity protocols Protocol Soup implements and which flows each one can execute.',
    body: `# Browse the Protocol Soup Protocol Catalog

Use this skill to find out which protocols and flows are available before
starting any work against ${SITE_ORIGIN}.

## List every protocol

    GET ${SITE_ORIGIN}/api/protocols

Returns:

    {
      "protocols": [
        {
          "id": "oauth2",
          "name": "OAuth 2.0",
          "version": "1.0.0",
          "description": "...",
          "tags": ["authorization", "tokens"]
        }
      ]
    }

The \`id\` is the value every other endpoint expects, and it is also the path
prefix the protocol is mounted on (\`/oauth2\`, \`/oidc\`, \`/scim\`, and so on).

## Inspect one protocol

    GET ${SITE_ORIGIN}/api/protocols/{id}

Responds \`404\` with \`{"error": "Protocol not found"}\` for an unknown id.

## List the flows a protocol can run

    GET ${SITE_ORIGIN}/api/protocols/{id}/flows

Returns \`{"flows": [...]}\`. Each flow definition carries an \`id\`, \`name\`,
\`description\`, \`category\`, an \`executable\` boolean, and an ordered \`steps\`
array. Every step names the sending and receiving party, the parameters that
travel with it, and the security properties that step provides, with the
governing specification section quoted.

Only flows with \`"executable": true\` can be started with the
\`run-protocol-flow\` skill.

## Notes

- No credentials are required. Requests are rate limited to 100 per minute per
  client IP; over the limit the API returns \`429\`.
- Machine-readable contracts for these endpoints are linked from
  ${siteUrl(AGENT_PATHS.apiCatalog)} and rendered at ${API_REFERENCE_URL}.
`,
  },
  {
    name: 'run-protocol-flow',
    description:
      'Start a real OAuth 2.0, OIDC, SAML, SCIM, SPIFFE, SSF, OID4VCI, or OID4VP flow and follow every request it makes.',
    body: `# Run a Real Protocol Flow

Protocol Soup executes genuine protocol flows against live infrastructure and
records every step. Use \`browse-protocol-catalog\` first to pick a protocol id
and an executable flow id.

## Start the flow

    POST ${SITE_ORIGIN}/api/protocols/{protocolId}/demo/{flowId}

No request body is required. A successful start returns:

    {
      "session_id": "...",
      "session_token": "...",
      "protocol": "oauth2",
      "flow": "authorization_code",
      "ws_endpoint": "/ws/lookingglass/{session_id}",
      "scenario": { ... }
    }

\`session_token\` is an owner capability. Keep it: it is the only way to read
back the session's captured traffic, and it is not recoverable.

## Follow the flow live

Connect a WebSocket to the returned \`ws_endpoint\`:

    wss://protocolsoup.com/ws/lookingglass/{session_id}

Events stream as the flow executes. Each carries a type (flow step, security
warning, token issuance, and so on), the real request or response payload, and
annotations citing the specification section that governs the behaviour.

## Read the session back

    GET ${SITE_ORIGIN}/api/lookingglass/sessions/{session_id}
    ${LOOKING_GLASS_TOKEN_HEADER}: {session_token}

Without the owner token the session's captured traffic is not returned.

## Errors

- \`404\` — unknown protocol or flow id.
- \`503\` — the Looking Glass engine is disabled in this deployment.

## Notes

The tokens, assertions, and credentials produced by a flow are really signed
and really verified, but they are issued by a sandbox identity provider and are
valid nowhere else. Decode them with the \`decode-token\` skill.
`,
  },
  {
    name: 'decode-token',
    description:
      'Decode and explain a JWT, SAML assertion, or verifiable credential, including signature verification and per-claim specification references.',
    body: `# Decode a Token or Credential

Protocol Soup decodes security tokens and explains each claim against the
specification that defines it.

## Decode a JWT

    POST ${SITE_ORIGIN}/api/lookingglass/decode
    Content-Type: application/json

    {"token": "eyJhbGciOiJSUzI1NiIs..."}

The response contains the decoded header and payload, the signature
verification result against the sandbox key set, and annotations explaining
what each claim means and which specification section requires it.

A malformed token returns \`400\` with \`{"error": "..."}\` describing what failed
to parse — useful on its own when debugging a client that emits bad tokens.

## Decode a verifiable credential

    POST ${SITE_ORIGIN}/api/lookingglass/decode/credential
    Content-Type: application/json

    {"credential": "..."}

Accepts SD-JWT VC and ISO mdoc credentials. The request body is capped at
64 KiB. The response reports the credential format, the disclosed and withheld
claims, and the outcome of verifying the issuer signature.

## Getting a token to decode

Public keys for verification are published at
\`${SITE_ORIGIN}/api/.well-known/jwks.json\`. To produce a token first, run a
flow with the \`run-protocol-flow\` skill, or exchange a pre-registered demo
client's credentials as described at ${siteUrl(AGENT_PATHS.authMd)}.

## Notes

- No credentials are required for either endpoint.
- Rate limited to 100 requests per minute per client IP.
`,
  },
  {
    name: 'use-wallet-harness',
    description:
      'Issue and present verifiable credentials through the Protocol Soup OID4VCI/OID4VP wallet at wallet.protocolsoup.com.',
    body: `# Use the Protocol Soup Wallet Harness

The wallet is a **separate origin**. This host is Looking Glass and the protocol APIs; the holder is ${WALLET_ORIGIN}.

Do not invent wallet behavior in the browser. Fetch the wallet's own skill — it is generated by the wallet process from the APIs it actually serves:

    GET ${WALLET_ORIGIN}/llms.txt
    GET ${WALLET_ORIGIN}/.well-known/agent-skills/use-wallet-harness/SKILL.md
    GET ${WALLET_ORIGIN}/.well-known/api-catalog

Ask for \`Accept: text/markdown\` on \`${WALLET_ORIGIN}/\` if you want the recipes without executing JavaScript.

## What it does

- OID4VCI: \`POST ${WALLET_ORIGIN}/api/issue\` (bootstrap) and \`POST ${WALLET_ORIGIN}/api/import\` (offer / issuer / credential).
- OID4VP: \`POST ${WALLET_ORIGIN}/submit\` (\`mode=one_click\` or stepwise) after a verifier request exists.
- Session: send \`X-Wallet-Session\` on API calls. For Looking Glass runs, also pass \`looking_glass_session_id\` in the JSON body.

This origin's \`/mcp\` server does **not** proxy the wallet. Call ${WALLET_ORIGIN} directly.
`,
  },
]

export function listSkills(): AgentSkill[] {
  return SKILLS
}

export function findSkill(name: string): AgentSkill | undefined {
  return SKILLS.find((skill) => skill.name === name)
}

/**
 * The exact bytes served for a skill artifact. The index digests this output,
 * so every caller must go through it.
 */
export function renderSkill(skill: AgentSkill): string {
  return skill.body
}

export function skillUrl(skill: AgentSkill): string {
  return siteUrl(`/.well-known/agent-skills/${skill.name}/SKILL.md`)
}
