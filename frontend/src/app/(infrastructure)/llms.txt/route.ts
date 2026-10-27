import { sortedProtocolCatalogData } from '@/protocols/presentation/protocol-catalog-data'
import { DOCS_ORIGIN, SITE_ORIGIN, WALLET_ORIGIN } from '@/lib/seo'
import { getConformanceSpecs, specPath } from '@/lib/conformance.server'

export const revalidate = 300

/** Indexable specification index pages, or nothing when none qualify or the backend is unavailable. */
async function requirementLines(): Promise<string[]> {
  try {
    const response = await getConformanceSpecs()
    return response.specs
      .filter((spec) => spec.indexable)
      .map((spec) => `- [${spec.short_title} normative requirements](${SITE_ORIGIN}${specPath(spec.id)})`)
  } catch {
    return []
  }
}

export async function GET() {
  const protocolLines = sortedProtocolCatalogData().map(
    (protocol) => `- [${protocol.name}](${SITE_ORIGIN}/protocol/${protocol.id})`,
  )
  const specLines = await requirementLines()

  // Every task names an endpoint that is mounted on its origin and answers
  // without authentication. Keep each line in step with the backend router.
  const body = [
    '# ProtocolSoup',
    '',
    '> Live sandbox for OAuth 2.0, OpenID Connect, SAML 2.0, SPIFFE/SPIRE, SCIM 2.0, the Shared Signals Framework, and OpenID for Verifiable Credentials. Every token is signed by a real key and every endpoint below is live.',
    '',
    `Paths below are on ${SITE_ORIGIN} unless they name another origin. None needs authentication. The wallet at ${WALLET_ORIGIN} is a separate origin with its own HTTP API; it is not an MCP server.`,
    '',
    '## Explore the protocol catalog',
    '',
    '- To list the protocols this sandbox implements, `GET /api/protocols`, or call the MCP tool `list_protocols` with `POST /mcp`.',
    '- To read one protocol, `GET /api/protocols/{protocolId}`, for example `/api/protocols/oauth2`.',
    '- To list the flows a protocol defines, `GET /api/protocols/{protocolId}/flows`, or call the MCP tool `list_protocol_flows` with the argument `protocolId`.',
    '- To read the ordered steps of one flow, call the MCP tool `describe_protocol_flow` with the arguments `protocolId` and `flowId`, for example `oauth2` and `authorization_code`.',
    '',
    '## Decode a token',
    '',
    '- To decode a JWT and check its signature against the sandbox key set, call the MCP tool `decode_jwt` with `POST /mcp`, or `POST /api/lookingglass/decode` with the JSON body `{"token": "<compact JWT>"}`.',
    '- To fetch the key set those decoders verify against, `GET /api/.well-known/jwks.json`.',
    '',
    '## Call the MCP server',
    '',
    '- To find the MCP servers on this domain, `GET /.well-known/ai-catalog.json`.',
    '- To read the MCP Server Card, `GET /mcp/server-card` with `Accept: application/mcp-server-card+json`.',
    '- To list the tools, `POST /mcp` with the JSON-RPC method `tools/list`.',
    '- Every `POST /mcp` is stateless Streamable HTTP, revision `2026-07-28`: no `initialize` handshake and no session header. Send `MCP-Protocol-Version: 2026-07-28` and an `Mcp-Method` header equal to the JSON-RPC method, plus `Mcp-Name` equal to the tool name on `tools/call`. `params._meta` carries `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities`.',
    '- The tools are read-only: `list_protocols`, `list_protocol_flows`, `describe_protocol_flow`, and `decode_jwt`. They do not start flows or drive the wallet.',
    `- [Worked tools/call request](${DOCS_ORIGIN}/protocols/mcp/)`,
    '',
    '## Read discovery metadata',
    '',
    '- To read the OpenID Connect discovery document, `GET /.well-known/openid-configuration`.',
    '- To fetch the OpenID Provider signing keys, `GET /oidc/.well-known/jwks.json`, the `jwks_uri` that document names.',
    '- To read OAuth 2.0 Authorization Server metadata (RFC 8414), `GET /.well-known/oauth-authorization-server` for the origin issuer, or `GET /.well-known/oauth-authorization-server/oauth2` for the OAuth 2.0 issuer.',
    '- To read OAuth 2.0 Protected Resource Metadata (RFC 9728), `GET /.well-known/oauth-protected-resource`.',
    '- To read the OID4VCI Credential Issuer metadata, `GET /.well-known/openid-credential-issuer/oid4vci`. Send `Accept: application/jwt` for the signed form.',
    '- To read the OID4VCI issuer\'s Authorization Server metadata, `GET /.well-known/oauth-authorization-server/oid4vci`.',
    '- To fetch the OID4VCI issuer signing keys, `GET /oid4vci/.well-known/jwks.json`.',
    '- To list the HTTP APIs on this origin (RFC 9727), `GET /.well-known/api-catalog`.',
    '- To list the agent skills and their `sha256` digests, `GET /.well-known/agent-skills/index.json`.',
    '- To register as an agent, `GET /auth.md` for the procedure and `GET /.well-known/oauth-authorization-server/agentauth` for the authorization server metadata.',
    '',
    '## Look up normative requirements',
    '',
    '- To list the specifications in the conformance registry, `GET /api/conformance/specs`.',
    '- To list one specification\'s requirements, `GET /api/conformance/specs/{specId}`, for example `/api/conformance/specs/oid4vp`.',
    '- To read one requirement with its statement, specification section, and the self-test verdict for this build, `GET /api/conformance/requirements/{requirementId}`, for example `/api/conformance/requirements/vp-001`.',
    '- To read the passing and failing exchanges captured from production for one requirement, `GET /api/conformance/requirements/{requirementId}/artefacts`.',
    '',
    '## Read any page as markdown',
    '',
    '- To read a page without parsing HTML, `GET` it with `Accept: text/markdown`, for example `GET /protocols`.',
    '',
    `## Drive the wallet (${WALLET_ORIGIN})`,
    '',
    `- To issue a credential from the ProtocolSoup issuer into the wallet, \`POST ${WALLET_ORIGIN}/api/issue\`.`,
    `- To redeem a credential offer, \`POST ${WALLET_ORIGIN}/api/import\`.`,
    `- To resolve an OID4VP authorization request, \`POST ${WALLET_ORIGIN}/api/resolve\`, then \`POST ${WALLET_ORIGIN}/api/present\` to send the presentation. \`POST ${WALLET_ORIGIN}/submit\` does both in one call.`,
    `- To read the wallet's stored credentials, \`GET ${WALLET_ORIGIN}/api/session\`. Send the same \`X-Wallet-Session\` header on every wallet call.`,
    `- [Wallet request bodies](${WALLET_ORIGIN}/llms-full.txt)`,
    `- [Wallet llms.txt](${WALLET_ORIGIN}/llms.txt)`,
    '',
    '## Protocol Guides',
    ...protocolLines,
    '',
    ...(specLines.length > 0
      ? [
          '## Normative requirements',
          'Per-requirement pages with the registry statement, the specification section, and ProtocolSoup\'s self-test verdict for the serving build.',
          ...specLines,
          '',
        ]
      : []),
    '## Related',
    `- [Full profile](${SITE_ORIGIN}/llms-full.txt)`,
    `- [Docs llms.txt](${DOCS_ORIGIN}/llms.txt)`,
    `- [Agent discovery](${DOCS_ORIGIN}/deploy/agent-discovery/)`,
    `- [Looking Glass](${SITE_ORIGIN}/looking-glass)`,
    `- [Sitemap index](${SITE_ORIGIN}/sitemap-index.xml)`,
    '',
  ].join('\n')

  return new Response(body, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=3600, s-maxage=3600',
    },
  })
}
