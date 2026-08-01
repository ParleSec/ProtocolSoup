import { DOCS_ORIGIN, SITE_ORIGIN } from '@/lib/seo'

/**
 * Shared source of truth for the machine-readable surfaces agents use to
 * discover this deployment: the RFC 9727 API catalog, the RFC 8288 Link
 * headers on page responses, the agent skills index, and auth.md.
 *
 * Every URL here must resolve to something this deployment actually serves.
 */

/** Paths served by the Go runtime rather than the Next.js app. */
export const BACKEND_PATH_PREFIXES = [
  '/api',
  '/ws',
  '/agentauth',
  '/mcp',
  '/oauth2',
  '/oidc',
  '/oid4vci',
  '/oid4vp',
  '/saml',
  '/spiffe',
  '/scim',
  '/ssf',
] as const

export const AGENT_PATHS = {
  apiCatalog: '/.well-known/api-catalog',
  protectedResource: '/.well-known/oauth-protected-resource',
  /** RFC 8414 metadata for the origin issuer; carries the auth.md agent_auth block. */
  authorizationServer: '/.well-known/oauth-authorization-server',
  /** RFC 8414 metadata for the agentic registration server. */
  agentAuthServer: '/.well-known/oauth-authorization-server/agentauth',
  skillsIndex: '/.well-known/agent-skills/index.json',
  /** Site-wide index of AI artifacts; the entry point for MCP server discovery. */
  aiCatalog: '/.well-known/ai-catalog.json',
  /** MCP Server Card, at the location SEP-2127 reserves on the server's own endpoint. */
  mcpServerCard: '/mcp/server-card',
  authMd: '/auth.md',
  llms: '/llms.txt',
  llmsFull: '/llms-full.txt',
  health: '/health',
} as const

/**
 * OpenAPI contracts. The source files live in `openapi/v1/` and are copied to
 * the docs site's public directory at build time, which is the only origin
 * that serves them.
 */
export const OPENAPI_CONTRACTS = {
  gateway: `${DOCS_ORIGIN}/openapi/gateway.yaml`,
  federation: `${DOCS_ORIGIN}/openapi/federation.yaml`,
  scim: `${DOCS_ORIGIN}/openapi/scim.yaml`,
  vc: `${DOCS_ORIGIN}/openapi/vc.yaml`,
} as const

export type OpenApiContract = keyof typeof OPENAPI_CONTRACTS

/**
 * Which published contract documents each protocol namespace. SPIFFE and SSF
 * are served by the runtime but have no published OpenAPI contract yet, so
 * their catalog entries carry documentation and status links only.
 */
export const PROTOCOL_CONTRACTS: Partial<Record<string, OpenApiContract>> = {
  oauth2: 'federation',
  oidc: 'federation',
  saml: 'federation',
  oid4vci: 'vc',
  oid4vp: 'vc',
  scim: 'scim',
}

export const API_REFERENCE_URL = `${DOCS_ORIGIN}/api/reference/`
export const API_OVERVIEW_URL = `${DOCS_ORIGIN}/api/overview/`

export function siteUrl(path: string): string {
  return `${SITE_ORIGIN}${path}`
}

export function protocolDocsUrl(protocolId: string): string {
  return `${DOCS_ORIGIN}/protocols/${protocolId}/`
}

/**
 * RFC 8288 Link header advertised on page responses. Relation types are drawn
 * from the IANA Link Relations registry: `api-catalog` and `status` are
 * registered by RFC 9727, `service-desc` and `service-doc` by RFC 8631.
 */
export const AGENT_LINK_HEADER = [
  `<${AGENT_PATHS.apiCatalog}>; rel="api-catalog"; type="application/linkset+json"`,
  `<${OPENAPI_CONTRACTS.gateway}>; rel="service-desc"; type="application/yaml"`,
  `<${API_REFERENCE_URL}>; rel="service-doc"; type="text/html"`,
  `<${AGENT_PATHS.skillsIndex}>; rel="describedby"; type="application/json"`,
  `<${AGENT_PATHS.aiCatalog}>; rel="describedby"; type="application/ai-catalog+json"`,
  `<${AGENT_PATHS.llms}>; rel="describedby"; type="text/plain"`,
  `<${AGENT_PATHS.health}>; rel="status"; type="application/json"`,
].join(', ')

export function isBackendPath(pathname: string): boolean {
  return BACKEND_PATH_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`),
  )
}
