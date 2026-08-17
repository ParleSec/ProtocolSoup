/**
 * SEO configuration for ProtocolSoup.
 *
 * Centralized SEO metadata, keywords, and configuration for all pages.
 * Optimized for competitive identity/security protocol keywords.
 */

export const SITE_CONFIG = {
  name: 'ProtocolSoup',
  tagline: 'Live OAuth 2.0, OIDC, OpenID4VC, SAML, SPIFFE, SCIM and SSF execution with a hosted wallet harness',
  baseUrl: 'https://protocolsoup.com',
  docsUrl: 'https://docs.protocolsoup.com',
  walletUrl: 'https://wallet.protocolsoup.com',
  defaultImage: 'https://protocolsoup.com/opengraph-image',
  twitterHandle: '@protocolsoup',
  author: 'Mason Parle',
  locale: 'en_US',
}

export interface PageSEO {
  title: string
  description: string
  keywords: string[]
  ogType?: 'website' | 'article'
  canonical?: string
  noIndex?: boolean
}

/**
 * SEO metadata for each route.
 * Page titles omit the brand; the root layout appends `| ProtocolSoup`.
 * Keywords keep high-volume search phrases (tutorial, playground) even when
 * visible copy leads with execute/inspect.
 */
export const PAGE_SEO: Record<string, PageSEO> = {
  // Homepage - Primary landing page
  '/': {
    title: 'Live OAuth 2.0, OIDC, and Identity Protocol Execution',
    description: 'Execute real OAuth 2.0, OpenID Connect, OID4VCI, OID4VP, SAML, SPIFFE, SCIM and SSF flows against live infrastructure. Inspect every request, decode tokens and assertions, and issue or present credentials with the hosted wallet harness.',
    keywords: [
      'oauth2 playground',
      'oauth 2.0 testing tool',
      'oidc testing',
      'openid connect playground',
      'authentication protocol sandbox',
      'jwt decoder',
      'token inspector',
      'saml testing tool',
      'verifiable credentials',
      'oid4vci playground',
      'oid4vp testing',
      'oid4vci wallet',
      'oid4vp wallet',
      'verifiable credential wallet',
      'mdoc wallet',
      'sd-jwt vc wallet',
      'wallet harness',
      'spiffe spire tutorial',
      'scim 2.0 testing',
      'identity protocol testing',
      'oauth flow visualization',
      'pkce tutorial',
      'security protocol sandbox',
      'protocolsoup',
      'protocol soup',
    ],
    ogType: 'website',
  },

  // Protocols Hub
  '/protocols': {
    title: 'Identity Protocol Reference - OAuth 2.0, OIDC, OpenID4VC, SAML, SPIFFE, SCIM, SSF',
    description: 'Reference for every shipped identity protocol family. Sequence diagrams, parameters, and security considerations for OAuth 2.0, OpenID Connect, OID4VCI, OID4VP, SAML 2.0, SPIFFE/SPIRE, SCIM 2.0, and SSF.',
    keywords: [
      'identity protocol reference',
      'authentication protocols',
      'verifiable credential protocols',
      'oid4vci',
      'oid4vp',
      'oauth2 documentation',
      'oidc specification',
      'saml documentation',
      'security protocols',
    ],
    ogType: 'website',
  },

  // Looking Glass Tool
  '/looking-glass': {
    title: 'Looking Glass - Live Protocol Flow Execution and Traffic Inspector',
    description: 'Execute identity protocol flows in real time and inspect every HTTP request, response, header, and token. Run OAuth 2.0, OIDC, SAML, SCIM, SPIFFE, SSF, OID4VCI, and OID4VP — including holder-side hops through the hosted wallet harness.',
    keywords: [
      'protocol debugger',
      'oauth flow inspector',
      'http traffic inspector',
      'authentication debugger',
      'token debugger',
      'api testing tool',
      'oid4vci debugger',
      'oid4vp debugger',
      'verifiable credential inspector',
    ],
    ogType: 'website',
  },

  // Legacy SSF sandbox URL (redirects to Looking Glass)
  '/ssf-sandbox': {
    title: 'Shared Signals (SSF) in Looking Glass',
    description: 'Fire CAEP and RISC security events in Looking Glass, decode SET tokens, and inspect Transmitter and Receiver traffic on a durable stream session.',
    keywords: [
      'shared signals framework',
      'ssf tutorial',
      'caep events',
      'risc events',
      'security event tokens',
      'zero trust signals',
      'continuous access evaluation',
    ],
    ogType: 'website',
  },

  // OAuth 2.0 Protocol
  '/protocol/oauth2': {
    title: 'OAuth 2.0 Reference - Authorization Framework',
    description: 'Execute live OAuth 2.0 Authorization Code, PKCE, Client Credentials, Refresh Token, Introspection, and Revocation against a working authorization server. Inspect every request, token, and RFC 9700 check.',
    keywords: [
      'oauth 2.0 tutorial',
      'oauth authorization code flow',
      'oauth2 explained',
      'oauth client credentials',
      'oauth2 grant types',
      'rfc 6749',
    ],
    ogType: 'article',
  },

  // OpenID Connect Protocol
  '/protocol/oidc': {
    title: 'OpenID Connect Reference - Authentication Layer for OAuth 2.0',
    description: 'Run OpenID Connect against a live OpenID Provider. Inspect ID tokens, UserInfo, Discovery, Hybrid, and Implicit flows, and see how OIDC adds authentication to OAuth 2.0.',
    keywords: [
      'openid connect tutorial',
      'oidc authentication',
      'id token explained',
      'oidc vs oauth',
      'openid connect flow',
      'oidc discovery',
    ],
    ogType: 'article',
  },

  // OID4VCI Protocol
  '/protocol/oid4vci': {
    title: 'OID4VCI Reference - Verifiable Credential Issuance with OpenID',
    description: 'Issue verifiable credentials with live OID4VCI. Inspect credential offers, pre-authorized code grants, tx_code challenges, proof binding, c_nonce freshness, and deferred issuance.',
    keywords: [
      'oid4vci tutorial',
      'openid for verifiable credential issuance',
      'pre-authorized code',
      'credential offer uri',
      'sd-jwt vc issuance',
      'verifiable credential issuance',
    ],
    ogType: 'article',
  },

  // OID4VP Protocol
  '/protocol/oid4vp': {
    title: 'OID4VP Reference - Verifiable Presentation Requests and Validation',
    description: 'Run OpenID for Verifiable Presentations against a live verifier. Inspect DCQL queries, request objects, direct_post/direct_post.jwt, holder binding, and policy evaluation.',
    keywords: [
      'oid4vp tutorial',
      'openid for verifiable presentations',
      'dcql query',
      'direct_post.jwt',
      'vp token validation',
      'verifiable presentation verification',
    ],
    ogType: 'article',
  },

  // SAML 2.0 Protocol
  '/protocol/saml': {
    title: 'SAML 2.0 Reference - Enterprise SSO and Federation',
    description: 'Execute live SAML 2.0 SP-Initiated SSO, IdP-Initiated SSO, Single Logout, and metadata exchange. Inspect assertions, AuthnRequests, and XML signatures.',
    keywords: [
      'saml 2.0 tutorial',
      'saml sso explained',
      'saml assertion',
      'sp initiated sso',
      'idp initiated sso',
      'saml metadata',
      'enterprise sso',
    ],
    ogType: 'article',
  },

  // SPIFFE/SPIRE Protocol
  '/protocol/spiffe': {
    title: 'SPIFFE/SPIRE Reference - Zero Trust Workload Identity',
    description: 'Run SPIFFE/SPIRE Workload API flows: X.509-SVID issuance, JWT-SVID issuance, mTLS, and certificate rotation. Inspect SVIDs and trust bundles as they are issued.',
    keywords: [
      'spiffe tutorial',
      'spire workload identity',
      'zero trust identity',
      'x509 svid',
      'jwt svid',
      'workload attestation',
      'mtls authentication',
    ],
    ogType: 'article',
  },

  // SCIM 2.0 Protocol
  '/protocol/scim': {
    title: 'SCIM 2.0 Reference - Cross-Domain Identity Provisioning',
    description: 'Execute live SCIM 2.0 user lifecycle, group management, filter queries, and schema discovery against a working SCIM server. Inspect Users, Groups, PATCH, and filter traffic.',
    keywords: [
      'scim 2.0 tutorial',
      'scim provisioning',
      'scim api tutorial',
      'user provisioning protocol',
      'identity provisioning',
      'rfc 7644',
    ],
    ogType: 'article',
  },

  // Shared Signals Framework
  '/protocol/ssf': {
    title: 'Shared Signals (SSF) Reference - CAEP, RISC, and SET Delivery',
    description: 'Execute Shared Signals Framework streams in Looking Glass. Configure Transmitter and Receiver sessions, fire CAEP and RISC events, and inspect Security Event Tokens over push and poll delivery.',
    keywords: [
      'shared signals framework',
      'ssf',
      'caep',
      'risc',
      'security event token',
      'rfc 8417',
      'continuous access evaluation',
    ],
    ogType: 'article',
  },

  // Agentic Registration (auth.md)
  '/protocol/agentauth': {
    title: 'Agentic Registration - Agent Identity and Claim Ceremony',
    description: 'Register an anonymous agent, inspect identity assertions and RFC 7523 JWT bearer grants, and run the claim ceremony that binds an agent to a person.',
    keywords: [
      'agentic registration',
      'agent auth',
      'auth.md',
      'identity assertion',
      'rfc 7523',
      'agent claim ceremony',
      'rfc 8628 device grant',
    ],
    ogType: 'article',
  },

  // Model Context Protocol
  '/protocol/mcp': {
    title: 'Model Context Protocol - MCP Server Discovery and Tool Calls',
    description: 'Explore MCP Streamable HTTP, Server Cards, AI Catalog discovery, and JSON-RPC tool calls against ProtocolSoup\'s remote MCP server.',
    keywords: [
      'model context protocol',
      'mcp tutorial',
      'mcp server card',
      'streamable http',
      'json-rpc tools',
      'sep-2127',
      'ai catalog',
    ],
    ogType: 'article',
  },
}

/**
 * Flow-specific SEO data generator
 * Creates optimized titles and descriptions for protocol flow pages
 */
export function getFlowSEO(protocolId: string, flowId: string, flowName: string): PageSEO {
  const protocolNames: Record<string, string> = {
    oauth2: 'OAuth 2.0',
    oidc: 'OpenID Connect',
    oid4vci: 'OID4VCI',
    oid4vp: 'OID4VP',
    saml: 'SAML 2.0',
    spiffe: 'SPIFFE/SPIRE',
    scim: 'SCIM 2.0',
    ssf: 'Shared Signals (SSF)',
    agentauth: 'Agentic Registration',
    mcp: 'Model Context Protocol',
  }

  const protocolName = protocolNames[protocolId] || protocolId.toUpperCase()
  
  // Flow-specific keyword mappings
  const flowKeywords: Record<string, string[]> = {
    'authorization-code': ['oauth authorization code', 'oauth2 code flow', 'authorization code grant'],
    'authorization-code-pkce': ['oauth pkce', 'pkce flow', 'code verifier', 'code challenge', 'pkce implementation'],
    'client-credentials': ['client credentials flow', 'machine to machine auth', 'service account oauth'],
    'refresh-token': ['oauth refresh token', 'token refresh', 'refresh token grant'],
    'token-introspection': ['token introspection', 'rfc 7662', 'validate access token'],
    'token-revocation': ['token revocation', 'rfc 7009', 'revoke oauth token'],
    'oidc-authorization-code': ['oidc authorization code', 'openid code flow', 'id token flow'],
    'oidc-implicit': ['oidc implicit flow', 'implicit grant', 'spa authentication'],
    'hybrid': ['oidc hybrid flow', 'hybrid grant type'],
    'userinfo': ['userinfo endpoint', 'oidc claims', 'user profile endpoint'],
    'discovery': ['oidc discovery', 'well-known openid-configuration', 'provider metadata'],
    'oid4vci-pre-authorized': ['oid4vci pre-authorized code', 'credential offer uri', 'openid4vci issuance'],
    'oid4vci-pre-authorized-tx-code': ['oid4vci tx_code', 'pre-authorized tx code', 'openid4vci token exchange'],
    'oid4vci-deferred-issuance': ['oid4vci deferred issuance', 'deferred_credential', 'transaction_id polling'],
    'oid4vp-direct-post': ['oid4vp direct_post', 'dcql presentation request', 'vp_token response'],
    'oid4vp-direct-post-jwt': ['oid4vp direct_post.jwt', 'encrypted presentation response', 'oauth-authz-resp+jwt'],
    'sp-initiated-sso': ['sp initiated sso', 'service provider sso', 'saml redirect'],
    'idp-initiated-sso': ['idp initiated sso', 'identity provider sso', 'unsolicited response'],
    'single-logout': ['saml single logout', 'slo', 'federated logout'],
    'metadata': ['saml metadata', 'federation metadata', 'entity descriptor'],
    'x509-svid-issuance': ['x509 svid', 'spiffe certificate', 'workload certificate'],
    'jwt-svid-issuance': ['jwt svid', 'spiffe jwt', 'workload jwt token'],
    'mtls-handshake': ['mtls handshake', 'mutual tls', 'client certificate auth'],
    'certificate-rotation': ['certificate rotation', 'auto cert renewal', 'svid rotation'],
    'user-lifecycle': ['scim user lifecycle', 'user provisioning', 'create update delete user'],
    'group-management': ['scim groups', 'group provisioning', 'membership management'],
    'filter-queries': ['scim filter', 'scim query', 'rfc 7644 filter'],
    'schema-discovery': ['scim schema', 'resource types', 'service provider config'],
    'bulk-operations': ['scim bulk', 'batch provisioning', 'bulk user creation'],
    'anonymous-registration': ['agent registration', 'anonymous agent', 'identity assertion', 'rfc 7523'],
    'claim-ceremony': ['agent claim ceremony', 'user code', 'device authorization grant', 'rfc 8628'],
    'mcp-tool-call': ['mcp tool call', 'server discover', 'mcp server card', 'json-rpc mcp'],
  }

  const keywords = flowKeywords[flowId] || [`${protocolId} ${flowId}`, flowName.toLowerCase()]

  return {
    title: `${flowName} — ${protocolName} Flow`,
    description: `Execute the ${flowName} flow in Looking Glass. Inspect each HTTP hop, token, and validation decision for ${protocolName}.`,
    keywords: [
      ...keywords,
      `${protocolId} tutorial`,
      `${flowName.toLowerCase()} example`,
      'authentication flow',
    ],
    ogType: 'article',
  }
}

/**
 * Protocol-specific SEO helper
 */
export function getProtocolSEO(protocolId: string): PageSEO {
  const key = `/protocol/${protocolId}`
  return PAGE_SEO[key] || {
    title: `${protocolId.toUpperCase()} Protocol`,
    description: `Execute ${protocolId.toUpperCase()} flows against live infrastructure, with request inspection and spec-linked reference.`,
    keywords: [protocolId, 'authentication', 'identity protocol'],
    ogType: 'article',
  }
}
