export interface ProtocolFlowCatalogData {
  id: string
  name: string
  rfc: string
  backendId?: string
}

export interface ProtocolCatalogDataItem {
  id: string
  name: string
  description: string
  spec: string
  specUrl: string
  flows: ProtocolFlowCatalogData[]
}

// Build-safe route and sitemap source: no UI component imports.
export const PROTOCOL_CATALOG_DATA: ProtocolCatalogDataItem[] = [
  {
    id: 'oauth2',
    name: 'OAuth 2.0',
    description: 'The industry-standard authorization framework for delegated access. Enables applications to obtain limited access to user accounts without exposing credentials.',
    spec: 'RFC 6749',
    specUrl: 'https://datatracker.ietf.org/doc/html/rfc6749',
    flows: [
      { id: 'authorization-code', backendId: 'authorization_code', name: 'Authorization Code', rfc: '§4.1' },
      { id: 'authorization-code-pkce', backendId: 'authorization_code_pkce', name: 'Authorization Code + PKCE', rfc: 'RFC 7636' },
      { id: 'client-credentials', backendId: 'client_credentials', name: 'Client Credentials', rfc: '§4.4' },
      { id: 'refresh-token', backendId: 'refresh_token', name: 'Refresh Token', rfc: '§6' },
      { id: 'token-introspection', backendId: 'token_introspection', name: 'Token Introspection', rfc: 'RFC 7662' },
      { id: 'token-revocation', backendId: 'token_revocation', name: 'Token Revocation', rfc: 'RFC 7009' },
    ],
  },
  {
    id: 'oidc',
    name: 'OpenID Connect',
    description: 'An identity layer built on top of OAuth 2.0. Adds authentication to authorization, enabling clients to verify user identity and obtain basic profile information.',
    spec: 'OpenID Connect Core 1.0',
    specUrl: 'https://openid.net/specs/openid-connect-core-1_0.html',
    flows: [
      { id: 'oidc-authorization-code', backendId: 'oidc_authorization_code', name: 'Authorization Code Flow', rfc: '§3.1' },
      { id: 'oidc-implicit', backendId: 'oidc_implicit', name: 'Implicit Flow (Legacy)', rfc: '§3.2' },
      { id: 'hybrid', backendId: 'oidc_hybrid', name: 'Hybrid Flow', rfc: '§3.3' },
      { id: 'userinfo', backendId: 'oidc_userinfo', name: 'UserInfo Endpoint', rfc: '§5.3' },
      { id: 'discovery', backendId: 'oidc_discovery', name: 'Discovery', rfc: 'Discovery 1.0' },
    ],
  },
  {
    id: 'oid4vci',
    name: 'OID4VCI',
    description: 'OpenID for Verifiable Credential Issuance. Demonstrates credential offers, pre-authorized code token exchange, nonce-bound proof validation, and SD-JWT VC issuance.',
    spec: 'OpenID4VCI 1.0',
    specUrl: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html',
    flows: [
      { id: 'oid4vci-pre-authorized', name: 'Pre-Authorized Code', rfc: 'OID4VCI §4, §6.1, §8' },
      { id: 'oid4vci-pre-authorized-tx-code', name: 'Pre-Authorized + tx_code', rfc: 'OID4VCI §6.1' },
      { id: 'oid4vci-deferred-issuance', name: 'Deferred Issuance', rfc: 'OID4VCI Deferred Endpoint' },
    ],
  },
  {
    id: 'oid4vp',
    name: 'OID4VP',
    description: 'OpenID for Verifiable Presentations. Shows DCQL request contracts, request object validation, direct_post/direct_post.jwt responses, and verifier policy decisions.',
    spec: 'OpenID4VP 1.0',
    specUrl: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html',
    flows: [
      { id: 'oid4vp-direct-post', name: 'DCQL + direct_post', rfc: 'OID4VP §5, §8.2' },
      { id: 'oid4vp-direct-post-jwt', name: 'DCQL + direct_post.jwt', rfc: 'OID4VP §8.3.1' },
    ],
  },
  {
    id: 'saml',
    name: 'SAML 2.0',
    description: 'XML-based standard for exchanging authentication and authorization data between identity providers and service providers. Enables enterprise single sign-on.',
    spec: 'SAML 2.0 Core',
    specUrl: 'https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf',
    flows: [
      { id: 'sp-initiated-sso', backendId: 'sp_initiated_sso', name: 'SP-Initiated SSO', rfc: 'Profiles §4.1' },
      { id: 'idp-initiated-sso', backendId: 'idp_initiated_sso', name: 'IdP-Initiated SSO', rfc: 'Profiles §4.1.5' },
      { id: 'single-logout', backendId: 'single_logout', name: 'Single Logout (SLO)', rfc: 'Profiles §4.4' },
      { id: 'metadata', name: 'Metadata Exchange', rfc: 'Metadata' },
    ],
  },
  {
    id: 'spiffe',
    name: 'SPIFFE/SPIRE',
    description: 'Secure Production Identity Framework for Everyone. Provides cryptographic workload identity for zero-trust architectures via X.509 and JWT SVIDs.',
    spec: 'SPIFFE Specifications',
    specUrl: 'https://spiffe.io/docs/latest/spiffe-about/overview/',
    flows: [
      { id: 'x509-svid-issuance', name: 'X.509-SVID Acquisition', rfc: 'X.509-SVID' },
      { id: 'jwt-svid-issuance', name: 'JWT-SVID Acquisition', rfc: 'JWT-SVID' },
      { id: 'mtls-handshake', name: 'mTLS with X.509-SVIDs', rfc: 'RFC 8446' },
      { id: 'certificate-rotation', name: 'Certificate Rotation', rfc: 'Workload API' },
    ],
  },
  {
    id: 'scim',
    name: 'SCIM 2.0',
    description: 'System for Cross-domain Identity Management. Standards-based protocol for automating user provisioning and lifecycle management between identity providers and service providers.',
    spec: 'RFC 7642, 7643, 7644',
    specUrl: 'https://datatracker.ietf.org/doc/html/rfc7644',
    flows: [
      { id: 'user-lifecycle', name: 'User Lifecycle', rfc: 'RFC 7644 §3.2-3.6' },
      { id: 'group-management', backendId: 'group-membership', name: 'Group Management', rfc: 'RFC 7644 §3.2-3.6' },
      { id: 'filter-queries', backendId: 'user-discovery', name: 'Filter Queries', rfc: 'RFC 7644 §3.4.2' },
      { id: 'schema-discovery', name: 'Schema Discovery', rfc: 'RFC 7644 §4' },
      { id: 'bulk-operations', name: 'Bulk Operations', rfc: 'RFC 7644 §3.7' },
    ],
  },
  {
    id: 'ssf',
    name: 'Shared Signals (SSF)',
    description: 'OpenID Shared Signals Framework for real-time security event sharing. Enables continuous access evaluation (CAEP) and risk incident coordination (RISC) between identity providers and relying parties.',
    spec: 'SSF 1.0, CAEP 1.0, RISC 1.0, RFC 8417',
    specUrl: 'https://openid.net/specs/openid-sse-framework-1_0.html',
    flows: [
      { id: 'ssf-stream-configuration', name: 'Stream Configuration', rfc: 'SSF §4' },
      { id: 'ssf-push-delivery', name: 'Push Delivery', rfc: 'SSF §5.2.1' },
      { id: 'ssf-poll-delivery', name: 'Poll Delivery', rfc: 'SSF §5.2.2' },
      { id: 'caep-session-revoked', name: 'Session Revoked (CAEP)', rfc: 'CAEP §3.1' },
      { id: 'caep-credential-change', name: 'Credential Change (CAEP)', rfc: 'CAEP §3.2' },
      { id: 'risc-account-disabled', name: 'Account Disabled (RISC)', rfc: 'RISC §2.2' },
      { id: 'risc-credential-compromise', name: 'Credential Compromise (RISC)', rfc: 'RISC §2.1' },
    ],
  },
]

export const PROTOCOL_IDS = PROTOCOL_CATALOG_DATA.map((protocol) => protocol.id)

const PROTOCOL_CATALOG_BY_ID = new Map(
  PROTOCOL_CATALOG_DATA.map((protocol) => [protocol.id, protocol]),
)

export function getCatalogProtocol(protocolId: string): ProtocolCatalogDataItem | undefined {
  return PROTOCOL_CATALOG_BY_ID.get(protocolId)
}

export function getCatalogFlow(
  protocolId: string,
  flowRouteId: string,
): ProtocolFlowCatalogData | undefined {
  return getCatalogProtocol(protocolId)?.flows.find((flow) => flow.id === flowRouteId)
}

export function getBackendFlowId(
  protocolId: string,
  flowRouteId: string,
): string | null {
  const catalogFlow = getCatalogFlow(protocolId, flowRouteId)
  if (!catalogFlow) {
    return null
  }
  return catalogFlow.backendId || catalogFlow.id
}

export function getFlowRouteId(
  protocolId: string,
  backendFlowId: string,
): string {
  const protocol = getCatalogProtocol(protocolId)
  if (!protocol) {
    return backendFlowId.replace(/_/g, '-')
  }

  const catalogFlow = protocol.flows.find(
    (flow) => (flow.backendId || flow.id) === backendFlowId,
  )
  if (catalogFlow) {
    return catalogFlow.id
  }

  return backendFlowId.replace(/_/g, '-')
}

export function getAllowedBackendFlowIds(protocolId: string): Set<string> {
  const protocol = getCatalogProtocol(protocolId)
  if (!protocol) {
    return new Set()
  }
  return new Set(protocol.flows.map((flow) => flow.backendId || flow.id))
}
