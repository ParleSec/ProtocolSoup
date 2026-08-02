import type { ElementType } from 'react'
import {
  AlertTriangle,
  Bot,
  Cpu,
  Eye,
  Fingerprint,
  Key,
  KeyRound,
  Lock,
  Radio,
  RefreshCw,
  Send,
  Shield,
  Unlock,
  UserCheck,
  Users,
  Zap,
} from 'lucide-react'

export interface FlowPresentationMeta {
  icon: ElementType
  color: string
  features: string[]
  recommended?: boolean
}

export const FLOW_PRESENTATION_META: Record<string, FlowPresentationMeta> = {
  authorization_code: {
    icon: Shield,
    color: 'from-purple-500 to-indigo-600',
    features: ['Server-side Apps', 'Confidential Clients', 'Client Secret'],
  },
  authorization_code_pkce: {
    icon: Lock,
    color: 'from-cyan-500 to-blue-600',
    features: ['Single Page Apps', 'Mobile Apps', 'No Client Secret'],
    recommended: true,
  },
  client_credentials: {
    icon: Key,
    color: 'from-orange-500 to-red-600',
    features: ['Microservices', 'Background Jobs', 'No User Context'],
  },
  refresh_token: {
    icon: Unlock,
    color: 'from-green-500 to-emerald-600',
    features: ['Token Rotation', 'Long Sessions', 'Silent Refresh'],
  },
  oidc_authorization_code: {
    icon: Fingerprint,
    color: 'from-purple-500 to-pink-600',
    features: ['ID Token (JWT)', 'UserInfo Endpoint', 'Verified Identity'],
    recommended: true,
  },
  'interaction-code': {
    icon: Fingerprint,
    color: 'from-violet-500 to-fuchsia-600',
    features: ['Discovery + JWKS', 'PKCE + Nonce', 'ID Token + UserInfo'],
  },
  oidc_implicit: {
    icon: Unlock,
    color: 'from-amber-500 to-orange-600',
    features: ['Legacy Flow', 'Direct Token Response', 'Not Recommended'],
  },
  'oid4vci-pre-authorized': {
    icon: KeyRound,
    color: 'from-emerald-500 to-teal-600',
    features: ['Pre-Authorized Code', 'Proof JWT', 'c_nonce Binding'],
    recommended: true,
  },
  'oid4vci-pre-authorized-tx-code': {
    icon: Lock,
    color: 'from-teal-500 to-cyan-600',
    features: ['tx_code Required', 'Pre-Authorized Flow', 'Nonce Freshness'],
  },
  'oid4vci-deferred-issuance': {
    icon: RefreshCw,
    color: 'from-green-500 to-emerald-600',
    features: ['Deferred Polling', 'transaction_id', 'Issued Credential'],
  },
  'oid4vp-direct-post': {
    icon: Eye,
    color: 'from-indigo-500 to-violet-600',
    features: ['DCQL Query', 'direct_post', 'Verifier Policy'],
    recommended: true,
  },
  'oid4vp-direct-post-jwt': {
    icon: Shield,
    color: 'from-violet-500 to-purple-600',
    features: ['Encrypted Response', 'direct_post.jwt', 'Nonce + State'],
  },
  'x509-svid-issuance': {
    icon: Shield,
    color: 'from-green-500 to-emerald-600',
    features: ['X.509 Certificate', 'Workload Identity', 'mTLS Ready'],
    recommended: true,
  },
  'jwt-svid-issuance': {
    icon: Key,
    color: 'from-teal-500 to-cyan-600',
    features: ['JWT Token', 'API Authentication', 'Short-Lived'],
  },
  'mtls-handshake': {
    icon: Lock,
    color: 'from-emerald-500 to-green-600',
    features: ['Mutual TLS', 'Zero Trust', 'Service-to-Service'],
  },
  'certificate-rotation': {
    icon: Zap,
    color: 'from-lime-500 to-green-600',
    features: ['Auto-Rotation', 'Zero Downtime', 'Streaming API'],
  },
  ssf_stream_configuration: {
    icon: Radio,
    color: 'from-amber-500 to-orange-600',
    features: ['Stream Setup', 'Discovery', 'JWKS'],
    recommended: true,
  },
  ssf_push_delivery: {
    icon: Send,
    color: 'from-green-500 to-emerald-600',
    features: ['Real-time', 'RFC 8935', 'Immediate'],
  },
  ssf_poll_delivery: {
    icon: Zap,
    color: 'from-blue-500 to-indigo-600',
    features: ['Receiver-initiated', 'RFC 8936', 'Firewall-friendly'],
  },
  caep_session_revoked: {
    icon: Lock,
    color: 'from-blue-500 to-cyan-600',
    features: ['CAEP', 'Session Mgmt', 'Zero Trust'],
  },
  caep_credential_change: {
    icon: Key,
    color: 'from-purple-500 to-indigo-600',
    features: ['CAEP', 'Credential Events', 'Re-auth'],
  },
  risc_account_disabled: {
    icon: Shield,
    color: 'from-amber-500 to-red-600',
    features: ['RISC', 'High Severity', 'Block Access'],
  },
  risc_credential_compromise: {
    icon: AlertTriangle,
    color: 'from-red-500 to-rose-600',
    features: ['RISC', 'CRITICAL', 'Emergency'],
  },
  scim_user_lifecycle: {
    icon: Users,
    color: 'from-purple-500 to-violet-600',
    features: ['User CRUD', 'Provisioning', 'IdP Sync'],
    recommended: true,
  },
  scim_group_management: {
    icon: Users,
    color: 'from-blue-500 to-indigo-600',
    features: ['Group Sync', 'Membership', 'Access Control'],
  },
  scim_filter_queries: {
    icon: Zap,
    color: 'from-cyan-500 to-blue-600',
    features: ['RFC 7644', 'Filter Syntax', 'Pagination'],
  },
  scim_schema_discovery: {
    icon: Eye,
    color: 'from-teal-500 to-cyan-600',
    features: ['Auto-Config', 'Capabilities', 'Schemas'],
  },
  scim_bulk_operations: {
    icon: Zap,
    color: 'from-orange-500 to-amber-600',
    features: ['Batch Processing', 'Atomic', 'Efficient'],
  },
  agent_anonymous_registration: {
    icon: Bot,
    color: 'from-teal-500 to-cyan-600',
    features: ['Anonymous Register', 'Identity Assertion', 'JWT Bearer Grant'],
    recommended: true,
  },
  agent_claim_ceremony: {
    icon: UserCheck,
    color: 'from-cyan-500 to-blue-600',
    features: ['Claim Ceremony', 'User Code', 'Ownership Binding'],
  },
  mcp_tool_call: {
    icon: Cpu,
    color: 'from-sky-500 to-blue-600',
    features: ['Server Card', 'server/discover', 'JSON-RPC Tools'],
    recommended: true,
  },
}

const FEATURE_DESCRIPTIONS: Record<string, string> = {
  'Authorization Code Flow': 'Standard flow for server-side applications',
  'PKCE for Public Clients': 'Enhanced security for SPAs and mobile apps (RFC 7636)',
  'Client Credentials': 'Machine-to-machine authentication',
  'Refresh Token Rotation': 'Secure token refresh with rotation',
  'Token Introspection': 'Verify token validity and metadata (RFC 7662)',
  'Token Revocation': 'Invalidate access/refresh tokens (RFC 7009)',
  'RFC 6749 Compliant': 'Full OAuth 2.0 Authorization Framework compliance',
  'RFC 7636 PKCE Validation': 'Strict 43-128 char verifier with character validation',
  'RFC 7009 Token Revocation': 'Both access and refresh token revocation support',
  'ID Token (JWT)': 'JWT containing verified identity claims (sub, name, email)',
  'UserInfo Endpoint': 'API endpoint returning additional user claims',
  'Discovery Document': 'Auto-configuration via /.well-known/openid-configuration',
  'Standard Claims': 'Standardized user attributes (sub, name, email, picture)',
  'Nonce Protection': 'Required for id_token response types (OIDC Core §3.2.2.1)',
  'Signature Verification': 'Validate tokens using JWKS public keys',
  'Claims & Scopes': 'Request specific user data with standard scopes',
  'Hybrid Flows': 'Combined response types for flexibility',
  'Session Management': 'Track and manage user sessions',
  'at_hash / c_hash Claims': 'Hash claims for hybrid/implicit flow integrity (§3.3.2.11)',
  'Hybrid Flow Support': 'Full support for code+id_token response types',
  'azp Claim for Multi-Audience': 'Authorized party claim per OIDC Core §2',
  'User Provisioning': 'Automated user account creation and management',
  'Group Management': 'Sync groups and memberships between IdP and SP',
  'Filter Queries': 'RFC 7644 compliant filter syntax for queries',
  'PATCH Operations': 'Partial updates with SCIM PATCH operations',
  'Bulk Operations': 'Batch multiple operations in single request',
  'Schema Discovery': 'Auto-discover server capabilities and schemas',
  'ETag Support': 'Optimistic locking with entity tags',
  'IdP Integration': 'Connect to identity providers like Okta, Azure AD',
  'Security Event Tokens (SET)': 'RFC 8417 signed JWTs for security events',
  'CAEP Events': 'Continuous Access Evaluation Profile events',
  'RISC Events': 'Risk Incident Sharing and Coordination events',
  'Push Delivery': 'Real-time event delivery via HTTP POST (RFC 8935)',
  'Poll Delivery': 'Receiver-initiated polling for events (RFC 8936)',
  'Stream Management': 'Configure and manage event streams',
  'Real-time Signals': 'Immediate notification of security events',
  'Zero Trust Ready': 'Enable continuous access evaluation',
  'Anonymous Agent Registration': 'Self-register without a human owner via the identity endpoint',
  'Identity Assertion (JWT)': 'Service-signed JWT asserting agent identity per auth.md',
  'RFC 7523 JWT Bearer Grant': 'Exchange an identity assertion for an access token',
  'Claim Ceremony': 'Bind a registered agent to a person using a device-grant pattern',
  'Device-Grant Pattern': 'User code + browser approval borrowed from RFC 8628',
  'Pre-Claim Scopes': 'Read-only agent:read scope until ownership is proven',
  'auth.md Profile': 'Agentic registration profile on top of OAuth metadata',
  'Agent Ownership Binding': 'Widen scope after a person claims the agent',
  'Streamable HTTP Transport': 'MCP revision 2026-07-28 over HTTP without sessions',
  'Server Cards (SEP-2127)': 'Discoverable MCP server identity and transport metadata',
  'JSON-RPC Tool Calls': 'Call tools with mirrored Mcp-Method and Mcp-Name headers',
  'Stateless Revision': 'Every request carries protocol version and client identity',
  'AI Catalog Discovery': 'Find MCP servers via /.well-known/ai-catalog.json',
  'Protocol Catalog Tools': 'Read-only tools exposing protocols, flows, and JWT decode',
  'JWT Decode Tool': 'Decode and inspect JWTs from an MCP client',
  'Header Mirroring': 'Validate transport headers against the JSON-RPC body',
}

export function getFeatureDescription(feature: string): string {
  return FEATURE_DESCRIPTIONS[feature] || feature
}
