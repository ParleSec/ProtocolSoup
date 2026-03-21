/**
 * Protocol Registry - shared protocol types and presentation metadata
 */

export interface FlowStep {
  order: number
  name: string
  description: string
  from: string
  to: string
  type: 'request' | 'response' | 'redirect' | 'internal'
  parameters?: Record<string, string>
  security?: string[]
}

export interface FlowDefinition {
  id: string
  name: string
  description: string
  steps: FlowStep[]
  executable: boolean
  category?: string // "workload-api", "admin", "infrastructure"
}

export interface DemoStep {
  order: number
  name: string
  description: string
  endpoint?: string
  method?: string
  auto: boolean
}

export interface DemoScenario {
  id: string
  name: string
  description: string
  steps: DemoStep[]
  config?: Record<string, string>
}

export interface Inspector {
  id: string
  name: string
  description: string
  type: 'token' | 'request' | 'response' | 'flow'
}

export interface Protocol {
  id: string
  name: string
  version: string
  description: string
  tags: string[]
  rfcs?: string[]
  flows?: FlowDefinition[]
  inspectors?: Inspector[]
  demoScenarios?: DemoScenario[]
}

/**
 * Protocol metadata for UI rendering
 */
export const protocolMeta: Record<string, {
  icon: string
  color: string
  gradient: string
  features: string[]
}> = {
  oauth2: {
    icon: 'Shield',
    color: 'orange',
    gradient: 'from-orange-500 to-amber-500',
    features: [
      'Authorization Code Flow',
      'PKCE for Public Clients',
      'Client Credentials',
      'Refresh Token Rotation',
      'Token Introspection',
      'Token Revocation',
      // Standards compliance features
      'RFC 6749 Compliant',
      'RFC 7636 PKCE Validation',
      'RFC 7009 Token Revocation',
    ],
  },
  oidc: {
    icon: 'Fingerprint',
    color: 'purple',
    gradient: 'from-purple-500 to-pink-500',
    features: [
      'ID Token (JWT)',
      'UserInfo Endpoint',
      'Discovery Document',
      'Standard Claims',
      'Nonce Protection',
      'Signature Verification',
      // OIDC Core 1.0 compliance features
      'at_hash / c_hash Claims',
      'Hybrid Flow Support',
      'azp Claim for Multi-Audience',
    ],
  },
  oid4vci: {
    icon: 'Wallet',
    color: 'emerald',
    gradient: 'from-emerald-500 to-teal-500',
    features: [
      'Credential Offer (by value/reference)',
      'Pre-Authorized Code Grant',
      'tx_code Enforcement',
      'Credential Endpoint',
      'c_nonce Freshness',
      'Deferred Issuance',
      'SD-JWT VC Output',
      'Real HTTP + Signatures',
    ],
  },
  oid4vp: {
    icon: 'ScanSearch',
    color: 'indigo',
    gradient: 'from-indigo-500 to-violet-500',
    features: [
      'DCQL-first Requests',
      'Request Object (JAR)',
      'direct_post Transport',
      'direct_post.jwt Transport',
      'Nonce + State Binding',
      'Client ID Scheme Matrix',
      'Verifier Policy Decisions',
      'Wallet Emulator Flow',
    ],
  },
  saml: {
    icon: 'FileKey',
    color: 'cyan',
    gradient: 'from-cyan-500 to-blue-500',
    features: [
      'SP-Initiated SSO',
      'IdP-Initiated SSO',
      'Single Logout (SLO)',
      'HTTP-POST Binding',
      'HTTP-Redirect Binding',
      'XML Assertions',
      'Attribute Statements',
      'Metadata Documents',
    ],
  },
  // SPIFFE/SPIRE - Workload Identity
  spiffe: {
    icon: 'Shield',
    color: 'green',
    gradient: 'from-green-500 to-emerald-500',
    features: [
      'Workload Identity',
      'X.509-SVID',
      'JWT-SVID',
      'Trust Domains',
      'Workload API',
      'mTLS Authentication',
      'Auto Certificate Rotation',
      'Zero Trust Ready',
    ],
  },
  // SCIM 2.0 - Identity Provisioning
  scim: {
    icon: 'Users',
    color: 'purple',
    gradient: 'from-purple-500 to-violet-500',
    features: [
      'User Provisioning',
      'Group Management',
      'Filter Queries',
      'PATCH Operations',
      'Bulk Operations',
      'Schema Discovery',
      'ETag Support',
      'IdP Integration',
    ],
  },
  // SSF - Shared Signals Framework
  ssf: {
    icon: 'Radio',
    color: 'amber',
    gradient: 'from-amber-500 to-orange-500',
    features: [
      'Security Event Tokens (SET)',
      'CAEP Events',
      'RISC Events',
      'Push Delivery',
      'Poll Delivery',
      'Stream Management',
      'Real-time Signals',
      'Zero Trust Ready',
    ],
  },
}

