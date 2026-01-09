/**
 * Protocol Registry - Frontend module system
 * 
 * This module provides a frontend registry for protocols that mirrors
 * the backend plugin architecture. It fetches protocol definitions
 * from the API and provides them to components.
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

const API_BASE = '/api'

/**
 * Fetch all registered protocols from the backend
 */
export async function fetchProtocols(): Promise<Protocol[]> {
  const response = await fetch(`${API_BASE}/protocols`)
  if (!response.ok) {
    throw new Error(`Failed to fetch protocols: ${response.statusText}`)
  }
  const data = await response.json()
  return data.protocols
}

/**
 * Fetch a single protocol by ID
 */
export async function fetchProtocol(id: string): Promise<Protocol> {
  const response = await fetch(`${API_BASE}/protocols/${id}`)
  if (!response.ok) {
    throw new Error(`Failed to fetch protocol ${id}: ${response.statusText}`)
  }
  return response.json()
}

/**
 * Fetch flows for a specific protocol
 */
export async function fetchProtocolFlows(protocolId: string): Promise<FlowDefinition[]> {
  const response = await fetch(`${API_BASE}/protocols/${protocolId}/flows`)
  if (!response.ok) {
    throw new Error(`Failed to fetch flows for ${protocolId}: ${response.statusText}`)
  }
  const data = await response.json()
  return data.flows
}

/**
 * Start a demo session
 */
export async function startDemo(protocolId: string, flowId: string): Promise<{
  session_id: string
  ws_endpoint: string
  scenario: DemoScenario
}> {
  const response = await fetch(`${API_BASE}/protocols/${protocolId}/demo/${flowId}`, {
    method: 'POST',
  })
  if (!response.ok) {
    throw new Error(`Failed to start demo: ${response.statusText}`)
  }
  return response.json()
}

/**
 * Decode a JWT token via the backend
 */
export async function decodeToken(token: string): Promise<{
  header: Record<string, unknown>
  payload: Record<string, unknown>
  signature: string
  valid: boolean
  errors?: string[]
}> {
  const response = await fetch(`${API_BASE}/lookingglass/decode`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  })
  if (!response.ok) {
    throw new Error(`Failed to decode token: ${response.statusText}`)
  }
  return response.json()
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
}

