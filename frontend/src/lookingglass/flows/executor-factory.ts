/**
 * Flow Executor Factory
 * 
 * Creates the appropriate executor for each flow type.
 * Maps flow IDs from the backend to RFC-compliant executors.
 */

import type { FlowExecutorBase, FlowExecutorConfig } from './base'
import { AuthorizationCodeExecutor } from './authorization-code'
import { ClientCredentialsExecutor, type ClientCredentialsConfig } from './client-credentials'
import { ImplicitExecutor } from './implicit'
import { RefreshTokenExecutor, type RefreshTokenConfig } from './refresh-token'
import { DeviceCodeExecutor } from './device-code'
import { ResourceOwnerExecutor, type ResourceOwnerConfig } from './resource-owner'
import { OIDCHybridExecutor, type HybridResponseType } from './oidc-hybrid'
import { SPInitiatedSSOExecutor, IdPInitiatedSSOExecutor, type SAMLSSOConfig } from './saml-sso'
import { SAMLLogoutExecutor, type SAMLLogoutConfig } from './saml-logout'
import { X509SVIDExecutor, JWTSVIDExecutor, MTLSExecutor, CertRotationExecutor, type SPIFFESVIDConfig } from './spiffe-svid'

// ============================================================================
// Flow ID Mapping
// ============================================================================

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type ExecutorClass = new (config: any) => FlowExecutorBase

/**
 * Maps flow IDs from the backend to executor types
 */
export const FLOW_EXECUTOR_MAP: Record<string, {
  executorClass: ExecutorClass
  description: string
  rfcReference: string
  requiresUserInteraction: boolean
  additionalConfig?: Record<string, unknown>
}> = {
  // OAuth 2.0 Flows
  'authorization-code': {
    executorClass: AuthorizationCodeExecutor,
    description: 'Standard authorization code flow for server-side applications',
    rfcReference: 'RFC 6749 Section 4.1',
    requiresUserInteraction: true,
    additionalConfig: { usePkce: false },
  },
  'authorization-code-pkce': {
    executorClass: AuthorizationCodeExecutor,
    description: 'Authorization code with PKCE for public clients (SPAs, mobile)',
    rfcReference: 'RFC 6749 Section 4.1 + RFC 7636',
    requiresUserInteraction: true,
    additionalConfig: { usePkce: true },
  },
  'client-credentials': {
    executorClass: ClientCredentialsExecutor,
    description: 'Machine-to-machine authentication',
    rfcReference: 'RFC 6749 Section 4.4',
    requiresUserInteraction: false,
  },
  'implicit': {
    executorClass: ImplicitExecutor,
    description: 'Legacy flow - tokens returned directly (NOT recommended)',
    rfcReference: 'RFC 6749 Section 4.2',
    requiresUserInteraction: true,
    additionalConfig: { responseType: 'token' },
  },
  'refresh-token': {
    executorClass: RefreshTokenExecutor,
    description: 'Obtain new access token using refresh token',
    rfcReference: 'RFC 6749 Section 6',
    requiresUserInteraction: false,
  },
  'device-code': {
    executorClass: DeviceCodeExecutor,
    description: 'For devices with limited input capabilities',
    rfcReference: 'RFC 8628',
    requiresUserInteraction: true, // User interaction on separate device
  },
  'password': {
    executorClass: ResourceOwnerExecutor,
    description: 'Legacy flow - direct username/password (NOT recommended)',
    rfcReference: 'RFC 6749 Section 4.3',
    requiresUserInteraction: false, // No browser interaction
  },
  
  // OIDC Flows
  'oidc-authorization-code': {
    executorClass: AuthorizationCodeExecutor,
    description: 'OIDC authorization code flow with ID token',
    rfcReference: 'OIDC Core 1.0 Section 3.1',
    requiresUserInteraction: true,
    additionalConfig: { usePkce: true, includeNonce: true },
  },
  'oidc-implicit': {
    executorClass: ImplicitExecutor,
    description: 'OIDC implicit flow with id_token',
    rfcReference: 'OIDC Core 1.0 Section 3.2',
    requiresUserInteraction: true,
    additionalConfig: { responseType: 'id_token token', includeNonce: true },
  },
  'oidc-hybrid': {
    executorClass: OIDCHybridExecutor,
    description: 'OIDC hybrid flow - some tokens from authz, some from token endpoint',
    rfcReference: 'OIDC Core 1.0 Section 3.3',
    requiresUserInteraction: true,
    additionalConfig: { responseType: 'code id_token' as HybridResponseType },
  },

  // SAML 2.0 Flows
  'saml-sp-sso': {
    executorClass: SPInitiatedSSOExecutor,
    description: 'SP-initiated SAML Single Sign-On',
    rfcReference: 'SAML 2.0 Profiles Section 4.1.3',
    requiresUserInteraction: true,
    additionalConfig: { binding: 'post' as const },
  },
  'saml-sp-sso-redirect': {
    executorClass: SPInitiatedSSOExecutor,
    description: 'SP-initiated SAML SSO with HTTP-Redirect binding',
    rfcReference: 'SAML 2.0 Bindings Section 3.4',
    requiresUserInteraction: true,
    additionalConfig: { binding: 'redirect' as const },
  },
  'saml-idp-sso': {
    executorClass: IdPInitiatedSSOExecutor,
    description: 'IdP-initiated SAML SSO (unsolicited response)',
    rfcReference: 'SAML 2.0 Profiles Section 4.1.5',
    requiresUserInteraction: true,
    additionalConfig: { binding: 'post' as const },
  },
  'saml-logout': {
    executorClass: SAMLLogoutExecutor,
    description: 'SAML Single Logout',
    rfcReference: 'SAML 2.0 Profiles Section 4.4',
    requiresUserInteraction: false,
    additionalConfig: { spInitiated: true, binding: 'post' as const },
  },
  'saml-logout-redirect': {
    executorClass: SAMLLogoutExecutor,
    description: 'SAML Single Logout with HTTP-Redirect binding',
    rfcReference: 'SAML 2.0 Bindings Section 3.4',
    requiresUserInteraction: false,
    additionalConfig: { spInitiated: true, binding: 'redirect' as const },
  },

  // SPIFFE/SPIRE Flows
  'x509-svid-issuance': {
    executorClass: X509SVIDExecutor,
    description: 'X.509-SVID certificate acquisition from SPIRE Workload API',
    rfcReference: 'SPIFFE X.509-SVID Specification',
    requiresUserInteraction: false,
    additionalConfig: { trustDomain: 'protocolsoup.com' },
  },
  'jwt-svid-issuance': {
    executorClass: JWTSVIDExecutor,
    description: 'JWT-SVID token acquisition from SPIRE Workload API',
    rfcReference: 'SPIFFE JWT-SVID Specification',
    requiresUserInteraction: false,
    additionalConfig: { trustDomain: 'protocolsoup.com', audience: 'protocolsoup' },
  },
  'mtls-service-call': {
    executorClass: MTLSExecutor,
    description: 'Mutual TLS service-to-service call using X.509-SVIDs',
    rfcReference: 'SPIFFE mTLS + RFC 8446',
    requiresUserInteraction: false,
    additionalConfig: { trustDomain: 'protocolsoup.com' },
  },
  'mtls-handshake': {
    executorClass: MTLSExecutor,
    description: 'mTLS handshake with X.509-SVIDs',
    rfcReference: 'SPIFFE mTLS + RFC 8446',
    requiresUserInteraction: false,
    additionalConfig: { trustDomain: 'protocolsoup.com' },
  },
  'certificate-rotation': {
    executorClass: CertRotationExecutor,
    description: 'Analyze automatic X.509-SVID certificate rotation mechanism',
    rfcReference: 'SPIFFE Workload API',
    requiresUserInteraction: false,
    additionalConfig: { trustDomain: 'protocolsoup.com' },
  },
  'jwt-api-auth': {
    executorClass: JWTSVIDExecutor,
    description: 'Acquire JWT-SVID for API authentication',
    rfcReference: 'SPIFFE JWT-SVID Specification',
    requiresUserInteraction: false,
    additionalConfig: { trustDomain: 'protocolsoup.com', audience: 'api' },
  },
  'workload-attestation': {
    executorClass: X509SVIDExecutor,
    description: 'SPIRE workload identity attestation via Workload API',
    rfcReference: 'SPIFFE Workload API',
    requiresUserInteraction: false,
    additionalConfig: { trustDomain: 'protocolsoup.com' },
  },
  'trust-bundle': {
    executorClass: X509SVIDExecutor,
    description: 'Fetch trust bundle for certificate chain validation',
    rfcReference: 'SPIFFE Trust Bundle',
    requiresUserInteraction: false,
    additionalConfig: { trustDomain: 'protocolsoup.com' },
  },
  'trust-bundle-federation': {
    executorClass: X509SVIDExecutor,
    description: 'Cross-trust-domain federation via SPIFFE bundles',
    rfcReference: 'SPIFFE Federation',
    requiresUserInteraction: false,
    additionalConfig: { trustDomain: 'protocolsoup.com' },
  },
  'workload-registration': {
    executorClass: X509SVIDExecutor,
    description: 'Workload registration with SPIRE Server',
    rfcReference: 'SPIFFE Workload API',
    requiresUserInteraction: false,
    additionalConfig: { trustDomain: 'protocolsoup.com' },
  },
  'node-attestation': {
    executorClass: X509SVIDExecutor,
    description: 'SPIRE node attestation and agent bootstrap',
    rfcReference: 'SPIFFE Node Attestation',
    requiresUserInteraction: false,
    additionalConfig: { trustDomain: 'protocolsoup.com' },
  },
}

// ============================================================================
// Factory Functions
// ============================================================================

export interface ExecutorFactoryConfig {
  /** Protocol base URL (e.g., /oauth2, /oidc) */
  protocolBaseUrl: string
  /** Client ID */
  clientId: string
  /** Client secret (for confidential clients) */
  clientSecret?: string
  /** Redirect URI */
  redirectUri?: string
  /** Scopes to request */
  scopes: string[]
  /** Refresh token (for refresh-token flow) */
  refreshToken?: string
  /** Username (for password flow) */
  username?: string
  /** Password (for password flow) */
  password?: string
}

/**
 * Create an executor for the specified flow
 */
export function createFlowExecutor(
  flowId: string,
  config: ExecutorFactoryConfig
): FlowExecutorBase | null {
  console.log('[ExecutorFactory] Creating executor for flowId:', flowId)
  console.log('[ExecutorFactory] Available flows:', Object.keys(FLOW_EXECUTOR_MAP))
  
  const flowConfig = FLOW_EXECUTOR_MAP[flowId]
  
  if (!flowConfig) {
    console.warn(`[ExecutorFactory] No executor found for flow: ${flowId}`)
    return null
  }
  
  console.log('[ExecutorFactory] Found config:', flowConfig.description)

  const baseConfig: FlowExecutorConfig = {
    baseUrl: config.protocolBaseUrl,
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    redirectUri: config.redirectUri,
    scopes: config.scopes,
  }

  // Merge additional config for the flow
  const fullConfig = {
    ...baseConfig,
    ...flowConfig.additionalConfig,
  }

  // Add flow-specific config
  if (flowId === 'refresh-token' && config.refreshToken) {
    (fullConfig as RefreshTokenConfig).refreshToken = config.refreshToken
  }

  if (flowId === 'password' && config.username && config.password) {
    (fullConfig as ResourceOwnerConfig).username = config.username;
    (fullConfig as ResourceOwnerConfig).password = config.password
  }

  if (flowId === 'client-credentials' && config.clientSecret) {
    (fullConfig as ClientCredentialsConfig).clientSecret = config.clientSecret
  }

  // Handle SAML flows
  if (flowId.startsWith('saml-')) {
    // SAML flows don't use OAuth scopes
    (fullConfig as SAMLSSOConfig | SAMLLogoutConfig).scopes = []
  }

  // Handle SPIFFE flows
  if (flowId.includes('svid') || flowId.includes('mtls') || flowId.includes('rotation') || flowId.includes('attestation') || flowId.includes('bundle')) {
    // SPIFFE flows need trustDomain
    (fullConfig as SPIFFESVIDConfig).trustDomain = (flowConfig.additionalConfig?.trustDomain as string) || 'protocolsoup.com'
    if (flowConfig.additionalConfig?.audience) {
      (fullConfig as SPIFFESVIDConfig).audience = flowConfig.additionalConfig.audience as string
    }
  }

  try {
    return new flowConfig.executorClass(fullConfig)
  } catch (error) {
    console.error(`Failed to create executor for ${flowId}:`, error)
    return null
  }
}

/**
 * Get information about a flow
 */
export function getFlowInfo(flowId: string): {
  supported: boolean
  description: string
  rfcReference: string
  requiresUserInteraction: boolean
} | null {
  console.log('[getFlowInfo] Looking up:', flowId, 'Available:', Object.keys(FLOW_EXECUTOR_MAP))
  const flowConfig = FLOW_EXECUTOR_MAP[flowId]
  
  if (!flowConfig) {
    console.log('[getFlowInfo] Not found:', flowId)
    return null
  }

  console.log('[getFlowInfo] Found:', flowConfig.description)
  return {
    supported: true,
    description: flowConfig.description,
    rfcReference: flowConfig.rfcReference,
    requiresUserInteraction: flowConfig.requiresUserInteraction,
  }
}

/**
 * List all supported flows
 */
export function listSupportedFlows(): string[] {
  return Object.keys(FLOW_EXECUTOR_MAP)
}

/**
 * Check if a flow requires additional config
 */
export function getFlowRequirements(flowId: string): {
  requiresClientSecret: boolean
  requiresRefreshToken: boolean
  requiresCredentials: boolean
  requiresSessionInfo?: boolean
} {
  switch (flowId) {
    case 'client-credentials':
      return { requiresClientSecret: true, requiresRefreshToken: false, requiresCredentials: false }
    case 'refresh-token':
      return { requiresClientSecret: false, requiresRefreshToken: true, requiresCredentials: false }
    case 'password':
      return { requiresClientSecret: false, requiresRefreshToken: false, requiresCredentials: true }
    case 'saml-logout':
    case 'saml-logout-redirect':
      return { requiresClientSecret: false, requiresRefreshToken: false, requiresCredentials: false, requiresSessionInfo: true }
    default:
      return { requiresClientSecret: false, requiresRefreshToken: false, requiresCredentials: false }
  }
}
