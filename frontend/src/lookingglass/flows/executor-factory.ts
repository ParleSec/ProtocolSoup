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
} {
  switch (flowId) {
    case 'client-credentials':
      return { requiresClientSecret: true, requiresRefreshToken: false, requiresCredentials: false }
    case 'refresh-token':
      return { requiresClientSecret: false, requiresRefreshToken: true, requiresCredentials: false }
    case 'password':
      return { requiresClientSecret: false, requiresRefreshToken: false, requiresCredentials: true }
    default:
      return { requiresClientSecret: false, requiresRefreshToken: false, requiresCredentials: false }
  }
}
