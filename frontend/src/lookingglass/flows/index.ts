/**
 * Flow Executors Index
 * 
 * Each flow executor implements the EXACT protocol flow per the relevant RFC.
 * This is not simulation - these are real protocol calls.
 */

// Base types and utilities
export {
  FlowExecutorBase,
  generateSecureRandom,
  generateCodeVerifier,
  generateCodeChallenge,
  type FlowExecutorConfig,
  type FlowExecutorState,
  type FlowEvent,
  type CapturedExchange,
  type DecodedToken,
  type FlowStateListener,
} from './base'

// Individual executors
export { AuthorizationCodeExecutor, type AuthorizationCodeConfig } from './authorization-code'
export { ClientCredentialsExecutor, type ClientCredentialsConfig } from './client-credentials'
export { ImplicitExecutor, type ImplicitConfig } from './implicit'
export { RefreshTokenExecutor, type RefreshTokenConfig } from './refresh-token'
export { DeviceCodeExecutor, type DeviceCodeConfig } from './device-code'
export { OIDCHybridExecutor, type OIDCHybridConfig, type HybridResponseType } from './oidc-hybrid'
export { ResourceOwnerExecutor, type ResourceOwnerConfig } from './resource-owner'

// SAML executors
export { 
  SAMLSSOExecutor, 
  SPInitiatedSSOExecutor, 
  IdPInitiatedSSOExecutor,
  type SAMLSSOConfig 
} from './saml-sso'
export { 
  SAMLLogoutExecutor, 
  SPInitiatedLogoutExecutor,
  type SAMLLogoutConfig 
} from './saml-logout'

// Factory
export {
  createFlowExecutor,
  getFlowInfo,
  listSupportedFlows,
  getFlowRequirements,
  FLOW_EXECUTOR_MAP,
  type ExecutorFactoryConfig,
} from './executor-factory'

