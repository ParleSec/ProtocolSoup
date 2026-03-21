/**
 * Looking Glass Module Barrel Export
 * 
 * The Looking Glass is a protocol-agnostic inspection engine that can
 * visualize and explain any authentication/authorization flow.
 */

// Types
export * from './types'

// Registry
export { flowRegistry, getActorsForFlow } from './registry'

// Hooks
export {
  useProtocols,
  useProtocol,
  useFlows,
  useFlow,
  useLookingGlassSession,
  useLookingGlassConfig,
  useRealFlowExecutor,
  type UseRealFlowExecutorOptions,
  type RealFlowExecutorResult,
} from './hooks'

// Flow-specific executors (RFC-compliant real protocol execution)
export {
  // Factory
  createFlowExecutor,
  getFlowInfo,
  listSupportedFlows,
  getFlowRequirements,
  FLOW_EXECUTOR_MAP,
  // Base types
  FlowExecutorBase,
  type FlowExecutorConfig as RealFlowConfig,
  type FlowExecutorState as RealFlowState,
  type FlowEvent,
  type CapturedExchange,
  type ExecutorFactoryConfig,
  // Individual executors
  AuthorizationCodeExecutor,
  ClientCredentialsExecutor,
  ImplicitExecutor,
  RefreshTokenExecutor,
  DeviceCodeExecutor,
  OIDCHybridExecutor,
  ResourceOwnerExecutor,
} from './flows'


// Components
export * from './components'

