/**
 * Looking Glass Core Types
 * 
 * Protocol-agnostic types for the Looking Glass inspection engine.
 * These types are designed to work with any authentication/authorization protocol.
 */

/**
 * A protocol supported by the Looking Glass
 */
export interface LookingGlassProtocol {
  id: string
  name: string
  version: string
  description: string
  icon?: string
  color?: string
  flows: LookingGlassFlow[]
}

/**
 * A flow within a protocol (e.g., Authorization Code, Client Credentials)
 */
export interface LookingGlassFlow {
  id: string
  protocolId: string
  name: string
  description: string
  steps: LookingGlassStep[]
  /** Security considerations for this flow */
  securityNotes?: string[]
  /** When to use this flow */
  useCases?: string[]
  /** RFC or spec reference */
  reference?: string
}

/**
 * A step within a flow
 */
export interface LookingGlassStep {
  id: string
  order: number
  name: string
  description: string
  /** Actor initiating this step */
  from: string
  /** Actor receiving this step */
  to: string
  /** Type of interaction */
  type: 'request' | 'response' | 'redirect' | 'internal' | 'user_action'
  /** Parameters involved in this step */
  parameters?: LookingGlassParameter[]
  /** Security considerations */
  security?: LookingGlassSecurity[]
  /** Code example */
  codeExample?: string
  /** Duration estimate in ms */
  estimatedDuration?: number
}

/**
 * A parameter in a protocol step
 */
export interface LookingGlassParameter {
  name: string
  description: string
  required: boolean
  /** Example value */
  example?: string
  /** Security sensitivity level */
  sensitivity?: 'public' | 'internal' | 'secret'
}

/**
 * Security annotation for a step
 */
export interface LookingGlassSecurity {
  type: 'info' | 'warning' | 'critical' | 'best_practice'
  title: string
  description: string
  reference?: string
}

/**
 * A real-time event from the Looking Glass engine
 */
export interface LookingGlassEvent {
  id: string
  sessionId: string
  timestamp: Date
  /** Event category */
  type: LookingGlassEventType
  /** Human-readable title */
  title: string
  /** Detailed description */
  description?: string
  /** Which flow step this relates to */
  stepId?: string
  /** Status of this event */
  status: 'pending' | 'success' | 'warning' | 'error'
  /** Event-specific data */
  data?: Record<string, unknown>
  /** Security annotations */
  annotations?: LookingGlassSecurity[]
  /** Duration in milliseconds */
  duration?: number
}

/**
 * Event types emitted by the Looking Glass
 */
export type LookingGlassEventType =
  | 'flow.started'
  | 'flow.step'
  | 'flow.completed'
  | 'flow.error'
  | 'request.sent'
  | 'request.received'
  | 'response.sent'
  | 'response.received'
  | 'token.issued'
  | 'token.validated'
  | 'token.refreshed'
  | 'token.revoked'
  | 'security.info'
  | 'security.warning'
  | 'security.error'
  | 'crypto.operation'
  | 'user.action'

/**
 * A Looking Glass session
 */
export interface LookingGlassSession {
  id: string
  protocolId: string
  flowId: string
  state: 'idle' | 'active' | 'paused' | 'completed' | 'error'
  events: LookingGlassEvent[]
  /** Current step index */
  currentStep: number
  /** Session metadata */
  metadata?: Record<string, unknown>
  createdAt: Date
  updatedAt: Date
}

/**
 * Actor in a flow diagram
 */
export interface LookingGlassActor {
  id: string
  name: string
  type: 'client' | 'server' | 'user' | 'resource' | 'identity_provider'
  description?: string
  icon?: string
}

/**
 * Configuration for the Looking Glass visualization
 */
export interface LookingGlassConfig {
  /** Show security annotations inline */
  showSecurityHints: boolean
  /** Auto-scroll to latest event */
  autoScroll: boolean
  /** Show code examples */
  showCodeExamples: boolean
  /** Show parameter details */
  showParameters: boolean
  /** Animation speed (ms per step) */
  animationSpeed: number
  /** Maximum events to display */
  maxEvents: number
}

/**
 * Default configuration
 */
export const DEFAULT_CONFIG: LookingGlassConfig = {
  showSecurityHints: true,
  autoScroll: true,
  showCodeExamples: true,
  showParameters: true,
  animationSpeed: 1000,
  maxEvents: 100,
}

/**
 * Standard actors used across protocols
 */
export const STANDARD_ACTORS: Record<string, LookingGlassActor> = {
  client: {
    id: 'client',
    name: 'Client Application',
    type: 'client',
    description: 'The application requesting access',
    icon: 'monitor',
  },
  user: {
    id: 'user',
    name: 'Resource Owner',
    type: 'user',
    description: 'The end user who owns the resources',
    icon: 'user',
  },
  auth_server: {
    id: 'auth_server',
    name: 'Authorization Server',
    type: 'identity_provider',
    description: 'The server issuing access tokens',
    icon: 'shield',
  },
  resource_server: {
    id: 'resource_server',
    name: 'Resource Server',
    type: 'resource',
    description: 'The server hosting protected resources',
    icon: 'database',
  },
  idp: {
    id: 'idp',
    name: 'Identity Provider',
    type: 'identity_provider',
    description: 'OpenID Provider authenticating users',
    icon: 'key',
  },
  scim_server: {
    id: 'scim_server',
    name: 'SCIM Server',
    type: 'resource',
    description: 'SCIM 2.0 server for user/group provisioning',
    icon: 'users',
  },
}


