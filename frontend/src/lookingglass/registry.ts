/**
 * Looking Glass Flow Registry
 * 
 * Manages loading and caching of protocol flows from the backend.
 * Provides a unified interface for accessing flow definitions.
 */

import { api } from '../utils'
import { 
  STANDARD_ACTORS,
  type LookingGlassProtocol, 
  type LookingGlassFlow, 
  type LookingGlassStep,
  type LookingGlassParameter,
  type LookingGlassSecurity,
  type LookingGlassActor,
} from './types'

/**
 * Backend protocol response type
 */
interface BackendProtocol {
  id: string
  name: string
  version: string
  description: string
  tags?: string[]
}

/**
 * Backend flow response type
 */
interface BackendFlow {
  id: string
  name: string
  description: string
  steps: BackendFlowStep[]
  executable: boolean
  category?: string // "workload-api", "admin", "infrastructure"
}

interface BackendFlowStep {
  order: number
  name: string
  description: string
  from: string
  to: string
  type: string
  parameters?: Record<string, string>
  security?: string[]
}

/**
 * Protocol color mapping
 */
const PROTOCOL_COLORS: Record<string, string> = {
  oauth2: 'blue',
  oidc: 'orange',
  saml: 'purple',
  webauthn: 'green',
  fido2: 'cyan',
}

/**
 * Protocol icon mapping
 */
const PROTOCOL_ICONS: Record<string, string> = {
  oauth2: 'key',
  oidc: 'fingerprint',
  saml: 'shield',
  webauthn: 'smartphone',
  fido2: 'lock',
}

/**
 * Transform backend protocol to Looking Glass protocol
 */
function transformProtocol(backend: BackendProtocol): Omit<LookingGlassProtocol, 'flows'> {
  return {
    id: backend.id,
    name: backend.name,
    version: backend.version,
    description: backend.description,
    color: PROTOCOL_COLORS[backend.id] || 'gray',
    icon: PROTOCOL_ICONS[backend.id] || 'circle',
  }
}

/**
 * Transform backend flow step to Looking Glass step
 */
function transformStep(backend: BackendFlowStep, flowId: string): LookingGlassStep {
  // Transform parameters
  const parameters: LookingGlassParameter[] = backend.parameters
    ? Object.entries(backend.parameters).map(([name, description]) => ({
        name,
        description,
        required: !description.toLowerCase().includes('optional'),
        sensitivity: inferSensitivity(name),
      }))
    : []

  // Transform security notes
  const security: LookingGlassSecurity[] = backend.security
    ? backend.security.map(note => ({
        type: inferSecurityType(note),
        title: extractSecurityTitle(note),
        description: note,
      }))
    : []

  return {
    id: `${flowId}-step-${backend.order}`,
    order: backend.order,
    name: backend.name,
    description: backend.description,
    from: backend.from,
    to: backend.to,
    type: backend.type as LookingGlassStep['type'],
    parameters,
    security,
  }
}

/**
 * Transform backend flow to Looking Glass flow
 */
function transformFlow(backend: BackendFlow, protocolId: string): LookingGlassFlow {
  return {
    id: backend.id,
    protocolId,
    name: backend.name,
    description: backend.description,
    steps: backend.steps.map(step => transformStep(step, backend.id)),
  }
}

/**
 * Infer parameter sensitivity from name
 */
function inferSensitivity(name: string): LookingGlassParameter['sensitivity'] {
  const secretPatterns = ['secret', 'password', 'token', 'key', 'credential', 'verifier']
  const internalPatterns = ['code', 'nonce', 'state', 'challenge']
  
  const lowerName = name.toLowerCase()
  
  if (secretPatterns.some(p => lowerName.includes(p))) {
    return 'secret'
  }
  if (internalPatterns.some(p => lowerName.includes(p))) {
    return 'internal'
  }
  return 'public'
}

/**
 * Infer security annotation type from text
 */
function inferSecurityType(text: string): LookingGlassSecurity['type'] {
  const lowerText = text.toLowerCase()
  
  if (lowerText.includes('critical') || lowerText.includes('vulnerability')) {
    return 'critical'
  }
  if (lowerText.includes('warning') || lowerText.includes('should')) {
    return 'warning'
  }
  if (lowerText.includes('best practice') || lowerText.includes('recommend')) {
    return 'best_practice'
  }
  return 'info'
}

/**
 * Extract a short title from security text
 */
function extractSecurityTitle(text: string): string {
  // Take first sentence or first 50 chars
  const firstSentence = text.split(/[.!?]/)[0]
  if (firstSentence.length <= 50) {
    return firstSentence
  }
  return firstSentence.slice(0, 47) + '...'
}

/**
 * Flow Registry - singleton for managing protocol/flow data
 */
class FlowRegistry {
  private protocols: Map<string, LookingGlassProtocol> = new Map()
  private loading: Map<string, Promise<LookingGlassProtocol>> = new Map()
  private allProtocolsLoaded = false
  private allProtocolsPromise: Promise<LookingGlassProtocol[]> | null = null

  /**
   * Load all available protocols
   */
  async loadAllProtocols(): Promise<LookingGlassProtocol[]> {
    if (this.allProtocolsLoaded) {
      return Array.from(this.protocols.values())
    }

    if (this.allProtocolsPromise) {
      return this.allProtocolsPromise
    }

    this.allProtocolsPromise = this._loadAllProtocols()
    return this.allProtocolsPromise
  }

  private async _loadAllProtocols(): Promise<LookingGlassProtocol[]> {
    try {
      const response = await api.getProtocols()
      
      // Load each protocol with its flows
      const protocols = await Promise.all(
        response.protocols.map(p => this.loadProtocol(p.id))
      )
      
      this.allProtocolsLoaded = true
      return protocols
    } catch (error) {
      console.error('Failed to load protocols:', error)
      throw error
    }
  }

  /**
   * Load a specific protocol with its flows
   */
  async loadProtocol(protocolId: string): Promise<LookingGlassProtocol> {
    // Return cached if available
    const cached = this.protocols.get(protocolId)
    if (cached) {
      return cached
    }

    // Return pending promise if loading
    const pending = this.loading.get(protocolId)
    if (pending) {
      return pending
    }

    // Start loading
    const promise = this._loadProtocol(protocolId)
    this.loading.set(protocolId, promise)
    
    try {
      const protocol = await promise
      this.protocols.set(protocolId, protocol)
      return protocol
    } finally {
      this.loading.delete(protocolId)
    }
  }

  private async _loadProtocol(protocolId: string): Promise<LookingGlassProtocol> {
    // Load protocol info and flows in parallel
    const [protocolInfo, flowsResponse] = await Promise.all([
      api.getProtocol(protocolId),
      api.getProtocolFlows(protocolId),
    ])

    const baseProtocol = transformProtocol(protocolInfo)
    
    // Filter to only include executable flows in the Looking Glass
    // Non-executable flows (admin, infrastructure) are for documentation only
    const executableFlows = flowsResponse.flows.filter(f => f.executable !== false)
    const flows = executableFlows.map(f => transformFlow(f, protocolId))

    return {
      ...baseProtocol,
      flows,
    }
  }

  /**
   * Get a specific flow
   */
  async getFlow(protocolId: string, flowId: string): Promise<LookingGlassFlow | null> {
    const protocol = await this.loadProtocol(protocolId)
    return protocol.flows.find(f => f.id === flowId) || null
  }

  /**
   * Get all flows for a protocol
   */
  async getFlows(protocolId: string): Promise<LookingGlassFlow[]> {
    const protocol = await this.loadProtocol(protocolId)
    return protocol.flows
  }

  /**
   * Get cached protocol (sync, returns null if not loaded)
   */
  getProtocolSync(protocolId: string): LookingGlassProtocol | null {
    return this.protocols.get(protocolId) || null
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.protocols.clear()
    this.loading.clear()
    this.allProtocolsLoaded = false
    this.allProtocolsPromise = null
  }
}

/**
 * Singleton registry instance
 */
export const flowRegistry = new FlowRegistry()

/**
 * Get actors for a flow based on step participants
 */
export function getActorsForFlow(flow: LookingGlassFlow): LookingGlassActor[] {
  const actorIds = new Set<string>()
  
  flow.steps.forEach(step => {
    actorIds.add(step.from.toLowerCase().replace(/\s+/g, '_'))
    actorIds.add(step.to.toLowerCase().replace(/\s+/g, '_'))
  })

  // Map to standard actors or create custom ones
  const actors: LookingGlassActor[] = []
  
  actorIds.forEach(id => {
    // Check for standard actor mappings
    const standardMappings: Record<string, string> = {
      'client': 'client',
      'client_application': 'client',
      'application': 'client',
      'user': 'user',
      'resource_owner': 'user',
      'end_user': 'user',
      'authorization_server': 'auth_server',
      'auth_server': 'auth_server',
      'openid_provider': 'idp',
      'identity_provider': 'idp',
      'idp': 'idp',
      'resource_server': 'resource_server',
      'api': 'resource_server',
    }

    const mappedId = standardMappings[id]
    if (mappedId && STANDARD_ACTORS[mappedId]) {
      if (!actors.find(a => a.id === mappedId)) {
        actors.push(STANDARD_ACTORS[mappedId])
      }
    } else {
      // Create custom actor
      actors.push({
        id,
        name: id.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' '),
        type: 'server',
        icon: 'server',
      })
    }
  })

  return actors
}

