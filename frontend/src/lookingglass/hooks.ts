/**
 * Looking Glass React Hooks
 * 
 * Provides React hooks for integrating with the Looking Glass engine.
 */

import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { useWebSocket } from '../hooks/useWebSocket'
import { flowRegistry, getActorsForFlow } from './registry'
import {
  DEFAULT_CONFIG,
  type LookingGlassProtocol,
  type LookingGlassFlow,
  type LookingGlassSession,
  type LookingGlassEvent,
  type LookingGlassEventType,
  type LookingGlassConfig,
  type LookingGlassActor,
} from './types'

/**
 * Hook to load all available protocols
 */
export function useProtocols() {
  const [protocols, setProtocols] = useState<LookingGlassProtocol[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    setLoading(true)
    flowRegistry.loadAllProtocols()
      .then(setProtocols)
      .catch(setError)
      .finally(() => setLoading(false))
  }, [])

  return { protocols, loading, error }
}

/**
 * Hook to load a specific protocol
 */
export function useProtocol(protocolId: string | null) {
  const [protocol, setProtocol] = useState<LookingGlassProtocol | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    if (!protocolId) {
      setProtocol(null)
      return
    }

    setLoading(true)
    flowRegistry.loadProtocol(protocolId)
      .then(setProtocol)
      .catch(setError)
      .finally(() => setLoading(false))
  }, [protocolId])

  return { protocol, loading, error }
}

/**
 * Hook to load flows for a protocol
 */
export function useFlows(protocolId: string | null) {
  const [flows, setFlows] = useState<LookingGlassFlow[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    if (!protocolId) {
      setFlows([])
      return
    }

    setLoading(true)
    flowRegistry.getFlows(protocolId)
      .then(setFlows)
      .catch(setError)
      .finally(() => setLoading(false))
  }, [protocolId])

  return { flows, loading, error }
}

/**
 * Hook to load a specific flow
 */
export function useFlow(protocolId: string | null, flowId: string | null) {
  const [flow, setFlow] = useState<LookingGlassFlow | null>(null)
  const [actors, setActors] = useState<LookingGlassActor[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    if (!protocolId || !flowId) {
      setFlow(null)
      setActors([])
      return
    }

    setLoading(true)
    flowRegistry.getFlow(protocolId, flowId)
      .then(f => {
        setFlow(f)
        if (f) {
          setActors(getActorsForFlow(f))
        }
      })
      .catch(setError)
      .finally(() => setLoading(false))
  }, [protocolId, flowId])

  return { flow, actors, loading, error }
}

/**
 * Hook for managing a Looking Glass session
 */
export function useLookingGlassSession(
  sessionId: string | null,
  config: Partial<LookingGlassConfig> = {}
) {
  const mergedConfig = useMemo(() => ({ ...DEFAULT_CONFIG, ...config }), [config])
  
  const [session] = useState<LookingGlassSession | null>(null)
  const [events, setEvents] = useState<LookingGlassEvent[]>([])
  const [currentStepIndex, setCurrentStepIndex] = useState(0)
  const eventsRef = useRef<LookingGlassEvent[]>([])

  // WebSocket URL for the session
  const wsUrl = sessionId ? `/ws/lookingglass/${sessionId}` : null

  // Handle incoming WebSocket messages
  const handleMessage = useCallback((message: string) => {
    try {
      const parsed = JSON.parse(message)
      
      const event: LookingGlassEvent = {
        id: parsed.id || crypto.randomUUID(),
        sessionId: sessionId || '',
        timestamp: parsed.timestamp ? new Date(parsed.timestamp) : new Date(),
        type: parsed.type as LookingGlassEventType || 'flow.step',
        title: parsed.title || 'Event',
        description: parsed.description,
        stepId: parsed.step_id,
        status: inferEventStatus(parsed),
        data: parsed.data,
        annotations: parsed.annotations,
        duration: parsed.duration,
      }

      // Update events with limit
      setEvents(prev => {
        const updated = [event, ...prev].slice(0, mergedConfig.maxEvents)
        eventsRef.current = updated
        return updated
      })

      // Update current step if this is a step event
      if (event.type === 'flow.step' && event.data?.step !== undefined) {
        setCurrentStepIndex(Number(event.data.step))
      }
    } catch {
      // Ignore non-JSON messages
    }
  }, [sessionId, mergedConfig.maxEvents])

  const { connected, send } = useWebSocket(wsUrl, {
    onMessage: handleMessage,
    reconnect: true,
    reconnectInterval: 3000,
    maxReconnectAttempts: 10,
  })

  // Clear events
  const clearEvents = useCallback(() => {
    setEvents([])
    eventsRef.current = []
    setCurrentStepIndex(0)
  }, [])

  // Send a command to the session
  const sendCommand = useCallback((command: string, data?: Record<string, unknown>) => {
    send(JSON.stringify({ command, ...data }))
  }, [send])

  return {
    session,
    events,
    currentStepIndex,
    connected,
    clearEvents,
    sendCommand,
    config: mergedConfig,
  }
}

/**
 * Hook for running a flow simulation
 */
export function useFlowSimulation(flow: LookingGlassFlow | null) {
  const [isSimulating, setIsSimulating] = useState(false)
  const [currentStepIndex, setCurrentStepIndex] = useState(-1)
  const [completedSteps, setCompletedSteps] = useState<Set<number>>(new Set())
  const [events, setEvents] = useState<LookingGlassEvent[]>([])
  const timeoutRef = useRef<ReturnType<typeof setTimeout>[]>([])

  // Clean up timeouts on unmount
  useEffect(() => {
    return () => {
      timeoutRef.current.forEach(clearTimeout)
    }
  }, [])

  const startSimulation = useCallback((speed: number = 1200) => {
    if (!flow || isSimulating) return

    // Clear previous state
    setIsSimulating(true)
    setCurrentStepIndex(-1)
    setCompletedSteps(new Set())
    setEvents([])
    timeoutRef.current.forEach(clearTimeout)
    timeoutRef.current = []

    // Schedule each step
    flow.steps.forEach((step, index) => {
      const timeout = setTimeout(() => {
        // Create event for this step
        const event: LookingGlassEvent = {
          id: crypto.randomUUID(),
          sessionId: 'simulation',
          timestamp: new Date(),
          type: 'flow.step',
          title: step.name,
          description: step.description,
          stepId: step.id,
          status: 'success',
          data: {
            step: index,
            from: step.from,
            to: step.to,
            type: step.type,
          },
          duration: Math.floor(Math.random() * 200) + 50,
        }

        setEvents(prev => [event, ...prev])
        setCurrentStepIndex(index)
        setCompletedSteps(prev => new Set([...prev, index]))

        // End simulation after last step
        if (index === flow.steps.length - 1) {
          setTimeout(() => setIsSimulating(false), 500)
        }
      }, (index + 1) * speed)

      timeoutRef.current.push(timeout)
    })
  }, [flow, isSimulating])

  const stopSimulation = useCallback(() => {
    timeoutRef.current.forEach(clearTimeout)
    timeoutRef.current = []
    setIsSimulating(false)
  }, [])

  const resetSimulation = useCallback(() => {
    stopSimulation()
    setCurrentStepIndex(-1)
    setCompletedSteps(new Set())
    setEvents([])
  }, [stopSimulation])

  return {
    isSimulating,
    currentStepIndex,
    completedSteps,
    events,
    startSimulation,
    stopSimulation,
    resetSimulation,
  }
}

/**
 * Infer event status from parsed data
 */
function inferEventStatus(parsed: Record<string, unknown>): LookingGlassEvent['status'] {
  const type = String(parsed.type || '')
  
  if (type.includes('error')) return 'error'
  if (type.includes('warning')) return 'warning'
  if (type.includes('pending')) return 'pending'
  return 'success'
}

/**
 * Hook for Looking Glass configuration
 */
export function useLookingGlassConfig(initialConfig: Partial<LookingGlassConfig> = {}) {
  const [config, setConfig] = useState<LookingGlassConfig>({
    ...DEFAULT_CONFIG,
    ...initialConfig,
  })

  const updateConfig = useCallback((updates: Partial<LookingGlassConfig>) => {
    setConfig(prev => ({ ...prev, ...updates }))
  }, [])

  return { config, updateConfig }
}

// ============================================================================
// Real Flow Executor Hook
// ============================================================================

import {
  createFlowExecutor,
  getFlowInfo,
  getFlowRequirements,
  type FlowExecutorBase,
  type FlowExecutorState,
  type ExecutorFactoryConfig,
} from './flows'

export interface UseRealFlowExecutorOptions {
  /** Protocol ID (oauth2, oidc) */
  protocolId: string | null
  /** Flow ID from the backend */
  flowId: string | null
  /** Client ID */
  clientId: string
  /** Client secret (for confidential client flows) */
  clientSecret?: string
  /** Redirect URI */
  redirectUri: string
  /** Scopes */
  scopes: string[]
  /** Refresh token (for refresh-token flow) */
  refreshToken?: string
  /** Username (for password flow) */
  username?: string
  /** Password (for password flow) */
  password?: string
}

export interface RealFlowExecutorResult {
  /** Current execution state */
  state: FlowExecutorState | null
  /** Execute the flow */
  execute: () => Promise<void>
  /** Abort execution */
  abort: () => void
  /** Reset to initial state */
  reset: () => void
  /** Whether currently executing */
  isExecuting: boolean
  /** Flow info */
  flowInfo: {
    supported: boolean
    description: string
    rfcReference: string
    requiresUserInteraction: boolean
  } | null
  /** What this flow requires */
  requirements: {
    requiresClientSecret: boolean
    requiresRefreshToken: boolean
    requiresCredentials: boolean
  }
  /** Error message if flow not supported */
  error: string | null
}

/**
 * Map backend flow IDs to executor flow IDs
 */
function mapFlowId(protocolId: string | null, backendFlowId: string | null): string | null {
  if (!backendFlowId) return null

  // Normalize the flow ID (replace underscores with hyphens, lowercase)
  const normalizedId = backendFlowId.toLowerCase().replace(/_/g, '-')

  console.log('[FlowMapping] Protocol:', protocolId, 'Flow:', backendFlowId, '→ Normalized:', normalizedId)

  // Handle OIDC-prefixed flow IDs from backend (e.g., oidc_authorization_code → oidc-authorization-code)
  if (normalizedId.startsWith('oidc-')) {
    const oidcFlow = normalizedId.replace('oidc-', '')
    switch (oidcFlow) {
      case 'authorization-code':
        return 'oidc-authorization-code'
      case 'implicit':
        return 'oidc-implicit'
      case 'hybrid':
        return 'oidc-hybrid'
    }
  }

  // Protocol-specific mappings for OIDC protocol
  if (protocolId === 'oidc') {
    switch (normalizedId) {
      case 'authorization-code':
      case 'authorization-code-pkce':
        return 'oidc-authorization-code'
      case 'implicit':
        return 'oidc-implicit'
      case 'hybrid':
      case 'code-id-token':
      case 'code-token':
        return 'oidc-hybrid'
      // Don't break - allow fallthrough for flows like client-credentials that work in OIDC too
    }
  }

  // SAML 2.0 mappings
  if (protocolId === 'saml') {
    switch (normalizedId) {
      case 'sp-initiated-sso':
      case 'sp-sso':
        return 'saml-sp-sso'
      case 'sp-initiated-sso-redirect':
        return 'saml-sp-sso-redirect'
      case 'idp-initiated-sso':
      case 'idp-sso':
        return 'saml-idp-sso'
      case 'single-logout':
      case 'slo':
      case 'logout':
        return 'saml-logout'
      case 'single-logout-redirect':
        return 'saml-logout-redirect'
      default:
        // Fall through to default handling
    }
  }

  // SPIFFE/SPIRE mappings
  if (protocolId === 'spiffe') {
    switch (normalizedId) {
      case 'x509-svid-issuance':
      case 'x509-svid':
      case 'x509':
        return 'x509-svid-issuance'
      case 'jwt-svid-issuance':
      case 'jwt-svid':
      case 'jwt':
        return 'jwt-svid-issuance'
      case 'mtls-service-call':
      case 'mtls':
      case 'mtls-call':
      case 'mtls-handshake':
        return 'mtls-service-call'
      case 'certificate-rotation':
      case 'cert-rotation':
      case 'rotation':
        return 'certificate-rotation'
      case 'jwt-api-auth':
      case 'jwt-auth':
        return 'jwt-api-auth'
      case 'workload-attestation':
      case 'attestation':
        return 'workload-attestation'
      case 'trust-bundle':
      case 'bundle':
      case 'trust-bundle-federation':
        return 'trust-bundle'
      case 'workload-registration':
      case 'registration':
        return 'workload-registration'
      case 'node-attestation':
        return 'node-attestation'
      default:
        // Return as-is for SPIFFE
        return normalizedId
    }
  }

  // OAuth 2.0 mappings (also work for OIDC)
  switch (normalizedId) {
    case 'authorization-code':
      return 'authorization-code'
    case 'authorization-code-pkce':
    case 'pkce':
      return 'authorization-code-pkce'
    case 'client-credentials':
      return 'client-credentials'
    case 'implicit':
      return 'implicit'
    case 'refresh-token':
    case 'refresh':
      return 'refresh-token'
    case 'device-code':
    case 'device':
    case 'device-authorization':
      return 'device-code'
    case 'password':
    case 'resource-owner':
    case 'ropc':
      return 'password'
    default:
      console.log('[FlowMapping] No mapping found for:', normalizedId)
      return normalizedId
  }
}

/**
 * Hook for creating and managing RFC-compliant flow executors
 */
export function useRealFlowExecutor(options: UseRealFlowExecutorOptions): RealFlowExecutorResult {
  const executorRef = useRef<FlowExecutorBase | null>(null)
  const [state, setState] = useState<FlowExecutorState | null>(null)
  const [error, setError] = useState<string | null>(null)

  // Map the flow ID
  const executorFlowId = useMemo(() => 
    mapFlowId(options.protocolId, options.flowId),
    [options.protocolId, options.flowId]
  )

  // Get flow info and requirements
  const flowInfo = useMemo(() => 
    executorFlowId ? getFlowInfo(executorFlowId) : null,
    [executorFlowId]
  )

  const requirements = useMemo(() => 
    executorFlowId ? getFlowRequirements(executorFlowId) : {
      requiresClientSecret: false,
      requiresRefreshToken: false,
      requiresCredentials: false,
    },
    [executorFlowId]
  )

  // Create executor when flow changes
  useEffect(() => {
    console.log('[useRealFlowExecutor] Effect triggered:', {
      executorFlowId,
      protocolId: options.protocolId,
      flowId: options.flowId,
    })

    // Clean up previous executor
    if (executorRef.current) {
      executorRef.current.abort()
      executorRef.current = null
    }
    setState(null)
    setError(null)

    if (!executorFlowId || !options.protocolId) {
      console.log('[useRealFlowExecutor] Missing executorFlowId or protocolId, skipping')
      return
    }

    // Build config - all protocols are mounted at /{protocol-id}
    const protocolBaseUrl = `/${options.protocolId}`

    const config: ExecutorFactoryConfig = {
      protocolBaseUrl,
      clientId: options.clientId,
      clientSecret: options.clientSecret,
      redirectUri: options.redirectUri,
      scopes: options.scopes,
      refreshToken: options.refreshToken,
      username: options.username,
      password: options.password,
    }

    console.log('[useRealFlowExecutor] Creating executor for:', executorFlowId, 'with config:', config)

    // Create the executor
    const executor = createFlowExecutor(executorFlowId, config)

    if (!executor) {
      console.log('[useRealFlowExecutor] Failed to create executor for:', executorFlowId)
      setError(`Flow "${options.flowId}" is not supported for live execution yet`)
      return
    }

    console.log('[useRealFlowExecutor] Executor created successfully:', executor.flowName)
    executorRef.current = executor

    // Subscribe to state changes
    const unsubscribe = executor.subscribe((newState) => {
      console.log('[useRealFlowExecutor] State update:', newState.status, newState.events.length, 'events')
      setState(newState)
    })

    return () => {
      unsubscribe()
      executor.abort()
    }
  // Use JSON stringify for array comparison to avoid unnecessary re-runs
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    executorFlowId,
    options.protocolId,
    options.clientId,
    options.clientSecret,
    options.redirectUri,
    // eslint-disable-next-line react-hooks/exhaustive-deps
    JSON.stringify(options.scopes),
    options.refreshToken,
    options.username,
    options.password,
    options.flowId,
  ])

  const execute = useCallback(async () => {
    console.log('[useRealFlowExecutor] Execute called, executor:', executorRef.current?.flowName)
    if (!executorRef.current) {
      console.error('[useRealFlowExecutor] No executor available!')
      setError('No executor available')
      return
    }

    try {
      console.log('[useRealFlowExecutor] Starting execution...')
      await executorRef.current.execute()
      console.log('[useRealFlowExecutor] Execution completed')
    } catch (err) {
      console.error('[useRealFlowExecutor] Flow execution error:', err)
    }
  }, [])

  const abort = useCallback(() => {
    executorRef.current?.abort()
  }, [])

  const reset = useCallback(() => {
    executorRef.current?.reset()
  }, [])

  const isExecuting = state?.status === 'executing' || state?.status === 'awaiting_user'

  return {
    state,
    execute,
    abort,
    reset,
    isExecuting,
    flowInfo,
    requirements,
    error,
  }
}
