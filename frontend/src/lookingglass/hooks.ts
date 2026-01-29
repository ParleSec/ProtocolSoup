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
  type WireCapturedExchange,
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
  
  const [session, setSession] = useState<LookingGlassSession | null>(null)
  const [events, setEvents] = useState<LookingGlassEvent[]>([])
  const [wireExchanges, setWireExchanges] = useState<WireCapturedExchange[]>([])
  const [currentStepIndex, setCurrentStepIndex] = useState(0)
  const eventsRef = useRef<LookingGlassEvent[]>([])
  const eventIdsRef = useRef<Set<string>>(new Set())
  const wireExchangeIdsRef = useRef<Set<string>>(new Set())

  // WebSocket URL for the session
  const wsUrl = sessionId ? `/ws/lookingglass/${sessionId}` : null

  useEffect(() => {
    setEvents([])
    setWireExchanges([])
    setCurrentStepIndex(0)
    eventsRef.current = []
    eventIdsRef.current = new Set()
    wireExchangeIdsRef.current = new Set()
  }, [sessionId])

  // Handle incoming WebSocket messages
  const handleMessage = useCallback((message: string) => {
    const chunks = message.split('\n').filter(Boolean)
    for (const chunk of chunks) {
      try {
        const parsed = JSON.parse(chunk) as {
          type?: string
          payload?: Record<string, unknown>
        }
        const messageType = parsed.type || ''
        const payload = (parsed.payload || parsed) as Record<string, unknown>

        if (messageType === 'session.info') {
          const sessionInfo = payload as Record<string, unknown>
          setSession({
            id: String(sessionInfo.id || sessionId || ''),
            protocolId: String(sessionInfo.protocol_id || ''),
            flowId: String(sessionInfo.flow_id || ''),
            state: (sessionInfo.state as LookingGlassSession['state']) || 'active',
            events: [],
            currentStep: 0,
            metadata: {},
            createdAt: sessionInfo.created_at ? new Date(String(sessionInfo.created_at)) : new Date(),
            updatedAt: sessionInfo.created_at ? new Date(String(sessionInfo.created_at)) : new Date(),
          })
          continue
        }

        const eventType = (payload.type || messageType) as LookingGlassEventType || 'flow.step'
        const eventId = String(payload.id || crypto.randomUUID())
        if (eventIdsRef.current.has(eventId)) {
          continue
        }
        eventIdsRef.current.add(eventId)

        const event: LookingGlassEvent = {
          id: eventId,
          sessionId: sessionId || '',
          timestamp: payload.timestamp ? new Date(String(payload.timestamp)) : new Date(),
          type: eventType,
          title: String(payload.title || 'Event'),
          description: payload.description ? String(payload.description) : undefined,
          stepId: payload.step_id ? String(payload.step_id) : undefined,
          status: inferEventStatus(eventType),
          data: payload.data as Record<string, unknown> | undefined,
          annotations: payload.annotations as LookingGlassEvent['annotations'],
          duration: typeof payload.duration === 'number' ? payload.duration : undefined,
        }

        setEvents(prev => {
          const updated = [event, ...prev].slice(0, mergedConfig.maxEvents)
          eventsRef.current = updated
          return updated
        })

        if (event.type === 'flow.step' && event.data?.step !== undefined) {
          setCurrentStepIndex(Number(event.data.step))
        }

        if (event.type === 'http.exchange' && event.data?.exchange) {
          const exchange = normalizeWireExchange(event.data.exchange)
          if (exchange && !wireExchangeIdsRef.current.has(exchange.id)) {
            wireExchangeIdsRef.current.add(exchange.id)
            setWireExchanges(prev => [exchange, ...prev].slice(0, mergedConfig.maxEvents))
          }
        }
      } catch {
        // Ignore malformed message chunks
      }
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
    setWireExchanges([])
    eventsRef.current = []
    eventIdsRef.current = new Set()
    wireExchangeIdsRef.current = new Set()
    setCurrentStepIndex(0)
  }, [])

  // Send a command to the session
  const sendCommand = useCallback((command: string, data?: Record<string, unknown>) => {
    send(JSON.stringify({ command, ...data }))
  }, [send])

  return {
    session,
    events,
    wireExchanges,
    currentStepIndex,
    connected,
    clearEvents,
    sendCommand,
    config: mergedConfig,
  }
}

/**
 * Infer event status from parsed data
 */
function inferEventStatus(eventType: string): LookingGlassEvent['status'] {
  if (eventType.includes('error')) return 'error'
  if (eventType.includes('warning')) return 'warning'
  if (eventType.includes('pending')) return 'pending'
  return 'success'
}

function normalizeWireExchange(raw: unknown): WireCapturedExchange | null {
  if (!raw || typeof raw !== 'object') {
    return null
  }
  const data = raw as Record<string, unknown>
  const request = normalizeWireMessage(data.request)
  const response = normalizeWireMessage(data.response)
  if (!request || !response) {
    return null
  }

  return {
    id: String(data.id || crypto.randomUUID()),
    sessionId: data.session_id ? String(data.session_id) : undefined,
    request,
    response,
    timing: normalizeWireTiming(data.timing),
    tls: normalizeWireTLS(data.tls),
    meta: normalizeWireMeta(data.meta),
  }
}

function normalizeWireMessage(raw: unknown): WireCapturedExchange['request'] | null {
  if (!raw || typeof raw !== 'object') {
    return null
  }
  const data = raw as Record<string, unknown>
  return {
    method: data.method ? String(data.method) : undefined,
    url: data.url ? String(data.url) : undefined,
    host: data.host ? String(data.host) : undefined,
    proto: data.proto ? String(data.proto) : undefined,
    headers: normalizeWireHeaders(data.headers),
    body: normalizeWirePayload(data.body),
    raw: normalizeWirePayload(data.raw),
    status: typeof data.status === 'number' ? data.status : undefined,
    statusText: data.status_text ? String(data.status_text) : undefined,
  }
}

function normalizeWireHeaders(raw: unknown): Record<string, string[]> | undefined {
  if (!raw || typeof raw !== 'object') {
    return undefined
  }
  const headers = raw as Record<string, unknown>
  const normalized: Record<string, string[]> = {}
  for (const [key, value] of Object.entries(headers)) {
    if (Array.isArray(value)) {
      normalized[key] = value.map(item => String(item))
    } else if (value != null) {
      normalized[key] = [String(value)]
    }
  }
  return normalized
}

function normalizeWirePayload(raw: unknown): WireCapturedExchange['request']['body'] | undefined {
  if (!raw || typeof raw !== 'object') {
    return undefined
  }
  const payload = raw as Record<string, unknown>
  const encoding = payload.encoding === 'base64' ? 'base64' : 'utf-8'
  return {
    encoding,
    data: typeof payload.data === 'string' ? payload.data : undefined,
    size: typeof payload.size === 'number' ? payload.size : 0,
    truncated: Boolean(payload.truncated),
    contentType: typeof payload.content_type === 'string' ? payload.content_type : undefined,
  }
}

function normalizeWireTiming(raw: unknown): WireCapturedExchange['timing'] {
  if (!raw || typeof raw !== 'object') {
    return { startUnixMicro: 0, endUnixMicro: 0, durationMicro: 0 }
  }
  const timing = raw as Record<string, unknown>
  return {
    startUnixMicro: Number(timing.start_unix_micro || 0),
    endUnixMicro: Number(timing.end_unix_micro || 0),
    durationMicro: Number(timing.duration_micro || 0),
  }
}

function normalizeWireTLS(raw: unknown): WireCapturedExchange['tls'] | undefined {
  if (!raw || typeof raw !== 'object') {
    return undefined
  }
  const tls = raw as Record<string, unknown>
  return {
    version: tls.version ? String(tls.version) : undefined,
    cipherSuite: tls.cipher_suite ? String(tls.cipher_suite) : undefined,
    serverName: tls.server_name ? String(tls.server_name) : undefined,
    negotiatedProtocol: tls.negotiated_protocol ? String(tls.negotiated_protocol) : undefined,
    peerCertSubjects: Array.isArray(tls.peer_cert_subjects)
      ? tls.peer_cert_subjects.map(item => String(item))
      : undefined,
  }
}

function normalizeWireMeta(raw: unknown): WireCapturedExchange['meta'] {
  if (!raw || typeof raw !== 'object') {
    return {
      captureSource: 'unknown',
      headerOrderPreserved: false,
      bodyLimitBytes: 0,
      requestBodyReadBytes: 0,
      responseBodyWrittenBytes: 0,
      rawReconstructed: false,
    }
  }
  const meta = raw as Record<string, unknown>
  return {
    captureSource: String(meta.capture_source || 'middleware'),
    headerOrderPreserved: Boolean(meta.header_order_preserved),
    bodyLimitBytes: Number(meta.body_limit_bytes || 0),
    requestBodyReadBytes: Number(meta.request_body_read_bytes || 0),
    responseBodyWrittenBytes: Number(meta.response_body_written_bytes || 0),
    rawReconstructed: Boolean(meta.raw_reconstructed),
  }
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
  /** Bearer token (for SCIM flows) */
  bearerToken?: string
  /** Token to introspect or revoke */
  token?: string
  /** Access token (for UserInfo endpoint) */
  accessToken?: string
  /** Looking Glass session ID for wire capture */
  lookingGlassSessionId?: string
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
      case 'interaction-code':
        // Interaction code flow - comprehensive OIDC flow with discovery, PKCE, nonce
        return 'interaction-code'
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

  // SCIM 2.0 mappings
  if (protocolId === 'scim') {
    switch (normalizedId) {
      case 'user-lifecycle':
      case 'user-provisioning':
        return 'user-lifecycle'
      case 'group-membership':
      case 'group-management':
        return 'group-membership'
      case 'user-discovery':
      case 'filter-query':
      case 'filter-queries':
        return 'user-discovery'
      case 'bulk-operations':
      case 'bulk':
        return 'bulk-operations'
      case 'schema-discovery':
      case 'discovery':
        return 'schema-discovery'
      default:
        // Return as-is for SCIM
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
      bearerToken: options.bearerToken,
      token: options.token,
      accessToken: options.accessToken,
      lookingGlassSessionId: options.lookingGlassSessionId,
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
    options.bearerToken,
    options.flowId,
    options.token,
    options.accessToken,
    options.lookingGlassSessionId,
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
