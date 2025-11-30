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

