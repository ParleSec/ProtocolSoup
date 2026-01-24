/**
 * Protocol Hooks - React hooks for the protocol registry
 * 
 * These hooks provide a clean interface for components to
 * access protocol data from the backend plugin system.
 * Uses backend protocol data only.
 */

import { useState, useEffect, useCallback } from 'react'
import {
  Protocol,
  FlowDefinition,
  FlowStep,
  fetchProtocols,
  fetchProtocol,
  fetchProtocolFlows,
} from './registry'
// Re-export types for convenience
export type { FlowStep, FlowDefinition, Protocol }

/**
 * Hook to fetch all protocols
 */
export function useProtocols() {
  const [protocols, setProtocols] = useState<Protocol[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    fetchProtocols()
      .then(setProtocols)
      .catch(setError)
      .finally(() => setLoading(false))
  }, [])

  return { protocols, loading, error }
}

/**
 * Hook to fetch a single protocol
 */
export function useProtocol(id: string | undefined) {
  const [protocol, setProtocol] = useState<Protocol | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    if (!id) {
      setLoading(false)
      return
    }

    setLoading(true)
    fetchProtocol(id)
      .then(setProtocol)
      .catch(setError)
      .finally(() => setLoading(false))
  }, [id])

  return { protocol, loading, error }
}

/**
 * Hook to fetch flows for a protocol from backend plugins
 */
export function useProtocolFlows(protocolId: string | undefined) {
  const [flows, setFlows] = useState<FlowDefinition[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  const refetch = useCallback(() => {
    if (!protocolId) {
      setLoading(false)
      return
    }

    setLoading(true)
    fetchProtocolFlows(protocolId)
      .then((apiFlows) => {
        if (!apiFlows || apiFlows.length === 0) {
          setFlows([])
          setError(new Error(`No flows returned for protocol "${protocolId}"`))
          return
        }
        setFlows(apiFlows)
      })
      .catch((err) => {
        setFlows([])
        setError(err)
      })
      .finally(() => setLoading(false))
  }, [protocolId])

  useEffect(() => {
    refetch()
  }, [refetch])

  return { flows, loading, error, refetch }
}

/**
 * Hook to get a specific flow from a protocol
 */
export function useFlow(protocolId: string | undefined, flowId: string | undefined) {
  const { flows, loading, error } = useProtocolFlows(protocolId)
  
  const flow = flows.find(f =>
    f.id === flowId ||
    f.id === flowId?.replace(/-/g, '_') ||
    f.id.replace(/_/g, '-') === flowId
  )

  return { flow, loading, error }
}

