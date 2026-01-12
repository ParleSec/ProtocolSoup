/**
 * Protocol Hooks - React hooks for the protocol registry
 * 
 * These hooks provide a clean interface for components to
 * access protocol data from the backend plugin system.
 * Falls back to frontend fallback-data when API doesn't return flows.
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
import { fallbackFlows } from './fallback-data'

// Re-export types for convenience
export type { FlowStep, FlowDefinition, Protocol }

/**
 * Get fallback flows for a protocol from frontend data
 */
function getFallbackFlowsForProtocol(protocolId: string): FlowDefinition[] {
  // Map protocol IDs to their flow prefixes
  const protocolFlowPrefixes: Record<string, string[]> = {
    oauth2: ['authorization_code', 'client_credentials', 'refresh_token', 'token_introspection', 'token_revocation'],
    oidc: ['oidc_authorization_code', 'oidc_implicit', 'oidc_hybrid', 'oidc_userinfo', 'oidc_discovery'],
    saml: ['saml_sp_initiated_sso', 'saml_idp_initiated_sso', 'saml_single_logout', 'saml_metadata'],
    spiffe: ['x509-svid-issuance', 'jwt-svid-issuance', 'mtls-handshake', 'certificate-rotation'],
    scim: ['scim_user_lifecycle', 'scim_group_management', 'scim_filter_queries', 'scim_schema_discovery', 'scim_bulk_operations'],
    ssf: ['ssf_stream_configuration', 'ssf_push_delivery', 'ssf_poll_delivery', 'caep_session_revoked', 'caep_credential_change', 'risc_account_disabled', 'risc_credential_compromise'],
  }

  const flowIds = protocolFlowPrefixes[protocolId] || []
  
  return flowIds
    .filter(id => fallbackFlows[id])
    .map(id => ({
      id,
      name: fallbackFlows[id].title,
      description: fallbackFlows[id].description,
      steps: fallbackFlows[id].steps,
      executable: false,
    }))
}

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
 * Hook to fetch flows for a protocol
 * Falls back to frontend fallback-data when API returns empty or fails
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
        // If API returns flows, use them
        if (apiFlows && apiFlows.length > 0) {
          setFlows(apiFlows)
        } else {
          // Otherwise, fall back to frontend fallback data
          const fallback = getFallbackFlowsForProtocol(protocolId)
          setFlows(fallback)
        }
      })
      .catch((err) => {
        // On error, try fallback data instead of showing error
        const fallback = getFallbackFlowsForProtocol(protocolId)
        if (fallback.length > 0) {
          setFlows(fallback)
          setError(null)
        } else {
          setError(err)
        }
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
    f.id === flowId?.replace(/-/g, '_')
  )

  return { flow, loading, error }
}

