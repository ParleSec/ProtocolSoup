/**
 * Looking Glass - Protocol Execution & Inspection
 */

import React, { useState, useCallback, useMemo, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  Eye, Play, RotateCcw, Key, Terminal, Square,
  ChevronRight, Fingerprint, Shield, Lock, Sparkles,
  RefreshCw, FileKey, KeyRound, Workflow, Search, Trash2, User
} from 'lucide-react'

import {
  useProtocols,
  useRealFlowExecutor,
  useLookingGlassSession,
  ProtocolSelector,
  RealFlowPanel,
  type LookingGlassProtocol,
  type LookingGlassFlow,
} from '../lookingglass'

import { TokenInspector } from '../components/lookingglass/TokenInspector'
import { LookingGlassSEO } from '../components/common/SEO'

export function LookingGlass() {
  useParams<{ sessionId?: string }>()
  const navigate = useNavigate()

  const [selectedProtocol, setSelectedProtocol] = useState<LookingGlassProtocol | null>(null)
  const [selectedFlow, setSelectedFlow] = useState<LookingGlassFlow | null>(null)
  const [inspectedToken, setInspectedToken] = useState('')
  const [refreshTokenInput, setRefreshTokenInput] = useState('')
  const [storedRefreshToken, setStoredRefreshToken] = useState<string | null>(null)
  const [storedAccessToken, setStoredAccessToken] = useState<string | null>(null)
  // Token input for introspection/revocation/userinfo flows
  const [tokenInput, setTokenInput] = useState('')
  const [scimBearerToken, setScimBearerToken] = useState('')
  const [scimTokenLoading, setScimTokenLoading] = useState(false)
  const [scimAuthEnabled, setScimAuthEnabled] = useState(true)
  const [wireSessionId, setWireSessionId] = useState<string | null>(null)
  const [wireSessionError, setWireSessionError] = useState<string | null>(null)
  const [pendingExecute, setPendingExecute] = useState(false)

  const { protocols, loading: protocolsLoading } = useProtocols()
  const {
    wireExchanges,
    connected: wireConnected,
    clearEvents: clearWireEvents,
  } = useLookingGlassSession(wireSessionId)

  // Fetch SCIM token when SCIM protocol is selected
  useEffect(() => {
    if (selectedProtocol?.id === 'scim' && !scimBearerToken) {
      setScimTokenLoading(true)
      fetch('/scim/internal/token')
        .then(res => res.json())
        .then(data => {
          if (data.token) {
            setScimBearerToken(data.token)
          }
          setScimAuthEnabled(data.authEnabled ?? true)
        })
        .catch(err => {
          console.error('Failed to fetch SCIM token:', err)
        })
        .finally(() => {
          setScimTokenLoading(false)
        })
    }
  }, [selectedProtocol?.id, scimBearerToken])

  const scopes = useMemo(() => {
    // Client credentials flow uses machine-client scopes (api:read, api:write)
    if (selectedFlow?.id?.toLowerCase().replace(/_/g, '-') === 'client-credentials') {
      return ['api:read', 'api:write']
    }
    return selectedProtocol?.id === 'oidc' 
      ? ['openid', 'profile', 'email'] 
      : ['profile', 'email']
  }, [selectedProtocol?.id, selectedFlow?.id])

  const flowId = useMemo(() => 
    selectedFlow?.id?.toLowerCase().replace(/_/g, '-'),
    [selectedFlow?.id]
  )

  const showTLSContext = useMemo(() => {
    const normalizedFlowId = flowId || ''
    const protocolId = selectedProtocol?.id || ''
    return normalizedFlowId.includes('mtls')
      || normalizedFlowId.includes('certificate')
      || protocolId === 'spiffe'
      || (protocolId === 'oauth2' && normalizedFlowId === 'mtls-token-binding')
  }, [flowId, selectedProtocol?.id])

  const isRefreshTokenFlow = flowId === 'refresh-token'
  const isTokenIntrospectionFlow = flowId === 'token-introspection'
  const isTokenRevocationFlow = flowId === 'token-revocation'
  const isUserInfoFlow = flowId === 'oidc-userinfo'
  const isTokenBasedFlow = isTokenIntrospectionFlow || isTokenRevocationFlow || isUserInfoFlow
  const isSCIMFlow = selectedProtocol?.id === 'scim'
  
  // Use stored token or user input for flows that need a token
  const activeToken = tokenInput || storedAccessToken || ''

  const [machineClientSecret, setMachineClientSecret] = useState<string | null>(null)

  useEffect(() => {
    if (flowId !== 'client-credentials') {
      setMachineClientSecret(null)
      return
    }

    let cancelled = false
    fetch('/oauth2/demo/clients')
      .then(async (res) => {
        if (!res.ok) {
          throw new Error('Failed to fetch demo clients')
        }
        return res.json()
      })
      .then((data) => {
        if (cancelled) return
        const clients = Array.isArray(data?.clients) ? data.clients : []
        const machineClient = clients.find((client: { id?: string }) => client?.id === 'machine-client')
        setMachineClientSecret(machineClient?.secret || null)
      })
      .catch(() => {
        if (!cancelled) {
          setMachineClientSecret(null)
        }
      })

    return () => {
      cancelled = true
    }
  }, [flowId])

  const clientConfig = useMemo(() => {
    if (flowId === 'client-credentials') {
      return { clientId: 'machine-client', clientSecret: machineClientSecret || undefined }
    }
    // All other flows (including refresh-token) use public-app
    // The refresh token must be used with the same client that obtained it
    return { clientId: 'public-app', clientSecret: undefined }
  }, [flowId, machineClientSecret])

  // Use stored token, input, or empty
  const activeRefreshToken = refreshTokenInput || storedRefreshToken || ''

  const realExecutor = useRealFlowExecutor({
    protocolId: selectedProtocol?.id || null,
    flowId: selectedFlow?.id || null,
    clientId: clientConfig.clientId,
    clientSecret: clientConfig.clientSecret,
    redirectUri: `${window.location.origin}/callback`,
    scopes,
    refreshToken: isRefreshTokenFlow ? activeRefreshToken : undefined,
    token: (isTokenIntrospectionFlow || isTokenRevocationFlow) ? activeToken : undefined,
    accessToken: isUserInfoFlow ? activeToken : undefined,
    bearerToken: isSCIMFlow ? scimBearerToken : undefined,
    lookingGlassSessionId: wireSessionId || undefined,
  })

  // Store tokens from completed flows
  useEffect(() => {
    if (realExecutor.state?.status === 'completed') {
      if (realExecutor.state.tokens.refreshToken) {
        setStoredRefreshToken(realExecutor.state.tokens.refreshToken)
      }
      if (realExecutor.state.tokens.accessToken) {
        setStoredAccessToken(realExecutor.state.tokens.accessToken)
      }
    }
  }, [realExecutor.state?.status, realExecutor.state?.tokens.refreshToken, realExecutor.state?.tokens.accessToken])

  const handleProtocolSelect = useCallback((protocol: LookingGlassProtocol) => {
    // SSF has its own dedicated sandbox - redirect there
    if (protocol.id === 'ssf') {
      navigate('/ssf-sandbox')
      return
    }
    setSelectedProtocol(protocol)
    setSelectedFlow(null)
    realExecutor.reset()
    setWireSessionId(null)
    clearWireEvents()
    setWireSessionError(null)
    setPendingExecute(false)
    setInspectedToken('')
  }, [realExecutor, clearWireEvents, navigate])

  const handleFlowSelect = useCallback((flow: LookingGlassFlow) => {
    // SSF flows should redirect to the SSF Sandbox
    if (selectedProtocol?.id === 'ssf') {
      navigate('/ssf-sandbox')
      return
    }
    setSelectedFlow(flow)
    realExecutor.reset()
    setWireSessionId(null)
    clearWireEvents()
    setWireSessionError(null)
    setPendingExecute(false)
    setInspectedToken('')
  }, [realExecutor, clearWireEvents, selectedProtocol, navigate])

  const handleReset = useCallback(() => {
    realExecutor.reset()
    setWireSessionId(null)
    clearWireEvents()
    setWireSessionError(null)
    setPendingExecute(false)
    setInspectedToken('')
  }, [realExecutor, clearWireEvents])

  const startWireSession = useCallback(async () => {
    if (!selectedProtocol || !selectedFlow) {
      return null
    }
    setWireSessionError(null)
    try {
      clearWireEvents()
      const response = await fetch(`/api/protocols/${selectedProtocol.id}/demo/${selectedFlow.id}`, {
        method: 'POST',
      })
      if (!response.ok) {
        const errorData = await response.json().catch(() => null) as { error?: string } | null
        throw new Error(errorData?.error || 'Failed to start wire capture session')
      }
      const data = await response.json() as { session_id?: string }
      if (!data.session_id) {
        throw new Error('No session ID returned for wire capture')
      }
      setWireSessionId(data.session_id)
      return data.session_id
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to start wire capture session'
      setWireSessionError(message)
      return null
    }
  }, [selectedProtocol, selectedFlow, clearWireEvents])

  const handleExecute = useCallback(async () => {
    if (!wireSessionId) {
      setPendingExecute(true)
      const created = await startWireSession()
      if (!created) {
        setPendingExecute(false)
      }
      return
    }
    realExecutor.execute()
  }, [wireSessionId, startWireSession, realExecutor])

  useEffect(() => {
    if (pendingExecute && wireSessionId) {
      realExecutor.execute()
      setPendingExecute(false)
    }
  }, [pendingExecute, wireSessionId, realExecutor])

  const handleQuickSelect = useCallback((protocolId: string, flowId: string) => {
    const normalizeFlowId = (id: string) => id.toLowerCase().replace(/_/g, '-')

    // SSF flows should redirect to the SSF Sandbox
    if (protocolId === 'ssf') {
      navigate('/ssf-sandbox')
      return
    }
    const protocol = protocols.find(p => p.id === protocolId)
    if (protocol) {
      setSelectedProtocol(protocol)
      const normalizedTarget = normalizeFlowId(flowId)
      const flow = (protocol.flows || []).find(f => normalizeFlowId(f.id) === normalizedTarget)
      if (flow) {
        setSelectedFlow(flow)
        realExecutor.reset()
        setWireSessionId(null)
        clearWireEvents()
        setWireSessionError(null)
        setPendingExecute(false)
        setInspectedToken('')
      }
    }
  }, [protocols, realExecutor, clearWireEvents, navigate])

  const hasCapturedTokens = realExecutor.state?.decodedTokens && realExecutor.state.decodedTokens.length > 0
  const status = realExecutor.state?.status || 'idle'

  return (
    <>
      <LookingGlassSEO />
      <div className="max-w-5xl mx-auto space-y-4 sm:space-y-6">
      {/* Header */}
      <header className="py-2">
        <div className="flex flex-col gap-3">
          <div className="flex items-start justify-between gap-2">
            <h1 className="text-lg sm:text-2xl font-semibold text-white flex items-center gap-2 sm:gap-3 min-w-0">
              <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-purple-500/20 flex items-center justify-center flex-shrink-0">
                <Eye className="w-4 h-4 sm:w-5 sm:h-5 text-cyan-400" />
              </div>
              <span className="truncate">Looking Glass</span>
            </h1>
            {status !== 'idle' && (
              <StatusBadge status={status} />
            )}
          </div>
          <p className="text-surface-400 text-xs sm:text-base ml-10 sm:ml-[52px] leading-relaxed">
            Execute protocol flows and inspect the traffic
          </p>
        </div>
      </header>

      {/* Quick Select - when nothing selected */}
      {!selectedFlow && !protocolsLoading && (
        <section>
          <div className="flex items-center gap-2 text-surface-400 text-sm mb-3">
            <Sparkles className="w-4 h-4 text-amber-400" />
            <span>Quick start - select a flow to begin</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            <FlowButton
              icon={Workflow}
              label="Interaction Code Flow"
              sublabel="Full OAuth 2.0 + OIDC"
              color="cyan"
              onClick={() => handleQuickSelect('oidc', 'interaction-code')}
            />
            <FlowButton
              icon={Shield}
              label="Authorization Code"
              sublabel="OAuth 2.0"
              color="blue"
              onClick={() => handleQuickSelect('oauth2', 'authorization_code')}
            />
            <FlowButton
              icon={Lock}
              label="Client Credentials"
              sublabel="OAuth 2.0"
              color="green"
              onClick={() => handleQuickSelect('oauth2', 'client_credentials')}
            />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 mt-3">
            <FlowButton
              icon={RefreshCw}
              label="Refresh Token"
              sublabel="OAuth 2.0"
              color="purple"
              onClick={() => handleQuickSelect('oauth2', 'refresh_token')}
            />
            <FlowButton
              icon={Fingerprint}
              label="OIDC Auth Code"
              sublabel="OpenID Connect"
              color="orange"
              onClick={() => handleQuickSelect('oidc', 'oidc_authorization_code')}
            />
            <FlowButton
              icon={FileKey}
              label="SP-Initiated SSO"
              sublabel="SAML 2.0"
              color="blue"
              onClick={() => handleQuickSelect('saml', 'sp_initiated_sso')}
            />
          </div>
        </section>
      )}

      {/* Protocol Selector */}
      <section className="rounded-xl border border-white/10 bg-surface-900/30 p-3 sm:p-5">
        <div className="flex items-center justify-between mb-3 sm:mb-4">
          <div className="flex items-center gap-2">
            <Terminal className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-surface-400" />
            <span className="text-xs sm:text-sm font-medium text-surface-300">Configuration</span>
          </div>
          {selectedFlow && (
            <button
              onClick={handleReset}
              className="flex items-center gap-1 sm:gap-1.5 text-xs sm:text-sm text-surface-400 hover:text-white transition-colors"
            >
              <RotateCcw className="w-3 h-3 sm:w-3.5 sm:h-3.5" />
              Reset
            </button>
          )}
        </div>
        
        <ProtocolSelector
          protocols={protocols}
          selectedProtocol={selectedProtocol}
          selectedFlow={selectedFlow}
          onProtocolSelect={handleProtocolSelect}
          onFlowSelect={handleFlowSelect}
          loading={protocolsLoading}
        />

        {/* Refresh Token Input - shown when refresh token flow is selected */}
        {isRefreshTokenFlow && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="mt-3 sm:mt-4 pt-3 sm:pt-4 border-t border-white/10"
          >
            <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 mb-2">
              <RefreshCw className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-blue-400" />
              <span className="text-xs sm:text-sm font-medium text-surface-300">Refresh Token</span>
              {storedRefreshToken && !refreshTokenInput && (
                <span className="px-1.5 sm:px-2 py-0.5 rounded text-[10px] sm:text-xs bg-green-500/10 text-green-400">
                  Captured ✓
                </span>
              )}
            </div>
            <p className="text-[10px] sm:text-xs text-surface-400 mb-2 sm:mb-3 leading-relaxed">
              Run Authorization Code flow first, or paste a token below.
            </p>
            <div className="flex gap-2">
              <input
                type="text"
                value={refreshTokenInput}
                onChange={(e) => setRefreshTokenInput(e.target.value)}
                placeholder={storedRefreshToken ? "Using captured (or paste new)" : "Paste token here..."}
                className="flex-1 min-w-0 px-2.5 sm:px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-xs sm:text-sm font-mono text-white placeholder-surface-600 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 transition-all"
              />
              {storedRefreshToken && (
                <button
                  onClick={() => setRefreshTokenInput(storedRefreshToken)}
                  className="px-2.5 sm:px-3 py-2 rounded-lg bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs sm:text-sm hover:bg-blue-500/20 transition-colors flex-shrink-0"
                  title="Use captured refresh token"
                >
                  <RefreshCw className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                </button>
              )}
            </div>
            {!activeRefreshToken && (
              <p className="mt-2 text-[10px] sm:text-xs text-amber-400 leading-relaxed">
                ⚠️ No token available. Run Auth Code flow first.
              </p>
            )}
          </motion.div>
        )}

        {/* Access Token Input - shown for introspection, revocation, userinfo flows */}
        {isTokenBasedFlow && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="mt-3 sm:mt-4 pt-3 sm:pt-4 border-t border-white/10"
          >
            <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 mb-2">
              {isTokenIntrospectionFlow && <Search className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-cyan-400" />}
              {isTokenRevocationFlow && <Trash2 className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-red-400" />}
              {isUserInfoFlow && <User className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-green-400" />}
              <span className="text-xs sm:text-sm font-medium text-surface-300">
                {isTokenIntrospectionFlow && 'Token to Introspect'}
                {isTokenRevocationFlow && 'Token to Revoke'}
                {isUserInfoFlow && 'Access Token'}
              </span>
              {storedAccessToken && !tokenInput && (
                <span className="px-1.5 sm:px-2 py-0.5 rounded text-[10px] sm:text-xs bg-green-500/10 text-green-400">
                  Captured ✓
                </span>
              )}
            </div>
            <p className="text-[10px] sm:text-xs text-surface-400 mb-2 sm:mb-3 leading-relaxed">
              {isTokenIntrospectionFlow && 'Run Authorization Code or Client Credentials flow first, or paste a token below.'}
              {isTokenRevocationFlow && 'Run an authorization flow first to get a token, or paste one below.'}
              {isUserInfoFlow && 'Run OIDC Authorization Code flow first (with openid scope), or paste a token below.'}
            </p>
            <div className="flex gap-2">
              <input
                type="text"
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value)}
                placeholder={storedAccessToken ? "Using captured (or paste new)" : "Paste token here..."}
                className={`flex-1 min-w-0 px-2.5 sm:px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-xs sm:text-sm font-mono text-white placeholder-surface-600 focus:outline-none transition-all ${
                  isTokenIntrospectionFlow ? 'focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20' :
                  isTokenRevocationFlow ? 'focus:border-red-500/50 focus:ring-1 focus:ring-red-500/20' :
                  'focus:border-green-500/50 focus:ring-1 focus:ring-green-500/20'
                }`}
              />
              {storedAccessToken && (
                <button
                  onClick={() => setTokenInput(storedAccessToken)}
                  className={`px-2.5 sm:px-3 py-2 rounded-lg text-xs sm:text-sm transition-colors flex-shrink-0 ${
                    isTokenIntrospectionFlow ? 'bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20' :
                    isTokenRevocationFlow ? 'bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20' :
                    'bg-green-500/10 border border-green-500/30 text-green-400 hover:bg-green-500/20'
                  }`}
                  title="Use captured access token"
                >
                  <Key className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                </button>
              )}
            </div>
            {!activeToken && (
              <p className="mt-2 text-[10px] sm:text-xs text-amber-400 leading-relaxed">
                ⚠️ No token available. Run Auth Code flow first.
              </p>
            )}
          </motion.div>
        )}

        {/* SCIM Bearer Token Input - shown when SCIM protocol is selected */}
        {isSCIMFlow && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="mt-3 sm:mt-4 pt-3 sm:pt-4 border-t border-white/10"
          >
            <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 mb-2">
              <KeyRound className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-purple-400" />
              <span className="text-xs sm:text-sm font-medium text-surface-300">SCIM Bearer Token</span>
              {scimTokenLoading && (
                <span className="px-1.5 sm:px-2 py-0.5 rounded text-[10px] sm:text-xs bg-blue-500/10 text-blue-400 animate-pulse">
                  Loading...
                </span>
              )}
              {!scimTokenLoading && scimBearerToken && (
                <span className="px-1.5 sm:px-2 py-0.5 rounded text-[10px] sm:text-xs bg-green-500/10 text-green-400">
                  Auto-configured ✓
                </span>
              )}
              {!scimTokenLoading && !scimAuthEnabled && (
                <span className="px-1.5 sm:px-2 py-0.5 rounded text-[10px] sm:text-xs bg-amber-500/10 text-amber-400">
                  Auth Disabled
                </span>
              )}
            </div>
            {scimAuthEnabled ? (
              <>
                <p className="text-[10px] sm:text-xs text-surface-400 mb-2 sm:mb-3 leading-relaxed">
                  Bearer token for SCIM API authentication. This is the same token configured for external IdPs like Okta.
                </p>
                <input
                  type="password"
                  value={scimBearerToken}
                  onChange={(e) => setScimBearerToken(e.target.value)}
                  placeholder={scimTokenLoading ? "Loading token..." : "Enter your SCIM bearer token..."}
                  disabled={scimTokenLoading}
                  className="w-full px-2.5 sm:px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-xs sm:text-sm font-mono text-white placeholder-surface-600 focus:outline-none focus:border-purple-500/50 focus:ring-1 focus:ring-purple-500/20 transition-all disabled:opacity-50"
                />
                {!scimBearerToken && !scimTokenLoading && (
                  <p className="mt-2 text-[10px] sm:text-xs text-amber-400 leading-relaxed">
                    ⚠️ Bearer token required. Set SCIM_API_TOKEN in production or enter manually.
                  </p>
                )}
              </>
            ) : (
              <p className="text-[10px] sm:text-xs text-surface-400 leading-relaxed">
                SCIM authentication is disabled. Set <code className="text-purple-400">SCIM_API_TOKEN</code> environment variable to enable.
              </p>
            )}
          </motion.div>
        )}
      </section>

      {/* Execution */}
      {selectedFlow && (
        <motion.section
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-xl border border-white/10 bg-surface-900/30 overflow-hidden"
        >
          {/* Flow Header */}
          <div className="px-3 sm:px-5 py-3 sm:py-4 border-b border-white/10">
            <div className="flex items-start justify-between gap-2 mb-2 sm:mb-0">
              <div className="flex items-center gap-2 sm:gap-3 min-w-0 flex-1">
                <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-lg bg-cyan-500/20 flex items-center justify-center flex-shrink-0">
                  <Play className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-cyan-400" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <code className="text-white font-medium text-xs sm:text-base truncate max-w-[160px] sm:max-w-none">{selectedFlow.id}</code>
                    {realExecutor.flowInfo && (
                      <span className="text-[10px] sm:text-xs text-surface-400 font-mono flex-shrink-0">
                        {realExecutor.flowInfo.rfcReference}
                      </span>
                    )}
                  </div>
                </div>
              </div>
              
              <div className="flex items-center gap-1.5 sm:gap-2 flex-shrink-0">
                {status === 'idle' && (
                  <button
                  onClick={handleExecute}
                    className="flex items-center gap-1.5 sm:gap-2 px-2.5 sm:px-4 py-1.5 sm:py-2 rounded-lg bg-gradient-to-r from-green-500/20 to-emerald-500/20 border border-green-500/30 text-green-400 text-xs sm:text-sm font-medium hover:from-green-500/30 hover:to-emerald-500/30 transition-all"
                  >
                    <Play className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                    <span className="hidden sm:inline">Execute</span>
                    <span className="sm:hidden">Run</span>
                  </button>
                )}
                {(status === 'executing' || status === 'awaiting_user') && (
                  <button
                    onClick={realExecutor.abort}
                    className="flex items-center gap-1.5 sm:gap-2 px-2.5 sm:px-4 py-1.5 sm:py-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs sm:text-sm hover:bg-red-500/20 transition-colors"
                  >
                    <Square className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                    <span className="hidden xs:inline">Abort</span>
                  </button>
                )}
                {status === 'completed' && (
                  <button
                    onClick={realExecutor.reset}
                    className="flex items-center gap-1.5 sm:gap-2 px-2.5 sm:px-4 py-1.5 sm:py-2 rounded-lg bg-surface-800 border border-white/10 text-surface-400 text-xs sm:text-sm hover:text-white transition-colors"
                  >
                    <RotateCcw className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                    <span className="hidden sm:inline">Run Again</span>
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Execution Panel */}
          <div className="p-4 sm:p-5">
            <RealFlowPanel
              state={realExecutor.state}
              onExecute={handleExecute}
              onAbort={realExecutor.abort}
              onReset={handleReset}
              isExecuting={realExecutor.isExecuting}
              flowInfo={realExecutor.flowInfo}
              requirements={realExecutor.requirements}
              error={realExecutor.error}
              wireExchanges={wireExchanges}
              wireConnected={wireConnected}
              wireSessionError={wireSessionError}
              showTLSContext={showTLSContext}
            />
          </div>
        </motion.section>
      )}

      {/* Token Inspector */}
      <AnimatePresence>
        {(hasCapturedTokens || inspectedToken) && (
          <motion.section
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="rounded-xl border border-white/10 bg-surface-900/30 overflow-hidden"
          >
            <div className="px-3 sm:px-5 py-3 sm:py-4 border-b border-white/10 overflow-hidden">
              <div className="flex items-center gap-2 sm:gap-3 mb-2">
                <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-lg bg-amber-500/20 flex items-center justify-center flex-shrink-0">
                  <Key className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-amber-400" />
                </div>
                <span className="font-medium text-white text-xs sm:text-base">Tokens</span>
              </div>
              
              {hasCapturedTokens && (
                <div className="overflow-x-auto scrollbar-hide -mx-3 px-3 sm:mx-0 sm:px-0">
                  <div className="flex items-center gap-1.5 sm:gap-2 pb-1 min-w-max">
                    {realExecutor.state?.tokens.accessToken && (
                      <TokenButton
                        label="access"
                        color="green"
                        active={inspectedToken === realExecutor.state?.tokens.accessToken}
                        onClick={() => setInspectedToken(realExecutor.state?.tokens.accessToken || '')}
                      />
                    )}
                    {realExecutor.state?.tokens.idToken && (
                      <TokenButton
                        label="id"
                        color="orange"
                        active={inspectedToken === realExecutor.state?.tokens.idToken}
                        onClick={() => setInspectedToken(realExecutor.state?.tokens.idToken || '')}
                      />
                    )}
                    {realExecutor.state?.tokens.refreshToken && (
                      <TokenButton
                        label="refresh"
                        color="blue"
                        active={inspectedToken === realExecutor.state?.tokens.refreshToken}
                        onClick={() => setInspectedToken(realExecutor.state?.tokens.refreshToken || '')}
                      />
                    )}
                  </div>
                </div>
              )}
            </div>

            <div className="p-4 sm:p-5">
              {inspectedToken ? (
                <TokenInspector token={inspectedToken} />
              ) : (
                <div className="text-center py-6 text-surface-400 text-sm">
                  Select a token above to decode
                </div>
              )}
            </div>
          </motion.section>
        )}
      </AnimatePresence>

      {/* Manual JWT Input */}
      <section className="rounded-xl border border-white/10 bg-surface-900/30 p-3 sm:p-5">
        <div className="flex items-center gap-2 mb-2 sm:mb-3">
          <Sparkles className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-purple-400" />
          <span className="text-xs sm:text-sm font-medium text-surface-300">Decode any JWT</span>
        </div>
        <div className="flex gap-2">
          <input
            type="text"
            value={inspectedToken}
            onChange={(e) => setInspectedToken(e.target.value)}
            placeholder="Paste token here..."
            className="flex-1 min-w-0 px-2.5 sm:px-4 py-2 sm:py-2.5 rounded-lg bg-surface-900 border border-white/10 text-xs sm:text-sm font-mono text-white placeholder-surface-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
          />
          {inspectedToken && (
            <button
              onClick={() => setInspectedToken('')}
              className="px-3 sm:px-4 py-2 sm:py-2.5 rounded-lg bg-surface-800 text-surface-400 hover:text-white text-xs sm:text-sm transition-colors flex-shrink-0"
            >
              Clear
            </button>
          )}
        </div>
      </section>
    </div>
    </>
  )
}

function StatusBadge({ status }: { status: string }) {
  const config = {
    completed: { bg: 'bg-green-500/10', border: 'border-green-500/30', text: 'text-green-400', label: 'Completed', shortLabel: 'Done' },
    executing: { bg: 'bg-amber-500/10', border: 'border-amber-500/30', text: 'text-amber-400', label: 'Executing...', shortLabel: 'Running' },
    awaiting_user: { bg: 'bg-blue-500/10', border: 'border-blue-500/30', text: 'text-blue-400', label: 'Awaiting input', shortLabel: 'Waiting' },
    error: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', label: 'Error', shortLabel: 'Error' },
  }[status] || { bg: 'bg-surface-800', border: 'border-white/10', text: 'text-surface-400', label: status, shortLabel: status }

  return (
    <div className={`px-2 sm:px-3 py-1 sm:py-1.5 rounded-full ${config.bg} border ${config.border} flex-shrink-0`}>
      <span className={`text-xs sm:text-sm font-medium ${config.text} whitespace-nowrap`}>
        <span className="hidden sm:inline">{config.label}</span>
        <span className="sm:hidden">{config.shortLabel}</span>
      </span>
    </div>
  )
}

function FlowButton({ 
  icon: Icon, 
  label, 
  sublabel, 
  color,
  onClick 
}: {
  icon: React.ElementType
  label: string
  sublabel: string
  color: 'blue' | 'green' | 'orange' | 'purple' | 'cyan'
  onClick: () => void
}) {
  const colors = {
    blue: { border: 'border-blue-500/20 hover:border-blue-500/40 active:border-blue-500/60', bg: 'bg-blue-500/10', text: 'text-blue-400' },
    green: { border: 'border-green-500/20 hover:border-green-500/40 active:border-green-500/60', bg: 'bg-green-500/10', text: 'text-green-400' },
    orange: { border: 'border-orange-500/20 hover:border-orange-500/40 active:border-orange-500/60', bg: 'bg-orange-500/10', text: 'text-orange-400' },
    purple: { border: 'border-purple-500/20 hover:border-purple-500/40 active:border-purple-500/60', bg: 'bg-purple-500/10', text: 'text-purple-400' },
    cyan: { border: 'border-cyan-500/20 hover:border-cyan-500/40 active:border-cyan-500/60', bg: 'bg-cyan-500/10', text: 'text-cyan-400' },
  }
  const c = colors[color]

  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2.5 sm:gap-4 p-2.5 sm:p-4 rounded-xl border ${c.border} bg-gradient-to-br from-white/[0.02] to-transparent hover:from-white/[0.04] active:from-white/[0.06] transition-all text-left group touch-manipulation`}
    >
      <div className={`w-8 h-8 sm:w-10 sm:h-10 rounded-lg ${c.bg} flex items-center justify-center flex-shrink-0`}>
        <Icon className={`w-4 h-4 sm:w-5 sm:h-5 ${c.text}`} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="font-medium text-white text-xs sm:text-base truncate">{label}</div>
        <div className="text-[10px] sm:text-sm text-surface-400">{sublabel}</div>
      </div>
      <ChevronRight className="w-4 h-4 sm:w-5 sm:h-5 text-surface-600 group-hover:text-surface-400 transition-colors flex-shrink-0" />
    </button>
  )
}

function TokenButton({ 
  label, 
  color,
  active, 
  onClick 
}: {
  label: string
  color: 'green' | 'orange' | 'blue'
  active: boolean
  onClick: () => void
}) {
  const colors = {
    green: active ? 'bg-green-500/20 text-green-400 border-green-500/30' : 'bg-surface-800 text-surface-400 border-transparent hover:text-green-400',
    orange: active ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' : 'bg-surface-800 text-surface-400 border-transparent hover:text-orange-400',
    blue: active ? 'bg-blue-500/20 text-blue-400 border-blue-500/30' : 'bg-surface-800 text-surface-400 border-transparent hover:text-blue-400',
  }

  return (
    <button
      onClick={onClick}
      className={`px-2.5 py-1.5 rounded-md text-xs font-mono border transition-all whitespace-nowrap flex-shrink-0 ${colors[color]}`}
    >
      {label}
    </button>
  )
}
