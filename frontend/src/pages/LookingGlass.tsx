/**
 * Looking Glass Page
 * 
 * Protocol-agnostic inspection interface for authentication flows.
 * Supports both simulation mode (animated walkthrough) and live execution
 * mode (real protocol flows against the MockIdP).
 */

import React, { useState, useCallback, useMemo } from 'react'
import { useParams } from 'react-router-dom'
import { 
  Eye, Clock, Play, RotateCcw, Zap, Key, 
  Wifi, WifiOff, Info, Shield, AlertTriangle,
  Sparkles, Radio,
} from 'lucide-react'

// Import modular Looking Glass system
import {
  useProtocols,
  useFlowSimulation,
  useLookingGlassSession,
  useFlowExecutor,
  FlowVisualizer,
  StepDetail,
  ProtocolSelector,
  ProtocolFlowBadge,
  LiveExecutionPanel,
  getActorsForFlow,
  type LookingGlassProtocol,
  type LookingGlassFlow,
  type LookingGlassStep,
  type LookingGlassEvent,
  type FlowExecutionConfig,
} from '../lookingglass'

import { TokenInspector } from '../components/lookingglass/TokenInspector'
import { Timeline, type TimelineEvent } from '../components/lookingglass/Timeline'

type ExecutionMode = 'simulation' | 'live'

export function LookingGlass() {
  // URL params for direct session access
  const { sessionId: urlSessionId } = useParams<{ sessionId?: string }>()

  // Execution mode toggle
  const [mode, setMode] = useState<ExecutionMode>('live')

  // Protocol and flow selection state
  const [selectedProtocol, setSelectedProtocol] = useState<LookingGlassProtocol | null>(null)
  const [selectedFlow, setSelectedFlow] = useState<LookingGlassFlow | null>(null)
  const [selectedStep, setSelectedStep] = useState<LookingGlassStep | null>(null)
  const [selectedStepIndex, setSelectedStepIndex] = useState<number>(-1)

  // Token inspector state
  const [pastedToken, setPastedToken] = useState('')

  // Load all protocols
  const { protocols, loading: protocolsLoading } = useProtocols()

  // Get actors for selected flow
  const actors = selectedFlow ? getActorsForFlow(selectedFlow) : []

  // Flow simulation (for animation mode)
  const simulation = useFlowSimulation(selectedFlow)

  // Live session (if sessionId provided in URL)
  const session = useLookingGlassSession(urlSessionId || null)

  // Build executor config based on selected flow
  // Protocol routes are at root level: /oauth2/authorize, /oidc/authorize, etc.
  // Use 'public-app' for browser-based flows with PKCE (no client secret needed)
  const executorConfig: FlowExecutionConfig = useMemo(() => ({
    authServerUrl: `/${selectedProtocol?.id || 'oauth2'}`, // Routes are at /{protocol}/...
    clientId: 'public-app', // Public client for SPA - uses PKCE instead of client secret
    redirectUri: `${window.location.origin}/callback`,
    scopes: selectedProtocol?.id === 'oidc' 
      ? ['openid', 'profile', 'email'] 
      : ['profile', 'email'],
    usePkce: true,
    isOidc: selectedProtocol?.id === 'oidc',
  }), [selectedProtocol])

  // Live flow executor
  const executor = useFlowExecutor(executorConfig)

  // Handle protocol selection
  const handleProtocolSelect = useCallback((protocol: LookingGlassProtocol) => {
    setSelectedProtocol(protocol)
    setSelectedFlow(null)
    setSelectedStep(null)
    setSelectedStepIndex(-1)
    simulation.resetSimulation()
    executor.reset()
  }, [simulation, executor])

  // Handle flow selection
  const handleFlowSelect = useCallback((flow: LookingGlassFlow) => {
    setSelectedFlow(flow)
    setSelectedStep(null)
    setSelectedStepIndex(-1)
    simulation.resetSimulation()
    executor.reset()
  }, [simulation, executor])

  // Handle step click
  const handleStepClick = useCallback((step: LookingGlassStep, index: number) => {
    setSelectedStep(step)
    setSelectedStepIndex(index)
  }, [])

  // Start simulation
  const handleStartSimulation = useCallback(() => {
    if (selectedFlow) {
      setSelectedStep(null)
      setSelectedStepIndex(-1)
      simulation.startSimulation(1200)
    }
  }, [selectedFlow, simulation])

  // Reset everything
  const handleReset = useCallback(() => {
    simulation.resetSimulation()
    session.clearEvents()
    executor.reset()
    setSelectedStep(null)
    setSelectedStepIndex(-1)
  }, [simulation, session, executor])

  // Convert simulation events to timeline events
  const timelineEvents: TimelineEvent[] = (urlSessionId ? session.events : simulation.events).map((event: LookingGlassEvent) => ({
    id: event.id,
    type: event.type,
    timestamp: event.timestamp,
    status: event.status === 'error' ? 'error' : event.status === 'warning' ? 'warning' : event.status === 'pending' ? 'pending' : 'success',
    title: event.title,
    description: event.description,
    duration: event.duration,
    data: event.data,
  }))

  // Determine connection status
  const isLive = urlSessionId ? session.connected : false
  const hasEvents = timelineEvents.length > 0

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-4">
          <div>
            <h1 className="font-display text-2xl font-bold text-white flex items-center gap-3">
              <Eye className="w-7 h-7 text-accent-cyan" />
              Looking Glass
            </h1>
            <p className="text-surface-400 mt-1">
              Deep inspection of authentication flows
            </p>
          </div>
          {selectedProtocol && (
            <ProtocolFlowBadge protocol={selectedProtocol} flow={selectedFlow} />
          )}
        </div>
        
        <div className="flex items-center gap-3">
          {/* Mode Toggle */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-800 border border-white/10">
            <button
              onClick={() => setMode('simulation')}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${
                mode === 'simulation'
                  ? 'bg-purple-500/20 text-purple-400'
                  : 'text-surface-400 hover:text-white'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5" />
              Simulation
            </button>
            <button
              onClick={() => setMode('live')}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${
                mode === 'live'
                  ? 'bg-green-500/20 text-green-400'
                  : 'text-surface-400 hover:text-white'
              }`}
            >
              <Radio className="w-3.5 h-3.5" />
              Live Execution
            </button>
          </div>

          {/* Live status indicator */}
          {urlSessionId && (
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium ${
              isLive 
                ? 'bg-green-500/10 border border-green-500/20 text-green-400' 
                : 'bg-red-500/10 border border-red-500/20 text-red-400'
            }`}>
              {isLive ? (
                <>
                  <Wifi className="w-3.5 h-3.5" />
                  <span>Live</span>
                  <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
                </>
              ) : (
                <>
                  <WifiOff className="w-3.5 h-3.5" />
                  <span>Disconnected</span>
                </>
              )}
            </div>
          )}

          <button
            onClick={handleReset}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-surface-400 hover:text-white hover:bg-white/10 transition-colors"
          >
            <RotateCcw className="w-4 h-4" />
            Reset
          </button>
          
          {mode === 'simulation' && (
            <button
              onClick={handleStartSimulation}
              disabled={!selectedFlow || simulation.isSimulating}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-purple-500 to-indigo-500 text-white font-medium hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {simulation.isSimulating ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Simulating...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  Run Simulation
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {/* Protocol & Flow Selector - needs high z-index for dropdowns */}
      <div className="glass rounded-xl p-6 relative z-30">
        <h2 className="font-display font-semibold text-white mb-4 flex items-center gap-2">
          <Shield className="w-5 h-5 text-accent-purple" />
          Select Protocol & Flow
        </h2>
        <ProtocolSelector
          protocols={protocols}
          selectedProtocol={selectedProtocol}
          selectedFlow={selectedFlow}
          onProtocolSelect={handleProtocolSelect}
          onFlowSelect={handleFlowSelect}
          loading={protocolsLoading}
        />
      </div>

      {/* Live Execution Panel - Only shown in live mode when flow is selected */}
      {mode === 'live' && selectedFlow && (
        <div className="glass rounded-xl p-6 relative z-10">
          <h2 className="font-display font-semibold text-white mb-4 flex items-center gap-2">
            <Radio className="w-5 h-5 text-green-400" />
            Live Protocol Execution
            <span className="ml-2 px-2 py-0.5 rounded text-xs bg-green-500/10 text-green-400 border border-green-500/20">
              Real Flow
            </span>
          </h2>
          <p className="text-surface-400 text-sm mb-4">
            Execute a real {selectedProtocol?.name} {selectedFlow.name} against the MockIdP. 
            All requests, responses, and tokens are captured and decoded in real-time.
          </p>
          <LiveExecutionPanel
            state={executor.state}
            onExecute={executor.execute}
            onAbort={executor.abort}
            onReset={executor.reset}
            isExecuting={executor.isExecuting}
            flowName={selectedFlow.name}
          />
        </div>
      )}

      {/* Flow Visualization - Only shown in simulation mode */}
      {mode === 'simulation' && selectedFlow && (
        <div className="glass rounded-xl p-6 relative z-10">
          <h2 className="font-display font-semibold text-white mb-4 flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-purple-400" />
            Flow Visualization
            <span className="ml-2 px-2 py-0.5 rounded text-xs bg-purple-500/10 text-purple-400 border border-purple-500/20">
              Simulation
            </span>
          </h2>
          <FlowVisualizer
            flow={selectedFlow}
            actors={actors}
            currentStepIndex={simulation.currentStepIndex}
            completedSteps={simulation.completedSteps}
            onStepClick={handleStepClick}
            selectedStepIndex={selectedStepIndex}
            isAnimating={simulation.isSimulating}
          />
        </div>
      )}

      {/* Main Content Grid - Shown in simulation mode */}
      {mode === 'simulation' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 relative z-10">
          {/* Step Detail Panel */}
          <div className="glass rounded-xl p-6">
            <h2 className="font-display font-semibold text-white mb-4 flex items-center gap-2">
              <Info className="w-5 h-5 text-accent-purple" />
              Step Details
            </h2>
            <StepDetail
              step={selectedStep}
              stepNumber={selectedStepIndex >= 0 ? selectedStepIndex + 1 : undefined}
            />
          </div>

          {/* Event Timeline */}
          <div className="glass rounded-xl p-6">
            <h2 className="font-display font-semibold text-white mb-4 flex items-center gap-2">
              <Clock className="w-5 h-5 text-accent-orange" />
              Event Timeline
            </h2>

            {!hasEvents ? (
              <div className="flex flex-col items-center justify-center py-12 text-center">
                <div className="w-16 h-16 rounded-full bg-surface-800 flex items-center justify-center mb-4">
                  <Zap className="w-8 h-8 text-surface-600" />
                </div>
                <p className="text-surface-400">No events yet</p>
                <p className="text-surface-500 text-sm mt-1">
                  {selectedFlow 
                    ? 'Run a simulation to see events'
                    : 'Select a protocol and flow to begin'
                  }
                </p>
              </div>
            ) : (
              <Timeline
                events={timelineEvents}
                onEventClick={(event) => {
                  // Find matching step if event has step data
                  if (selectedFlow && event.data?.step !== undefined) {
                    const stepIndex = Number(event.data.step)
                    if (stepIndex >= 0 && stepIndex < selectedFlow.steps.length) {
                      setSelectedStep(selectedFlow.steps[stepIndex])
                      setSelectedStepIndex(stepIndex)
                    }
                  }
                }}
                selectedEventId={undefined}
                isLive={isLive}
                maxEvents={50}
              />
            )}
          </div>
        </div>
      )}

      {/* Token Inspector */}
      <div className="glass rounded-xl p-6">
        <h2 className="font-display font-semibold text-white mb-4 flex items-center gap-2">
          <Key className="w-5 h-5 text-accent-green" />
          Token Inspector
        </h2>
        <p className="text-surface-400 text-sm mb-4">
          Paste any JWT token to decode it and see the header, payload, and signature validation status.
          {mode === 'live' && executor.state?.accessToken && (
            <button
              onClick={() => setPastedToken(executor.state?.accessToken || '')}
              className="ml-2 text-accent-cyan hover:underline"
            >
              Use captured access token →
            </button>
          )}
        </p>
        <textarea
          value={pastedToken}
          onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setPastedToken(e.target.value)}
          placeholder="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
          className="w-full h-28 px-4 py-3 rounded-lg bg-surface-900 border border-white/10 text-sm font-mono text-white placeholder-surface-600 focus:outline-none focus:border-accent-cyan/50 resize-none mb-4"
        />
        {pastedToken && <TokenInspector token={pastedToken} />}
      </div>

      {/* Quick Reference - Protocol Specific */}
      {selectedProtocol && (
        <div className="glass rounded-xl p-6">
          <h2 className="font-display font-semibold text-white mb-4">
            {selectedProtocol.name} Quick Reference
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-lg bg-surface-900/50">
              <h3 className="font-medium text-cyan-400 mb-2 flex items-center gap-2">
                <Key className="w-4 h-4" />
                Available Flows
              </h3>
              <ul className="space-y-1.5 text-sm text-surface-300">
                {selectedProtocol.flows.map((flow: LookingGlassFlow) => (
                  <li key={flow.id}>
                    <button
                      onClick={() => handleFlowSelect(flow)}
                      className={`hover:text-white transition-colors ${
                        selectedFlow?.id === flow.id ? 'text-white font-medium' : ''
                      }`}
                    >
                      {flow.name}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
            <div className="p-4 rounded-lg bg-surface-900/50">
              <h3 className="font-medium text-purple-400 mb-2 flex items-center gap-2">
                <Shield className="w-4 h-4" />
                Security Best Practices
              </h3>
              <ul className="space-y-1.5 text-sm text-surface-300">
                <li>Always validate state parameter</li>
                <li>Use PKCE for public clients</li>
                <li>Validate token signatures</li>
                <li>Check token expiration</li>
              </ul>
            </div>
            <div className="p-4 rounded-lg bg-surface-900/50">
              <h3 className="font-medium text-orange-400 mb-2 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" />
                Common Pitfalls
              </h3>
              <ul className="space-y-1.5 text-sm text-surface-300">
                <li>Not validating redirect URIs</li>
                <li>Storing tokens insecurely</li>
                <li>Ignoring token expiration</li>
                <li>Missing CSRF protection</li>
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
