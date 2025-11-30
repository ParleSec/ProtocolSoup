/**
 * Real Flow Execution Panel
 * 
 * Displays live execution state from RFC-compliant flow executors.
 * Shows captured requests, responses, tokens, and RFC references.
 */

import { motion, AnimatePresence } from 'framer-motion'
import {
  Play, Square, RotateCcw, CheckCircle, XCircle, Clock,
  Send, ArrowDownLeft, Key, Shield, AlertTriangle, Info,
  Lock, Eye, EyeOff, Copy, Check, ChevronDown,
  ChevronRight, Fingerprint, Code, Book, User, Server,
  Zap
} from 'lucide-react'
import { useState } from 'react'
import type { 
  FlowExecutorState, 
  FlowEvent, 
  CapturedExchange,
  DecodedToken 
} from '../flows'

// ============================================================================
// Main Panel Component
// ============================================================================

interface RealFlowPanelProps {
  state: FlowExecutorState | null
  onExecute: () => void
  onAbort: () => void
  onReset: () => void
  isExecuting: boolean
  flowInfo: {
    supported: boolean
    description: string
    rfcReference: string
    requiresUserInteraction: boolean
  } | null
  requirements: {
    requiresClientSecret: boolean
    requiresRefreshToken: boolean
    requiresCredentials: boolean
  }
  error: string | null
}

export function RealFlowPanel({
  state,
  onExecute,
  onAbort,
  onReset,
  isExecuting,
  flowInfo,
  requirements,
  error,
}: RealFlowPanelProps) {
  const [activeTab, setActiveTab] = useState<'events' | 'http' | 'tokens'>('events')

  const statusConfig = {
    idle: { icon: Play, color: 'text-surface-400', bg: 'bg-surface-800', label: 'Ready to Execute' },
    executing: { icon: Clock, color: 'text-cyan-400', bg: 'bg-cyan-500/10', label: 'Executing...' },
    awaiting_user: { icon: User, color: 'text-orange-400', bg: 'bg-orange-500/10', label: 'Awaiting User Action' },
    completed: { icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-500/10', label: 'Completed' },
    error: { icon: XCircle, color: 'text-red-400', bg: 'bg-red-500/10', label: 'Error' },
  }

  const currentStatus = state ? statusConfig[state.status] : statusConfig.idle
  const StatusIcon = currentStatus.icon

  // For now, allow all flows to be executed
  // Specific flows that need extra config (client_secret, refresh_token, username/password) 
  // will show an error when executed if the config is missing
  const hasUnmetRequirements = false

  if (error) {
    return (
      <div className="p-6 rounded-xl bg-red-500/5 border border-red-500/20">
        <div className="flex items-center gap-3 mb-3">
          <AlertTriangle className="w-6 h-6 text-red-400" />
          <h3 className="font-medium text-red-400">Flow Not Supported</h3>
        </div>
        <p className="text-red-300 text-sm">{error}</p>
      </div>
    )
  }

  if (!flowInfo) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <Zap className="w-12 h-12 text-surface-600 mb-3" />
        <p className="text-surface-400">Select a flow to execute</p>
        <p className="text-surface-500 text-sm mt-1">
          Each flow runs the exact protocol per RFC specifications
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Flow Info Header */}
      <div className="flex items-start justify-between gap-4 p-4 rounded-xl bg-surface-900/50 border border-white/5">
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-2">
            <div className={`p-2 rounded-lg ${currentStatus.bg}`}>
              <StatusIcon className={`w-5 h-5 ${currentStatus.color}`} />
            </div>
            <div>
              <h3 className="font-medium text-white">{flowInfo.description}</h3>
              <p className={`text-sm ${currentStatus.color}`}>{currentStatus.label}</p>
            </div>
          </div>
          
          {/* RFC Reference */}
          <div className="flex items-center gap-2 mt-3">
            <Book className="w-4 h-4 text-blue-400" />
            <span className="text-sm text-blue-400 font-mono">{flowInfo.rfcReference}</span>
            {flowInfo.requiresUserInteraction && (
              <span className="ml-2 px-2 py-0.5 rounded text-xs bg-orange-500/10 text-orange-400">
                Requires User Interaction
              </span>
            )}
          </div>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-2">
          {isExecuting ? (
            <button
              onClick={onAbort}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 transition-colors"
            >
              <Square className="w-4 h-4" />
              Abort
            </button>
          ) : (
            <button
              onClick={onExecute}
              disabled={hasUnmetRequirements || state?.status === 'completed'}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-green-500 to-emerald-500 text-white font-medium hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Play className="w-4 h-4" />
              Execute Flow
            </button>
          )}
          <button
            onClick={onReset}
            className="p-2 rounded-lg bg-surface-800 border border-white/10 text-surface-400 hover:text-white transition-colors"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Requirements Warning */}
      {requirements.requiresClientSecret && (
        <div className="p-3 rounded-lg bg-yellow-500/5 border border-yellow-500/20">
          <div className="flex items-center gap-2 text-sm text-yellow-400">
            <Lock className="w-4 h-4" />
            <span>This flow requires a <strong>client_secret</strong> (confidential client)</span>
          </div>
        </div>
      )}
      {requirements.requiresRefreshToken && (
        <div className="p-3 rounded-lg bg-yellow-500/5 border border-yellow-500/20">
          <div className="flex items-center gap-2 text-sm text-yellow-400">
            <Key className="w-4 h-4" />
            <span>This flow requires an existing <strong>refresh_token</strong></span>
          </div>
        </div>
      )}
      {requirements.requiresCredentials && (
        <div className="p-3 rounded-lg bg-red-500/5 border border-red-500/20">
          <div className="flex items-center gap-2 text-sm text-red-400">
            <AlertTriangle className="w-4 h-4" />
            <span>This flow requires <strong>username/password</strong> (legacy, not recommended)</span>
          </div>
        </div>
      )}

      {/* Tab Navigation - always shown */}
      <div className="flex gap-1 p-1 rounded-lg bg-surface-900/50">
        {[
          { id: 'events', label: 'Events', count: state?.events.length || 0, icon: Zap },
          { id: 'http', label: 'HTTP', count: state?.exchanges.length || 0, icon: Server },
          { id: 'tokens', label: 'Tokens', count: state?.decodedTokens.length || 0, icon: Key },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as typeof activeTab)}
            className={`flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? 'bg-surface-800 text-white'
                : 'text-surface-400 hover:text-white'
            }`}
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
            {tab.count > 0 && (
              <span className="px-1.5 py-0.5 rounded text-xs bg-surface-700">
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="min-h-[400px] max-h-[600px] overflow-y-auto">
        <AnimatePresence mode="wait">
          {activeTab === 'events' && (
            <motion.div
              key="events"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
            >
              <EventsList events={state?.events || []} />
            </motion.div>
          )}
          {activeTab === 'http' && (
            <motion.div
              key="http"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
            >
              <ExchangesList exchanges={state?.exchanges || []} />
            </motion.div>
          )}
          {activeTab === 'tokens' && (
            <motion.div
              key="tokens"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
            >
              <TokensList tokens={state?.decodedTokens || []} />
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Security Parameters */}
      {state && (state.securityParams.state || state.securityParams.codeChallenge || state.securityParams.nonce) && (
        <SecurityParams params={state.securityParams} />
      )}
    </div>
  )
}

// ============================================================================
// Events List with RFC References
// ============================================================================

function EventsList({ events }: { events: FlowEvent[] }) {
  if (events.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <Info className="w-12 h-12 text-surface-600 mb-3" />
        <p className="text-surface-400">No events yet</p>
        <p className="text-surface-500 text-sm">Execute the flow to see RFC-compliant events</p>
      </div>
    )
  }

  const eventConfig: Record<FlowEvent['type'], { icon: React.ElementType; color: string }> = {
    info: { icon: Info, color: 'text-blue-400 bg-blue-500/10' },
    request: { icon: Send, color: 'text-cyan-400 bg-cyan-500/10' },
    response: { icon: ArrowDownLeft, color: 'text-green-400 bg-green-500/10' },
    token: { icon: Key, color: 'text-yellow-400 bg-yellow-500/10' },
    crypto: { icon: Lock, color: 'text-purple-400 bg-purple-500/10' },
    security: { icon: Shield, color: 'text-orange-400 bg-orange-500/10' },
    user_action: { icon: User, color: 'text-pink-400 bg-pink-500/10' },
    error: { icon: AlertTriangle, color: 'text-red-400 bg-red-500/10' },
    rfc: { icon: Book, color: 'text-indigo-400 bg-indigo-500/10' },
  }

  return (
    <div className="space-y-2">
      {events.map((event, index) => {
        const config = eventConfig[event.type]
        const Icon = config.icon
        const [textColor, bgColor] = config.color.split(' ')

        return (
          <motion.div
            key={event.id}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.03 }}
            className="p-3 rounded-lg bg-surface-900/50 border border-white/5"
          >
            <div className="flex items-start gap-3">
              <div className={`p-1.5 rounded-lg ${bgColor}`}>
                <Icon className={`w-4 h-4 ${textColor}`} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <h4 className="font-medium text-white text-sm">{event.title}</h4>
                  <span className="text-xs text-surface-500 shrink-0">
                    {event.timestamp.toLocaleTimeString()}
                  </span>
                </div>
                <p className="text-sm text-surface-400 mt-0.5">{event.description}</p>
                
                {/* RFC Reference Badge */}
                {event.rfcReference && (
                  <div className="mt-2">
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-indigo-500/10 text-indigo-400 font-mono">
                      <Book className="w-3 h-3" />
                      {event.rfcReference}
                    </span>
                  </div>
                )}
                
                {event.data && Object.keys(event.data).length > 0 && (
                  <ExpandableData data={event.data} />
                )}
              </div>
            </div>
          </motion.div>
        )
      })}
    </div>
  )
}

// ============================================================================
// HTTP Exchanges List
// ============================================================================

function ExchangesList({ exchanges }: { exchanges: CapturedExchange[] }) {
  if (exchanges.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <Server className="w-12 h-12 text-surface-600 mb-3" />
        <p className="text-surface-400">No HTTP exchanges captured</p>
        <p className="text-surface-500 text-sm">Execute the flow to see real HTTP traffic</p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {exchanges.map(exchange => (
        <ExchangeCard key={exchange.id} exchange={exchange} />
      ))}
    </div>
  )
}

function ExchangeCard({ exchange }: { exchange: CapturedExchange }) {
  const [isExpanded, setIsExpanded] = useState(false)

  return (
    <div className="rounded-lg bg-surface-900/50 border border-white/5 overflow-hidden">
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full p-3 flex items-center gap-3 hover:bg-white/5 transition-colors"
      >
        <div className="p-1.5 rounded bg-cyan-500/10">
          <Send className="w-4 h-4 text-cyan-400" />
        </div>
        <div className="flex-1 text-left min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-mono text-sm font-medium text-cyan-400">
              {exchange.request.method}
            </span>
            <span className="text-sm text-surface-300 truncate">
              {exchange.request.url}
            </span>
          </div>
          <p className="text-xs text-surface-500 mt-0.5">{exchange.step}</p>
        </div>
        {exchange.response && (
          <span className={`px-2 py-0.5 rounded text-xs font-medium ${
            exchange.response.status < 300 
              ? 'bg-green-500/10 text-green-400' 
              : exchange.response.status < 400 
              ? 'bg-yellow-500/10 text-yellow-400'
              : 'bg-red-500/10 text-red-400'
          }`}>
            {exchange.response.status}
          </span>
        )}
        {exchange.rfcReference && (
          <span className="px-1.5 py-0.5 rounded text-xs bg-indigo-500/10 text-indigo-400 font-mono">
            {exchange.rfcReference}
          </span>
        )}
        {isExpanded ? (
          <ChevronDown className="w-4 h-4 text-surface-400" />
        ) : (
          <ChevronRight className="w-4 h-4 text-surface-400" />
        )}
      </button>

      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="border-t border-white/5"
          >
            <div className="p-3 space-y-3">
              {/* Request */}
              <div>
                <h4 className="text-xs font-medium text-surface-400 mb-2">Request</h4>
                <pre className="p-2 rounded bg-surface-950 text-xs font-mono overflow-x-auto">
                  <div className="text-cyan-400">
                    {exchange.request.method} {exchange.request.url}
                  </div>
                  {Object.entries(exchange.request.headers).map(([k, v]) => (
                    <div key={k} className="text-surface-400">
                      <span className="text-surface-500">{k}:</span> {v}
                    </div>
                  ))}
                  {exchange.request.body && (
                    <div className="mt-2 pt-2 border-t border-white/5 text-surface-300">
                      {typeof exchange.request.body === 'string' 
                        ? exchange.request.body
                        : JSON.stringify(exchange.request.body, null, 2)
                      }
                    </div>
                  )}
                </pre>
              </div>

              {/* Response */}
              {exchange.response && (
                <div>
                  <h4 className="text-xs font-medium text-surface-400 mb-2">
                    Response ({exchange.response.duration}ms)
                  </h4>
                  <pre className="p-2 rounded bg-surface-950 text-xs font-mono overflow-x-auto">
                    <div className={
                      exchange.response.status < 300 ? 'text-green-400' :
                      exchange.response.status < 400 ? 'text-yellow-400' : 'text-red-400'
                    }>
                      {exchange.response.status} {exchange.response.statusText}
                    </div>
                    <div className="mt-2 text-surface-300">
                      {JSON.stringify(exchange.response.body, null, 2)}
                    </div>
                  </pre>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

// ============================================================================
// Tokens List
// ============================================================================

function TokensList({ tokens }: { tokens: DecodedToken[] }) {
  if (tokens.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <Key className="w-12 h-12 text-surface-600 mb-3" />
        <p className="text-surface-400">No tokens captured</p>
        <p className="text-surface-500 text-sm">Complete the flow to see decoded tokens</p>
      </div>
    )
  }

  const tokenConfig: Record<DecodedToken['type'], { label: string; color: string; icon: React.ElementType }> = {
    access_token: { label: 'Access Token', color: 'text-green-400', icon: Key },
    id_token: { label: 'ID Token (OIDC)', color: 'text-orange-400', icon: Fingerprint },
    refresh_token: { label: 'Refresh Token', color: 'text-blue-400', icon: RotateCcw },
  }

  return (
    <div className="space-y-4">
      {tokens.map(token => {
        const config = tokenConfig[token.type]
        const Icon = config.icon

        return (
          <div key={token.type} className="rounded-lg bg-surface-900/50 border border-white/5 overflow-hidden">
            <div className="p-3 border-b border-white/5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Icon className={`w-5 h-5 ${config.color}`} />
                  <span className="font-medium text-white">{config.label}</span>
                </div>
                <div className="flex items-center gap-2">
                  {token.isValid !== undefined && (
                    token.isValid ? (
                      <span className="flex items-center gap-1 text-xs text-green-400">
                        <CheckCircle className="w-3.5 h-3.5" />
                        Valid
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-xs text-red-400">
                        <XCircle className="w-3.5 h-3.5" />
                        Invalid
                      </span>
                    )
                  )}
                  <CopyButton text={token.raw} />
                </div>
              </div>
            </div>

            <div className="p-3 space-y-3">
              {token.header && (
                <div>
                  <h4 className="text-xs font-medium text-surface-400 mb-1">Header</h4>
                  <pre className="p-2 rounded bg-surface-950 text-xs font-mono text-surface-300 overflow-x-auto">
                    {JSON.stringify(token.header, null, 2)}
                  </pre>
                </div>
              )}

              {token.payload && (
                <div>
                  <h4 className="text-xs font-medium text-surface-400 mb-1">Payload</h4>
                  <pre className="p-2 rounded bg-surface-950 text-xs font-mono text-surface-300 overflow-x-auto">
                    {JSON.stringify(token.payload, null, 2)}
                  </pre>
                </div>
              )}

              {token.validationErrors && token.validationErrors.length > 0 && (
                <div className="p-2 rounded bg-red-500/5 border border-red-500/20">
                  <h4 className="text-xs font-medium text-red-400 mb-1">Validation Errors</h4>
                  <ul className="text-xs text-red-300 space-y-0.5">
                    {token.validationErrors.map((err, i) => (
                      <li key={i}>• {err}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ============================================================================
// Security Parameters
// ============================================================================

function SecurityParams({ params }: { params: FlowExecutorState['securityParams'] }) {
  const [showSecrets, setShowSecrets] = useState(false)

  return (
    <div className="p-4 rounded-lg bg-surface-900/50 border border-white/5">
      <div className="flex items-center justify-between mb-3">
        <h3 className="flex items-center gap-2 font-medium text-white">
          <Shield className="w-4 h-4 text-orange-400" />
          Security Parameters
        </h3>
        <button
          onClick={() => setShowSecrets(!showSecrets)}
          className="flex items-center gap-1 text-xs text-surface-400 hover:text-white transition-colors"
        >
          {showSecrets ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
          {showSecrets ? 'Hide Secrets' : 'Show Secrets'}
        </button>
      </div>

      <div className="space-y-2 font-mono text-xs">
        {params.state && (
          <ParamRow label="state" value={params.state} color="text-blue-400" />
        )}
        {params.nonce && (
          <ParamRow label="nonce" value={params.nonce} color="text-purple-400" />
        )}
        {params.codeChallenge && (
          <ParamRow label="code_challenge" value={params.codeChallenge} color="text-cyan-400" truncate />
        )}
        {showSecrets && params.codeVerifier && (
          <div className="p-2 rounded bg-red-500/5 border border-red-500/20">
            <ParamRow label="code_verifier (SECRET)" value={params.codeVerifier} color="text-red-400" truncate />
          </div>
        )}
        {params.deviceCode && (
          <ParamRow label="device_code" value={params.deviceCode} color="text-green-400" truncate />
        )}
      </div>
    </div>
  )
}

function ParamRow({ label, value, color, truncate }: { label: string; value: string; color: string; truncate?: boolean }) {
  return (
    <div className="flex items-center gap-2">
      <span className={color}>{label}:</span>
      <span className={`text-surface-300 ${truncate ? 'truncate max-w-[200px]' : ''}`}>{value}</span>
      <CopyButton text={value} />
    </div>
  )
}

// ============================================================================
// Utility Components
// ============================================================================

function ExpandableData({ data }: { data: Record<string, unknown> }) {
  const [isExpanded, setIsExpanded] = useState(false)
  
  if (Object.keys(data).length === 0) return null

  return (
    <div className="mt-2">
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="flex items-center gap-1 text-xs text-surface-500 hover:text-surface-300 transition-colors"
      >
        <Code className="w-3 h-3" />
        {isExpanded ? 'Hide' : 'Show'} data
        {isExpanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
      </button>
      
      <AnimatePresence>
        {isExpanded && (
          <motion.pre
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="mt-2 p-2 rounded bg-surface-950 text-xs font-mono text-surface-400 overflow-x-auto"
          >
            {JSON.stringify(data, null, 2)}
          </motion.pre>
        )}
      </AnimatePresence>
    </div>
  )
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <button
      onClick={handleCopy}
      className="p-1 rounded hover:bg-white/10 transition-colors"
      title="Copy to clipboard"
    >
      {copied ? (
        <Check className="w-3 h-3 text-green-400" />
      ) : (
        <Copy className="w-3 h-3 text-surface-500" />
      )}
    </button>
  )
}

