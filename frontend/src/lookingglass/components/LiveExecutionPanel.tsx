/**
 * Live Execution Panel
 * 
 * Displays real-time execution state from a running protocol flow,
 * including captured requests, responses, decoded tokens, and events.
 */

import { motion, AnimatePresence } from 'framer-motion'
import {
  Play, Square, RotateCcw, CheckCircle, XCircle, Clock,
  Send, ArrowDownLeft, Key, Shield, AlertTriangle, Info,
  Lock, Eye, EyeOff, Copy, Check, ChevronDown,
  ChevronRight, Fingerprint, Code
} from 'lucide-react'
import { useState } from 'react'
import type { 
  FlowExecutionState, 
  ExecutionEvent, 
  CapturedRequest, 
  CapturedResponse,
  DecodedToken 
} from '../executor'

// ============================================================================
// Main Panel Component
// ============================================================================

interface LiveExecutionPanelProps {
  state: FlowExecutionState | null
  onExecute: () => void
  onAbort: () => void
  onReset: () => void
  isExecuting: boolean
  flowName?: string
}

export function LiveExecutionPanel({
  state,
  onExecute,
  onAbort,
  onReset,
  isExecuting,
  flowName = 'Authorization Code Flow',
}: LiveExecutionPanelProps) {
  const [activeTab, setActiveTab] = useState<'events' | 'requests' | 'tokens'>('events')

  const statusConfig = {
    idle: { icon: Play, color: 'text-surface-400', bg: 'bg-surface-800', label: 'Ready' },
    started: { icon: Clock, color: 'text-cyan-400', bg: 'bg-cyan-500/10', label: 'Starting...' },
    authorizing: { icon: Lock, color: 'text-orange-400', bg: 'bg-orange-500/10', label: 'Awaiting Authorization' },
    exchanging: { icon: Send, color: 'text-blue-400', bg: 'bg-blue-500/10', label: 'Exchanging Tokens' },
    completed: { icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-500/10', label: 'Completed' },
    error: { icon: XCircle, color: 'text-red-400', bg: 'bg-red-500/10', label: 'Error' },
  }

  const currentStatus = state ? statusConfig[state.status] : statusConfig.idle
  const StatusIcon = currentStatus.icon

  return (
    <div className="space-y-4">
      {/* Header with Controls */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg ${currentStatus.bg}`}>
            <StatusIcon className={`w-5 h-5 ${currentStatus.color}`} />
          </div>
          <div>
            <h3 className="font-medium text-white">{flowName}</h3>
            <p className={`text-sm ${currentStatus.color}`}>{currentStatus.label}</p>
          </div>
        </div>

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
              disabled={!state || state.status === 'completed'}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-green-500 to-emerald-500 text-white font-medium hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Play className="w-4 h-4" />
              Execute Real Flow
            </button>
          )}
          <button
            onClick={onReset}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-surface-800 border border-white/10 text-surface-400 hover:text-white transition-colors"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-1 p-1 rounded-lg bg-surface-900/50">
        {[
          { id: 'events', label: 'Events', count: state?.events.length || 0 },
          { id: 'requests', label: 'HTTP', count: (state?.requests.length || 0) + (state?.responses.length || 0) },
          { id: 'tokens', label: 'Tokens', count: state?.decodedTokens.length || 0 },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as typeof activeTab)}
            className={`flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? 'bg-surface-800 text-white'
                : 'text-surface-400 hover:text-white'
            }`}
          >
            {tab.label}
            {tab.count > 0 && (
              <span className="ml-2 px-1.5 py-0.5 rounded text-xs bg-surface-700">
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
          {activeTab === 'requests' && (
            <motion.div
              key="requests"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
            >
              <RequestsList 
                requests={state?.requests || []} 
                responses={state?.responses || []} 
              />
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

      {/* Security Parameters Summary */}
      {state && (state.state || state.codeChallenge || state.nonce) && (
        <SecurityParametersSummary state={state} />
      )}
    </div>
  )
}

// ============================================================================
// Events List
// ============================================================================

function EventsList({ events }: { events: ExecutionEvent[] }) {
  if (events.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <Info className="w-12 h-12 text-surface-600 mb-3" />
        <p className="text-surface-400">No events yet</p>
        <p className="text-surface-500 text-sm">Execute a real flow to capture events</p>
      </div>
    )
  }

  const eventIcons: Record<ExecutionEvent['type'], React.ElementType> = {
    info: Info,
    request: Send,
    response: ArrowDownLeft,
    token: Key,
    crypto: Lock,
    security: Shield,
    error: AlertTriangle,
  }

  const eventColors: Record<ExecutionEvent['type'], string> = {
    info: 'text-blue-400 bg-blue-500/10',
    request: 'text-cyan-400 bg-cyan-500/10',
    response: 'text-green-400 bg-green-500/10',
    token: 'text-yellow-400 bg-yellow-500/10',
    crypto: 'text-purple-400 bg-purple-500/10',
    security: 'text-orange-400 bg-orange-500/10',
    error: 'text-red-400 bg-red-500/10',
  }

  return (
    <div className="space-y-2">
      {events.map((event, index) => {
        const Icon = eventIcons[event.type]
        const colorClass = eventColors[event.type]
        
        return (
          <motion.div
            key={event.id}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.05 }}
            className="p-3 rounded-lg bg-surface-900/50 border border-white/5"
          >
            <div className="flex items-start gap-3">
              <div className={`p-1.5 rounded-lg ${colorClass.split(' ')[1]}`}>
                <Icon className={`w-4 h-4 ${colorClass.split(' ')[0]}`} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <h4 className="font-medium text-white text-sm">{event.title}</h4>
                  <span className="text-xs text-surface-500">
                    {event.timestamp.toLocaleTimeString()}
                  </span>
                </div>
                <p className="text-sm text-surface-400 mt-0.5">{event.description}</p>
                
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
// Requests List
// ============================================================================

function RequestsList({ 
  requests, 
  responses 
}: { 
  requests: CapturedRequest[]
  responses: CapturedResponse[]
}) {
  if (requests.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <Send className="w-12 h-12 text-surface-600 mb-3" />
        <p className="text-surface-400">No HTTP requests captured</p>
        <p className="text-surface-500 text-sm">Execute a real flow to capture traffic</p>
      </div>
    )
  }

  const responseMap = new Map(responses.map(r => [r.requestId, r]))

  return (
    <div className="space-y-3">
      {requests.map(request => {
        const response = responseMap.get(request.id)
        
        return (
          <RequestResponsePair 
            key={request.id} 
            request={request} 
            response={response} 
          />
        )
      })}
    </div>
  )
}

function RequestResponsePair({ 
  request, 
  response 
}: { 
  request: CapturedRequest
  response?: CapturedResponse
}) {
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
        <div className="flex-1 text-left">
          <div className="flex items-center gap-2">
            <span className="font-mono text-sm font-medium text-cyan-400">
              {request.method}
            </span>
            <span className="text-sm text-surface-300 truncate">
              {request.url}
            </span>
          </div>
        </div>
        {response && (
          <span className={`px-2 py-0.5 rounded text-xs font-medium ${
            response.status < 300 
              ? 'bg-green-500/10 text-green-400' 
              : response.status < 400 
              ? 'bg-yellow-500/10 text-yellow-400'
              : 'bg-red-500/10 text-red-400'
          }`}>
            {response.status}
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
              {/* Request Details */}
              <div>
                <h4 className="text-xs font-medium text-surface-400 mb-2">Request</h4>
                <div className="p-2 rounded bg-surface-950 font-mono text-xs">
                  <div className="text-cyan-400">
                    {request.method} {request.url}
                  </div>
                  {request.headers && Object.entries(request.headers).map(([key, value]) => (
                    <div key={key} className="text-surface-400">
                      <span className="text-surface-500">{key}:</span> {value}
                    </div>
                  ))}
                  {request.body && (
                    <div className="mt-2 pt-2 border-t border-white/5">
                      <ExpandableData 
                        data={typeof request.body === 'string' ? { body: request.body } : request.body} 
                      />
                    </div>
                  )}
                </div>
              </div>

              {/* Response Details */}
              {response && (
                <div>
                  <h4 className="text-xs font-medium text-surface-400 mb-2">
                    Response ({response.duration}ms)
                  </h4>
                  <div className="p-2 rounded bg-surface-950 font-mono text-xs">
                    <div className={
                      response.status < 300 ? 'text-green-400' :
                      response.status < 400 ? 'text-yellow-400' : 'text-red-400'
                    }>
                      {response.status} {response.statusText}
                    </div>
                    {response.body != null && typeof response.body === 'object' && (
                      <div className="mt-2 pt-2 border-t border-white/5">
                        <ExpandableData data={response.body as Record<string, unknown>} />
                      </div>
                    )}
                  </div>
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
        <p className="text-surface-500 text-sm">Complete a flow to see decoded tokens</p>
      </div>
    )
  }

  const tokenTypeConfig: Record<DecodedToken['type'], { label: string; color: string; icon: React.ElementType }> = {
    access_token: { label: 'Access Token', color: 'text-green-400', icon: Key },
    id_token: { label: 'ID Token (OIDC)', color: 'text-orange-400', icon: Fingerprint },
    refresh_token: { label: 'Refresh Token', color: 'text-blue-400', icon: RotateCcw },
  }

  return (
    <div className="space-y-4">
      {tokens.map(token => {
        const config = tokenTypeConfig[token.type]
        const Icon = config.icon

        return (
          <div 
            key={token.id}
            className="rounded-lg bg-surface-900/50 border border-white/5 overflow-hidden"
          >
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
              {/* Header */}
              {token.header && (
                <div>
                  <h4 className="text-xs font-medium text-surface-400 mb-1">Header</h4>
                  <pre className="p-2 rounded bg-surface-950 text-xs font-mono text-surface-300 overflow-x-auto">
                    {JSON.stringify(token.header, null, 2)}
                  </pre>
                </div>
              )}

              {/* Payload */}
              {token.payload && (
                <div>
                  <h4 className="text-xs font-medium text-surface-400 mb-1">Payload</h4>
                  <pre className="p-2 rounded bg-surface-950 text-xs font-mono text-surface-300 overflow-x-auto">
                    {JSON.stringify(token.payload, null, 2)}
                  </pre>
                </div>
              )}

              {/* Validation Errors */}
              {token.validationErrors && token.validationErrors.length > 0 && (
                <div className="p-2 rounded bg-red-500/5 border border-red-500/20">
                  <h4 className="text-xs font-medium text-red-400 mb-1">Validation Errors</h4>
                  <ul className="text-xs text-red-300 space-y-1">
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
// Security Parameters Summary
// ============================================================================

function SecurityParametersSummary({ state }: { state: FlowExecutionState }) {
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
          {showSecrets ? 'Hide' : 'Show'}
        </button>
      </div>

      <div className="space-y-2 font-mono text-xs">
        {state.state && (
          <div className="flex items-center gap-2">
            <span className="text-blue-400">state:</span>
            <span className="text-surface-300">{state.state}</span>
            <CopyButton text={state.state} />
          </div>
        )}
        
        {state.nonce && (
          <div className="flex items-center gap-2">
            <span className="text-purple-400">nonce:</span>
            <span className="text-surface-300">{state.nonce}</span>
            <CopyButton text={state.nonce} />
          </div>
        )}

        {state.codeChallenge && (
          <div className="flex items-center gap-2">
            <span className="text-cyan-400">code_challenge:</span>
            <span className="text-surface-300 truncate max-w-[200px]">{state.codeChallenge}</span>
            <CopyButton text={state.codeChallenge} />
          </div>
        )}

        {showSecrets && state.codeVerifier && (
          <div className="flex items-center gap-2 p-2 rounded bg-red-500/5 border border-red-500/20">
            <span className="text-red-400">code_verifier (SECRET):</span>
            <span className="text-red-300 truncate max-w-[200px]">{state.codeVerifier}</span>
            <CopyButton text={state.codeVerifier} />
          </div>
        )}

        {state.authorizationCode && (
          <div className="flex items-center gap-2">
            <span className="text-green-400">authorization_code:</span>
            <span className="text-surface-300 truncate max-w-[200px]">
              {state.authorizationCode.substring(0, 30)}...
            </span>
            <CopyButton text={state.authorizationCode} />
          </div>
        )}
      </div>
    </div>
  )
}

// ============================================================================
// Utility Components
// ============================================================================

function ExpandableData({ data }: { data: Record<string, unknown> }) {
  const [isExpanded, setIsExpanded] = useState(false)
  
  const entries = Object.entries(data)
  if (entries.length === 0) return null

  return (
    <div className="mt-2">
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="flex items-center gap-1 text-xs text-surface-500 hover:text-surface-300 transition-colors"
      >
        <Code className="w-3 h-3" />
        {isExpanded ? 'Hide' : 'Show'} data
        {isExpanded ? (
          <ChevronDown className="w-3 h-3" />
        ) : (
          <ChevronRight className="w-3 h-3" />
        )}
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

