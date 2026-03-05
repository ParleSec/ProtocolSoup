import { useState, type ElementType } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import {
  AlertTriangle,
  ArrowDownLeft,
  Bell,
  Book,
  CheckCircle,
  ChevronDown,
  ChevronRight,
  Clock,
  Code,
  Globe,
  Info,
  Key,
  Lock,
  Play,
  Send,
  Shield,
  User,
  XCircle,
  Zap,
} from 'lucide-react'
import { CopyButton, ExpandableSection } from '../shared'
import type {
  CapturedHTTPExchange,
  DecodedSET,
  EventDef,
  FlowEvent,
  SecurityState,
  SSFExecutionStatus,
  SSFFlowTab,
} from '../../ssf/types'

export interface SSFFlowPanelProps {
  status: SSFExecutionStatus
  events: FlowEvent[]
  httpExchanges: CapturedHTTPExchange[]
  decodedSET: DecodedSET | null
  securityState: SecurityState | null
  activeTab: SSFFlowTab
  onTabChange: (tab: SSFFlowTab) => void
  onResetState: () => void
  selectedEvent: EventDef
  isSSEConnected: boolean
}

export function SSFFlowPanel({
  status,
  events,
  httpExchanges,
  decodedSET,
  securityState,
  activeTab,
  onTabChange,
  onResetState,
  selectedEvent,
  isSSEConnected,
}: SSFFlowPanelProps) {
  const statusConfig = {
    idle: { icon: Play, color: 'text-surface-400', bg: 'bg-surface-800', label: 'Ready to Execute' },
    executing: { icon: Clock, color: 'text-cyan-400', bg: 'bg-cyan-500/10', label: 'Executing...' },
    completed: { icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-500/10', label: 'Completed' },
    error: { icon: XCircle, color: 'text-red-400', bg: 'bg-red-500/10', label: 'Error' },
  }

  const currentStatus = statusConfig[status]
  const StatusIcon = currentStatus.icon

  return (
    <div className="space-y-3 sm:space-y-4">
      <div className="p-3 sm:p-4 rounded-xl bg-surface-900/50 border border-white/5">
        <div className="flex items-start justify-between gap-2 mb-3">
          <div className="flex items-center gap-2 sm:gap-3 min-w-0 flex-1">
            <div className={`p-1.5 sm:p-2 rounded-lg flex-shrink-0 ${currentStatus.bg}`}>
              <StatusIcon className={`w-4 h-4 ${currentStatus.color}`} />
            </div>
            <div className="min-w-0">
              <p className={`text-xs sm:text-sm font-medium ${currentStatus.color}`}>{currentStatus.label}</p>
            </div>
          </div>
        </div>

        <h2 className="font-medium text-white text-xs sm:text-sm leading-relaxed mb-2">{selectedEvent.description}</h2>

        <div className="flex flex-wrap items-center gap-1.5 sm:gap-2">
          <div className="flex items-center gap-1">
            <Book className="w-3 h-3 sm:w-4 sm:h-4 text-blue-400 flex-shrink-0" />
            <span className="text-[10px] sm:text-xs text-blue-400 font-mono">{selectedEvent.rfcReference}</span>
          </div>
          <span
            className={`px-1.5 sm:px-2 py-0.5 rounded text-[10px] sm:text-xs ${
              selectedEvent.category === 'CAEP'
                ? 'bg-blue-500/10 text-blue-400'
                : 'bg-amber-500/10 text-amber-400'
            }`}
          >
            {selectedEvent.category}
          </span>
        </div>
      </div>

      <div className="flex items-center gap-2 text-xs">
        <div className={`w-2 h-2 rounded-full ${isSSEConnected ? 'bg-green-400 animate-pulse' : 'bg-surface-600'}`} />
        <span className="text-surface-500">{isSSEConnected ? 'Live stream connected' : 'Connecting...'}</span>
      </div>

      <div className="flex gap-1 p-1 rounded-lg bg-surface-900/50 overflow-x-auto scrollbar-hide">
        {[
          { id: 'events', label: 'Pipeline', count: events.length, icon: Zap },
          { id: 'traffic', label: 'Traffic', count: httpExchanges.length, icon: Globe },
          { id: 'set', label: 'SET', count: decodedSET ? 1 : 0, icon: Key },
          { id: 'state', label: 'State', count: securityState ? 1 : 0, icon: User },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => onTabChange(tab.id as SSFFlowTab)}
            className={`flex-1 min-w-0 flex items-center justify-center gap-1.5 sm:gap-2 px-2 sm:px-4 py-2.5 sm:py-2 rounded-md text-sm font-medium transition-colors whitespace-nowrap ${
              activeTab === tab.id
                ? 'bg-surface-800 text-white'
                : 'text-surface-400 hover:text-white active:text-white'
            }`}
          >
            <tab.icon className="w-4 h-4 flex-shrink-0" />
            <span className="hidden sm:inline">{tab.label}</span>
            {tab.count > 0 && (
              <span className="px-1.5 py-0.5 rounded text-xs bg-surface-700 flex-shrink-0">
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      <div className="min-h-[300px] sm:min-h-[400px] max-h-[450px] sm:max-h-[600px] overflow-y-auto">
        <AnimatePresence mode="wait">
          {activeTab === 'events' && (
            <motion.div key="events" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}>
              <EventsList events={events} />
            </motion.div>
          )}
          {activeTab === 'traffic' && (
            <motion.div key="traffic" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}>
              <TrafficPanel exchanges={httpExchanges} />
            </motion.div>
          )}
          {activeTab === 'set' && (
            <motion.div key="set" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}>
              <SETInspector decodedSET={decodedSET} />
            </motion.div>
          )}
          {activeTab === 'state' && (
            <motion.div key="state" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}>
              <SecurityStatePanel state={securityState} onReset={onResetState} />
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  )
}

function EventsList({ events }: { events: FlowEvent[] }) {
  if (events.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <Info className="w-12 h-12 text-surface-600 mb-3" />
        <p className="text-surface-400">No events yet</p>
        <p className="text-surface-400 text-sm">Execute the flow to see SSF protocol events</p>
      </div>
    )
  }

  const eventConfig: Record<FlowEvent['type'], { icon: ElementType; color: string }> = {
    info: { icon: Info, color: 'text-blue-400 bg-blue-500/10' },
    request: { icon: Send, color: 'text-cyan-400 bg-cyan-500/10' },
    response: { icon: ArrowDownLeft, color: 'text-green-400 bg-green-500/10' },
    token: { icon: Key, color: 'text-yellow-400 bg-yellow-500/10' },
    crypto: { icon: Lock, color: 'text-purple-400 bg-purple-500/10' },
    security: { icon: Shield, color: 'text-orange-400 bg-orange-500/10' },
    action: { icon: Bell, color: 'text-pink-400 bg-pink-500/10' },
    error: { icon: AlertTriangle, color: 'text-red-400 bg-red-500/10' },
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
                  <h3 className="font-medium text-white text-sm">{event.title}</h3>
                  <span className="text-xs text-surface-400 shrink-0">{event.timestamp.toLocaleTimeString()}</span>
                </div>
                <p className="text-sm text-surface-400 mt-0.5">{event.description}</p>

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

function SETInspector({ decodedSET }: { decodedSET: DecodedSET | null }) {
  if (!decodedSET) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <Key className="w-12 h-12 text-surface-600 mb-3" />
        <p className="text-surface-400">No SET captured</p>
        <p className="text-surface-400 text-sm">Complete the flow to see the decoded SET</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="rounded-lg bg-surface-900/50 border border-white/5 overflow-hidden">
        <div className="p-2.5 sm:p-3 border-b border-white/5">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-1.5 sm:gap-2 min-w-0">
              <Key className="w-4 h-4 sm:w-5 sm:h-5 flex-shrink-0 text-amber-400" />
              <span className="font-medium text-white text-sm sm:text-base truncate">
                Security Event Token (SET)
              </span>
            </div>
            <div className="flex items-center gap-1.5 sm:gap-2 flex-shrink-0">
              <span className="flex items-center gap-1 text-[10px] sm:text-xs text-green-400">
                <CheckCircle className="w-3 h-3 sm:w-3.5 sm:h-3.5" />
                <span className="hidden sm:inline">Valid</span>
              </span>
              <CopyButton text={decodedSET.raw_token} />
            </div>
          </div>
        </div>

        <div className="p-2.5 sm:p-3 space-y-2 sm:space-y-3">
          <div>
            <h3 className="text-[10px] sm:text-xs font-medium text-surface-400 mb-1">Header</h3>
            <pre className="p-2 rounded bg-surface-950 text-[10px] sm:text-xs font-mono text-surface-300 overflow-x-auto scrollbar-hide">
              {JSON.stringify(decodedSET.header, null, 2)}
            </pre>
          </div>

          <div>
            <h3 className="text-[10px] sm:text-xs font-medium text-surface-400 mb-1">Payload</h3>
            <pre className="p-2 rounded bg-surface-950 text-[10px] sm:text-xs font-mono text-surface-300 overflow-x-auto scrollbar-hide">
              {JSON.stringify({
                jti: decodedSET.jti,
                iss: decodedSET.iss,
                aud: decodedSET.aud,
                iat: decodedSET.iat,
                sub_id: decodedSET.sub_id,
                events: decodedSET.events.map((e) => ({ [e.type]: e.payload })),
              }, null, 2)}
            </pre>
          </div>

          {decodedSET.events[0] && (
            <div className={`p-3 rounded-lg ${
              decodedSET.events[0].metadata.category === 'CAEP'
                ? 'bg-blue-500/5 border border-blue-500/20'
                : 'bg-amber-500/5 border border-amber-500/20'
            }`}>
              <div className="flex items-center gap-2 mb-2">
                <span className={`text-xs font-bold px-2 py-0.5 rounded ${
                  decodedSET.events[0].metadata.category === 'CAEP' ? 'bg-blue-500 text-white' : 'bg-amber-500 text-white'
                }`}>
                  {decodedSET.events[0].metadata.category}
                </span>
                <span className="text-sm text-surface-200">{decodedSET.events[0].metadata.name}</span>
              </div>
              <p className="text-xs text-surface-400">{decodedSET.events[0].metadata.zero_trust_impact}</p>
            </div>
          )}

          <div>
            <div className="flex items-center justify-between mb-1">
              <h3 className="text-[10px] sm:text-xs font-medium text-surface-400">Raw Token</h3>
              <CopyButton text={decodedSET.raw_token} />
            </div>
            <div className="p-2 rounded bg-surface-950 font-mono text-[10px] break-all">
              <span className="text-red-400">{decodedSET.raw_token.split('.')[0]}</span>
              <span className="text-surface-600">.</span>
              <span className="text-purple-400">{decodedSET.raw_token.split('.')[1]}</span>
              <span className="text-surface-600">.</span>
              <span className="text-cyan-400">{decodedSET.raw_token.split('.')[2]}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function SecurityStatePanel({ state, onReset }: { state: SecurityState | null; onReset?: () => void }) {
  if (!state) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <User className="w-12 h-12 text-surface-600 mb-3" />
        <p className="text-surface-400">No security state</p>
        <p className="text-surface-400 text-sm">Execute a flow to see state changes</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="rounded-lg bg-surface-900/50 border border-white/5 overflow-hidden">
        <div className="p-3 border-b border-white/5 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <User className="w-4 h-4 text-purple-400" />
            <span className="font-medium text-white text-sm">Security State: {state.email}</span>
          </div>
          {onReset && (
            <button
              onClick={onReset}
              className="text-xs px-2 py-1 rounded bg-surface-800 text-surface-400 hover:text-white transition-colors"
            >
              Reset State
            </button>
          )}
        </div>
        <div className="p-3 grid grid-cols-2 gap-3">
          <StateItem label="Active Sessions" value={state.sessions_active.toString()} status={state.sessions_active > 0 ? 'good' : 'neutral'} />
          <StateItem label="Account Status" value={state.account_enabled ? 'Enabled' : 'Disabled'} status={state.account_enabled ? 'good' : 'bad'} />
          <StateItem label="Tokens" value={state.tokens_valid ? 'Valid' : 'Invalid'} status={state.tokens_valid ? 'good' : 'bad'} />
          <StateItem label="Password Reset" value={state.password_reset_required ? 'Required' : 'Not Required'} status={state.password_reset_required ? 'warn' : 'good'} />
        </div>
        <div className="px-3 pb-3 text-xs text-surface-400">
          Last modified: {new Date(state.last_modified).toLocaleString()} by {state.modified_by}
        </div>
      </div>
    </div>
  )
}

function StateItem({ label, value, status }: { label: string; value: string; status: 'good' | 'warn' | 'bad' | 'neutral' }) {
  const colors = {
    good: 'text-green-400',
    warn: 'text-amber-400',
    bad: 'text-red-400',
    neutral: 'text-surface-300',
  }
  return (
    <div className="p-2 rounded bg-surface-800/50">
      <div className="text-[10px] text-surface-400 uppercase tracking-wider">{label}</div>
      <div className={`text-sm font-medium ${colors[status]}`}>{value}</div>
    </div>
  )
}

function TrafficPanel({ exchanges }: { exchanges: CapturedHTTPExchange[] }) {
  if (exchanges.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <Globe className="w-12 h-12 text-surface-600 mb-3" />
        <p className="text-surface-400">No HTTP traffic captured</p>
        <p className="text-surface-500 text-sm mt-1">Execute the flow to see real HTTP exchanges<br />between the transmitter and receiver</p>
      </div>
    )
  }

  return (
    <div className="space-y-2">
      {exchanges.map((exchange, index) => (
        <HTTPExchangeCard key={index} exchange={exchange} />
      ))}
    </div>
  )
}

function HTTPExchangeCard({ exchange }: { exchange: CapturedHTTPExchange }) {
  const [isExpanded, setIsExpanded] = useState(false)

  const statusCode = exchange.response.status_code
  const statusBg = statusCode >= 200 && statusCode < 300
    ? 'bg-green-500/10 text-green-400'
    : statusCode >= 400
      ? 'bg-red-500/10 text-red-400'
      : 'bg-yellow-500/10 text-yellow-400'
  const statusTextColor = statusCode >= 200 && statusCode < 300
    ? 'text-green-400'
    : statusCode >= 400
      ? 'text-red-400'
      : 'text-yellow-400'

  const rfcMatch = exchange.label.match(/\(([^)]+)\)/)
  const rfcReference = rfcMatch ? rfcMatch[1] : null
  const stepLabel = exchange.label.replace(/\s*\([^)]*\)/, '')

  return (
    <div className="rounded-lg bg-surface-900/50 border border-white/5 overflow-hidden">
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full p-3 flex items-center gap-2 sm:gap-3 hover:bg-white/5 active:bg-white/10 transition-colors text-left"
      >
        <div className="p-1.5 rounded bg-cyan-500/10 flex-shrink-0">
          <Send className="w-4 h-4 text-cyan-400" />
        </div>
        <div className="flex-1 min-w-0 overflow-hidden">
          <div className="flex items-center gap-2 flex-wrap sm:flex-nowrap">
            <span className="font-mono text-xs sm:text-sm font-medium text-cyan-400 flex-shrink-0">
              {exchange.request.method}
            </span>
            <span className="text-xs sm:text-sm text-surface-300 truncate max-w-full">
              {exchange.request.url}
            </span>
          </div>
          <p className="text-xs text-surface-400 mt-0.5 truncate">{stepLabel}</p>
        </div>
        <div className="flex items-center gap-1.5 sm:gap-2 flex-shrink-0">
          <span className={`px-1.5 sm:px-2 py-0.5 rounded text-xs font-medium ${statusBg}`}>
            {statusCode}
          </span>
          {rfcReference && (
            <span className="hidden sm:inline px-1.5 py-0.5 rounded text-xs bg-indigo-500/10 text-indigo-400 font-mono">
              {rfcReference}
            </span>
          )}
          {isExpanded ? (
            <ChevronDown className="w-4 h-4 text-surface-400" />
          ) : (
            <ChevronRight className="w-4 h-4 text-surface-400" />
          )}
        </div>
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
              <div>
                <h4 className="text-xs font-medium text-surface-400 mb-2">Request</h4>
                <pre className="p-2 rounded bg-surface-950 text-xs font-mono overflow-x-auto">
                  <div className="text-cyan-400">
                    {exchange.request.method} {exchange.request.url}
                  </div>
                  {exchange.request.headers && Object.entries(exchange.request.headers).map(([k, v]) => (
                    <div key={k} className="text-surface-400">
                      <span className="text-surface-400">{k}:</span> {v}
                    </div>
                  ))}
                  {exchange.request.body && (
                    <div className="mt-2 pt-2 border-t border-white/5 text-surface-300">
                      {tryFormatJSON(exchange.request.body)}
                    </div>
                  )}
                </pre>
              </div>

              <div>
                <h4 className="text-xs font-medium text-surface-400 mb-2">
                  Response ({exchange.duration_ms}ms)
                </h4>
                <pre className="p-2 rounded bg-surface-950 text-xs font-mono overflow-x-auto">
                  <div className={statusTextColor}>
                    {statusCode} {statusCode === 202 ? 'OK' : statusCode < 300 ? 'OK' : statusCode < 400 ? 'Redirect' : 'Error'}
                  </div>
                  {exchange.response.body && (
                    <div className="mt-2 text-surface-300">
                      {tryFormatJSON(exchange.response.body)}
                    </div>
                  )}
                </pre>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function tryFormatJSON(str: string): string {
  try {
    return JSON.stringify(JSON.parse(str), null, 2)
  } catch {
    return str
  }
}

function ExpandableData({ data }: { data: Record<string, unknown> }) {
  const [isExpanded, setIsExpanded] = useState(false)

  if (Object.keys(data).length === 0) return null

  return (
    <div className="mt-2">
      <ExpandableSection
        isExpanded={isExpanded}
        onToggle={() => setIsExpanded(!isExpanded)}
        header={(
          <span className="flex items-center gap-1 text-xs text-surface-400 hover:text-surface-300 transition-colors">
            <Code className="w-3 h-3" />
            {isExpanded ? 'Hide' : 'Show'} data
            {isExpanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
          </span>
        )}
        headerClassName="flex items-center gap-1 text-xs text-surface-400 hover:text-surface-300 transition-colors"
      >
        <pre className="mt-2 p-2 rounded bg-surface-950 text-xs font-mono text-surface-400 overflow-x-auto">
          {JSON.stringify(data, null, 2)}
        </pre>
      </ExpandableSection>
    </div>
  )
}
