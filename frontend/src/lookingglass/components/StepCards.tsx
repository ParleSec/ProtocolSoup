import { motion } from 'framer-motion'
import { useState, useEffect, useRef, useMemo, type ElementType } from 'react'
import {
  CheckCircle, XCircle, Clock, Send, ArrowDownLeft, Key, Shield,
  AlertTriangle, Info, Lock, ChevronDown, ChevronRight, Book,
  User, Fingerprint, Zap, Radio, Code
} from 'lucide-react'
import type { FlowEvent, CapturedExchange, DecodedToken, FlowExecutorState } from '../flows'
import type { WireCapturedExchange } from '../types'
import { TLSInspector } from './inspectors/TLSInspector'
import { CopyButton } from './shared'

// ============================================================================
// Props & Types
// ============================================================================

interface StepCardsProps {
  events: FlowEvent[]
  exchanges: CapturedExchange[]
  wireExchanges: WireCapturedExchange[]
  decodedTokens: DecodedToken[]
  status: FlowExecutorState['status']
  currentStep: string
  showTLSContext?: boolean
}

interface PhaseGroup {
  phase: string
  events: FlowEvent[]
  exchangeIds: Set<string>
}

interface ResolvedPhase {
  phase: string
  stepNumber: number
  events: FlowEvent[]
  clientExchanges: CapturedExchange[]
  wireCaptures: WireCapturedExchange[]
  tokens: DecodedToken[]
  timing: { first: Date; last: Date; durationMs: number }
  rfcReference: string | undefined
  status: 'executing' | 'complete' | 'error' | 'awaiting'
}

// ============================================================================
// Main Component
// ============================================================================

export function StepCards({
  events,
  exchanges,
  wireExchanges,
  decodedTokens,
  status,
  currentStep,
  showTLSContext = false,
}: StepCardsProps) {
  const phases = useMemo(
    () => resolvePhases(events, exchanges, wireExchanges, decodedTokens, status, currentStep),
    [events, exchanges, wireExchanges, decodedTokens, status, currentStep],
  )

  if (phases.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <div className="w-12 h-12 rounded-xl bg-surface-800 border border-white/5 flex items-center justify-center mb-4">
          <Zap className="w-6 h-6 text-surface-500" />
        </div>
        <p className="text-surface-300 font-medium">No events yet</p>
        <p className="text-surface-400 text-sm mt-1.5 max-w-xs leading-relaxed">
          Press <span className="text-green-400 font-medium">Execute</span> to run
          the flow and see each protocol step in real time
        </p>
      </div>
    )
  }

  return (
    <div className="relative">
      {phases.map((phase, idx) => (
        <div key={phase.phase + idx} className="relative">
          {idx > 0 && (
            <div className="flex items-center justify-center">
              <div className="w-px h-2.5 bg-gradient-to-b from-surface-700/80 to-surface-700/30" />
            </div>
          )}
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: idx * 0.04, duration: 0.25 }}
          >
            <StepCard phase={phase} showTLSContext={showTLSContext} />
          </motion.div>
        </div>
      ))}
    </div>
  )
}

// ============================================================================
// Grouping & Correlation
// ============================================================================

function resolvePhases(
  events: FlowEvent[],
  exchanges: CapturedExchange[],
  wireExchanges: WireCapturedExchange[],
  decodedTokens: DecodedToken[],
  flowStatus: FlowExecutorState['status'],
  _currentStep: string,
): ResolvedPhase[] {
  const groups: PhaseGroup[] = []
  const phaseOrder: string[] = []

  for (const event of events) {
    const phaseName = event.phase || 'Initialized'
    let group = groups.find(g => g.phase === phaseName)
    if (!group) {
      group = { phase: phaseName, events: [], exchangeIds: new Set() }
      groups.push(group)
      phaseOrder.push(phaseName)
    }
    group.events.push(event)
    const eid = event.data?.exchangeId
    if (typeof eid === 'string') {
      group.exchangeIds.add(eid)
    }
  }

  const exchangeMap = new Map(exchanges.map(e => [e.id, e]))
  const usedWireIds = new Set<string>()
  let tokenIdx = 0

  return groups.map((group, idx) => {
    const clientExchanges = [...group.exchangeIds]
      .map(id => exchangeMap.get(id))
      .filter((e): e is CapturedExchange => !!e)

    const matched = matchWireExchanges(clientExchanges, wireExchanges, usedWireIds)
    matched.forEach(w => usedWireIds.add(w.id))

    const tokenEvents = group.events.filter(e => e.type === 'token')
    const tokens: DecodedToken[] = []
    for (let i = 0; i < tokenEvents.length && tokenIdx < decodedTokens.length; i++) {
      tokens.push(decodedTokens[tokenIdx++])
    }

    const first = group.events[0]?.timestamp ?? new Date()
    const last = group.events[group.events.length - 1]?.timestamp ?? first
    const durationMs = last.getTime() - first.getTime()

    const rfcReference = pickBestRfcReference(group.events)

    const isLast = idx === groups.length - 1
    const hasError = group.events.some(e => e.type === 'error')
    const hasAwaiting = group.events.some(e => e.type === 'user_action')
    let phaseStatus: ResolvedPhase['status'] = 'complete'
    if (hasError) phaseStatus = 'error'
    else if (isLast && (flowStatus === 'executing' || (flowStatus === 'awaiting_user' && !hasAwaiting))) phaseStatus = 'executing'
    else if (isLast && flowStatus === 'awaiting_user' && hasAwaiting) phaseStatus = 'awaiting'

    return {
      phase: group.phase,
      stepNumber: idx + 1,
      events: group.events,
      clientExchanges,
      wireCaptures: matched,
      tokens,
      timing: { first, last, durationMs },
      rfcReference,
      status: phaseStatus,
    }
  })
}

function matchWireExchanges(
  clientExchanges: CapturedExchange[],
  wireExchanges: WireCapturedExchange[],
  used: Set<string>,
): WireCapturedExchange[] {
  const matched: WireCapturedExchange[] = []
  for (const ce of clientExchanges) {
    const clientPath = extractPath(ce.request.url)
    const clientMethod = ce.request.method
    const clientTime = ce.timestamp.getTime()

    let best: WireCapturedExchange | null = null
    let bestDelta = Infinity
    for (const we of wireExchanges) {
      if (used.has(we.id)) continue
      const wirePath = extractPath(we.request.url || '')
      const wireMethod = we.request.method || ''
      if (wirePath !== clientPath || wireMethod !== clientMethod) continue
      const wireTime = we.timing.startUnixMicro / 1000
      const delta = Math.abs(wireTime - clientTime)
      if (delta < bestDelta && delta < 10000) {
        bestDelta = delta
        best = we
      }
    }
    if (best) matched.push(best)
  }
  return matched
}

function extractPath(url: string): string {
  try {
    return new URL(url, 'http://localhost').pathname
  } catch {
    return url.split('?')[0]
  }
}

function pickBestRfcReference(events: FlowEvent[]): string | undefined {
  for (const e of events) {
    if (e.type === 'rfc' && e.rfcReference) return e.rfcReference
  }
  for (const e of events) {
    if (e.rfcReference) return e.rfcReference
  }
  return undefined
}

// ============================================================================
// Step Card
// ============================================================================

const statusAccent: Record<ResolvedPhase['status'], string> = {
  executing: 'border-l-cyan-400',
  complete: 'border-l-green-500/60',
  error: 'border-l-red-500/80',
  awaiting: 'border-l-orange-400',
}

const statusIcon: Record<ResolvedPhase['status'], { icon: ElementType; color: string }> = {
  executing: { icon: Clock, color: 'text-cyan-400' },
  complete: { icon: CheckCircle, color: 'text-green-400' },
  error: { icon: XCircle, color: 'text-red-400' },
  awaiting: { icon: User, color: 'text-orange-400' },
}

function StepCard({ phase, showTLSContext }: { phase: ResolvedPhase; showTLSContext: boolean }) {
  const si = statusIcon[phase.status]
  const StatusIcon = si.icon
  const isExecuting = phase.status === 'executing'
  const isAwaiting = phase.status === 'awaiting'

  const exchangeMap = useMemo(() => {
    const m = new Map<string, CapturedExchange>()
    phase.clientExchanges.forEach(e => m.set(e.id, e))
    return m
  }, [phase.clientExchanges])

  const wireByUrl = useMemo(() => {
    const m = new Map<string, WireCapturedExchange>()
    phase.wireCaptures.forEach(w => {
      const key = `${w.request.method || ''}:${extractPath(w.request.url || '')}`
      m.set(key, w)
    })
    return m
  }, [phase.wireCaptures])

  const renderedExchangeIds = useRef(new Set<string>())
  const tokenQueue = useRef([...phase.tokens])

  useEffect(() => {
    renderedExchangeIds.current = new Set<string>()
    tokenQueue.current = [...phase.tokens]
  }, [phase.tokens])

  renderedExchangeIds.current = new Set<string>()
  tokenQueue.current = [...phase.tokens]

  return (
    <div className={`rounded-xl bg-surface-900/50 border border-l-2 overflow-hidden transition-all duration-300 ${statusAccent[phase.status]} ${
      isExecuting
        ? 'border-white/10 ring-1 ring-cyan-500/20 shadow-[0_0_20px_rgba(6,182,212,0.15)]'
        : isAwaiting
          ? 'border-white/10 ring-1 ring-orange-500/15'
          : 'border-white/5'
    }`}>
      {/* Card header */}
      <div className={`px-3 sm:px-4 py-2.5 flex items-center gap-2 sm:gap-3 border-b border-white/5 ${
        isExecuting ? 'bg-cyan-500/[0.03]' : isAwaiting ? 'bg-orange-500/[0.03]' : 'bg-surface-900/30'
      }`}>
        <span className={`flex items-center justify-center w-6 h-6 rounded-md text-xs font-bold flex-shrink-0 ${
          isExecuting ? 'bg-cyan-500/15 text-cyan-300' : isAwaiting ? 'bg-orange-500/15 text-orange-300' : 'bg-surface-800 text-surface-300'
        }`}>
          {phase.stepNumber}
        </span>
        <StatusIcon className={`w-4 h-4 flex-shrink-0 ${si.color} ${isExecuting ? 'animate-pulse' : ''}`} />
        <h3 className="flex-1 min-w-0 text-sm font-medium text-white truncate">
          {phase.phase}
        </h3>
        <div className="flex items-center gap-2 flex-shrink-0">
          {phase.timing.durationMs > 0 && (
            <span className="text-[11px] text-surface-500 font-mono tabular-nums">
              {formatDuration(phase.timing.durationMs)}
            </span>
          )}
          {phase.rfcReference && (
            <span className="hidden sm:inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-indigo-500/10 text-indigo-400 font-mono">
              <Book className="w-3 h-3" />
              {phase.rfcReference}
            </span>
          )}
        </div>
      </div>

      {/* Card body */}
      <div className="px-3 sm:px-4 py-2.5 space-y-2">
        {phase.events.map(event => {
          if (event.type === 'request') {
            const eid = event.data?.exchangeId as string | undefined
            if (eid && renderedExchangeIds.current.has(eid)) return null
            if (eid) renderedExchangeIds.current.add(eid)

            const exchange = eid ? exchangeMap.get(eid) : undefined
            const responseEvent = eid
              ? phase.events.find(e => e.type === 'response' && e.data?.exchangeId === eid)
              : undefined
            const wireKey = exchange ? `${exchange.request.method}:${extractPath(exchange.request.url)}` : undefined
            const wire = wireKey ? wireByUrl.get(wireKey) : undefined

            return (
              <HttpExchangeBlock
                key={event.id}
                requestEvent={event}
                responseEvent={responseEvent}
                exchange={exchange}
                wire={wire}
                showTLSContext={showTLSContext}
              />
            )
          }

          if (event.type === 'response') {
            const eid = event.data?.exchangeId as string | undefined
            if (eid && renderedExchangeIds.current.has(eid)) return null
            return <AnnotationRow key={event.id} event={event} />
          }

          if (event.type === 'token') {
            const token = tokenQueue.current.shift()
            return <TokenBlock key={event.id} event={event} decoded={token} />
          }

          if (event.type === 'error') {
            return <ErrorBlock key={event.id} event={event} />
          }

          if (event.type === 'user_action') {
            return <UserActionRow key={event.id} event={event} />
          }

          return <AnnotationRow key={event.id} event={event} />
        })}

        {/* Orphan wire exchanges not matched to any client exchange */}
        {phase.wireCaptures
          .filter(w => {
            const key = `${w.request.method || ''}:${extractPath(w.request.url || '')}`
            return !phase.clientExchanges.some(
              ce => `${ce.request.method}:${extractPath(ce.request.url)}` === key,
            )
          })
          .map(w => (
            <OrphanWireBlock key={w.id} wire={w} showTLSContext={showTLSContext} />
          ))}
      </div>
    </div>
  )
}

// ============================================================================
// HTTP Exchange Block
// ============================================================================

function HttpExchangeBlock({
  requestEvent,
  responseEvent,
  exchange,
  wire,
  showTLSContext,
}: {
  requestEvent: FlowEvent
  responseEvent: FlowEvent | undefined
  exchange: CapturedExchange | undefined
  wire: WireCapturedExchange | undefined
  showTLSContext: boolean
}) {
  const [expanded, setExpanded] = useState(false)

  const method = exchange?.request.method ?? (requestEvent.data?.method as string) ?? 'REQUEST'
  const url = exchange?.request.url ?? (requestEvent.data?.url as string) ?? ''
  const path = extractPath(url)
  const statusCode = exchange?.response?.status ?? (responseEvent?.data?.status as number | undefined)
  const duration = exchange?.response?.duration ?? (responseEvent?.data?.duration as number | undefined)
  const statusOk = statusCode !== undefined && statusCode < 400

  const requestBody = exchange?.request.body
  const responseBody = exchange?.response?.body

  return (
    <div className="rounded-lg bg-surface-950/50 border border-white/5 overflow-hidden">
      {/* Exchange summary */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-3 py-2 flex items-center gap-2 hover:bg-white/[0.03] transition-colors text-left"
      >
        <Send className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />
        <span className="font-mono text-xs font-medium text-cyan-400 flex-shrink-0">{method}</span>
        <span className="text-xs text-surface-300 truncate flex-1 min-w-0">{path}</span>
        {statusCode !== undefined && (
          <>
            <ArrowDownLeft className="w-3 h-3 text-surface-500 flex-shrink-0" />
            <span className={`text-xs font-medium flex-shrink-0 ${statusOk ? 'text-green-400' : 'text-red-400'}`}>
              {statusCode}
            </span>
          </>
        )}
        {duration !== undefined && (
          <span className="text-[10px] text-surface-500 tabular-nums flex-shrink-0">{duration}ms</span>
        )}
        <span className="text-xs text-surface-400 font-mono tabular-nums flex-shrink-0">
          {requestEvent.timestamp.toLocaleTimeString(undefined, { hour12: false, fractionalSecondDigits: 3 } as Intl.DateTimeFormatOptions)}
        </span>
        {expanded ? <ChevronDown className="w-3.5 h-3.5 text-surface-500 flex-shrink-0" /> : <ChevronRight className="w-3.5 h-3.5 text-surface-500 flex-shrink-0" />}
      </button>

      {/* Key parameters (always visible) */}
      {!!requestBody && (
        <div className="px-3 pb-2">
          <ParamTable body={requestBody} />
        </div>
      )}

      {/* Response summary (always visible when present) */}
      {!!responseBody && (
        <div className="px-3 pb-2">
          <ResponseSummary body={responseBody} statusOk={statusOk} />
        </div>
      )}

      {/* Wire capture summary */}
      {wire && (
        <WireCaptureSummary wire={wire} showTLSContext={showTLSContext} />
      )}

      {/* Expanded: full exchange details */}
      {expanded && exchange && (
        <div className="border-t border-white/5 px-3 py-2 space-y-2">
          <FullExchangeDetail exchange={exchange} />
        </div>
      )}
    </div>
  )
}

function ParamTable({ body }: { body: Record<string, string> | string }) {
  const params = typeof body === 'string' ? parseFormParams(body) : body
  if (!params || typeof params !== 'object') return null
  const entries = Object.entries(params).filter(([k]) => !k.startsWith('_'))
  if (entries.length === 0) return null

  const sensitiveKeys = new Set(['client_secret', 'code_verifier', 'password', 'assertion'])

  return (
    <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-[11px] font-mono">
      {entries.map(([k, v]) => {
        const val = String(v)
        const isSensitive = sensitiveKeys.has(k)
        const displayed = isSensitive
          ? val.substring(0, 8) + '****'
          : val.length > 80
            ? val.substring(0, 77) + '...'
            : val
        return (
          <div key={k} className="flex gap-1.5 max-w-full">
            <span className="text-surface-500 flex-shrink-0">{k}</span>
            <span className={`text-surface-300 truncate ${isSensitive ? 'text-red-300/70' : ''}`}>{displayed}</span>
          </div>
        )
      })}
    </div>
  )
}

function ResponseSummary({ body, statusOk }: { body: unknown; statusOk: boolean }) {
  if (!body) return null

  if (typeof body === 'string') {
    if (body.length === 0) return null
    return (
      <div className={`rounded px-2 py-1.5 text-[11px] font-mono break-all ${statusOk ? 'bg-green-500/5 text-surface-300' : 'bg-red-500/5 text-red-300'}`}>
        {body.length > 200 ? body.substring(0, 197) + '...' : body}
      </div>
    )
  }

  if (typeof body !== 'object') return null
  const entries = Object.entries(body as Record<string, unknown>).slice(0, 6)
  if (entries.length === 0) return null

  return (
    <div className={`rounded px-2 py-1.5 text-[11px] font-mono ${statusOk ? 'bg-green-500/5' : 'bg-red-500/5'}`}>
      {entries.map(([k, v]) => (
        <div key={k} className="flex gap-1.5 leading-relaxed">
          <span className={statusOk ? 'text-green-400/70' : 'text-red-400/70'}>{k}</span>
          <span className="text-surface-300 truncate max-w-[300px]">{summarizeValue(v)}</span>
        </div>
      ))}
    </div>
  )
}

function WireCaptureSummary({ wire, showTLSContext }: { wire: WireCapturedExchange; showTLSContext: boolean }) {
  const [expanded, setExpanded] = useState(false)
  const reqBytes = wire.meta.requestBodyReadBytes
  const resBytes = wire.meta.responseBodyWrittenBytes
  const durationMs = Math.round((wire.timing.durationMicro || 0) / 1000)
  const tlsVersion = wire.tls?.version

  return (
    <div className="border-t border-white/5">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-3 py-1.5 flex items-center gap-2 text-left hover:bg-white/[0.03] transition-colors"
      >
        <Radio className="w-3 h-3 text-purple-400 flex-shrink-0" />
        <span className="text-[10px] text-purple-400 font-medium flex-shrink-0">Wire</span>
        <span className="text-[10px] text-surface-400 font-mono flex-1 truncate tabular-nums">
          {reqBytes > 0 && <>{formatBytes(reqBytes)} req</>}
          {reqBytes > 0 && resBytes > 0 && ' · '}
          {resBytes > 0 && <>{formatBytes(resBytes)} res</>}
          {durationMs > 0 && <> · {durationMs}ms</>}
          {tlsVersion && <> · {tlsVersion}</>}
          {wire.tls?.cipherSuite && <> · {wire.tls.cipherSuite}</>}
        </span>
        {expanded ? <ChevronDown className="w-3 h-3 text-surface-500 flex-shrink-0" /> : <ChevronRight className="w-3 h-3 text-surface-500 flex-shrink-0" />}
      </button>
      {expanded && (
        <div className="px-3 pb-2 space-y-2">
          <WireDetail wire={wire} />
          {showTLSContext && wire.tls && <TLSInspector exchange={wire} />}
        </div>
      )}
    </div>
  )
}

function WireDetail({ wire }: { wire: WireCapturedExchange }) {
  return (
    <div className="space-y-2">
      {wire.request.headers && Object.keys(wire.request.headers).length > 0 && (
        <div>
          <div className="text-[10px] text-surface-500 mb-1">Request Headers</div>
          <pre className="p-2 rounded bg-surface-950 text-[10px] font-mono text-surface-400 overflow-x-auto max-h-32 overflow-y-auto">
            {Object.entries(wire.request.headers).map(([k, vs]) => `${k}: ${vs.join(', ')}`).join('\n')}
          </pre>
        </div>
      )}
      {wire.request.raw?.data && (
        <div>
          <div className="text-[10px] text-surface-500 mb-1">
            Request Body ({wire.request.raw.size} B{wire.request.raw.truncated ? ', truncated' : ''})
          </div>
          <pre className="p-2 rounded bg-surface-950 text-[10px] font-mono text-surface-400 overflow-x-auto max-h-32 overflow-y-auto">
            {wire.request.raw.data}
          </pre>
        </div>
      )}
      {wire.response.headers && Object.keys(wire.response.headers).length > 0 && (
        <div>
          <div className="text-[10px] text-surface-500 mb-1">Response Headers</div>
          <pre className="p-2 rounded bg-surface-950 text-[10px] font-mono text-surface-400 overflow-x-auto max-h-32 overflow-y-auto">
            {Object.entries(wire.response.headers).map(([k, vs]) => `${k}: ${vs.join(', ')}`).join('\n')}
          </pre>
        </div>
      )}
      {wire.response.raw?.data && (
        <div>
          <div className="text-[10px] text-surface-500 mb-1">
            Response Body ({wire.response.raw.size} B{wire.response.raw.truncated ? ', truncated' : ''})
          </div>
          <pre className="p-2 rounded bg-surface-950 text-[10px] font-mono text-surface-400 overflow-x-auto max-h-32 overflow-y-auto">
            {wire.response.raw.data}
          </pre>
        </div>
      )}
    </div>
  )
}

function FullExchangeDetail({ exchange }: { exchange: CapturedExchange }) {
  return (
    <div className="space-y-2">
      <div>
        <div className="flex items-center gap-2 text-[10px] text-surface-500 mb-1">
          <span>Request Headers</span>
          {exchange.rfcReference && (
            <span className="px-1 py-0.5 rounded bg-indigo-500/10 text-indigo-400 font-mono">{exchange.rfcReference}</span>
          )}
        </div>
        <pre className="p-2 rounded bg-surface-950 text-[10px] font-mono overflow-x-auto max-h-40 overflow-y-auto">
          <span className="text-cyan-400">{exchange.request.method} {exchange.request.url}</span>
          {'\n'}
          {Object.entries(exchange.request.headers).map(([k, v]) => (
            <span key={k} className="text-surface-400">{k}: {v}{'\n'}</span>
          ))}
          {exchange.request.body && (
            <>
              {'\n'}
              <span className="text-surface-300">
                {typeof exchange.request.body === 'string'
                  ? exchange.request.body
                  : new URLSearchParams(exchange.request.body).toString()}
              </span>
            </>
          )}
        </pre>
      </div>
      {exchange.response && (
        <div>
          <div className="text-[10px] text-surface-500 mb-1">Response ({exchange.response.duration}ms)</div>
          <pre className="p-2 rounded bg-surface-950 text-[10px] font-mono overflow-x-auto max-h-40 overflow-y-auto">
            <span className={exchange.response.status < 400 ? 'text-green-400' : 'text-red-400'}>
              {exchange.response.status} {exchange.response.statusText}
            </span>
            {'\n\n'}
            <span className="text-surface-300">
              {typeof exchange.response.body === 'string'
                ? exchange.response.body
                : JSON.stringify(exchange.response.body, null, 2)}
            </span>
          </pre>
        </div>
      )}
    </div>
  )
}

function OrphanWireBlock({ wire, showTLSContext }: { wire: WireCapturedExchange; showTLSContext: boolean }) {
  const [expanded, setExpanded] = useState(false)
  const method = wire.request.method || 'REQUEST'
  const url = wire.request.url || ''
  const durationMs = Math.round((wire.timing.durationMicro || 0) / 1000)

  return (
    <div className="rounded-lg bg-purple-500/5 border border-purple-500/10 overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-3 py-2 flex items-center gap-2 hover:bg-white/[0.03] transition-colors text-left"
      >
        <Radio className="w-3.5 h-3.5 text-purple-400 flex-shrink-0" />
        <span className="font-mono text-xs font-medium text-purple-400 flex-shrink-0">{method}</span>
        <span className="text-xs text-surface-300 truncate flex-1 min-w-0">{extractPath(url)}</span>
        {wire.response.status !== undefined && (
          <span className={`text-xs font-medium flex-shrink-0 ${wire.response.status < 400 ? 'text-green-400' : 'text-red-400'}`}>
            {wire.response.status}
          </span>
        )}
        {durationMs > 0 && <span className="text-[10px] text-surface-500 tabular-nums flex-shrink-0">{durationMs}ms</span>}
        {expanded ? <ChevronDown className="w-3 h-3 text-surface-500 flex-shrink-0" /> : <ChevronRight className="w-3 h-3 text-surface-500 flex-shrink-0" />}
      </button>
      {expanded && (
        <div className="border-t border-purple-500/10 px-3 py-2 space-y-2">
          <WireDetail wire={wire} />
          {showTLSContext && wire.tls && <TLSInspector exchange={wire} />}
        </div>
      )}
    </div>
  )
}

// ============================================================================
// Token Block
// ============================================================================

const tokenLabels: Record<string, { label: string; icon: ElementType; color: string }> = {
  access_token: { label: 'Access Token', icon: Key, color: 'text-green-400' },
  id_token: { label: 'ID Token (OIDC)', icon: Fingerprint, color: 'text-orange-400' },
  refresh_token: { label: 'Refresh Token', icon: Key, color: 'text-blue-400' },
}

function TokenBlock({ event, decoded }: { event: FlowEvent; decoded: DecodedToken | undefined }) {
  const [expanded, setExpanded] = useState(false)
  const info = decoded ? tokenLabels[decoded.type] : undefined
  const Icon = info?.icon ?? Key
  const label = info?.label ?? event.title
  const color = info?.color ?? 'text-yellow-400'

  return (
    <div className="rounded-lg bg-yellow-500/5 border border-yellow-500/10 overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-3 py-2 flex items-center gap-2 text-left hover:bg-white/[0.03] transition-colors"
      >
        <Icon className={`w-3.5 h-3.5 flex-shrink-0 ${color}`} />
        <span className={`text-xs font-medium flex-shrink-0 ${color}`}>{label}</span>
        {decoded?.isValid !== undefined && (
          decoded.isValid
            ? <CheckCircle className="w-3 h-3 text-green-400 flex-shrink-0" />
            : <XCircle className="w-3 h-3 text-red-400 flex-shrink-0" />
        )}
        <span className="text-[11px] text-surface-400 truncate flex-1 min-w-0">{event.description}</span>
        {event.rfcReference && (
          <span className="hidden sm:inline text-[10px] text-indigo-400 font-mono flex-shrink-0">{event.rfcReference}</span>
        )}
        {expanded ? <ChevronDown className="w-3 h-3 text-surface-500 flex-shrink-0" /> : <ChevronRight className="w-3 h-3 text-surface-500 flex-shrink-0" />}
      </button>

      {/* Key claims (always visible when decoded) */}
      {decoded?.payload && (
        <div className="px-3 pb-2">
          <TokenClaimsSummary header={decoded.header} payload={decoded.payload} />
        </div>
      )}

      {decoded?.validationErrors && decoded.validationErrors.length > 0 && (
        <div className="px-3 pb-2">
          <div className="rounded px-2 py-1 bg-red-500/10 text-[10px] text-red-300">
            {decoded.validationErrors.map((err, i) => <div key={i}>{err}</div>)}
          </div>
        </div>
      )}

      {expanded && decoded && (
        <div className="border-t border-yellow-500/10 px-3 py-2 space-y-2">
          {decoded.header && (
            <div>
              <div className="text-[10px] text-surface-500 mb-1">Header</div>
              <pre className="p-2 rounded bg-surface-950 text-[10px] font-mono text-surface-300 overflow-x-auto">
                {JSON.stringify(decoded.header, null, 2)}
              </pre>
            </div>
          )}
          {decoded.payload && (
            <div>
              <div className="text-[10px] text-surface-500 mb-1">Payload</div>
              <pre className="p-2 rounded bg-surface-950 text-[10px] font-mono text-surface-300 overflow-x-auto">
                {JSON.stringify(decoded.payload, null, 2)}
              </pre>
            </div>
          )}
          {decoded.raw && (
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-surface-500">Raw</span>
              <CopyButton text={decoded.raw} />
            </div>
          )}
        </div>
      )}
    </div>
  )
}

const KEY_CLAIMS = ['sub', 'iss', 'aud', 'exp', 'iat', 'scope', 'nonce', 'azp', 'client_id'] as const

function TokenClaimsSummary({
  header,
  payload,
}: {
  header: Record<string, unknown> | undefined
  payload: Record<string, unknown>
}) {
  const headerParts: string[] = []
  if (header?.alg) headerParts.push(`alg: ${header.alg}`)
  if (header?.kid) headerParts.push(`kid: ${String(header.kid).substring(0, 16)}`)

  const claimEntries = KEY_CLAIMS
    .filter(k => payload[k] !== undefined)
    .map(k => {
      let v = payload[k]
      if ((k === 'exp' || k === 'iat') && typeof v === 'number') {
        v = new Date(v * 1000).toISOString()
      }
      return { k, v: summarizeValue(v) }
    })

  return (
    <div className="text-[10px] font-mono space-y-0.5">
      {headerParts.length > 0 && (
        <div className="text-surface-500">{headerParts.join('  ')}</div>
      )}
      <div className="flex flex-wrap gap-x-3 gap-y-0.5">
        {claimEntries.map(({ k, v }) => (
          <div key={k} className="flex gap-1">
            <span className="text-yellow-400/60">{k}:</span>
            <span className="text-surface-300 truncate max-w-[180px]">{v}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ============================================================================
// Annotation / Error / User Action Rows
// ============================================================================

const annotationConfig: Record<string, { icon: ElementType; color: string; bg: string }> = {
  info: { icon: Info, color: 'text-blue-400', bg: 'bg-blue-500/10' },
  response: { icon: ArrowDownLeft, color: 'text-green-400', bg: 'bg-green-500/10' },
  security: { icon: Shield, color: 'text-orange-400', bg: 'bg-orange-500/10' },
  crypto: { icon: Lock, color: 'text-purple-400', bg: 'bg-purple-500/10' },
  rfc: { icon: Book, color: 'text-indigo-400', bg: 'bg-indigo-500/10' },
}

function AnnotationRow({ event }: { event: FlowEvent }) {
  const [expanded, setExpanded] = useState(false)
  const cfg = annotationConfig[event.type] ?? annotationConfig.info
  const Icon = cfg.icon
  const hasData = event.data && Object.keys(event.data).filter(k => k !== 'exchangeId').length > 0

  return (
    <div className="flex items-start gap-2 py-1">
      <div className={`p-1 rounded ${cfg.bg} flex-shrink-0 mt-0.5`}>
        <Icon className={`w-3 h-3 ${cfg.color}`} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-medium text-white">{event.title}</span>
          {event.rfcReference && (
            <span className="px-1 py-0.5 rounded text-[10px] bg-indigo-500/10 text-indigo-400 font-mono">{event.rfcReference}</span>
          )}
        </div>
        {event.description && (
          <p className="text-[11px] text-surface-400 mt-0.5">{event.description}</p>
        )}
        {hasData && (
          <button
            onClick={() => setExpanded(!expanded)}
            className="flex items-center gap-1 text-[10px] text-surface-500 hover:text-surface-300 transition-colors mt-1"
          >
            <Code className="w-3 h-3" />
            {expanded ? 'Hide' : 'Show'} data
            {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
          </button>
        )}
        {expanded && hasData && (
          <pre className="mt-1 p-2 rounded bg-surface-950 text-[10px] font-mono text-surface-400 overflow-x-auto max-h-32 overflow-y-auto">
            {JSON.stringify(filterEventData(event.data!), null, 2)}
          </pre>
        )}
      </div>
    </div>
  )
}

function ErrorBlock({ event }: { event: FlowEvent }) {
  const hasData = event.data && Object.keys(event.data).filter(k => k !== 'exchangeId').length > 0

  return (
    <div className="rounded-lg bg-red-500/5 border border-red-500/20 px-3 py-2 space-y-1">
      <div className="flex items-center gap-2">
        <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
        <span className="text-xs font-medium text-red-400">{event.title}</span>
        {event.rfcReference && (
          <span className="px-1 py-0.5 rounded text-[10px] bg-red-500/10 text-red-400 font-mono">{event.rfcReference}</span>
        )}
      </div>
      {event.description && (
        <p className="text-[11px] text-red-300">{event.description}</p>
      )}
      {hasData && (
        <pre className="p-1.5 rounded bg-red-950/30 text-[10px] font-mono text-red-300/80 overflow-x-auto max-h-24 overflow-y-auto">
          {JSON.stringify(filterEventData(event.data!), null, 2)}
        </pre>
      )}
    </div>
  )
}

function UserActionRow({ event }: { event: FlowEvent }) {
  return (
    <div className="rounded-lg bg-orange-500/5 border border-orange-500/20 px-3 py-2">
      <div className="flex items-center gap-2">
        <span className="relative flex-shrink-0">
          <User className="w-4 h-4 text-orange-400" />
          <span className="absolute -top-0.5 -right-0.5 w-2 h-2 bg-orange-400 rounded-full animate-pulse" />
        </span>
        <span className="text-xs font-medium text-orange-400">{event.title}</span>
      </div>
      {event.description && (
        <p className="text-[11px] text-orange-300 mt-1">{event.description}</p>
      )}
    </div>
  )
}

// ============================================================================
// Helpers
// ============================================================================

function formatDuration(ms: number): string {
  if (ms < 1) return '<1ms'
  if (ms < 1000) return `${Math.round(ms)}ms`
  return `${(ms / 1000).toFixed(1)}s`
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function summarizeValue(v: unknown): string {
  if (v === null || v === undefined) return ''
  if (typeof v === 'string') {
    if (v.length > 60) return v.substring(0, 57) + '...'
    return v
  }
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  if (Array.isArray(v)) return v.join(', ')
  return JSON.stringify(v)
}

function parseFormParams(body: string): Record<string, string> | null {
  try {
    const params = new URLSearchParams(body)
    const result: Record<string, string> = {}
    params.forEach((v, k) => { result[k] = v })
    return Object.keys(result).length > 0 ? result : null
  } catch {
    return null
  }
}

function filterEventData(data: Record<string, unknown>): Record<string, unknown> {
  const filtered: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(data)) {
    if (k === 'exchangeId') continue
    filtered[k] = v
  }
  return filtered
}
