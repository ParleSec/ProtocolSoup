/**
 * SSF Sandbox - Shared Signals Framework Execution
 * 
 * Matches the Looking Glass pattern for consistency.
 * Execute SSF flows and inspect the traffic.
 * 
 * Each browser session gets isolated data via session ID.
 */

'use client'

import { useState, useEffect, useCallback, useMemo, type ElementType } from 'react'
import { motion } from 'framer-motion'
import { 
  Radio, ChevronRight, Shield, AlertTriangle, 
  RotateCcw, Lock, UserX, UserCheck, Terminal,
  Sparkles, Play, Key, Info, Square, Code, User, ChevronDown,
  XCircle
} from 'lucide-react'
import { TokenInspector } from '../lookingglass/components/inspectors/TokenInspector'
import {
  StatusBadge as SharedStatusBadge,
  type StatusBadgeVariant,
} from '../lookingglass/components/shared'
import { getOrCreateSSFSessionId, ssfFetch, useSSFEventStream } from '../hooks/useSSFEventStream'
import type { DecodedSET, EventDef, SecurityState, Subject, SSEPipelineEvent } from '../lookingglass/ssf/types'
import { SSFFlowPanel } from '../lookingglass/components/ssf/SSFFlowPanel'

const SSF_STATUS_BADGE_VARIANTS: Record<string, StatusBadgeVariant> = {
  completed: { bg: 'bg-green-500/10', border: 'border-green-500/30', text: 'text-green-400', label: 'Completed', shortLabel: 'Done' },
  executing: { bg: 'bg-amber-500/10', border: 'border-amber-500/30', text: 'text-amber-400', label: 'Executing...', shortLabel: 'Running' },
  error: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', label: 'Error', shortLabel: 'Error' },
}
// ============================================================================
// Event Definitions
// ============================================================================

// Icon mapping for event types
const EVENT_ICONS: Record<string, ElementType> = {
  'session-revoked': Lock,
  'token-claims-change': Code,
  'credential-change': Key,
  'assurance-level-change': Shield,
  'device-compliance-change': AlertTriangle,
  'credential-compromise': AlertTriangle,
  'account-purged': XCircle,
  'account-disabled': UserX,
  'account-enabled': UserCheck,
  'identifier-changed': User,
  'identifier-recycled': RotateCcw,
  'account-credential-change-required': Key,
  'sessions-revoked': RotateCcw,
}

// No hardcoded event definitions -- everything comes from the backend's event registry

// ============================================================================
// Main Component
// ============================================================================

export function SSFSandbox() {
  const [subjects, setSubjects] = useState<Subject[]>([])
  const [selectedSubject, setSelectedSubject] = useState<Subject | null>(null)
  const [selectedEvent, setSelectedEvent] = useState<EventDef | null>(null)
  const [securityStates, setSecurityStates] = useState<Record<string, SecurityState>>({})
  const [eventDefs, setEventDefs] = useState<EventDef[]>([])
  
  // Execution state
  const [status, setStatus] = useState<'idle' | 'executing' | 'completed' | 'error'>('idle')
  const [decodedSET, setDecodedSET] = useState<DecodedSET | null>(null)
  const [activeTab, setActiveTab] = useState<'events' | 'traffic' | 'set' | 'state'>('events')
  
  // Manual SET decoder (uses TokenInspector component)
  const [manualSET, setManualSET] = useState('')

  // Session ID for this browser tab
  const sessionId = useMemo(() => getOrCreateSSFSessionId(), [])

  // Real-time SSE event stream from the backend
  const { pipelineEvents, httpExchanges, isConnected, clearEvents, ingestResponseEvents } = useSSFEventStream(sessionId)

  // Fetch event type definitions from backend (real data, not hardcoded)
  useEffect(() => {
    ssfFetch('/ssf/event-types').then(r => r.json()).then((grouped: Record<string, Array<Record<string, unknown>>>) => {
      const defs: EventDef[] = []
      for (const [category, types] of Object.entries(grouped)) {
        if (!Array.isArray(types)) continue
        for (const t of types) {
          const uri = t.uri as string || ''
          const id = uri.split('/').pop() || ''
          if (!id) continue
          defs.push({
            id,
            name: (t.name as string) || id,
            icon: EVENT_ICONS[id] || Info,
            description: (t.description as string) || '',
            category: (category === 'RISC' ? 'RISC' : 'CAEP') as 'CAEP' | 'RISC',
            rfcReference: category === 'RISC' ? 'RISC §2' : 'CAEP §3',
          })
        }
      }
      if (defs.length > 0) setEventDefs(defs)
    }).catch(err => { console.error('[SSF] Failed to fetch event types from backend:', err) })
  }, [])

  // Fetch data function - only fetches, no polling logic here
  const fetchAll = useCallback(async () => {
    try {
      const [subjectsRes, statesRes] = await Promise.all([
        ssfFetch('/ssf/subjects'),
        ssfFetch('/ssf/security-state'),
      ])
      
      if (!subjectsRes.ok || !statesRes.ok) {
        console.warn('SSF fetch returned non-OK status')
        return
      }
      
      const [subjectsData, statesData] = await Promise.all([
        subjectsRes.json(),
        statesRes.json(),
      ])

      setSubjects(subjectsData.subjects || [])
      setSecurityStates(statesData.states || {})

      setSelectedSubject((prev) => prev ?? subjectsData.subjects?.[0] ?? null)
    } catch (err) {
      console.error('Failed to fetch data:', err)
    }
  }, [])

  // Gentle background polling - 30 seconds when idle to avoid rate limits
  // This enables live state updates without overwhelming the server
  useEffect(() => {
    fetchAll() // Initial fetch
    
    // Only poll when idle - 30 second interval is gentle enough
    if (status === 'idle') {
      const interval = setInterval(fetchAll, 30000) // 30 seconds
      return () => clearInterval(interval)
    }
  }, [status, fetchAll])

  // After execution completes, poll more frequently for a short period to capture state updates
  useEffect(() => {
    if (status === 'completed') {
      // Fetch immediately after a delay for receiver processing
      const timer1 = setTimeout(fetchAll, 1000)
      const timer2 = setTimeout(fetchAll, 3000)
      const timer3 = setTimeout(fetchAll, 6000)
      
      // After 10 seconds, switch back to idle to resume gentle polling
      const resetTimer = setTimeout(() => setStatus('idle'), 10000)
      
      return () => {
        clearTimeout(timer1)
        clearTimeout(timer2)
        clearTimeout(timer3)
        clearTimeout(resetTimer)
      }
    }
  }, [status, fetchAll])

  // Execute event - triggers the real backend flow, SSE stream delivers events in real-time
  const execute = useCallback(async () => {
    if (!selectedSubject || !selectedEvent || status === 'executing') return

    setStatus('executing')
    clearEvents()
    setDecodedSET(null)
    setActiveTab('events')

    try {
      // Single API call — delivery is synchronous, response includes ALL
      // pipeline events (transmitter + receiver) captured during execution.
      const res = await ssfFetch(`/ssf/actions/${selectedEvent.id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subject_identifier: selectedSubject.identifier }),
      })

      if (!res.ok) {
        const errData = await res.json().catch(() => ({ error: 'Request failed' }))
        throw new Error(errData.error || `HTTP ${res.status}`)
      }

      const actionData = await res.json()

      // Ingest pipeline events from the response (reliable, not SSE-dependent)
      if (actionData.pipeline_events?.length) {
        ingestResponseEvents(actionData.pipeline_events as SSEPipelineEvent[])
      }

      setStatus('completed')

      // Fetch the decoded SET token
      const latestEvents = await ssfFetch('/ssf/events').then(r => r.json())
      const latestEvent = latestEvents.events?.[0]

      if (latestEvent?.set_token) {
        try {
          const decoded = await ssfFetch('/ssf/decode', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: latestEvent.set_token }),
          }).then(r => r.json())
          setDecodedSET(decoded)
        } catch (e) {
          console.warn('Failed to decode SET:', e)
        }
      }

      // Fetch updated security state
      await fetchAll()

    } catch (err) {
      console.error('Event failed:', err)
      setStatus('error')
    }
  }, [selectedSubject, selectedEvent, status, clearEvents, ingestResponseEvents, fetchAll])

  const reset = useCallback(() => {
    setStatus('idle')
    clearEvents()
    setDecodedSET(null)
  }, [clearEvents])

  const resetSecurityState = useCallback(async () => {
    if (!selectedSubject) return
    try {
      await ssfFetch(`/ssf/security-state/${encodeURIComponent(selectedSubject.identifier)}/reset`, {
        method: 'POST',
      })
      await fetchAll()
    } catch (err) {
      console.error('Failed to reset security state:', err)
    }
  }, [selectedSubject, fetchAll])


  const selectedState = selectedSubject ? securityStates[selectedSubject.identifier] : null

  return (
    <div className="max-w-5xl mx-auto space-y-4 sm:space-y-6">
      {/* Header */}
      <header className="py-2">
        <div className="flex flex-col gap-3">
          <div className="flex items-start justify-between gap-2">
            <h1 className="text-lg sm:text-2xl font-semibold text-white flex items-center gap-2 sm:gap-3 min-w-0">
              <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-xl bg-gradient-to-br from-amber-500/20 to-orange-500/20 flex items-center justify-center flex-shrink-0">
                <Radio className="w-4 h-4 sm:w-5 sm:h-5 text-amber-400" />
              </div>
              <span className="truncate">SSF Sandbox</span>
            </h1>
            <div className="flex items-center gap-2">
              {status !== 'idle' && <SharedStatusBadge status={status} variants={SSF_STATUS_BADGE_VARIANTS} />}
              <span className="text-xs text-surface-500 font-mono hidden sm:block" title={`Session: ${sessionId}`}>
                🔒 private session
              </span>
            </div>
          </div>
          <p className="text-surface-400 text-xs sm:text-base ml-10 sm:ml-[52px] leading-relaxed">
            Execute SSF flows and inspect the traffic - your sandbox is isolated from other users
          </p>
        </div>
      </header>

      {/* Quick Select - when nothing selected */}
      {!selectedEvent && (
        <section>
          <div className="flex items-center gap-2 text-surface-400 text-sm mb-3">
            <Sparkles className="w-4 h-4 text-amber-400" />
            <span>Quick start - select an event to trigger</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            <QuickButton
              icon={Lock}
              label="Session Revoked"
              sublabel="CAEP Event"
              color="blue"
              onClick={() => setSelectedEvent(eventDefs.find(e => e.id === 'session-revoked') || eventDefs[0])}
            />
            <QuickButton
              icon={AlertTriangle}
              label="Credential Compromise"
              sublabel="RISC Event"
              color="red"
              onClick={() => setSelectedEvent(eventDefs.find(e => e.id === 'credential-compromise') || eventDefs[0])}
            />
            <QuickButton
              icon={RotateCcw}
              label="All Sessions Revoked"
              sublabel="RISC Event"
              color="purple"
              onClick={() => setSelectedEvent(eventDefs.find(e => e.id === 'sessions-revoked') || eventDefs[0])}
            />
          </div>
        </section>
      )}

      {/* Configuration */}
      <section className="rounded-xl border border-white/10 bg-surface-900/30 p-3 sm:p-5">
        <div className="flex items-center justify-between mb-3 sm:mb-4">
          <div className="flex items-center gap-2">
            <Terminal className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-surface-400" />
            <span className="text-xs sm:text-sm font-medium text-surface-300">Configuration</span>
          </div>
          {(selectedEvent || pipelineEvents.length > 0) && (
            <button
              onClick={() => { setSelectedEvent(null); reset(); resetSecurityState() }}
              className="flex items-center gap-1 sm:gap-1.5 text-xs sm:text-sm text-surface-400 hover:text-white transition-colors"
            >
              <RotateCcw className="w-3 h-3 sm:w-3.5 sm:h-3.5" />
              Reset
            </button>
          )}
        </div>

        <div className="flex flex-col sm:flex-row gap-3 sm:gap-4">
          {/* Subject Selector */}
          <div className="flex-1">
            <label className="text-xs text-surface-400 mb-1.5 block">subject:</label>
            <div className="relative">
              <select
                value={selectedSubject?.id || ''}
                onChange={(e) => {
                  const subject = subjects.find(s => s.id === e.target.value)
                  setSelectedSubject(subject || null)
                }}
                className="w-full appearance-none px-3 py-2 pr-8 rounded-lg bg-surface-800 border border-white/10 text-sm text-white focus:outline-none focus:border-amber-500/50"
              >
                {subjects.map(s => (
                  <option key={s.id} value={s.id}>{s.display_name} ({s.identifier})</option>
                ))}
              </select>
              <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-surface-400 pointer-events-none" />
            </div>
          </div>

          {/* Event Selector */}
          <div className="flex-1">
            <label className="text-xs text-surface-400 mb-1.5 block">event:</label>
            <div className="relative">
              <select
                value={selectedEvent?.id || ''}
                onChange={(e) => {
                  const event = eventDefs.find(ev => ev.id === e.target.value)
                  setSelectedEvent(event || null)
                }}
                className="w-full appearance-none px-3 py-2 pr-8 rounded-lg bg-surface-800 border border-white/10 text-sm text-white focus:outline-none focus:border-amber-500/50"
              >
                <option value="">Select an event...</option>
                <optgroup label="CAEP Events">
                  {eventDefs.filter(e => e.category === 'CAEP').map(e => (
                    <option key={e.id} value={e.id}>{e.name}</option>
                  ))}
                </optgroup>
                <optgroup label="RISC Events">
                  {eventDefs.filter(e => e.category === 'RISC').map(e => (
                    <option key={e.id} value={e.id}>{e.name}</option>
                  ))}
                </optgroup>
              </select>
              <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-surface-400 pointer-events-none" />
            </div>
          </div>
        </div>
      </section>

      {/* Execution Panel */}
      {selectedEvent && (
        <motion.section
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-xl border border-white/10 bg-surface-900/30 overflow-hidden"
        >
          {/* Flow Header */}
          <div className="px-3 sm:px-5 py-3 sm:py-4 border-b border-white/10">
            <div className="flex items-start justify-between gap-2 mb-2 sm:mb-0">
              <div className="flex items-center gap-2 sm:gap-3 min-w-0 flex-1">
                <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-lg bg-amber-500/20 flex items-center justify-center flex-shrink-0">
                  <Play className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-amber-400" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <code className="text-white font-medium text-xs sm:text-base truncate max-w-[160px] sm:max-w-none">{selectedEvent.id}</code>
                    <span className="text-[10px] sm:text-xs text-surface-400 font-mono flex-shrink-0">
                      {selectedEvent.rfcReference}
                    </span>
                  </div>
                </div>
              </div>
              
              <div className="flex items-center gap-1.5 sm:gap-2 flex-shrink-0">
                {status === 'idle' && (
                  <button
                    onClick={execute}
                    disabled={!selectedSubject}
                    className="flex items-center gap-1.5 sm:gap-2 px-2.5 sm:px-4 py-1.5 sm:py-2 rounded-lg bg-gradient-to-r from-green-500/20 to-emerald-500/20 border border-green-500/30 text-green-400 text-xs sm:text-sm font-medium hover:from-green-500/30 hover:to-emerald-500/30 transition-all disabled:opacity-50"
                  >
                    <Play className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                    <span className="hidden sm:inline">Execute</span>
                    <span className="sm:hidden">Run</span>
                  </button>
                )}
                {status === 'executing' && (
                  <button
                    onClick={reset}
                    className="flex items-center gap-1.5 sm:gap-2 px-2.5 sm:px-4 py-1.5 sm:py-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs sm:text-sm hover:bg-red-500/20 transition-colors"
                  >
                    <Square className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                    <span className="hidden xs:inline">Abort</span>
                  </button>
                )}
                {status === 'completed' && (
                  <button
                    onClick={reset}
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
            <SSFFlowPanel
              status={status}
              events={pipelineEvents}
              httpExchanges={httpExchanges}
              decodedSET={decodedSET}
              securityState={selectedState}
              activeTab={activeTab}
              onTabChange={setActiveTab}
              onResetState={resetSecurityState}
              selectedEvent={selectedEvent}
              isSSEConnected={isConnected}
            />
          </div>
        </motion.section>
      )}

      {/* Decode any SET */}
      {/* Decode any SET (reuses TokenInspector since SET = JWT) */}
      <section className="rounded-xl border border-white/10 bg-surface-900/30 p-3 sm:p-5">
        <div className="flex items-center gap-2 mb-2 sm:mb-3">
          <Sparkles className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-amber-400" />
          <span className="text-xs sm:text-sm font-medium text-surface-300">Decode any SET</span>
        </div>
        <div className="flex gap-2">
          <input
            type="text"
            value={manualSET}
            onChange={(e) => setManualSET(e.target.value)}
            placeholder="Paste SET token here..."
            className="flex-1 min-w-0 px-2.5 sm:px-4 py-2 sm:py-2.5 rounded-lg bg-surface-900 border border-white/10 text-xs sm:text-sm font-mono text-white placeholder-surface-600 focus:outline-none focus:border-amber-500/50 focus:ring-1 focus:ring-amber-500/20 transition-all"
          />
          {manualSET && (
            <button
              onClick={() => setManualSET('')}
              className="px-3 sm:px-4 py-2 sm:py-2.5 rounded-lg bg-surface-800 text-surface-400 hover:text-white text-xs sm:text-sm transition-colors flex-shrink-0"
            >
              Clear
            </button>
          )}
        </div>
        {manualSET && (
          <div className="mt-4">
            <TokenInspector token={manualSET} />
          </div>
        )}
      </section>

      {/* Specifications */}
      <section className="rounded-xl border border-dashed border-white/10 p-4">
        <div className="flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-xs">
          <a
            href="https://datatracker.ietf.org/doc/html/rfc8417"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 text-surface-400 hover:text-amber-400 transition-colors group"
          >
            <span className="font-mono group-hover:text-amber-400">RFC 8417</span>
            <span className="text-surface-600">SET</span>
          </a>
          <a
            href="https://openid.net/specs/openid-sse-framework-1_0.html"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 text-surface-400 hover:text-amber-400 transition-colors group"
          >
            <span className="font-mono group-hover:text-amber-400">SSF 1.0</span>
            <span className="text-surface-600">Framework</span>
          </a>
          <a
            href="https://openid.net/specs/openid-caep-1_0.html"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 text-surface-400 hover:text-amber-400 transition-colors group"
          >
            <span className="font-mono group-hover:text-amber-400">CAEP 1.0</span>
            <span className="text-surface-600">Access Events</span>
          </a>
          <a
            href="https://openid.net/specs/openid-risc-profile-1_0.html"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 text-surface-400 hover:text-amber-400 transition-colors group"
          >
            <span className="font-mono group-hover:text-amber-400">RISC 1.0</span>
            <span className="text-surface-600">Incident Sharing</span>
          </a>
        </div>
      </section>
    </div>
  )
}

export default SSFSandbox
// ============================================================================
// Sub-Components
// ============================================================================

function QuickButton({ 
  icon: Icon, 
  label, 
  sublabel, 
  color,
  onClick 
}: {
  icon: React.ElementType
  label: string
  sublabel: string
  color: 'blue' | 'red' | 'purple'
  onClick: () => void
}) {
  const colors = {
    blue: { border: 'border-blue-500/20 hover:border-blue-500/40', bg: 'bg-blue-500/10', text: 'text-blue-400' },
    red: { border: 'border-red-500/20 hover:border-red-500/40', bg: 'bg-red-500/10', text: 'text-red-400' },
    purple: { border: 'border-purple-500/20 hover:border-purple-500/40', bg: 'bg-purple-500/10', text: 'text-purple-400' },
  }
  const c = colors[color]

  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2.5 sm:gap-4 p-2.5 sm:p-4 rounded-xl border ${c.border} bg-gradient-to-br from-white/[0.02] to-transparent hover:from-white/[0.04] active:from-white/[0.06] transition-all text-left group`}
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
