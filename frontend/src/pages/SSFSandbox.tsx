/**
 * SSF Sandbox - Shared Signals Framework Execution
 * 
 * Matches the Looking Glass pattern for consistency.
 * Execute SSF flows and inspect the traffic.
 * 
 * Each browser session gets isolated data via session ID.
 */

import { useState, useEffect, useCallback, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  Radio, ChevronRight, Shield, AlertTriangle, 
  User, CheckCircle, Clock, Zap, 
  RotateCcw, Send, ArrowDownLeft, Bell, 
  Lock, UserX, UserCheck, Terminal,
  Sparkles, Play, Key, Book, Info,
  ChevronDown, Code, Copy, Check, Square,
  XCircle
} from 'lucide-react'
import { TokenInspector } from '../components/lookingglass/TokenInspector'
import { SSFSandboxSEO } from '../components/common/SEO'

// ============================================================================
// Session Management - Isolates each user's sandbox
// ============================================================================

function getOrCreateSessionId(): string {
  const STORAGE_KEY = 'ssf_session_id'
  let sessionId = localStorage.getItem(STORAGE_KEY)
  
  if (!sessionId) {
    // Generate a random session ID
    sessionId = 'sess_' + Math.random().toString(36).substring(2, 15) + 
                Math.random().toString(36).substring(2, 15)
    localStorage.setItem(STORAGE_KEY, sessionId)
  }
  
  return sessionId
}

// Create fetch wrapper that includes session ID
function ssfFetch(url: string, options: RequestInit = {}): Promise<Response> {
  const sessionId = getOrCreateSessionId()
  
  return fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'X-SSF-Session': sessionId,
    },
  })
}

// ============================================================================
// Types
// ============================================================================

interface Subject {
  id: string
  stream_id: string
  format: string
  identifier: string
  display_name: string
  status: string
  active_sessions: number
  last_activity: string | null
  created_at: string
}

interface ActionResponse {
  event_id: string
  event_type: string
  event_name: string
  category: string
  subject: string
  status: string
  delivery_method: string
  response_actions: string[]
  zero_trust_impact: string
}

interface SecurityState {
  email: string
  sessions_active: number
  account_enabled: boolean
  password_reset_required: boolean
  tokens_valid: boolean
  last_modified: string
  modified_by: string
}

interface FlowEvent {
  id: string
  type: 'info' | 'request' | 'response' | 'token' | 'crypto' | 'security' | 'action' | 'error'
  title: string
  description: string
  timestamp: Date
  rfcReference?: string
  data?: Record<string, unknown>
}

interface DecodedSET {
  jti: string
  iss: string
  aud: string[]
  iat: string
  sub_id: { format: string; email?: string }
  events: Array<{
    type: string
    metadata: { name: string; category: string; response_actions: string[]; zero_trust_impact: string }
    payload: Record<string, unknown>
  }>
  header: Record<string, unknown>
  raw_token: string
}

// ============================================================================
// Event Definitions
// ============================================================================

interface EventDef {
  id: string
  name: string
  icon: React.ElementType
  description: string
  category: 'CAEP' | 'RISC'
  rfcReference: string
}

const SSF_EVENTS: EventDef[] = [
  { id: 'session-revoked', name: 'Session Revoked', icon: Lock, description: 'Terminate user session', category: 'CAEP', rfcReference: 'CAEP §3.1' },
  { id: 'credential-change', name: 'Credential Change', icon: Key, description: 'Password or credential updated', category: 'CAEP', rfcReference: 'CAEP §3.2' },
  { id: 'device-compliance-change', name: 'Device Non-Compliance', icon: AlertTriangle, description: 'Device fails security check', category: 'CAEP', rfcReference: 'CAEP §3.3' },
  { id: 'assurance-level-change', name: 'Auth Level Downgrade', icon: Shield, description: 'Reduced authentication assurance', category: 'CAEP', rfcReference: 'CAEP §3.4' },
  { id: 'credential-compromise', name: 'Credential Compromise', icon: AlertTriangle, description: 'Credentials potentially exposed', category: 'RISC', rfcReference: 'RISC §2.1' },
  { id: 'account-disabled', name: 'Account Disabled', icon: UserX, description: 'Suspend user account', category: 'RISC', rfcReference: 'RISC §2.2' },
  { id: 'account-enabled', name: 'Account Enabled', icon: UserCheck, description: 'Reactivate user account', category: 'RISC', rfcReference: 'RISC §2.3' },
  { id: 'sessions-revoked', name: 'All Sessions Revoked', icon: RotateCcw, description: 'Global session termination', category: 'RISC', rfcReference: 'RISC §2.4' },
]

// ============================================================================
// Main Component
// ============================================================================

export function SSFSandbox() {
  const [subjects, setSubjects] = useState<Subject[]>([])
  const [selectedSubject, setSelectedSubject] = useState<Subject | null>(null)
  const [selectedEvent, setSelectedEvent] = useState<EventDef | null>(null)
  const [securityStates, setSecurityStates] = useState<Record<string, SecurityState>>({})
  
  // Execution state
  const [status, setStatus] = useState<'idle' | 'executing' | 'completed' | 'error'>('idle')
  const [flowEvents, setFlowEvents] = useState<FlowEvent[]>([])
  const [decodedSET, setDecodedSET] = useState<DecodedSET | null>(null)
  const [activeTab, setActiveTab] = useState<'events' | 'set' | 'state'>('events')
  
  // Manual SET decoder (uses TokenInspector component)
  const [manualSET, setManualSET] = useState('')

  // Session ID for this browser tab
  const sessionId = useMemo(() => getOrCreateSessionId(), [])

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

      if (subjectsData.subjects?.length > 0 && !selectedSubject) {
        setSelectedSubject(subjectsData.subjects[0])
      }
    } catch (err) {
      console.error('Failed to fetch data:', err)
    }
  }, [selectedSubject])

  // Initial fetch only - no continuous polling to avoid rate limits
  useEffect(() => {
    fetchAll()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []) // Only run once on mount

  // Fetch state after execution completes (one-time, not polling)
  useEffect(() => {
    if (status === 'completed') {
      // Give the receiver time to process, then fetch updated state once
      const timer = setTimeout(() => {
        fetchAll()
      }, 1500)
      return () => clearTimeout(timer)
    }
  }, [status, fetchAll])

  const addFlowEvent = useCallback((event: Omit<FlowEvent, 'id' | 'timestamp'>) => {
    setFlowEvents(prev => [...prev, { ...event, id: crypto.randomUUID(), timestamp: new Date() }])
  }, [])

  // Execute event
  const execute = useCallback(async () => {
    if (!selectedSubject || !selectedEvent || status === 'executing') return

    setStatus('executing')
    setFlowEvents([])
    setDecodedSET(null)

    addFlowEvent({ 
      type: 'info', 
      title: 'Initiating SSF Event', 
      description: `Triggering ${selectedEvent.name} for ${selectedSubject.display_name}`,
      rfcReference: selectedEvent.rfcReference
    })

    try {
      // Simulate the protocol flow with events
      await delay(100)
      addFlowEvent({ 
        type: 'crypto', 
        title: 'Generating Security Event Token', 
        description: 'Creating SET with event payload and signing with RS256',
        rfcReference: 'RFC 8417 §2'
      })

      await delay(100)
      addFlowEvent({ 
        type: 'request', 
        title: `POST /ssf/actions/${selectedEvent.id}`, 
        description: 'Transmitter processing event trigger',
        rfcReference: 'SSF §4.1',
        data: { subject_identifier: selectedSubject.identifier, event_type: selectedEvent.id }
      })

      const res = await ssfFetch(`/ssf/actions/${selectedEvent.id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subject_identifier: selectedSubject.identifier }),
      })
      const data: ActionResponse = await res.json()

      addFlowEvent({ 
        type: 'response', 
        title: 'Event Created Successfully', 
        description: `Event ID: ${data.event_id}`,
        data: { event_id: data.event_id, category: data.category, status: data.status }
      })

      await delay(100)
      addFlowEvent({ 
        type: 'request', 
        title: 'Push Delivery to Receiver', 
        description: 'POST SET to receiver webhook endpoint',
        rfcReference: 'SSF §5.2.1',
        data: { endpoint: 'http://localhost:8081/ssf/push', method: 'push' }
      })

      await delay(100)
      addFlowEvent({ 
        type: 'crypto', 
        title: 'Receiver Validates SET Signature', 
        description: 'Fetching JWKS from transmitter and verifying RS256 signature',
        rfcReference: 'RFC 8417 §3'
      })

      await delay(100)
      addFlowEvent({ 
        type: 'security', 
        title: `${data.category} Event Processed`, 
        description: `Receiver processed ${data.event_name}`,
        rfcReference: data.category === 'CAEP' ? 'CAEP Spec' : 'RISC Spec'
      })

      // Log response actions
      for (const action of data.response_actions) {
        await delay(50)
        addFlowEvent({ 
          type: 'action', 
          title: 'Zero Trust Response Action', 
          description: action,
          data: { action, impact: data.zero_trust_impact }
        })
      }

      // Decode the SET token
      const latestEvents = await ssfFetch('/ssf/events').then(r => r.json())
      const latestEvent = latestEvents.events?.[0]
      if (latestEvent?.set_token) {
        const decoded = await ssfFetch('/ssf/decode', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: latestEvent.set_token }),
        }).then(r => r.json())
        setDecodedSET(decoded)
      }

      setStatus('completed')
      
      // Wait for receiver to process the event before fetching updated state
      await delay(500)
      await fetchAll()
      
      // Fetch again after a short delay to catch any async updates
      await delay(1000)
      await fetchAll()
      
      // Auto-switch to State tab to show the changes
      setActiveTab('state')

    } catch (err) {
      console.error('Event failed:', err)
      addFlowEvent({ 
        type: 'error', 
        title: 'Execution Failed', 
        description: err instanceof Error ? err.message : 'Unknown error'
      })
      setStatus('error')
    }
  }, [selectedSubject, selectedEvent, status, addFlowEvent, fetchAll])

  const reset = useCallback(() => {
    setStatus('idle')
    setFlowEvents([])
    setDecodedSET(null)
  }, [])

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
    <>
      <SSFSandboxSEO />
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
              {status !== 'idle' && <StatusBadge status={status} />}
              <span className="text-xs text-surface-500 font-mono hidden sm:block" title={`Session: ${sessionId}`}>
                🔒 private session
              </span>
            </div>
          </div>
          <p className="text-surface-400 text-xs sm:text-base ml-10 sm:ml-[52px] leading-relaxed">
            Execute SSF flows and inspect the traffic — your sandbox is isolated from other users
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
              onClick={() => setSelectedEvent(SSF_EVENTS[0])}
            />
            <QuickButton
              icon={AlertTriangle}
              label="Credential Compromise"
              sublabel="RISC Event"
              color="red"
              onClick={() => setSelectedEvent(SSF_EVENTS[4])}
            />
            <QuickButton
              icon={RotateCcw}
              label="All Sessions Revoked"
              sublabel="RISC Event"
              color="purple"
              onClick={() => setSelectedEvent(SSF_EVENTS[7])}
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
          {(selectedEvent || flowEvents.length > 0) && (
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
                  const event = SSF_EVENTS.find(ev => ev.id === e.target.value)
                  setSelectedEvent(event || null)
                }}
                className="w-full appearance-none px-3 py-2 pr-8 rounded-lg bg-surface-800 border border-white/10 text-sm text-white focus:outline-none focus:border-amber-500/50"
              >
                <option value="">Select an event...</option>
                <optgroup label="CAEP Events">
                  {SSF_EVENTS.filter(e => e.category === 'CAEP').map(e => (
                    <option key={e.id} value={e.id}>{e.name}</option>
                  ))}
                </optgroup>
                <optgroup label="RISC Events">
                  {SSF_EVENTS.filter(e => e.category === 'RISC').map(e => (
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
              events={flowEvents}
              decodedSET={decodedSET}
              securityState={selectedState}
              activeTab={activeTab}
              onTabChange={setActiveTab}
              onResetState={resetSecurityState}
              selectedEvent={selectedEvent}
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
    </>
  )
}

// Helper
function delay(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

// ============================================================================
// Sub-Components
// ============================================================================

function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { bg: string; border: string; text: string; label: string; shortLabel: string }> = {
    completed: { bg: 'bg-green-500/10', border: 'border-green-500/30', text: 'text-green-400', label: 'Completed', shortLabel: 'Done' },
    executing: { bg: 'bg-amber-500/10', border: 'border-amber-500/30', text: 'text-amber-400', label: 'Executing...', shortLabel: 'Running' },
    error: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', label: 'Error', shortLabel: 'Error' },
  }
  const c = config[status] || config.error

  return (
    <div className={`px-2 sm:px-3 py-1 sm:py-1.5 rounded-full ${c.bg} border ${c.border} flex-shrink-0`}>
      <span className={`text-xs sm:text-sm font-medium ${c.text} whitespace-nowrap`}>
        <span className="hidden sm:inline">{c.label}</span>
        <span className="sm:hidden">{c.shortLabel}</span>
      </span>
    </div>
  )
}

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

// ============================================================================
// SSF Flow Panel (matches RealFlowPanel structure)
// ============================================================================

interface SSFFlowPanelProps {
  status: 'idle' | 'executing' | 'completed' | 'error'
  events: FlowEvent[]
  decodedSET: DecodedSET | null
  securityState: SecurityState | null
  activeTab: 'events' | 'set' | 'state'
  onTabChange: (tab: 'events' | 'set' | 'state') => void
  onResetState: () => void
  selectedEvent: EventDef
}

function SSFFlowPanel({ 
  status, 
  events, 
  decodedSET, 
  securityState,
  activeTab, 
  onTabChange,
  onResetState,
  selectedEvent 
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
      {/* Flow Info Header */}
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
          <span className={`px-1.5 sm:px-2 py-0.5 rounded text-[10px] sm:text-xs ${
            selectedEvent.category === 'CAEP' 
              ? 'bg-blue-500/10 text-blue-400' 
              : 'bg-amber-500/10 text-amber-400'
          }`}>
            {selectedEvent.category}
          </span>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-1 p-1 rounded-lg bg-surface-900/50 overflow-x-auto scrollbar-hide">
        {[
          { id: 'events', label: 'Events', count: events.length, icon: Zap },
          { id: 'set', label: 'SET', count: decodedSET ? 1 : 0, icon: Key },
          { id: 'state', label: 'State', count: securityState ? 1 : 0, icon: User },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => onTabChange(tab.id as typeof activeTab)}
            className={`flex-1 min-w-0 flex items-center justify-center gap-1.5 sm:gap-2 px-3 sm:px-4 py-2.5 sm:py-2 rounded-md text-sm font-medium transition-colors whitespace-nowrap ${
              activeTab === tab.id
                ? 'bg-surface-800 text-white'
                : 'text-surface-400 hover:text-white active:text-white'
            }`}
          >
            <tab.icon className="w-4 h-4 flex-shrink-0" />
            <span className="hidden sm:inline">{tab.label}</span>
            <span className="sm:hidden">{tab.label}</span>
            {tab.count > 0 && (
              <span className="px-1.5 py-0.5 rounded text-xs bg-surface-700 flex-shrink-0">
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="min-h-[300px] sm:min-h-[400px] max-h-[450px] sm:max-h-[600px] overflow-y-auto">
        <AnimatePresence mode="wait">
          {activeTab === 'events' && (
            <motion.div
              key="events"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
            >
              <EventsList events={events} />
            </motion.div>
          )}
          {activeTab === 'set' && (
            <motion.div
              key="set"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
            >
              <SETInspector decodedSET={decodedSET} />
            </motion.div>
          )}
          {activeTab === 'state' && (
            <motion.div
              key="state"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
            >
              <SecurityStatePanel state={securityState} onReset={onResetState} />
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  )
}

// ============================================================================
// Events List (matches Looking Glass EventsList)
// ============================================================================

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

  const eventConfig: Record<FlowEvent['type'], { icon: React.ElementType; color: string }> = {
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
                  <span className="text-xs text-surface-400 shrink-0">
                    {event.timestamp.toLocaleTimeString()}
                  </span>
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

// ============================================================================
// SET Inspector (matches TokensList pattern)
// ============================================================================

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
          {/* Header */}
          <div>
            <h3 className="text-[10px] sm:text-xs font-medium text-surface-400 mb-1">Header</h3>
            <pre className="p-2 rounded bg-surface-950 text-[10px] sm:text-xs font-mono text-surface-300 overflow-x-auto scrollbar-hide">
              {JSON.stringify(decodedSET.header, null, 2)}
            </pre>
          </div>

          {/* Payload */}
          <div>
            <h3 className="text-[10px] sm:text-xs font-medium text-surface-400 mb-1">Payload</h3>
            <pre className="p-2 rounded bg-surface-950 text-[10px] sm:text-xs font-mono text-surface-300 overflow-x-auto scrollbar-hide">
              {JSON.stringify({
                jti: decodedSET.jti,
                iss: decodedSET.iss,
                aud: decodedSET.aud,
                iat: decodedSET.iat,
                sub_id: decodedSET.sub_id,
                events: decodedSET.events.map(e => ({
                  [e.type]: e.payload
                }))
              }, null, 2)}
            </pre>
          </div>

          {/* Event Metadata */}
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

          {/* Raw Token */}
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

// ============================================================================
// Security State Panel
// ============================================================================

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
      {/* State Card */}
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
        className="flex items-center gap-1 text-xs text-surface-400 hover:text-surface-300 transition-colors"
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
      className="p-1.5 sm:p-1 rounded hover:bg-white/10 active:bg-white/20 transition-colors flex-shrink-0"
      title="Copy to clipboard"
    >
      {copied ? (
        <Check className="w-3.5 h-3.5 sm:w-3 sm:h-3 text-green-400" />
      ) : (
        <Copy className="w-3.5 h-3.5 sm:w-3 sm:h-3 text-surface-400" />
      )}
    </button>
  )
}

export default SSFSandbox
