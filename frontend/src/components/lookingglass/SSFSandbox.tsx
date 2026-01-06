/**
 * SSF Interactive Sandbox
 * 
 * A tactile playground for exploring the Shared Signals Framework.
 * Users can trigger security actions and watch events flow in real-time.
 */

import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

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

interface Stream {
  stream_id: string
  iss: string
  aud: string[]
  events_supported: string[]
  events_requested: string[]
  delivery_method: string
  delivery_endpoint_url: string
  status: string
}

interface EventMetadata {
  uri: string
  name: string
  description: string
  category: 'CAEP' | 'RISC'
  response_actions: string[]
  zero_trust_impact: string
}

interface StoredEvent {
  id: string
  stream_id: string
  subject_id: string | null
  event_type: string
  event_data: string
  set_token: string
  status: string
  created_at: string
  delivered_at: string | null
  acknowledged_at: string | null
}

interface ResponseAction {
  id: string
  event_id: string
  event_type: string
  action: string
  description: string
  status: string
  executed_at: string
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

interface FlowStep {
  id: string
  type: 'action' | 'set_generated' | 'set_signed' | 'delivery' | 'verified' | 'processed' | 'response'
  title: string
  description: string
  timestamp: Date
  data?: Record<string, unknown>
  status: 'pending' | 'active' | 'complete' | 'error'
}

// ============================================================================
// Action Definitions
// ============================================================================

const ACTIONS = [
  {
    id: 'session-revoked',
    name: 'Revoke Session',
    description: 'Terminate an active user session',
    category: 'CAEP',
    icon: '🔒',
    color: 'from-blue-500 to-blue-700',
  },
  {
    id: 'credential-change',
    name: 'Credential Change',
    description: 'User password/credential updated',
    category: 'CAEP',
    icon: '🔑',
    color: 'from-blue-400 to-blue-600',
  },
  {
    id: 'device-compliance-change',
    name: 'Device Non-Compliant',
    description: 'Device fails compliance check',
    category: 'CAEP',
    icon: '📱',
    color: 'from-blue-600 to-blue-800',
  },
  {
    id: 'assurance-level-change',
    name: 'Auth Level Downgrade',
    description: 'Authentication assurance reduced',
    category: 'CAEP',
    icon: '📉',
    color: 'from-blue-300 to-blue-500',
  },
  {
    id: 'credential-compromise',
    name: 'Credential Compromise',
    description: 'Credentials potentially exposed',
    category: 'RISC',
    icon: '⚠️',
    color: 'from-amber-500 to-red-600',
  },
  {
    id: 'account-disabled',
    name: 'Disable Account',
    description: 'Suspend user account',
    category: 'RISC',
    icon: '🚫',
    color: 'from-orange-500 to-orange-700',
  },
  {
    id: 'account-enabled',
    name: 'Enable Account',
    description: 'Reactivate user account',
    category: 'RISC',
    icon: '✅',
    color: 'from-green-500 to-green-700',
  },
  {
    id: 'account-purged',
    name: 'Purge Account',
    description: 'Permanently delete account',
    category: 'RISC',
    icon: '🗑️',
    color: 'from-red-600 to-red-800',
  },
  {
    id: 'sessions-revoked',
    name: 'Revoke All Sessions',
    description: 'Terminate all user sessions globally',
    category: 'RISC',
    icon: '🔄',
    color: 'from-purple-500 to-purple-700',
  },
]

// ============================================================================
// Main Component
// ============================================================================

interface SSFSandboxProps {
  className?: string
}

export function SSFSandbox({ className = '' }: SSFSandboxProps) {
  // State
  const [subjects, setSubjects] = useState<Subject[]>([])
  const [stream, setStream] = useState<Stream | null>(null)
  const [selectedSubject, setSelectedSubject] = useState<Subject | null>(null)
  const [events, setEvents] = useState<StoredEvent[]>([])
  const [responseActions, setResponseActions] = useState<ResponseAction[]>([])
  const [flowSteps, setFlowSteps] = useState<FlowStep[]>([])
  const [isExecuting, setIsExecuting] = useState(false)
  const [lastAction, setLastAction] = useState<ActionResponse | null>(null)
  const [showSetInspector, setShowSetInspector] = useState(false)
  const [selectedSet, setSelectedSet] = useState<string | null>(null)
  const [decodedSet, setDecodedSet] = useState<DecodedSET | null>(null)

  // Fetch functions
  const fetchSubjects = useCallback(async () => {
    try {
      const res = await fetch('/ssf/subjects')
      const data = await res.json()
      setSubjects(data.subjects || [])
      if (data.subjects?.length > 0 && !selectedSubject) {
        setSelectedSubject(data.subjects[0])
      }
    } catch (err) {
      console.error('Failed to fetch subjects:', err)
    }
  }, [selectedSubject])

  const fetchStream = useCallback(async () => {
    try {
      const res = await fetch('/ssf/stream')
      const data = await res.json()
      setStream(data)
    } catch (err) {
      console.error('Failed to fetch stream:', err)
    }
  }, [])

  const fetchEvents = useCallback(async () => {
    try {
      const res = await fetch('/ssf/events')
      const data = await res.json()
      setEvents(data.events || [])
    } catch (err) {
      console.error('Failed to fetch events:', err)
    }
  }, [])

  const fetchResponseActions = useCallback(async () => {
    try {
      const res = await fetch('/ssf/responses')
      const data = await res.json()
      setResponseActions(data.actions || [])
    } catch (err) {
      console.error('Failed to fetch response actions:', err)
    }
  }, [])

  // Fetch initial data
  useEffect(() => {
    fetchSubjects()
    fetchStream()
    fetchEvents()
    fetchResponseActions()

    // Poll for updates
    const interval = setInterval(() => {
      fetchEvents()
      fetchResponseActions()
    }, 3000)

    return () => clearInterval(interval)
  }, [fetchSubjects, fetchStream, fetchEvents, fetchResponseActions])

  // Trigger an action
  const triggerAction = useCallback(async (actionId: string) => {
    if (!selectedSubject || isExecuting) return

    setIsExecuting(true)
    setFlowSteps([])
    setLastAction(null)

    // Add initial flow step
    const addStep = (step: Omit<FlowStep, 'id' | 'timestamp'>) => {
      setFlowSteps(prev => [...prev, {
        ...step,
        id: crypto.randomUUID(),
        timestamp: new Date(),
      }])
    }

    addStep({
      type: 'action',
      title: 'Action Triggered',
      description: `Triggering ${actionId} for ${selectedSubject.identifier}`,
      status: 'active',
    })

    try {
      const res = await fetch(`/ssf/actions/${actionId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject_identifier: selectedSubject.identifier,
        }),
      })

      const data: ActionResponse = await res.json()
      setLastAction(data)

      // Update flow steps based on response
      setFlowSteps(prev => prev.map(s => 
        s.type === 'action' ? { ...s, status: 'complete' as const } : s
      ))

      addStep({
        type: 'set_generated',
        title: 'SET Generated',
        description: `Security Event Token created for ${data.event_name}`,
        status: 'complete',
        data: { event_type: data.event_type },
      })

      addStep({
        type: 'set_signed',
        title: 'SET Signed',
        description: 'Token signed with RS256 private key',
        status: 'complete',
      })

      addStep({
        type: 'delivery',
        title: data.delivery_method.includes('push') ? 'Push Delivery' : 'Queued for Poll',
        description: data.delivery_method.includes('push') 
          ? 'Event pushed to receiver webhook'
          : 'Event queued for receiver to poll',
        status: 'complete',
      })

      addStep({
        type: 'verified',
        title: 'SET Verified',
        description: 'Signature verified by receiver',
        status: 'complete',
      })

      addStep({
        type: 'processed',
        title: 'Event Processed',
        description: `${data.category} event processed`,
        status: 'complete',
        data: { category: data.category },
      })

      // Add response actions
      for (const action of data.response_actions) {
        addStep({
          type: 'response',
          title: 'Response Action',
          description: action,
          status: 'complete',
        })
      }

      // Refresh data
      await fetchSubjects()
      await fetchEvents()
      await fetchResponseActions()

    } catch (err) {
      console.error('Action failed:', err)
      setFlowSteps(prev => prev.map(s => 
        s.status === 'active' ? { ...s, status: 'error' as const } : s
      ))
    } finally {
      setIsExecuting(false)
    }
  }, [selectedSubject, isExecuting, fetchSubjects, fetchEvents, fetchResponseActions])

  // Decode SET for inspection
  const inspectSet = async (token: string) => {
    setSelectedSet(token)
    setShowSetInspector(true)
    
    try {
      const res = await fetch('/ssf/decode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      })
      const data = await res.json()
      setDecodedSet(data)
    } catch (err) {
      console.error('Failed to decode SET:', err)
    }
  }

  // Add new subject
  const addSubject = async () => {
    const identifier = prompt('Enter email address for new subject:')
    if (!identifier) return

    const displayName = prompt('Enter display name:') || identifier.split('@')[0]

    try {
      await fetch('/ssf/subjects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          format: 'email',
          identifier,
          display_name: displayName,
        }),
      })
      await fetchSubjects()
    } catch (err) {
      console.error('Failed to add subject:', err)
    }
  }

  // Toggle delivery method
  const toggleDeliveryMethod = async () => {
    if (!stream) return

    const newMethod = stream.delivery_method.includes('push')
      ? 'https://schemas.openid.net/secevent/risc/delivery-method/poll'
      : 'https://schemas.openid.net/secevent/risc/delivery-method/push'

    try {
      await fetch('/ssf/stream', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ delivery_method: newMethod }),
      })
      await fetchStream()
    } catch (err) {
      console.error('Failed to update stream:', err)
    }
  }

  return (
    <div className={`grid grid-cols-12 gap-4 h-full ${className}`}>
      {/* Left Panel - Subjects & Actions */}
      <div className="col-span-3 space-y-4 overflow-y-auto">
        {/* Subject Manager */}
        <SubjectPanel
          subjects={subjects}
          selectedSubject={selectedSubject}
          onSelect={setSelectedSubject}
          onAdd={addSubject}
        />

        {/* Action Panel */}
        <ActionPanel
          actions={ACTIONS}
          selectedSubject={selectedSubject}
          isExecuting={isExecuting}
          onTrigger={triggerAction}
        />
      </div>

      {/* Center Panel - Flow Visualization */}
      <div className="col-span-6 space-y-4 overflow-y-auto">
        {/* Stream Configuration */}
        <StreamConfig
          stream={stream}
          onToggleDelivery={toggleDeliveryMethod}
        />

        {/* Live Event Flow */}
        <EventFlowTimeline
          steps={flowSteps}
          lastAction={lastAction}
        />

        {/* Zero Trust Impact */}
        {lastAction && (
          <ZeroTrustImpact impact={lastAction.zero_trust_impact} />
        )}
      </div>

      {/* Right Panel - Event Log & Responses */}
      <div className="col-span-3 space-y-4 overflow-y-auto">
        {/* Event History */}
        <EventLog
          events={events}
          onInspect={inspectSet}
        />

        {/* Response Actions */}
        <ResponseActionsLog actions={responseActions} />
      </div>

      {/* SET Inspector Modal */}
      <AnimatePresence>
        {showSetInspector && (
          <SETInspectorModal
            token={selectedSet}
            decoded={decodedSet}
            onClose={() => {
              setShowSetInspector(false)
              setSelectedSet(null)
              setDecodedSet(null)
            }}
          />
        )}
      </AnimatePresence>
    </div>
  )
}

// ============================================================================
// Sub-Components
// ============================================================================

interface SubjectPanelProps {
  subjects: Subject[]
  selectedSubject: Subject | null
  onSelect: (subject: Subject) => void
  onAdd: () => void
}

function SubjectPanel({ subjects, selectedSubject, onSelect, onAdd }: SubjectPanelProps) {
  return (
    <div className="bg-slate-900 rounded-lg border border-slate-700 overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-700 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-200">Subjects</h3>
        <button
          onClick={onAdd}
          className="text-xs px-2 py-1 bg-slate-700 hover:bg-slate-600 rounded text-slate-300"
        >
          + Add
        </button>
      </div>
      <div className="p-2 space-y-2 max-h-64 overflow-y-auto">
        {subjects.map(subject => (
          <motion.button
            key={subject.id}
            onClick={() => onSelect(subject)}
            className={`w-full p-3 rounded-lg text-left transition-colors ${
              selectedSubject?.id === subject.id
                ? 'bg-blue-600/20 border border-blue-500'
                : 'bg-slate-800 border border-slate-700 hover:border-slate-600'
            }`}
            whileHover={{ scale: 1.01 }}
            whileTap={{ scale: 0.99 }}
          >
            <div className="flex items-center justify-between mb-1">
              <span className="font-medium text-slate-200 text-sm truncate">
                {subject.display_name}
              </span>
              <StatusBadge status={subject.status} />
            </div>
            <div className="text-xs text-slate-400 truncate">{subject.identifier}</div>
            <div className="flex items-center gap-2 mt-2 text-xs">
              <span className="text-slate-500">
                Sessions: <span className="text-slate-300">{subject.active_sessions}</span>
              </span>
            </div>
          </motion.button>
        ))}
      </div>
    </div>
  )
}

interface ActionPanelProps {
  actions: typeof ACTIONS
  selectedSubject: Subject | null
  isExecuting: boolean
  onTrigger: (actionId: string) => void
}

function ActionPanel({ actions, selectedSubject, isExecuting, onTrigger }: ActionPanelProps) {
  const caepActions = actions.filter(a => a.category === 'CAEP')
  const riscActions = actions.filter(a => a.category === 'RISC')

  return (
    <div className="bg-slate-900 rounded-lg border border-slate-700 overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-700">
        <h3 className="text-sm font-semibold text-slate-200">Trigger Action</h3>
        {!selectedSubject && (
          <p className="text-xs text-amber-400 mt-1">Select a subject first</p>
        )}
      </div>
      
      <div className="p-2 space-y-4">
        {/* CAEP Actions */}
        <div>
          <div className="px-2 py-1 text-xs font-semibold text-blue-400 uppercase tracking-wider">
            CAEP Events
          </div>
          <div className="grid grid-cols-2 gap-2">
            {caepActions.map(action => (
              <ActionButton
                key={action.id}
                action={action}
                disabled={!selectedSubject || isExecuting}
                onClick={() => onTrigger(action.id)}
              />
            ))}
          </div>
        </div>

        {/* RISC Actions */}
        <div>
          <div className="px-2 py-1 text-xs font-semibold text-amber-400 uppercase tracking-wider">
            RISC Events
          </div>
          <div className="grid grid-cols-2 gap-2">
            {riscActions.map(action => (
              <ActionButton
                key={action.id}
                action={action}
                disabled={!selectedSubject || isExecuting}
                onClick={() => onTrigger(action.id)}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

interface ActionButtonProps {
  action: typeof ACTIONS[0]
  disabled: boolean
  onClick: () => void
}

function ActionButton({ action, disabled, onClick }: ActionButtonProps) {
  return (
    <motion.button
      onClick={onClick}
      disabled={disabled}
      className={`p-2 rounded-lg text-left transition-all ${
        disabled
          ? 'bg-slate-800 opacity-50 cursor-not-allowed'
          : `bg-gradient-to-br ${action.color} hover:opacity-90 cursor-pointer`
      }`}
      whileHover={disabled ? {} : { scale: 1.02 }}
      whileTap={disabled ? {} : { scale: 0.98 }}
      title={action.description}
    >
      <div className="text-lg mb-1">{action.icon}</div>
      <div className="text-xs font-medium text-white truncate">{action.name}</div>
    </motion.button>
  )
}

interface StreamConfigProps {
  stream: Stream | null
  onToggleDelivery: () => void
}

function StreamConfig({ stream, onToggleDelivery }: StreamConfigProps) {
  if (!stream) return null

  const isPush = stream.delivery_method.includes('push')

  return (
    <div className="bg-slate-900 rounded-lg border border-slate-700 p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-slate-200">Stream Configuration</h3>
        <span className={`text-xs px-2 py-1 rounded ${
          stream.status === 'enabled' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
        }`}>
          {stream.status}
        </span>
      </div>
      
      <div className="flex items-center gap-4">
        <div className="flex-1">
          <div className="text-xs text-slate-500 mb-1">Delivery Method</div>
          <button
            onClick={onToggleDelivery}
            className="flex items-center gap-2 px-3 py-2 bg-slate-800 rounded-lg hover:bg-slate-700 transition-colors"
          >
            <span className={`w-2 h-2 rounded-full ${isPush ? 'bg-green-400' : 'bg-amber-400'}`} />
            <span className="text-sm text-slate-200">{isPush ? 'Push (Webhook)' : 'Poll'}</span>
            <span className="text-xs text-slate-500">click to toggle</span>
          </button>
        </div>
        
        <div className="flex-1">
          <div className="text-xs text-slate-500 mb-1">Events Requested</div>
          <div className="text-sm text-slate-300">{stream.events_requested.length} event types</div>
        </div>
      </div>
    </div>
  )
}

interface EventFlowTimelineProps {
  steps: FlowStep[]
  lastAction: ActionResponse | null
}

function EventFlowTimeline({ steps, lastAction: _lastAction }: EventFlowTimelineProps) {
  // _lastAction reserved for future enhancements (showing action details inline)
  return (
    <div className="bg-slate-900 rounded-lg border border-slate-700 p-4">
      <h3 className="text-sm font-semibold text-slate-200 mb-4">Event Flow</h3>
      
      {steps.length === 0 ? (
        <div className="text-center py-12 text-slate-500">
          <div className="text-4xl mb-3">🎯</div>
          <div className="text-sm">Select a subject and trigger an action to see the event flow</div>
        </div>
      ) : (
        <div className="relative">
          {/* Connector line */}
          <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-slate-700" />
          
          <div className="space-y-3">
            {steps.map((step, index) => (
              <motion.div
                key={step.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
                className="relative flex items-start gap-3 pl-8"
              >
                {/* Step indicator */}
                <div className={`absolute left-2 w-5 h-5 rounded-full flex items-center justify-center text-xs ${
                  step.status === 'complete' ? 'bg-green-500' :
                  step.status === 'active' ? 'bg-blue-500 animate-pulse' :
                  step.status === 'error' ? 'bg-red-500' :
                  'bg-slate-600'
                }`}>
                  {step.status === 'complete' ? '✓' : 
                   step.status === 'error' ? '✕' :
                   step.type === 'action' ? '⚡' :
                   step.type === 'set_generated' ? '📝' :
                   step.type === 'set_signed' ? '🔐' :
                   step.type === 'delivery' ? '📤' :
                   step.type === 'verified' ? '✅' :
                   step.type === 'processed' ? '⚙️' :
                   step.type === 'response' ? '🎯' : '•'}
                </div>
                
                <div className="flex-1 bg-slate-800 rounded-lg p-3">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-medium text-slate-200">{step.title}</span>
                    <span className="text-xs text-slate-500">
                      {step.timestamp.toLocaleTimeString()}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">{step.description}</p>
                  {step.data && (
                    <div className="mt-2 text-xs text-slate-500 font-mono">
                      {JSON.stringify(step.data)}
                    </div>
                  )}
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

interface ZeroTrustImpactProps {
  impact: string
}

function ZeroTrustImpact({ impact }: ZeroTrustImpactProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-gradient-to-r from-blue-900/50 to-purple-900/50 rounded-lg border border-blue-700 p-4"
    >
      <div className="flex items-start gap-3">
        <div className="text-2xl">🛡️</div>
        <div>
          <h4 className="text-sm font-semibold text-blue-300 mb-1">Zero Trust Impact</h4>
          <p className="text-sm text-slate-300">{impact}</p>
        </div>
      </div>
    </motion.div>
  )
}

interface EventLogProps {
  events: StoredEvent[]
  onInspect: (token: string) => void
}

function EventLog({ events, onInspect }: EventLogProps) {
  return (
    <div className="bg-slate-900 rounded-lg border border-slate-700 overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-700">
        <h3 className="text-sm font-semibold text-slate-200">Event Log</h3>
      </div>
      <div className="max-h-64 overflow-y-auto">
        {events.length === 0 ? (
          <div className="p-4 text-center text-slate-500 text-sm">No events yet</div>
        ) : (
          <div className="divide-y divide-slate-800">
            {events.slice(0, 10).map(event => (
              <div key={event.id} className="p-3 hover:bg-slate-800/50">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-medium text-slate-300 truncate">
                    {event.event_type.split('/').pop()}
                  </span>
                  <EventStatusBadge status={event.status} />
                </div>
                <div className="text-xs text-slate-500 mb-2">
                  {new Date(event.created_at).toLocaleString()}
                </div>
                <button
                  onClick={() => onInspect(event.set_token)}
                  className="text-xs text-blue-400 hover:text-blue-300"
                >
                  Inspect SET →
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

interface ResponseActionsLogProps {
  actions: ResponseAction[]
}

function ResponseActionsLog({ actions }: ResponseActionsLogProps) {
  return (
    <div className="bg-slate-900 rounded-lg border border-slate-700 overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-700">
        <h3 className="text-sm font-semibold text-slate-200">Response Actions</h3>
      </div>
      <div className="max-h-64 overflow-y-auto">
        {actions.length === 0 ? (
          <div className="p-4 text-center text-slate-500 text-sm">No actions yet</div>
        ) : (
          <div className="p-2 space-y-2">
            {actions.slice(0, 15).map(action => (
              <motion.div
                key={action.id}
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className="p-2 bg-slate-800 rounded text-xs"
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-green-400">✓</span>
                  <span className="text-slate-300">{action.action}</span>
                </div>
                <div className="text-slate-500 pl-5">
                  {new Date(action.executed_at).toLocaleTimeString()}
                </div>
              </motion.div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ============================================================================
// Helper Components
// ============================================================================

function StatusBadge({ status }: { status: string }) {
  const colors = {
    active: 'bg-green-500/20 text-green-400',
    disabled: 'bg-red-500/20 text-red-400',
    purged: 'bg-slate-500/20 text-slate-400',
  }
  return (
    <span className={`text-xs px-1.5 py-0.5 rounded ${colors[status as keyof typeof colors] || colors.active}`}>
      {status}
    </span>
  )
}

function EventStatusBadge({ status }: { status: string }) {
  const colors = {
    pending: 'bg-amber-500/20 text-amber-400',
    delivering: 'bg-blue-500/20 text-blue-400',
    delivered: 'bg-green-500/20 text-green-400',
    acknowledged: 'bg-purple-500/20 text-purple-400',
    failed: 'bg-red-500/20 text-red-400',
  }
  return (
    <span className={`text-xs px-1.5 py-0.5 rounded ${colors[status as keyof typeof colors] || colors.pending}`}>
      {status}
    </span>
  )
}

// ============================================================================
// SET Inspector Modal
// ============================================================================

interface DecodedSET {
  jti: string
  iss: string
  aud: string[]
  iat: string
  sub_id: {
    format: string
    email?: string
  }
  events: Array<{
    type: string
    metadata: EventMetadata
    payload: Record<string, unknown>
  }>
  header: Record<string, unknown>
  raw_token: string
}

interface SETInspectorModalProps {
  token: string | null
  decoded: DecodedSET | null
  onClose: () => void
}

function SETInspectorModal({ token, decoded, onClose }: SETInspectorModalProps) {
  const [activeTab, setActiveTab] = useState<'header' | 'payload' | 'raw'>('payload')

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.95, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.95, opacity: 0 }}
        className="bg-slate-900 rounded-lg border border-slate-700 w-full max-w-2xl max-h-[80vh] overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        <div className="px-4 py-3 border-b border-slate-700 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-slate-200">SET Inspector</h3>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-200">✕</button>
        </div>

        {decoded ? (
          <>
            {/* Event Type Banner */}
            {decoded.events[0] && (
              <div className={`px-4 py-3 ${
                decoded.events[0].metadata.category === 'CAEP' 
                  ? 'bg-blue-900/30 border-b border-blue-800' 
                  : 'bg-amber-900/30 border-b border-amber-800'
              }`}>
                <div className="flex items-center gap-3">
                  <span className={`text-xs font-bold px-2 py-1 rounded ${
                    decoded.events[0].metadata.category === 'CAEP'
                      ? 'bg-blue-500 text-white'
                      : 'bg-amber-500 text-white'
                  }`}>
                    {decoded.events[0].metadata.category}
                  </span>
                  <span className="text-slate-200 font-medium">
                    {decoded.events[0].metadata.name}
                  </span>
                </div>
                <p className="text-sm text-slate-400 mt-1">
                  {decoded.events[0].metadata.description}
                </p>
              </div>
            )}

            {/* Tabs */}
            <div className="flex border-b border-slate-700">
              {(['payload', 'header', 'raw'] as const).map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-4 py-2 text-sm font-medium transition-colors ${
                    activeTab === tab
                      ? 'text-blue-400 border-b-2 border-blue-400'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab.charAt(0).toUpperCase() + tab.slice(1)}
                </button>
              ))}
            </div>

            {/* Content */}
            <div className="p-4 overflow-y-auto max-h-96">
              {activeTab === 'payload' && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <div className="text-xs text-slate-500 mb-1">Issuer</div>
                      <div className="text-sm text-slate-300 font-mono">{decoded.iss}</div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-500 mb-1">JTI</div>
                      <div className="text-sm text-slate-300 font-mono truncate">{decoded.jti}</div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-500 mb-1">Subject</div>
                      <div className="text-sm text-slate-300 font-mono">
                        {decoded.sub_id?.email || 'N/A'}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-500 mb-1">Issued At</div>
                      <div className="text-sm text-slate-300">
                        {decoded.iat ? new Date(decoded.iat).toLocaleString() : 'N/A'}
                      </div>
                    </div>
                  </div>

                  {decoded.events[0] && (
                    <div>
                      <div className="text-xs text-slate-500 mb-2">Event Payload</div>
                      <pre className="text-xs text-green-400 bg-slate-800 p-3 rounded overflow-x-auto">
                        {JSON.stringify(decoded.events[0].payload, null, 2)}
                      </pre>
                    </div>
                  )}

                  {decoded.events[0]?.metadata.response_actions && (
                    <div>
                      <div className="text-xs text-slate-500 mb-2">Expected Response Actions</div>
                      <ul className="space-y-1">
                        {decoded.events[0].metadata.response_actions.map((action, i) => (
                          <li key={i} className="text-sm text-slate-300 flex items-center gap-2">
                            <span className="text-green-400">→</span>
                            {action}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'header' && (
                <pre className="text-xs text-cyan-400 bg-slate-800 p-3 rounded overflow-x-auto">
                  {JSON.stringify(decoded.header, null, 2)}
                </pre>
              )}

              {activeTab === 'raw' && token && (
                <div className="space-y-2">
                  <div className="text-xs text-slate-500">Raw JWT Token</div>
                  <div className="font-mono text-xs break-all">
                    <span className="text-red-400">{token.split('.')[0]}</span>
                    <span className="text-slate-600">.</span>
                    <span className="text-purple-400">{token.split('.')[1]}</span>
                    <span className="text-slate-600">.</span>
                    <span className="text-cyan-400">{token.split('.')[2]}</span>
                  </div>
                </div>
              )}
            </div>
          </>
        ) : (
          <div className="p-8 text-center text-slate-500">Loading...</div>
        )}
      </motion.div>
    </motion.div>
  )
}

export default SSFSandbox

