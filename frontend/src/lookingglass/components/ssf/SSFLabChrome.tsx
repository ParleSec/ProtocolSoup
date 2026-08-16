'use client'

import { useCallback, useEffect, useState } from 'react'
import { ChevronDown, Radio } from 'lucide-react'
import type { EventDef, SecurityState, Subject } from '../../ssf/types'
import {
  SSF_DELIVERY_POLL,
  SSF_DELIVERY_PUSH,
  type SSFDeliveryMethod,
  updateSSFLab,
} from '../../ssf/lab-store'

export interface LookingGlassChromeProps {
  flowId: string | null
  sessionId: string | null
  sessionToken: string | null
  onReadyChange?: (ready: boolean) => void
  onSecurityStateChange?: (state: SecurityState | null) => void
  onVerifyStream?: () => void
}

const PRESET_EVENT: Record<string, string> = {
  'caep-session-revoked': 'session-revoked',
  'caep-credential-change': 'credential-change',
  'risc-account-disabled': 'account-disabled',
  'risc-credential-compromise': 'credential-compromise',
}

const PRESET_DELIVERY: Record<string, SSFDeliveryMethod> = {
  'ssf-push-delivery': SSF_DELIVERY_PUSH,
  'ssf-poll-delivery': SSF_DELIVERY_POLL,
}

function eventIdFromUri(uri: string): string {
  return uri.split('/').pop() || uri
}

function ssfHeaders(sessionId: string | null): HeadersInit {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (sessionId) {
    headers['X-Looking-Glass-Session'] = sessionId
  }
  return headers
}

export function SSFLabChrome({
  flowId,
  sessionId,
  onReadyChange,
  onSecurityStateChange,
  onVerifyStream,
}: LookingGlassChromeProps) {
  const [subjects, setSubjects] = useState<Subject[]>([])
  const [eventDefs, setEventDefs] = useState<EventDef[]>([])
  const [subjectId, setSubjectId] = useState('')
  const [eventId, setEventId] = useState('')
  const [delivery, setDelivery] = useState<SSFDeliveryMethod>(SSF_DELIVERY_PUSH)

  const selectedSubject = subjects.find((subject) => subject.id === subjectId) || subjects[0] || null
  const selectedEvent = eventDefs.find((event) => event.id === eventId) || null
  const ready = Boolean(selectedSubject && selectedEvent)
  const catalogIsStreamInspect = flowId === 'ssf-stream-configuration'

  const publish = useCallback((next: {
    subject?: Subject | null
    event?: EventDef | null
    deliveryMethod?: SSFDeliveryMethod
    state?: SecurityState | null
  }) => {
    const subject = next.subject === undefined ? selectedSubject : next.subject
    const event = next.event === undefined ? selectedEvent : next.event
    const deliveryMethod = next.deliveryMethod ?? delivery
    const isReady = Boolean(subject && event)
    updateSSFLab({
      subjectIdentifier: subject?.identifier || '',
      eventId: event?.id || '',
      deliveryMethod,
      preset: flowId,
      ready: isReady,
      ...(next.state !== undefined ? { securityState: next.state } : {}),
    })
    onReadyChange?.(isReady)
    if (next.state !== undefined) {
      onSecurityStateChange?.(next.state)
    }
  }, [delivery, flowId, onReadyChange, onSecurityStateChange, selectedEvent, selectedSubject])

  useEffect(() => {
    fetch('/ssf/event-types', { headers: ssfHeaders(sessionId) })
      .then((res) => res.json())
      .then((grouped: Record<string, Array<Record<string, unknown>>>) => {
        const defs: EventDef[] = []
        for (const [category, types] of Object.entries(grouped)) {
          if (!Array.isArray(types)) continue
          for (const item of types) {
            const uri = String(item.uri || '')
            const id = eventIdFromUri(uri)
            if (!id) continue
            defs.push({
              id,
              name: String(item.name || id),
              icon: Radio,
              description: String(item.description || ''),
              category: category === 'RISC' ? 'RISC' : 'CAEP',
              rfcReference: category === 'RISC' ? 'RISC 1.0' : 'CAEP 1.0',
            })
          }
        }
        setEventDefs(defs)
      })
      .catch((err) => console.error('[SSF] Failed to fetch event types:', err))
  }, [sessionId])

  useEffect(() => {
    if (!sessionId) return
    fetch('/ssf/subjects', { headers: ssfHeaders(sessionId) })
      .then((res) => res.json())
      .then((data: { subjects?: Subject[] }) => {
        const next = data.subjects || []
        setSubjects(next)
        setSubjectId((current) => current || next[0]?.id || '')
      })
      .catch((err) => console.error('[SSF] Failed to fetch subjects:', err))
  }, [sessionId])

  useEffect(() => {
    if (!flowId) return
    const presetEvent = PRESET_EVENT[flowId]
    if (presetEvent) {
      setEventId(presetEvent)
    }
    const presetDelivery = PRESET_DELIVERY[flowId]
    if (presetDelivery) {
      setDelivery(presetDelivery)
    }
  }, [flowId])

  useEffect(() => {
    if (eventId || eventDefs.length === 0) return
    const presetEvent = flowId ? PRESET_EVENT[flowId] : ''
    if (presetEvent && eventDefs.some((event) => event.id === presetEvent)) {
      setEventId(presetEvent)
      return
    }
    if (flowId === 'ssf-stream-configuration') {
      return
    }
    setEventId(eventDefs[0].id)
  }, [eventDefs, eventId, flowId])

  useEffect(() => {
    publish({})
  }, [publish, ready, selectedSubject, selectedEvent, delivery, flowId])

  useEffect(() => {
    if (!sessionId || !selectedSubject) return
    fetch(`/ssf/security-state/${encodeURIComponent(selectedSubject.identifier)}`, {
      headers: ssfHeaders(sessionId),
    })
      .then((res) => res.ok ? res.json() : null)
      .then((state: SecurityState | null) => {
        if (state) {
          updateSSFLab({ securityState: state })
          onSecurityStateChange?.(state)
        }
      })
      .catch(() => undefined)
  }, [sessionId, selectedSubject, onSecurityStateChange])

  const applyQuickEvent = (id: string) => {
    if (eventDefs.some((event) => event.id === id)) {
      setEventId(id)
    }
  }

  return (
    <div className="space-y-3">
      <p className="text-sm text-surface-400 leading-relaxed">
        <span className="text-surface-300 font-medium">Fire event</span> sends a signed SET for the subject and event below. That is what changes RP account state (State tab).
        {' '}
        <span className="text-surface-300 font-medium">Verify stream</span> only does SSF discovery, <code className="text-xs">GET /stream</code>, JWKS, and <code className="text-xs">POST /verify</code>. It does not revoke sessions or disable accounts.
      </p>

      {catalogIsStreamInspect && (
        <p className="text-xs text-amber-200/90 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2">
          Catalog preset “Stream Configuration” inspects the transmitter. Use Verify stream for that. Fire event still uses the event picker and is the only control that mutates RP posture.
        </p>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => onVerifyStream?.()}
          disabled={!onVerifyStream}
          className="px-3 py-1.5 rounded-lg border border-white/15 bg-surface-800 text-xs font-medium text-surface-200 hover:text-white hover:border-white/30 disabled:opacity-40 disabled:pointer-events-none"
        >
          Verify stream
        </button>
        <span className="text-[11px] text-surface-500">Shortcuts:</span>
        <button type="button" className="px-2 py-1 rounded bg-surface-800 text-surface-300 hover:text-white text-[11px]" onClick={() => applyQuickEvent('session-revoked')}>
          session-revoked
        </button>
        <button type="button" className="px-2 py-1 rounded bg-surface-800 text-surface-300 hover:text-white text-[11px]" onClick={() => applyQuickEvent('credential-compromise')}>
          credential-compromise
        </button>
        <button type="button" className="px-2 py-1 rounded bg-surface-800 text-surface-300 hover:text-white text-[11px]" onClick={() => applyQuickEvent('account-disabled')}>
          account-disabled
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <label className="block min-w-0">
          <span className="text-xs text-surface-400 mb-1.5 block">subject:</span>
          <div className="relative">
            <select
              value={selectedSubject?.id || ''}
              onChange={(event) => setSubjectId(event.target.value)}
              className="w-full appearance-none px-3 py-2 pr-8 rounded-lg bg-surface-800 border border-white/10 text-sm text-white focus:outline-none focus:border-amber-500/50"
            >
              {subjects.map((subject) => (
                <option key={subject.id} value={subject.id}>
                  {subject.display_name} ({subject.identifier})
                </option>
              ))}
            </select>
            <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-surface-400 pointer-events-none" />
          </div>
        </label>

        <label className="block min-w-0">
          <span className="text-xs text-surface-400 mb-1.5 block">event:</span>
          <div className="relative">
            <select
              value={selectedEvent?.id || ''}
              onChange={(event) => setEventId(event.target.value)}
              className="w-full appearance-none px-3 py-2 pr-8 rounded-lg bg-surface-800 border border-white/10 text-sm text-white focus:outline-none focus:border-amber-500/50"
            >
              <option value="">Select an event...</option>
              <optgroup label="CAEP Events">
                {eventDefs.filter((event) => event.category === 'CAEP').map((event) => (
                  <option key={event.id} value={event.id}>{event.name}</option>
                ))}
              </optgroup>
              <optgroup label="RISC Events">
                {eventDefs.filter((event) => event.category === 'RISC').map((event) => (
                  <option key={event.id} value={event.id}>{event.name}</option>
                ))}
              </optgroup>
            </select>
            <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-surface-400 pointer-events-none" />
          </div>
        </label>

        <fieldset className="block min-w-0">
          <legend className="text-xs text-surface-400 mb-1.5">delivery:</legend>
          <div className="flex rounded-lg border border-white/10 overflow-hidden">
            <button
              type="button"
              onClick={() => setDelivery(SSF_DELIVERY_PUSH)}
              className={`flex-1 px-3 py-2 text-xs font-mono ${delivery === SSF_DELIVERY_PUSH ? 'bg-amber-500/20 text-amber-200' : 'bg-surface-800 text-surface-400'}`}
            >
              push
            </button>
            <button
              type="button"
              onClick={() => setDelivery(SSF_DELIVERY_POLL)}
              className={`flex-1 px-3 py-2 text-xs font-mono ${delivery === SSF_DELIVERY_POLL ? 'bg-amber-500/20 text-amber-200' : 'bg-surface-800 text-surface-400'}`}
            >
              poll
            </button>
          </div>
        </fieldset>
      </div>
    </div>
  )
}
