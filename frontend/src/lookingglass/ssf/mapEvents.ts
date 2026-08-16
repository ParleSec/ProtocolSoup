import type { LookingGlassEvent } from '../types'
import type { DecodedToken, FlowEvent } from '../flows/base'

function rfcFromEvent(event: LookingGlassEvent): string | undefined {
  const annotations = event.annotations || []
  for (const annotation of annotations) {
    if (annotation.reference) return annotation.reference
    if (annotation.title) return annotation.title
  }
  return undefined
}

function flowTypeFor(event: LookingGlassEvent): FlowEvent['type'] {
  switch (event.type) {
    case 'token.issued':
    case 'token.validated':
      return 'token'
    case 'crypto.operation':
      return 'crypto'
    case 'security.warning':
    case 'flow.error':
      return event.type === 'flow.error' ? 'error' : 'security'
    case 'security.info':
      return 'security'
    case 'request.sent':
      return 'request'
    case 'response.received':
      return 'response'
    default:
      return 'info'
  }
}

function phaseFor(event: LookingGlassEvent): string {
  const jti = typeof event.data?.jti === 'string'
    ? event.data.jti
    : typeof event.data?.event_id === 'string'
      ? event.data.event_id
      : ''
  if (jti) {
    return `SET ${jti.slice(0, 8)}`
  }
  return event.title || 'Stream'
}

export function mapLookingGlassEventsToFlowEvents(events: LookingGlassEvent[]): FlowEvent[] {
  return [...events]
    .filter((event) => event.type !== 'http.exchange')
    .reverse()
    .map((event) => ({
      id: event.id,
      timestamp: event.timestamp,
      type: flowTypeFor(event),
      title: event.title,
      description: event.description || '',
      rfcReference: rfcFromEvent(event),
      data: event.data,
      phase: phaseFor(event),
    }))
}

function decodeCompactJwt(raw: string): DecodedToken {
  const decoded: DecodedToken = { type: 'set', raw, isValid: true }
  try {
    const parts = raw.split('.')
    if (parts.length === 3) {
      decoded.header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')))
      decoded.payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')))
      decoded.signature = parts[2]
    }
  } catch {
    decoded.isValid = false
    decoded.validationErrors = ['Failed to decode SET']
  }
  return decoded
}

export function setsFromLookingGlassEvents(events: LookingGlassEvent[]): DecodedToken[] {
  const seen = new Set<string>()
  const tokens: DecodedToken[] = []
  for (const event of [...events].reverse()) {
    const raw = typeof event.data?.token === 'string' ? event.data.token : ''
    if (!raw || seen.has(raw)) continue
    if (event.type !== 'token.issued' && event.type !== 'crypto.operation') continue
    seen.add(raw)
    tokens.push(decodeCompactJwt(raw))
  }
  return tokens
}
