import type { SecurityState } from './types'

export const SSF_DELIVERY_PUSH = 'urn:ietf:rfc:8935'
export const SSF_DELIVERY_POLL = 'urn:ietf:rfc:8936'

export type SSFDeliveryMethod = typeof SSF_DELIVERY_PUSH | typeof SSF_DELIVERY_POLL

export interface SSFLabSnapshot {
  subjectIdentifier: string
  eventId: string
  deliveryMethod: SSFDeliveryMethod
  preset: string | null
  securityState: SecurityState | null
  ready: boolean
}

const DEFAULT_LAB: SSFLabSnapshot = {
  subjectIdentifier: '',
  eventId: '',
  deliveryMethod: SSF_DELIVERY_PUSH,
  preset: null,
  securityState: null,
  ready: false,
}

let snapshot: SSFLabSnapshot = { ...DEFAULT_LAB }
const listeners = new Set<() => void>()

function emit() {
  listeners.forEach((listener) => listener())
}

export function getSSFLab(): SSFLabSnapshot {
  return snapshot
}

export function updateSSFLab(partial: Partial<SSFLabSnapshot>): void {
  snapshot = { ...snapshot, ...partial }
  emit()
}

export function resetSSFLab(): void {
  snapshot = { ...DEFAULT_LAB }
  emit()
}

export function subscribeSSFLab(listener: () => void): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}
