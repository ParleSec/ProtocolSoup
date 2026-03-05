import type { ElementType } from 'react'

export interface Subject {
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

export interface SecurityState {
  email: string
  sessions_active: number
  account_enabled: boolean
  password_reset_required: boolean
  tokens_valid: boolean
  last_modified: string
  modified_by: string
}

export interface FlowEvent {
  id: string
  type: 'info' | 'request' | 'response' | 'token' | 'crypto' | 'security' | 'action' | 'error'
  title: string
  description: string
  timestamp: Date
  rfcReference?: string
  data?: Record<string, unknown>
}

export interface DecodedSET {
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

export interface SSEPipelineEvent {
  source: 'transmitter' | 'receiver'
  event: {
    type: string
    timestamp: string
    event_id: string
    session_id?: string
    subject_id?: string
    event_type?: string
    data: Record<string, unknown>
  }
}

export interface CapturedHTTPExchange {
  label: string
  request: {
    method: string
    url: string
    status_code?: number
    headers: Record<string, string>
    body?: string
  }
  response: {
    method?: string
    url?: string
    status_code: number
    headers: Record<string, string>
    body?: string
  }
  duration_ms: number
  timestamp: string
  session_id?: string
}

export interface EventDef {
  id: string
  name: string
  icon: ElementType
  description: string
  category: 'CAEP' | 'RISC'
  rfcReference: string
}

export type SSFExecutionStatus = 'idle' | 'executing' | 'completed' | 'error'
export type SSFFlowTab = 'events' | 'traffic' | 'set' | 'state'
