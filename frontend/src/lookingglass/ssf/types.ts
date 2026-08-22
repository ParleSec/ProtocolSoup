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
  device_id?: string
  device_compliance?: string
  access_restricted?: boolean
  last_modified: string
  modified_by: string
}

export interface EventDef {
  id: string
  name: string
  icon: ElementType
  description: string
  category: 'CAEP' | 'RISC'
  rfcReference: string
}
