/**
 * SSF Sandbox Flow Executor
 * 
 * Unlike other flow executors, SSF uses a reactive/interactive model
 * where users trigger actions via UI and observe real-time results.
 */

import { FlowExecutorBase, FlowExecutorConfig } from './base'

// ============================================================================
// Types
// ============================================================================

export interface SSFSandboxConfig extends FlowExecutorConfig {
  /** SSF API base URL */
  ssfBaseUrl?: string
}

export interface SSFSubject {
  id: string
  stream_id: string
  format: string
  identifier: string
  display_name: string
  status: 'active' | 'disabled' | 'purged'
  active_sessions: number
  last_activity: string | null
  created_at: string
}

export interface SSFStream {
  stream_id: string
  iss: string
  aud: string[]
  events_supported: string[]
  events_requested: string[]
  delivery_method: string
  delivery_endpoint_url: string
  status: string
}

export interface SSFEventMetadata {
  uri: string
  name: string
  description: string
  category: 'CAEP' | 'RISC'
  response_actions: string[]
  zero_trust_impact: string
}

export interface SSFStoredEvent {
  id: string
  stream_id: string
  subject_id: string | null
  event_type: string
  event_data: string
  set_token: string
  status: 'pending' | 'delivering' | 'delivered' | 'acknowledged' | 'failed'
  created_at: string
  delivered_at: string | null
  acknowledged_at: string | null
}

export interface SSFActionResponse {
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

export interface DecodedSET {
  jti: string
  iss: string
  aud: string[]
  iat: string
  sub_id: {
    format: string
    email?: string
    phone_number?: string
  }
  txn?: string
  events: Array<{
    type: string
    metadata: SSFEventMetadata
    payload: Record<string, unknown>
    raw_payload: unknown
  }>
  header: Record<string, unknown>
  raw_token: string
}

// Action types
export type SSFActionType = 
  | 'session-revoked'
  | 'credential-change'
  | 'device-compliance-change'
  | 'assurance-level-change'
  | 'credential-compromise'
  | 'account-disabled'
  | 'account-enabled'
  | 'account-purged'
  | 'identifier-changed'
  | 'sessions-revoked'

// ============================================================================
// SSF Sandbox Executor
// ============================================================================

/**
 * SSF Sandbox Executor
 * 
 * This executor is different from others - it provides an API for
 * interactive sandbox operations rather than running a predefined flow.
 */
export class SSFSandboxExecutor extends FlowExecutorBase {
  readonly flowType = 'ssf-sandbox'
  readonly flowName = 'SSF Interactive Sandbox'
  readonly rfcReference = 'OpenID SSF 1.0, CAEP, RISC'

  private ssfBaseUrl: string

  constructor(config: SSFSandboxConfig) {
    super(config)
    this.ssfBaseUrl = config.ssfBaseUrl || '/ssf'
  }

  /**
   * Execute is a no-op for sandbox - actions are triggered via specific methods
   */
  async execute(): Promise<void> {
    this.updateState({ 
      status: 'executing', 
      currentStep: 'SSF Sandbox ready - trigger actions interactively' 
    })
  }

  /**
   * Fetch all subjects in the stream
   */
  async getSubjects(): Promise<SSFSubject[]> {
    const { data } = await this.makeSSFRequest<{ subjects: SSFSubject[] }>(
      'GET',
      '/subjects',
      { step: 'Fetching subjects' }
    )
    return data.subjects || []
  }

  /**
   * Add a new subject
   */
  async addSubject(identifier: string, displayName: string): Promise<SSFSubject> {
    const { data } = await this.makeSSFRequest<SSFSubject>(
      'POST',
      '/subjects',
      {
        step: 'Adding subject',
        body: JSON.stringify({
          format: 'email',
          identifier,
          display_name: displayName,
        }),
      }
    )
    return data
  }

  /**
   * Get stream configuration
   */
  async getStream(): Promise<SSFStream> {
    const { data } = await this.makeSSFRequest<SSFStream>(
      'GET',
      '/stream',
      { step: 'Fetching stream configuration' }
    )
    return data
  }

  /**
   * Update stream configuration
   */
  async updateStream(updates: Partial<{
    delivery_method: string
    events_requested: string[]
    status: string
  }>): Promise<SSFStream> {
    const { data } = await this.makeSSFRequest<SSFStream>(
      'PATCH',
      '/stream',
      {
        step: 'Updating stream',
        body: JSON.stringify(updates),
      }
    )
    return data
  }

  /**
   * Trigger a security action
   */
  async triggerAction(
    action: SSFActionType,
    subjectIdentifier: string,
    options?: {
      reason?: string
      initiator?: string
      credential_type?: string
      current_status?: string
      previous_status?: string
      new_value?: string
    }
  ): Promise<SSFActionResponse> {
    this.updateState({ 
      status: 'executing', 
      currentStep: `Triggering ${action} for ${subjectIdentifier}` 
    })

    this.addEvent({
      type: 'user_action',
      title: 'Action Triggered',
      description: `${action} for ${subjectIdentifier}`,
      data: { action, subject: subjectIdentifier },
    })

    const { data } = await this.makeSSFRequest<SSFActionResponse>(
      'POST',
      `/actions/${action}`,
      {
        step: `Execute ${action}`,
        rfcReference: this.getActionRfcReference(action),
        body: JSON.stringify({
          subject_identifier: subjectIdentifier,
          ...options,
        }),
      }
    )

    this.addEvent({
      type: 'info',
      title: 'Event Generated',
      description: `${data.event_name} (${data.category})`,
      data: {
        event_id: data.event_id,
        event_type: data.event_type,
        category: data.category,
      },
    })

    // Log response actions
    for (const responseAction of data.response_actions) {
      this.addEvent({
        type: 'security',
        title: 'Response Action',
        description: responseAction,
      })
    }

    this.addEvent({
      type: 'rfc',
      title: 'Zero Trust Impact',
      description: data.zero_trust_impact,
    })

    this.updateState({ 
      status: 'completed', 
      currentStep: `${action} completed successfully` 
    })

    return data
  }

  /**
   * Get event history
   */
  async getEvents(status?: string): Promise<SSFStoredEvent[]> {
    const path = status ? `/events?status=${status}` : '/events'
    const { data } = await this.makeSSFRequest<{ events: SSFStoredEvent[] }>(
      'GET',
      path,
      { step: 'Fetching events' }
    )
    return data.events || []
  }

  /**
   * Poll for events (when in poll delivery mode)
   */
  async pollEvents(ack?: string[]): Promise<{ sets: Record<string, string>; moreAvailable: boolean }> {
    const { data } = await this.makeSSFRequest<{ sets: Record<string, string>; moreAvailable: boolean }>(
      'POST',
      '/poll',
      {
        step: 'Polling for events',
        rfcReference: 'OpenID SSF 1.0 - Poll Delivery',
        body: JSON.stringify({ ack }),
      }
    )
    return data
  }

  /**
   * Decode a SET token
   */
  async decodeSET(token: string): Promise<DecodedSET> {
    const { data } = await this.makeSSFRequest<DecodedSET>(
      'POST',
      '/decode',
      {
        step: 'Decoding SET',
        body: JSON.stringify({ token }),
      }
    )
    return data
  }

  /**
   * Get all supported event types
   */
  async getEventTypes(): Promise<Record<'CAEP' | 'RISC', SSFEventMetadata[]>> {
    const { data } = await this.makeSSFRequest<Record<'CAEP' | 'RISC', SSFEventMetadata[]>>(
      'GET',
      '/event-types',
      { step: 'Fetching event types' }
    )
    return data
  }

  /**
   * Make an SSF API request
   */
  private async makeSSFRequest<T>(
    method: string,
    path: string,
    options: {
      step: string
      rfcReference?: string
      body?: string
    }
  ): Promise<{ response: Response; data: T }> {
    const url = `${this.ssfBaseUrl}${path}`
    const headers: Record<string, string> = this.withCaptureHeaders({
      'Accept': 'application/json',
    })

    if (options.body) {
      headers['Content-Type'] = 'application/json'
    }

    const exchange = this.addExchange({
      step: options.step,
      rfcReference: options.rfcReference,
      request: {
        method,
        url,
        headers,
        body: options.body,
      },
    })

    const startTime = Date.now()

    const response = await fetch(url, {
      method,
      headers,
      body: options.body,
      signal: this.abortController?.signal,
    })

    const duration = Date.now() - startTime
    const data = await response.json() as T

    exchange.response = {
      status: response.status,
      statusText: response.statusText,
      headers: Object.fromEntries(response.headers.entries()),
      body: data,
      duration,
    }

    this.updateState({
      exchanges: this.state.exchanges.map(e =>
        e.id === exchange.id ? exchange : e
      ),
    })

    return { response, data }
  }

  /**
   * Get RFC reference for an action
   */
  private getActionRfcReference(action: SSFActionType): string {
    const references: Record<SSFActionType, string> = {
      'session-revoked': 'CAEP - Session Revoked Event',
      'credential-change': 'CAEP - Credential Change Event',
      'device-compliance-change': 'CAEP - Device Compliance Change Event',
      'assurance-level-change': 'CAEP - Assurance Level Change Event',
      'credential-compromise': 'RISC - Credential Compromise Event',
      'account-disabled': 'RISC - Account Disabled Event',
      'account-enabled': 'RISC - Account Enabled Event',
      'account-purged': 'RISC - Account Purged Event',
      'identifier-changed': 'RISC - Identifier Changed Event',
      'sessions-revoked': 'RISC - Sessions Revoked Event',
    }
    return references[action] || 'OpenID SSF 1.0'
  }
}

// ============================================================================
// Factory & Constants
// ============================================================================

export function createSSFExecutor(config: SSFSandboxConfig): SSFSandboxExecutor {
  return new SSFSandboxExecutor(config)
}

export const SSF_ACTIONS: Record<SSFActionType, {
  name: string
  description: string
  category: 'CAEP' | 'RISC'
}> = {
  'session-revoked': {
    name: 'Session Revoked',
    description: 'Terminate an active user session',
    category: 'CAEP',
  },
  'credential-change': {
    name: 'Credential Change',
    description: 'User credential has been changed',
    category: 'CAEP',
  },
  'device-compliance-change': {
    name: 'Device Compliance Change',
    description: 'Device compliance status changed',
    category: 'CAEP',
  },
  'assurance-level-change': {
    name: 'Assurance Level Change',
    description: 'Authentication assurance level changed',
    category: 'CAEP',
  },
  'credential-compromise': {
    name: 'Credential Compromise',
    description: 'Credentials may be compromised',
    category: 'RISC',
  },
  'account-disabled': {
    name: 'Account Disabled',
    description: 'User account has been disabled',
    category: 'RISC',
  },
  'account-enabled': {
    name: 'Account Enabled',
    description: 'User account has been re-enabled',
    category: 'RISC',
  },
  'account-purged': {
    name: 'Account Purged',
    description: 'User account has been permanently deleted',
    category: 'RISC',
  },
  'identifier-changed': {
    name: 'Identifier Changed',
    description: 'User identifier (email/username) changed',
    category: 'RISC',
  },
  'sessions-revoked': {
    name: 'All Sessions Revoked',
    description: 'All sessions for the user have been terminated',
    category: 'RISC',
  },
}


