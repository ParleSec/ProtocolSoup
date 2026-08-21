import { FlowExecutorBase, type FlowExecutorConfig } from './base'
import { getSSFLab, SSF_DELIVERY_POLL, SSF_DELIVERY_PUSH, updateSSFLab } from '../ssf/lab-store'
import type { SecurityState } from '../ssf/types'

export class SSFLabExecutor extends FlowExecutorBase {
  readonly flowType = 'ssf-lab'
  readonly flowName = 'SSF in Looking Glass'
  readonly rfcReference = 'RFC 8417, RFC 8935, RFC 8936, OpenID SSF 1.0'

  constructor(config: FlowExecutorConfig) {
    super(config)
  }

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({ status: 'executing', currentStep: 'Firing security event' })

    try {
      const lab = getSSFLab()
      const intent = lab.intent
      updateSSFLab({ intent: 'fire' })

      if (intent === 'verify') {
        await this.runStreamConfiguration()
        this.updateState({
          status: 'idle',
          currentStep: 'Stream inspected — RP account state is unchanged',
        })
        return
      }

      if (lab.deliveryMethod) {
        await this.patchDelivery(lab.deliveryMethod)
      }

      if (!lab.subjectIdentifier || !lab.eventId) {
        throw new Error('Select a subject and event before firing')
      }
      await this.fireEvent(lab.eventId, lab.subjectIdentifier)
      if (lab.deliveryMethod === SSF_DELIVERY_POLL) {
        await this.pollAndAck()
      }
      await this.refreshSecurityState(lab.subjectIdentifier)

      this.updateState({
        status: 'idle',
        currentStep: 'Ready to fire another event',
      })
    } catch (error) {
      const description = error instanceof Error ? error.message : 'SSF lab execution failed'
      this.updateState({
        status: 'idle',
        currentStep: description,
        error: { code: 'ssf_lab_error', description },
      })
    }
  }

  private async jsonRequest(method: string, path: string, options: {
    body?: unknown
    step: string
    rfcReference?: string
  }): Promise<{ response: Response; data: unknown }> {
    const url = path.startsWith('http') ? path : path
    const headers: Record<string, string> = { Accept: 'application/json' }
    let body: string | undefined
    if (options.body !== undefined) {
      headers['Content-Type'] = 'application/json'
      body = JSON.stringify(options.body)
    }
    return this.makeRequest(method, url, {
      headers,
      body,
      step: options.step,
      rfcReference: options.rfcReference,
    })
  }

	private async resolveStreamID(): Promise<string> {
    const { data } = await this.jsonRequest('GET', `${this.config.baseUrl}/stream`, {
      step: 'List stream configuration',
      rfcReference: 'OpenID SSF 1.0 Section 8.1.1.2',
    })
    if (Array.isArray(data) && data.length > 0) {
      const id = (data[0] as { stream_id?: string }).stream_id
      if (id) return id
    }
    if (data && typeof data === 'object' && 'stream_id' in data) {
      const id = (data as { stream_id?: string }).stream_id
      if (id) return id
    }
    const created = await this.jsonRequest('POST', `${this.config.baseUrl}/stream`, {
      body: {
        delivery: { method: SSF_DELIVERY_PUSH },
      },
      step: 'Create Event Stream',
      rfcReference: 'OpenID SSF 1.0 Section 8.1.1.1',
    })
    const streamId = (created.data as { stream_id?: string })?.stream_id
    if (!streamId) {
      throw new Error('stream_id missing from POST /stream')
    }
    return streamId
  }

  private async patchDelivery(method: string): Promise<void> {
    const streamId = await this.resolveStreamID()
    await this.jsonRequest('PATCH', `${this.config.baseUrl}/stream?stream_id=${encodeURIComponent(streamId)}`, {
      body: {
        stream_id: streamId,
        delivery: { method },
      },
      step: 'Update stream delivery method',
      rfcReference: 'OpenID SSF 1.0 Section 8.1.1',
    })
  }

  private async runStreamConfiguration(): Promise<void> {
    await this.jsonRequest('GET', '/.well-known/ssf-configuration', {
      step: 'Fetch Transmitter configuration',
      rfcReference: 'OpenID SSF 1.0 Section 7.2',
    })
    const streamId = await this.resolveStreamID()
    await this.jsonRequest('GET', `${this.config.baseUrl}/stream?stream_id=${encodeURIComponent(streamId)}`, {
      step: 'Read stream configuration',
      rfcReference: 'OpenID SSF 1.0 Section 8.1.1',
    })
    await this.jsonRequest('GET', `${this.config.baseUrl}/jwks`, {
      step: 'Fetch Transmitter JWKS',
      rfcReference: 'RFC 7517',
    })
    const { response } = await this.jsonRequest('POST', `${this.config.baseUrl}/verify`, {
      body: { stream_id: streamId, state: crypto.randomUUID() },
      step: 'Trigger stream verification',
      rfcReference: 'OpenID SSF 1.0 Section 8.1.4.2',
    })
    if (response.status !== 204) {
      throw new Error(`verification expected 204, got ${response.status}`)
    }
  }

  private async fireEvent(eventId: string, subjectIdentifier: string): Promise<void> {
    const { response, data } = await this.jsonRequest('POST', `${this.config.baseUrl}/actions/${eventId}`, {
      body: { subject_identifier: subjectIdentifier },
      step: `Fire ${eventId}`,
      rfcReference: 'RFC 8417 Section 2',
    })
    if (!response.ok) {
      const err = (data as { error?: string })?.error || `HTTP ${response.status}`
      throw new Error(err)
    }
    const token = await this.latestSetToken()
    if (token) {
      const decoded = this.decodeJwt(token, 'set')
      this.updateState({
        decodedTokens: [...this.state.decodedTokens, decoded],
        tokens: { ...this.state.tokens, idToken: token },
      })
    }
  }

  private async latestSetToken(): Promise<string | null> {
    const { data } = await this.jsonRequest('GET', `${this.config.baseUrl}/events`, {
      step: 'Fetch stored SETs',
      rfcReference: 'RFC 8417 Section 2',
    })
    const events = (data as { events?: Array<{ set_token?: string }> })?.events || []
    return events[0]?.set_token || null
  }

  private async pollAndAck(): Promise<void> {
    const { data } = await this.jsonRequest('POST', `${this.config.baseUrl}/poll`, {
      body: { maxEvents: 10, returnImmediately: true },
      step: 'Poll Transmitter for SETs',
      rfcReference: 'RFC 8936 Section 2',
    })
    const sets = (data as { sets?: Record<string, string> })?.sets || {}
    const acks = Object.keys(sets)
    if (acks.length > 0) {
      await this.jsonRequest('POST', `${this.config.baseUrl}/poll`, {
        body: { ack: acks, maxEvents: 0, returnImmediately: true },
        step: 'Acknowledge polled SETs',
        rfcReference: 'RFC 8936 Section 2.4',
      })
    }
  }

  private async refreshSecurityState(email: string): Promise<void> {
    const { response, data } = await this.jsonRequest('GET', `${this.config.baseUrl}/security-state/${encodeURIComponent(email)}`, {
      step: 'Read RP security state',
    })
    if (!response.ok) return
    updateSSFLab({ securityState: data as SecurityState })
  }
}

export { SSF_DELIVERY_POLL, SSF_DELIVERY_PUSH }
