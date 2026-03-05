import { useCallback, useEffect, useRef, useState } from 'react'
import type { CapturedHTTPExchange, FlowEvent, SSEPipelineEvent } from '../lookingglass/ssf/types'

export function getOrCreateSSFSessionId(): string {
  const storageKey = 'ssf_session_id'
  let sessionId = localStorage.getItem(storageKey)

  if (!sessionId) {
    sessionId = `sess_${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`
    localStorage.setItem(storageKey, sessionId)
  }

  return sessionId
}

export function ssfFetch(url: string, options: RequestInit = {}): Promise<Response> {
  const sessionId = getOrCreateSSFSessionId()

  return fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'X-SSF-Session': sessionId,
    },
  })
}

// SSE event type -> FlowEvent mapping.
// Only events that carry real, observable data are shown.
// Metadata-only announcements (event_queued, delivery_started, delivery_success)
// are dropped — the captured http_exchange IS the delivery with real headers/body.
function mapSSEToFlowEvent(sse: SSEPipelineEvent): FlowEvent | null {
  const { source, event } = sse
  const base = {
    id: crypto.randomUUID(),
    timestamp: new Date(event.timestamp),
    data: event.data,
  }

  if (source === 'transmitter') {
    switch (event.type) {
      case 'action_triggered': {
        const meta = event.data?.metadata as Record<string, unknown> | undefined
        return {
          ...base,
          type: 'info',
          title: `Transmitter: ${(meta?.name as string) || 'Event Triggered'}`,
          description: `Subject: ${event.subject_id || '?'}  |  ${(meta?.category as string) || 'SSF'}`,
          rfcReference: 'SSF §4',
        }
      }
      case 'set_generated': {
        const claims = event.data?.claims as Record<string, unknown> | undefined
        return {
          ...base,
          type: 'crypto',
          title: 'Transmitter: SET Created',
          description: `JTI: ${(claims?.id as string)?.slice(0, 8) || '?'}…  |  iss: ${(claims?.issuer as string) || '?'}`,
          rfcReference: 'RFC 8417 §2',
        }
      }
      case 'set_signed':
        return {
          ...base,
          type: 'crypto',
          title: 'Transmitter: SET Signed (RS256)',
          description: `${((event.data?.token as string) || '').length} byte JWT`,
          rfcReference: 'RFC 7515',
        }
      case 'http_exchange':
      case 'event_queued':
      case 'delivery_started':
      case 'delivery_success':
        return null
      case 'delivery_failed':
        return {
          ...base,
          type: 'error',
          title: 'Transmitter: Delivery Failed',
          description: (event.data?.error as string) || 'Delivery error',
        }
      default:
        return null
    }
  }

  if (source === 'receiver') {
    switch (event.type) {
      case 'http_exchange':
        return null
      case 'event_received':
        return {
          ...base,
          type: 'request',
          title: 'Receiver: SET Received',
          description: `${(event.data?.token_length as number) || '?'} bytes via ${(event.data?.delivery_method as string) || 'push'}`,
          rfcReference: 'RFC 8935 §2',
        }
      case 'event_verified':
        return {
          ...base,
          type: 'crypto',
          title: 'Receiver: Signature Verified',
          description: `${(event.data?.algorithm as string) || 'RS256'} with key ${(event.data?.key_id as string) || '?'}`,
          rfcReference: 'RFC 7515 §5.2',
        }
      case 'event_verify_failed':
        return {
          ...base,
          type: 'error',
          title: 'Receiver: Verification Failed',
          description: (event.data?.error as string) || 'Signature verification failed',
        }
      case 'event_processed':
        return {
          ...base,
          type: 'security',
          title: 'Receiver: SET Processed',
          description: `Completed in ${(event.data?.processing_time_ms as number) || 0}ms`,
        }
      case 'response_action':
        return {
          ...base,
          type: 'action',
          title: `Action: ${(event.data?.action as string) || 'Response'}`,
          description: `${(event.data?.event_type as string) || ''} (${(event.data?.category as string) || 'SSF'})`,
        }
      case 'event_processing':
        return {
          ...base,
          type: 'info',
          title: 'Receiver: Processing SET',
          description: `Decoding ${(event.data?.event_count as number) || 1} event(s)`,
          rfcReference: 'RFC 8417 §2',
        }
      default:
        return null
    }
  }

  return null
}

export function useSSFEventStream(sessionId: string) {
  const [pipelineEvents, setPipelineEvents] = useState<FlowEvent[]>([])
  const [httpExchanges, setHttpExchanges] = useState<CapturedHTTPExchange[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const eventSourceRef = useRef<EventSource | null>(null)
  const retryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const mountedRef = useRef(true)

  const connect = useCallback(() => {
    if (retryTimerRef.current) {
      clearTimeout(retryTimerRef.current)
      retryTimerRef.current = null
    }
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
      eventSourceRef.current = null
    }

    const url = `/ssf/events/stream?session=${encodeURIComponent(sessionId)}`
    const es = new EventSource(url)
    eventSourceRef.current = es

    es.addEventListener('connected', () => {
      setIsConnected(true)
    })

    es.onerror = () => {
      es.close()
      eventSourceRef.current = null
      setIsConnected(false)

      if (mountedRef.current) {
        retryTimerRef.current = setTimeout(() => {
          if (mountedRef.current) connect()
        }, 2000)
      }
    }

    es.onopen = () => {
      setIsConnected(true)
    }
  }, [sessionId])

  const disconnect = useCallback(() => {
    if (retryTimerRef.current) {
      clearTimeout(retryTimerRef.current)
      retryTimerRef.current = null
    }
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
      eventSourceRef.current = null
    }
    setIsConnected(false)
  }, [])

  const clearEvents = useCallback(() => {
    setPipelineEvents([])
    setHttpExchanges([])
  }, [])

  // Process pipeline events returned directly in the action API response.
  // This is the reliable path — events come through HTTP responses.
  const ingestResponseEvents = useCallback((events: SSEPipelineEvent[]) => {
    const flowEvents: FlowEvent[] = []
    const exchanges: CapturedHTTPExchange[] = []

    for (const sse of events) {
      if (sse.event.type === 'http_exchange' && sse.event.data) {
        exchanges.push(sse.event.data as unknown as CapturedHTTPExchange)
        continue
      }
      const flowEvent = mapSSEToFlowEvent(sse)
      if (flowEvent) {
        flowEvents.push(flowEvent)
      }
    }

    if (flowEvents.length > 0) {
      setPipelineEvents((prev) => [...prev, ...flowEvents])
    }
    if (exchanges.length > 0) {
      setHttpExchanges((prev) => [...prev, ...exchanges])
    }
  }, [])

  useEffect(() => {
    mountedRef.current = true
    connect()
    return () => {
      mountedRef.current = false
      disconnect()
    }
  }, [connect, disconnect])

  return { pipelineEvents, httpExchanges, isConnected, clearEvents, ingestResponseEvents, connect, disconnect }
}
