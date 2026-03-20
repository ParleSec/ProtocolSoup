import { useEffect, useRef, useState, useCallback } from 'react'

interface UseWebSocketOptions {
  onOpen?: () => void
  onClose?: () => void
  onError?: (error: Event) => void
  onMessage?: (message: string) => void
  reconnect?: boolean
  reconnectInterval?: number
  maxReconnectAttempts?: number
}

interface UseWebSocketReturn {
  connected: boolean
  lastMessage: string | null
  send: (message: string) => void
  connect: () => void
  disconnect: () => void
}

function buildWebSocketURL(url: string): string {
  if (!url.startsWith('/')) {
    return url
  }

  const wsBase = (process.env.NEXT_PUBLIC_WS_BASE_URL || '').trim()
  if (wsBase) {
    try {
      const parsed = new URL(wsBase, window.location.origin)
      if (parsed.protocol === 'http:') parsed.protocol = 'ws:'
      if (parsed.protocol === 'https:') parsed.protocol = 'wss:'
      const basePath = parsed.pathname.replace(/\/$/, '')
      return `${parsed.protocol}//${parsed.host}${basePath}${url}`
    } catch {
      // Fall back to current host if override cannot be parsed.
    }
  }

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  return `${protocol}//${host}${url}`
}

export function useWebSocket(
  url: string | null,
  options: UseWebSocketOptions = {}
): UseWebSocketReturn {
  const {
    onOpen,
    onClose,
    onError,
    onMessage,
    reconnect = true,
    reconnectInterval = 3000,
    maxReconnectAttempts = 5,
  } = options

  const wsRef = useRef<WebSocket | null>(null)
  const reconnectAttemptsRef = useRef(0)
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout>>()
  const shouldReconnectRef = useRef(true)

  const [connected, setConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState<string | null>(null)

  const connect = useCallback(() => {
    if (!url) return
    if (wsRef.current?.readyState === WebSocket.OPEN) return
    shouldReconnectRef.current = true

    try {
      const fullUrl = buildWebSocketURL(url)
      wsRef.current = new WebSocket(fullUrl)

      wsRef.current.onopen = () => {
        setConnected(true)
        reconnectAttemptsRef.current = 0
        onOpen?.()
      }

      wsRef.current.onclose = () => {
        setConnected(false)
        onClose?.()

        // Attempt reconnection
        if (shouldReconnectRef.current && reconnect && reconnectAttemptsRef.current < maxReconnectAttempts) {
          reconnectTimeoutRef.current = setTimeout(() => {
            reconnectAttemptsRef.current += 1
            connect()
          }, reconnectInterval)
        }
      }

      wsRef.current.onerror = (error) => {
        onError?.(error)
      }

      wsRef.current.onmessage = (event) => {
        setLastMessage(event.data)
        onMessage?.(event.data)
      }
    } catch (error) {
      console.error('WebSocket connection error:', error)
    }
  }, [url, onOpen, onClose, onError, onMessage, reconnect, reconnectInterval, maxReconnectAttempts])

  const disconnect = useCallback(() => {
    shouldReconnectRef.current = false
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
    }

    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }

    setConnected(false)
  }, [])

  const send = useCallback((message: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(message)
    } else {
      console.warn('WebSocket is not connected')
    }
  }, [])

  // Connect on mount, disconnect on unmount
  useEffect(() => {
    if (url) {
      connect()
    }

    return () => {
      disconnect()
    }
  }, [url, connect, disconnect])

  return {
    connected,
    lastMessage,
    send,
    connect,
    disconnect,
  }
}

