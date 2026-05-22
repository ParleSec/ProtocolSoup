/**
 * usePaletteQuery — debounced React hook that queries POST /api/palette/query.
 *
 * The hook keeps the most recent successful response alongside loading and
 * error state. Race conditions are eliminated by tracking the latest
 * dispatched query id; out-of-order responses are dropped.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import type {
  PaletteFilter,
  PaletteRequest,
  PaletteResponse,
  PaletteScope,
} from './types'

interface UsePaletteQueryOptions {
  q: string
  scope?: PaletteScope
  filters?: PaletteFilter[]
  debounceMs?: number
  enabled?: boolean
}

interface UsePaletteQueryResult {
  data: PaletteResponse | null
  loading: boolean
  error: string | null
  refresh: () => void
}

const PALETTE_QUERY_ENDPOINT = '/api/palette/query'

export function usePaletteQuery({
  q,
  scope,
  filters,
  debounceMs = 80,
  enabled = true,
}: UsePaletteQueryOptions): UsePaletteQueryResult {
  const [data, setData] = useState<PaletteResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Stable JSON of the filters keyed array so effect deps stay simple.
  const filtersKey = useMemo(() => JSON.stringify(filters ?? []), [filters])

  const requestSeq = useRef(0)

  const issueQuery = useCallback(async () => {
    const body: PaletteRequest = {
      q,
      ...(scope ? { scope } : {}),
      ...(filters && filters.length ? { filters } : {}),
    }
    const seq = ++requestSeq.current
    setLoading(true)
    setError(null)
    try {
      const response = await fetch(PALETTE_QUERY_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!response.ok) {
        if (response.status === 404 || response.status === 405) {
          // Route not mounted — degrade silently; production always exposes this route.
          if (seq === requestSeq.current) {
            setData({
              query: q,
              results: [],
              refinement_chips: [],
              resolved_aliases: [],
              total_candidates: 0,
              elapsed_micros: 0,
            })
          }
          return
        }
        throw new Error(`palette query failed (${response.status})`)
      }
      const payload = (await response.json()) as PaletteResponse
      // Drop stale responses so we never overwrite a newer successful one.
      if (seq === requestSeq.current) {
        setData(payload)
      }
    } catch (err) {
      if (seq === requestSeq.current) {
        setError(err instanceof Error ? err.message : String(err))
      }
    } finally {
      if (seq === requestSeq.current) {
        setLoading(false)
      }
    }
  }, [q, scope, filters])

  useEffect(() => {
    if (!enabled) {
      setData(null)
      setLoading(false)
      setError(null)
      return
    }
    const handle = window.setTimeout(() => {
      void issueQuery()
    }, debounceMs)
    return () => window.clearTimeout(handle)
    // We deliberately include filtersKey instead of the array reference so
    // referentially-fresh-but-shallow-equal filter arrays do not retrigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, scope, filtersKey, debounceMs, enabled])

  return { data, loading, error, refresh: issueQuery }
}

let paletteEndpointCache: boolean | null = null

/**
 * Probes GET /api once to see whether endpoints.palette is advertised.
 * Used to hide live search on self-hosted deployments without an index.
 */
export function usePaletteEndpointAvailable(): boolean {
  const [available, setAvailable] = useState(paletteEndpointCache ?? true)

  useEffect(() => {
    if (paletteEndpointCache !== null) {
      setAvailable(paletteEndpointCache)
      return
    }
    let cancelled = false
    void (async () => {
      try {
        const response = await fetch('/api')
        if (!response.ok) {
          paletteEndpointCache = false
        } else {
          const payload = (await response.json()) as { endpoints?: { palette?: string } }
          paletteEndpointCache = Boolean(payload.endpoints?.palette)
        }
      } catch {
        paletteEndpointCache = false
      }
      if (!cancelled) {
        setAvailable(paletteEndpointCache ?? false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  return available
}

// usePlatformShortcutLabel
export function usePlatformShortcutLabel(): string | null {
  const [label, setLabel] = useState<string | null>(null)

  useEffect(() => {
    const ua = navigator.userAgent || ''
    const isMac = /Mac OS X|Macintosh|iPhone|iPad|iPod/.test(ua)
    setLabel(isMac ? '\u2318 K' : 'Ctrl K')
  }, [])

  return label
}

// useRecentSearches
const RECENT_STORAGE_KEY = 'protocolsoup.palette.recent.v1'
const MAX_RECENT = 5

function readRecentFromStorage(): string[] {
  if (typeof window === 'undefined') return []
  try {
    const raw = window.localStorage.getItem(RECENT_STORAGE_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw) as unknown
    if (!Array.isArray(parsed)) return []
    return parsed.filter((v): v is string => typeof v === 'string').slice(0, MAX_RECENT)
  } catch {
    return []
  }
}

function writeRecentToStorage(next: string[]): void {
  if (typeof window === 'undefined') return
  try {
    window.localStorage.setItem(RECENT_STORAGE_KEY, JSON.stringify(next))
  } catch {
    // Quota exceeded, private mode, or storage disabled — drop the write.
  }
}

export interface UseRecentSearchesResult {
  recent: string[]
  push: (query: string) => void
  clear: () => void
}

/**
 * localStorage-backed recent palette queries for the empty state.
 */
export function useRecentSearches(): UseRecentSearchesResult {
  const [recent, setRecent] = useState<string[]>([])

  useEffect(() => {
    setRecent(readRecentFromStorage())

    function onStorage(event: StorageEvent) {
      if (event.key !== RECENT_STORAGE_KEY) return
      setRecent(readRecentFromStorage())
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  const push = useCallback((query: string) => {
    const normalized = query.trim()
    if (normalized.length === 0) return
    setRecent((prev) => {
      const without = prev.filter((entry) => entry !== normalized)
      const next = [normalized, ...without].slice(0, MAX_RECENT)
      writeRecentToStorage(next)
      return next
    })
  }, [])

  const clear = useCallback(() => {
    writeRecentToStorage([])
    setRecent([])
  }, [])

  return { recent, push, clear }
}
