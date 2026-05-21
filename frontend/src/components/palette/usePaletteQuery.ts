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
