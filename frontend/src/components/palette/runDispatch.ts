/**
 * Helpers that translate a palette flow result into the existing Looking
 * Glass dispatch path. We reuse `/api/protocols/{id}/demo/{flow}` followed
 * by a navigation to the Looking Glass page with the flow pre-selected;
 * the Looking Glass page wires the rest of the dispatch.
 *
 * The Looking Glass deep-link contract is `?protocol=X&flow=Y`. The
 * backend's runURLFor (backend/internal/palette/rank.go) emits exactly
 * this shape on PaletteResult.run_url. Both the palette handoff and the
 * `/looking-glass` page parse it through `parseFlowDeepLink` below so the
 * contract has a single source of truth on the frontend.
 */

import type { PaletteResult } from './types'

export interface FlowDeepLink {
  protocolId: string
  flowId: string
}

export interface FlowRunHandoff extends FlowDeepLink {
  lookingGlassPath: string
}

/**
 * URLSearchParams-like surface. Next.js' `useSearchParams()` returns a
 * `ReadonlyURLSearchParams` which has the same `get` method as the
 * standard `URLSearchParams`, so we accept the lowest common shape and
 * stay agnostic of the call site.
 */
export interface ReadableSearchParams {
  get(name: string): string | null
}

/**
 * parseFlowDeepLink reads `?protocol=X&flow=Y` from a search-params
 * surface and returns the pair, or null when either parameter is missing
 * or empty. Trimming + empty-string rejection is centralised here so
 * callers don't accidentally treat `?protocol=&flow=` as a valid deep-link.
 */
export function parseFlowDeepLink(params: ReadableSearchParams): FlowDeepLink | null {
  const protocolId = (params.get('protocol') ?? '').trim()
  const flowId = (params.get('flow') ?? '').trim()
  if (!protocolId || !flowId) {
    return null
  }
  return { protocolId, flowId }
}

/**
 * resolveFlowHandoff extracts the (protocol, flow) pair the Looking Glass
 * page expects from a runnable palette result. Returns null when the result
 * is not runnable or lacks the metadata needed to dispatch.
 */
export function resolveFlowHandoff(result: PaletteResult): FlowRunHandoff | null {
  if (!result.runnable || result.type !== 'flow') {
    return null
  }
  if (!result.run_url) {
    return null
  }
  try {
    // run_url is /looking-glass?protocol=X&flow=Y on a same-origin path.
    const url = new URL(result.run_url, window.location.origin)
    const pair = parseFlowDeepLink(url.searchParams)
    if (!pair) {
      return null
    }
    return {
      ...pair,
      lookingGlassPath: buildLookingGlassPath(pair),
    }
  } catch {
    return null
  }
}

/**
 * buildLookingGlassPath constructs the canonical deep-link path for a
 * (protocol, flow) pair. Exported so callers that already have the pair
 * (e.g. tests, alternative entry points) can produce a consistent URL.
 */
export function buildLookingGlassPath({ protocolId, flowId }: FlowDeepLink): string {
  return `/looking-glass?protocol=${encodeURIComponent(protocolId)}&flow=${encodeURIComponent(flowId)}`
}
