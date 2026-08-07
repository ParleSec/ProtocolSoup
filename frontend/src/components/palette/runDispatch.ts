/**
 * Helpers that translate a palette flow result into the existing Looking
 * Glass dispatch path. We reuse `/api/protocols/{id}/demo/{flow}` followed
 * by a navigation to the Looking Glass page with the flow pre-selected;
 * the Looking Glass page wires the rest of the dispatch.
 *
 * The Looking Glass deep-link contract starts with `?protocol=X&flow=Y`.
 * Flow-specific selectors may add optional parameters; Client Credentials
 * uses `client_auth` and `token_mode` so shared demonstrations reproduce
 * both independent choices. The
 * backend's runURLFor (backend/internal/palette/rank.go) emits exactly
 * this shape on PaletteResult.run_url. Both the palette handoff and the
 * `/looking-glass` page parse it through `parseFlowDeepLink` below so the
 * contract has a single source of truth on the frontend.
 */

import type { PaletteResult } from './types'

export interface FlowDeepLink {
  protocolId: string
  flowId: string
  /** Optional Client Credentials authentication selection. */
  clientAuth?: 'client_secret_basic' | 'private_key_jwt'
  /** Optional Client Credentials access-token protection selection. */
  accessTokenMode?: 'bearer' | 'dpop'
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
 * parseFlowDeepLink reads the required `?protocol=X&flow=Y` pair plus
 * recognized optional flow configuration. Unknown selector values are
 * ignored so a malformed optional parameter cannot create an unsupported
 * executor configuration.
 */
export function parseFlowDeepLink(params: ReadableSearchParams): FlowDeepLink | null {
  const protocolId = (params.get('protocol') ?? '').trim()
  const flowId = (params.get('flow') ?? '').trim()
  if (!protocolId || !flowId) {
    return null
  }
  const clientAuthValue = (params.get('client_auth') ?? '').trim()
  const tokenModeValue = (params.get('token_mode') ?? '').trim()
  const clientAuth = clientAuthValue === 'client_secret_basic' || clientAuthValue === 'private_key_jwt'
    ? clientAuthValue
    : undefined
  const accessTokenMode = tokenModeValue === 'bearer' || tokenModeValue === 'dpop'
    ? tokenModeValue
    : undefined
  return { protocolId, flowId, clientAuth, accessTokenMode }
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
 * flow selection and any recognized reproducibility options. Exported so
 * callers that already have the selection can produce a consistent URL.
 */
export function buildLookingGlassPath({
  protocolId,
  flowId,
  clientAuth,
  accessTokenMode,
}: FlowDeepLink): string {
  const params = new URLSearchParams({ protocol: protocolId, flow: flowId })
  if (clientAuth) {
    params.set('client_auth', clientAuth)
  }
  if (accessTokenMode) {
    params.set('token_mode', accessTokenMode)
  }
  return `/looking-glass?${params.toString()}`
}

/**
 * buildFlowExecutionPath returns the URL that opens a runnable flow in the
 * correct execution surface. SSF flows use the dedicated sandbox; all other
 * protocols deep-link into Looking Glass with the flow pre-selected.
 */
export function buildFlowExecutionPath({ protocolId, flowId }: FlowDeepLink): string {
  if (protocolId === 'ssf') {
    return '/ssf-sandbox'
  }
  return buildLookingGlassPath({ protocolId, flowId })
}
