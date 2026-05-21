/**
 * paletteUrlState — serialise and parse homepage palette state in the URL.
 *
 * Homepage-only persistence keeps shareable searches (`/?q=pkce&scope=concept`)
 * without mutating unrelated pages when the cmd+K modal is used elsewhere.
 */

import type { PaletteAxis, PaletteFilter, PaletteScope } from './types'

export const VALID_AXES: ReadonlySet<PaletteAxis> = new Set<PaletteAxis>([
  'use_cases',
  'actors',
  'patterns',
  'problem_domains',
])

export const VALID_SCOPES: ReadonlySet<PaletteScope> = new Set<PaletteScope>([
  'flow',
  'protocol',
  'concept',
  'spec',
])

export interface PaletteUrlState {
  q: string
  scope?: PaletteScope
  filters: PaletteFilter[]
}

export interface ReadableSearchParams {
  get(name: string): string | null
  getAll(name: string): string[]
}

export function parsePaletteUrlState(params: ReadableSearchParams): PaletteUrlState {
  const q = params.get('q') ?? ''
  const scopeRaw = params.get('scope') as PaletteScope | null
  const scope = scopeRaw && VALID_SCOPES.has(scopeRaw) ? scopeRaw : undefined
  const filters: PaletteFilter[] = []
  for (const raw of params.getAll('filter')) {
    const idx = raw.indexOf(':')
    if (idx <= 0) continue
    const axis = raw.slice(0, idx) as PaletteAxis
    const value = raw.slice(idx + 1)
    if (!VALID_AXES.has(axis) || !value) continue
    filters.push({ axis, value })
  }
  return { q, scope, filters }
}

export function buildPaletteSearchParams(state: PaletteUrlState): URLSearchParams {
  const params = new URLSearchParams()
  if (state.q.trim().length > 0) params.set('q', state.q)
  if (state.scope) params.set('scope', state.scope)
  for (const f of state.filters) {
    params.append('filter', `${f.axis}:${f.value}`)
  }
  return params
}

export function buildPalettePathname(
  pathname: string,
  state: PaletteUrlState,
): string {
  const queryString = buildPaletteSearchParams(state).toString()
  return queryString ? `${pathname}?${queryString}` : pathname
}

/**
 * Returns true when the resolved alias points at a concrete search target
 * the palette can re-issue as a query string.
 */
export function aliasSearchTarget(alias: {
  value?: string
  artefact?: string
  matched_token?: string
}): string | null {
  const target = (alias.value || alias.artefact || alias.matched_token || '').trim()
  return target.length > 0 ? target : null
}
