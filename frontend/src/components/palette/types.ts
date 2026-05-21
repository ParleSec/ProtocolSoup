/**
 * Shared TypeScript types for the ProtocolSoup palette.
 *
 * Mirrors the JSON shapes produced by the backend at POST /api/palette/query.
 * Keep field names in sync with backend/internal/palette/query.go.
 */

export type PaletteArtefactType =
  | 'protocol'
  | 'flow'
  | 'concept'
  | 'walkthrough'
  | 'spec-assertion'

export type PaletteAxis =
  | 'use_cases'
  | 'actors'
  | 'patterns'
  | 'problem_domains'

export type PaletteScope = 'flow' | 'protocol' | 'spec' | 'concept'

export interface PaletteFilter {
  axis: PaletteAxis
  value: string
}

export interface PaletteRequest {
  q: string
  scope?: PaletteScope
  filters?: PaletteFilter[]
  limit?: number
}

export interface PaletteAxisChip {
  axis: PaletteAxis
  value: string
}

export type PaletteMatchReasonKind =
  | 'axis'
  | 'alias'
  | 'fts'
  | 'edge'
  | 'runnable'
  | 'protocol-name'

export interface PaletteMatchReason {
  kind: PaletteMatchReasonKind
  axis?: PaletteAxis
  value?: string
  artefact?: string
  matched_token?: string
  matched_phrase?: string
  edge_kind?: string
  weight: number
}

export interface PaletteNormativeAnchor {
  rfc: string
  sections: string[]
}

export interface PaletteSpecAssertionDetails {
  normative_level: 'MUST' | 'SHOULD' | 'MAY' | 'MUST NOT' | 'SHOULD NOT'
  assertion_text: string
  anchors: PaletteNormativeAnchor[]
}

export interface PaletteResult {
  id: string
  type: PaletteArtefactType
  name: string
  summary?: string
  protocol?: string
  axis_chips: PaletteAxisChip[]
  match_reasons: PaletteMatchReason[]
  runnable: boolean
  href: string
  run_url?: string
  score: number
  status?: string

  // Plain-text first paragraph of the artefact body. Always safe to render
  // as text. Used for the always-visible row summary.
  body_preview?: string

  // Full markdown body of the artefact. Used when the row is expanded so
  // the user can read the answer inline without navigating away.
  body?: string

  // Query-aware excerpt of the body with matching tokens wrapped in
  // `<mark>` tags. Empty when no body region matched the query.
  snippet?: string

  // RFC / spec anchors attached to the artefact frontmatter. Mirrored
  // onto each result so the frontend can render anchor chips without a
  // catalog lookup.
  normative_anchors?: PaletteNormativeAnchor[]

  // related_concepts list as artefact ids. The frontend resolves names
  // via follow-up navigation; not all ids in this list are guaranteed
  // to be in the current result set.
  related_concepts?: string[]

  spec_assertion?: PaletteSpecAssertionDetails
}

export interface PaletteRefinementChip {
  axis: PaletteAxis
  value: string
  count: number
}

export interface PaletteResolvedAlias {
  matched_token: string
  axis?: PaletteAxis
  value?: string
  artefact?: string
}

export interface PaletteResponse {
  query: string
  results: PaletteResult[]
  refinement_chips: PaletteRefinementChip[]
  resolved_aliases: PaletteResolvedAlias[]
  total_candidates: number
  elapsed_micros: number
}
