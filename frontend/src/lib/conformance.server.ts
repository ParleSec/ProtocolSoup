import 'server-only'

import { fetchBackendJSON } from '@/lib/protocols.server'

/**
 * Server-side access to the normative requirement catalogue served by the
 * backend at /api/conformance. Shapes mirror openapi/v1/gateway.yaml
 * (Conformance tag). Verdict, commit and source fields are absent whenever
 * the backend's loaded report does not describe the running build.
 */

const REVALIDATE_SECONDS = 300

export type ConformanceVerdict = 'PASS' | 'FAIL' | 'CHECK' | 'MISSING_TEST' | 'N/A' | 'DEVIATION'

export interface ConformanceSpecSummary {
  id: string
  short_title: string
  title: string
  version: string
  url: string
  requirement_count: number
  verdicts?: Partial<Record<ConformanceVerdict, number>>
  indexable: boolean
}

export interface ConformanceSpecsResponse {
  report_valid: boolean
  launch_gate_open: boolean
  commit?: string
  generated_at?: string
  specs: ConformanceSpecSummary[]
}

export interface ConformanceRequirementRow {
  id: string
  title: string
  section: string
  level: string
  roles: string[]
  verdict?: ConformanceVerdict
  indexable: boolean
}

export interface ConformanceSpecResponse extends ConformanceSpecSummary {
  report_valid: boolean
  launch_gate_open: boolean
  commit?: string
  generated_at?: string
  requirements: ConformanceRequirementRow[]
}

export interface ConformanceRequirementLink {
  id: string
  title: string
}

export interface ConformanceTestEvidence {
  package: string
  name: string
  file: string
  line?: number
  verdict?: ConformanceVerdict
}

export interface ConformanceRequirementResponse {
  id: string
  specification: ConformanceSpecSummary
  section: string
  section_url: string
  level: string
  title: string
  statement: string
  roles: string[]
  applicability: 'applicable' | 'not_applicable' | 'deviation'
  verdict?: ConformanceVerdict
  commit?: string
  generated_at?: string
  source_base_url?: string
  tests: ConformanceTestEvidence[]
  implementation: string[]
  adr?: string
  notes?: string
  explainer_markdown?: string
  indexable: boolean
  siblings: ConformanceRequirementLink[]
  previous?: ConformanceRequirementLink
  next?: ConformanceRequirementLink
}

export interface ConformanceSitemapEntry {
  path: string
  lastmod: string
}

export function getConformanceSpecs(): Promise<ConformanceSpecsResponse> {
  return fetchBackendJSON<ConformanceSpecsResponse>('/api/conformance/specs', REVALIDATE_SECONDS)
}

export function getConformanceSpec(specId: string): Promise<ConformanceSpecResponse> {
  return fetchBackendJSON<ConformanceSpecResponse>(
    `/api/conformance/specs/${encodeURIComponent(specId)}`,
    REVALIDATE_SECONDS,
  )
}

export function getConformanceRequirement(id: string): Promise<ConformanceRequirementResponse> {
  return fetchBackendJSON<ConformanceRequirementResponse>(
    `/api/conformance/requirements/${encodeURIComponent(id)}`,
    REVALIDATE_SECONDS,
  )
}

export function getConformanceSitemap(): Promise<ConformanceSitemapEntry[]> {
  return fetchBackendJSON<ConformanceSitemapEntry[]>('/api/conformance/sitemap', REVALIDATE_SECONDS)
}

/**
 * Spec summaries for a protocol page's "Normative requirements" list, in the
 * order the catalog entry lists them. Returns an empty list when the backend
 * is unreachable so the protocol page still renders.
 */
export async function getSpecSummariesFor(specIds: readonly string[]): Promise<ConformanceSpecSummary[]> {
  if (specIds.length === 0) {
    return []
  }
  let response: ConformanceSpecsResponse
  try {
    response = await getConformanceSpecs()
  } catch {
    return []
  }
  const byId = new Map(response.specs.map((spec) => [spec.id, spec]))
  return specIds.flatMap((id) => {
    const spec = byId.get(id)
    return spec ? [spec] : []
  })
}

/** Canonical page paths. Requirement IDs are lowercase in URLs. */
export function specPath(specId: string): string {
  return `/spec/${specId}`
}

export function requirementPath(specId: string, requirementId: string): string {
  return `/spec/${specId}/${requirementId.toLowerCase()}`
}

/** Truncates at a word boundary so meta descriptions never cut mid-word. */
export function truncateDescription(text: string, max = 155): string {
  const collapsed = text.replace(/\s+/g, ' ').trim()
  if (collapsed.length <= max) {
    return collapsed
  }
  const cut = collapsed.slice(0, max)
  const boundary = cut.lastIndexOf(' ')
  return `${(boundary > 0 ? cut.slice(0, boundary) : cut).replace(/[,;:.]+$/, '')}…`
}
