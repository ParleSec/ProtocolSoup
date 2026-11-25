import 'server-only'

import { fetchBackendJSON } from '@/lib/protocols.server'
import type { WireCapturedExchange } from '@/lookingglass/types'
import { normalizeWireExchange } from '@/lookingglass/wire'

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
  question: string
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
  question: string
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
  question: string
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
  /** Example pages with a field that satisfies this requirement. */
  examples: ConformanceExampleLink[]
}

export interface ConformanceExampleLink {
  id: string
  title: string
  question: string
}

export interface ConformanceExampleSummary extends ConformanceExampleLink {
  summary: string
  format: 'jwt' | 'json' | 'sd-jwt'
  indexable: boolean
}

export interface ConformanceExamplesResponse {
  examples: ConformanceExampleSummary[]
}

/** A requirement a field satisfies; path is its requirement page. */
export interface ConformanceExampleRequirementLink extends ConformanceRequirementLink {
  path: string
}

/** One member of the message with the specification text that defines it. */
export interface ConformanceExampleField {
  /** Decoded part and member, such as `header.typ` or `payload.cnf.jkt`. */
  path: string
  reference: string
  url: string
  /** The specification's own text, verbatim. */
  statement: string
  note?: string
  requirements: ConformanceExampleRequirementLink[]
}

export interface ConformanceExampleMember {
  path: string
  /** The member's JSON text exactly as the sender wrote it. */
  value: string
}

export interface ConformanceExamplePart {
  name: string
  /** The decoded part, byte for byte. */
  json: string
  /** The same tokens with line breaks and indentation between them. */
  indented: string
  members: ConformanceExampleMember[]
  /** For a Disclosure: the digest the signed JWT carries for it in _sd. */
  digest?: string
}

export interface ConformanceExampleSource {
  exchange: number
  message: 'request' | 'response'
  location: string
}

export interface ConformanceExampleVerification {
  method: 'embedded_jwk' | 'jwks' | 'issuer' | 'jwt_vc_issuer_metadata'
  /** JWS alg of a signed value. */
  algorithm?: string
  key_id?: string
  jwks_exchange?: number
  /** For method issuer: the member that names the issuer, and its value. */
  issuer_member?: string
  issuer?: string
}

/**
 * GET /api/conformance/examples/{id}. The definition is always present; the
 * value and everything derived from it only when status is published.
 */
export interface ConformanceExampleResponse extends ConformanceExampleSummary {
  /** Absent for a message no Looking Glass flow produces. */
  run_url?: string
  fields: ConformanceExampleField[]
  status: 'published' | 'pending' | 'not_captured'
  commit?: string
  captured_at?: string
  publish_after?: string
  actor?: ConformanceArtefactActor
  description?: string
  value?: string
  issued_at?: string
  parts?: ConformanceExamplePart[]
  source?: ConformanceExampleSource
  verification?: ConformanceExampleVerification
  exchanges?: WireCapturedExchange[]
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

/** Who sent an artefact's requests: never the hosted wallet for malformed ones. */
export type ConformanceArtefactActor = 'conformance_client' | 'hosted_wallet' | 'counterparty'

export type ConformanceArtefactOutcome = 'accepted' | 'rejected'

export type ConformanceArtefactKind = 'passing' | 'failing'

/** One scenario captured from the deployed server, every exchange in full. */
export interface ConformanceArtefact {
  scenario: string
  actor: ConformanceArtefactActor
  description: string
  expected_outcome: ConformanceArtefactOutcome
  outcome: ConformanceArtefactOutcome
  exchanges: WireCapturedExchange[]
}

/**
 * GET /api/conformance/requirements/{id}/artefacts. pending means captured
 * but withheld until every token, code and nonce in it has expired.
 */
export interface ConformanceRequirementArtefacts {
  id: string
  status: 'published' | 'pending' | 'not_captured'
  commit?: string
  captured_at?: string
  publish_after?: string
  source_base_url?: string
  passing?: ConformanceArtefact
  /** One artefact per way the requirement was broken and refused. */
  failing?: ConformanceArtefact[]
  unavailable?: Partial<Record<ConformanceArtefactKind, string>>
}

type RawArtefact = Omit<ConformanceArtefact, 'exchanges'> & { exchanges?: unknown[] }
type RawRequirementArtefacts = Omit<ConformanceRequirementArtefacts, 'passing' | 'failing'> & {
  passing?: RawArtefact
  failing?: RawArtefact[]
}

function normalizeArtefact(raw?: RawArtefact): ConformanceArtefact | undefined {
  if (!raw) return undefined
  const exchanges = (raw.exchanges ?? [])
    .map((exchange) => normalizeWireExchange(exchange))
    .filter((exchange): exchange is WireCapturedExchange => exchange !== null)
  return { ...raw, exchanges }
}

export async function getConformanceRequirementArtefacts(id: string): Promise<ConformanceRequirementArtefacts> {
  const raw = await fetchBackendJSON<RawRequirementArtefacts>(
    `/api/conformance/requirements/${encodeURIComponent(id)}/artefacts`,
    REVALIDATE_SECONDS,
  )
  return {
    ...raw,
    passing: normalizeArtefact(raw.passing),
    failing: (raw.failing ?? [])
      .map((artefact) => normalizeArtefact(artefact))
      .filter((artefact): artefact is ConformanceArtefact => artefact !== undefined),
  }
}

export function getConformanceExamples(): Promise<ConformanceExamplesResponse> {
  return fetchBackendJSON<ConformanceExamplesResponse>('/api/conformance/examples', REVALIDATE_SECONDS)
}

export async function getConformanceExample(id: string): Promise<ConformanceExampleResponse> {
  const raw = await fetchBackendJSON<Omit<ConformanceExampleResponse, 'exchanges'> & { exchanges?: unknown[] }>(
    `/api/conformance/examples/${encodeURIComponent(id)}`,
    REVALIDATE_SECONDS,
  )
  return {
    ...raw,
    exchanges: raw.exchanges
      ?.map((exchange) => normalizeWireExchange(exchange))
      .filter((exchange): exchange is WireCapturedExchange => exchange !== null),
  }
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

export function examplePath(exampleId: string): string {
  return `/example/${exampleId}`
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
