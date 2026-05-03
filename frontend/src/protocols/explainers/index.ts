/**
 * Parameter Explainer Registry — types + barrel + lookup
 *
 * Per-parameter educational metadata: what the parameter is for, the
 * concrete attacks against it, and the mitigations that address each
 * attack. Surfaced inline in FlowDetail via <ParameterExplainer>.
 *
 * Schema:
 *   purpose      — what the parameter is, briefly
 *   attacks      — list of named attacks; each has scenario + impact
 *   mitigations  — list of defences; each names which attacks it addresses
 *   references   — optional spec / advisory links
 *   contexts     — optional per-flow-step augmentation (additional attacks
 *                  that only apply in specific contexts; contextual notes)
 *
 * Lookup:
 *   getParameterExplainer(protocolId, name, ctx) — returns base entry
 *   merged with any matching ContextOverrides. Tries `${protocolId}:${name}`
 *   first, then bare `name`.
 *
 * Adding a new protocol's entries:
 *   1. Create `<protocol>.ts` exporting `<PROTOCOL>_EXPLAINERS:
 *      Record<string, ParameterExplainer>`.
 *   2. Import it below and spread it into `EXPLAINERS`.
 *   3. Per-protocol overrides use the key form `${protocolId}:${name}`.
 */

import { OAUTH2_EXPLAINERS } from './oauth2'
import { OIDC_EXPLAINERS } from './oidc'
import { OID4VCI_EXPLAINERS } from './oid4vci'
import { OID4VP_EXPLAINERS } from './oid4vp'
import { SAML_EXPLAINERS } from './saml'
import { SPIFFE_EXPLAINERS } from './spiffe'
import { SCIM_EXPLAINERS } from './scim'
import { SSF_EXPLAINERS } from './ssf'

export interface ParameterReference {
  label: string
  href: string
}

export interface Attack {
  /** Stable identifier for cross-reference from Mitigations. */
  id: string
  /** Human-readable name shown in the UI. */
  name: string
  /** Narrative description of the attack. */
  scenario: string
  /** Worst-case outcome if this attack succeeds. */
  impact: string
}

export interface Mitigation {
  /** Concrete action to take. */
  action: string
  /** Optional one-liner explaining why. */
  rationale?: string
  /** Attack.id values this mitigation addresses (one mitigation may cover several). */
  mitigates: string[]
}

export type FlowDirection = 'request' | 'response' | 'redirect' | 'internal'

export interface ContextMatch {
  /** Flow id (e.g. 'authorization_code'). Omit to match any flow. */
  flowId?: string
  /** Step.order within the flow. Omit to match any step. */
  stepOrder?: number
  /** Step.type. Omit to match any direction. */
  direction?: FlowDirection
}

export interface ContextOverride {
  matches: ContextMatch
  /** Attacks that only apply in this context (added to the base attacks). */
  additionalAttacks?: Attack[]
  /** Optional one-line note rendered alongside the parameter at this context. */
  contextualNote?: string
}

export interface ParameterExplainer {
  purpose: string
  attacks: Attack[]
  mitigations: Mitigation[]
  references?: ParameterReference[]
  contexts?: ContextOverride[]
}

/**
 * What `getParameterExplainer` returns: the base entry plus any
 * context-specific note resolved at lookup time. Authors never set
 * `contextualNote` directly on entries; it is populated from matching
 * ContextOverrides.
 */
export interface ResolvedParameterExplainer extends ParameterExplainer {
  contextualNote?: string
}

/** Context passed to lookup so contextual overrides can apply. */
export interface LookupContext {
  flowId?: string
  stepOrder?: number
  direction?: FlowDirection
}

const EXPLAINERS: Record<string, ParameterExplainer> = {
  ...OAUTH2_EXPLAINERS,
  ...OIDC_EXPLAINERS,
  ...OID4VCI_EXPLAINERS,
  ...OID4VP_EXPLAINERS,
  ...SAML_EXPLAINERS,
  ...SPIFFE_EXPLAINERS,
  ...SCIM_EXPLAINERS,
  ...SSF_EXPLAINERS,
}

function contextMatches(match: ContextMatch, ctx: LookupContext | undefined): boolean {
  if (!ctx) return false
  if (match.flowId !== undefined && match.flowId !== ctx.flowId) return false
  if (match.stepOrder !== undefined && match.stepOrder !== ctx.stepOrder) return false
  if (match.direction !== undefined && match.direction !== ctx.direction) return false
  return true
}

/**
 * Look up an explainer for a parameter. Tries protocol-scoped key first
 * (e.g. `oidc:nonce`), then falls back to the bare name. If a base entry
 * exists, any matching ContextOverrides are merged in:
 *   - additionalAttacks are appended to attacks[]
 *   - contextualNote (first matching) is attached
 */
export function getParameterExplainer(
  protocolId: string,
  name: string,
  ctx?: LookupContext,
): ResolvedParameterExplainer | undefined {
  const base = EXPLAINERS[`${protocolId}:${name}`] ?? EXPLAINERS[name]
  if (!base) return undefined
  if (!base.contexts || base.contexts.length === 0) return base

  const matched = base.contexts.filter((c) => contextMatches(c.matches, ctx))
  if (matched.length === 0) return base

  const additional = matched.flatMap((c) => c.additionalAttacks ?? [])
  const note = matched.find((c) => c.contextualNote)?.contextualNote

  return {
    ...base,
    attacks: additional.length > 0 ? [...base.attacks, ...additional] : base.attacks,
    contexts: undefined,
    contextualNote: note,
  }
}
