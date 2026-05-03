/**
 * Parameter Explainer Registry — barrel + lookup
 *
 * Per-parameter educational metadata: what the parameter is for, what
 * breaks without it, the concrete attack it mitigates, and the impact
 * on the victim. Surfaced inline in FlowDetail via <ParameterExplainer>.
 *
 * The registry is split per-protocol (`oauth2.ts`, `oidc.ts`,
 * `oid4vci.ts`, …) and assembled here. Lookup is by parameter name; the
 * same explainer applies anywhere the name appears (e.g. `state` in
 * OAuth2, OIDC, OID4VP) unless a per-protocol override (`oidc:nonce`)
 * is registered.
 *
 * Adding a new protocol's entries:
 *   1. Create `<protocol>.ts` exporting `<PROTOCOL>_EXPLAINERS: Record<string, ParameterExplainer>`.
 *   2. Import it below and spread it into `EXPLAINERS`.
 *   3. Per-protocol overrides use the key form `${protocolId}:${name}` and live
 *      in that protocol's file.
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

export interface ParameterExplainer {
  /** What the parameter is and what it does (1–2 lines). */
  purpose: string
  /** What still works without it — and where the gap actually is. */
  withoutIt: string
  /** Named adversary, ordered steps of a concrete exploit. */
  attack: string
  /** Worst-case outcome for the victim. */
  impact: string
  /** Optional pointers to specs, threat models, CVEs, or write-ups. */
  references?: ParameterReference[]
}

/**
 * Merged registry. Spread order = priority on key collision: protocols
 * spread later override earlier ones. Currently used only for explicit
 * `protocol:name` override keys, not for replacing bare names.
 */
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

/**
 * Look up an explainer for a parameter. Tries protocol-scoped key first
 * (e.g. `oidc:nonce`), then falls back to the bare name.
 */
export function getParameterExplainer(
  protocolId: string,
  name: string,
): ParameterExplainer | undefined {
  return EXPLAINERS[`${protocolId}:${name}`] ?? EXPLAINERS[name]
}
