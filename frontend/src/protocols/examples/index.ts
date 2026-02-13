/**
 * Code Examples Barrel
 *
 * Merges per-protocol example maps into a single flat lookup
 * keyed by the backend flow ID that FlowDetail.tsx receives.
 */

import { OAUTH2_EXAMPLES } from './oauth2'
import { OIDC_EXAMPLES } from './oidc'
import { SAML_EXAMPLES } from './saml'
import { SPIFFE_EXAMPLES } from './spiffe'
import { SCIM_EXAMPLES } from './scim'
import { SSF_EXAMPLES } from './ssf'

export interface CodeExample {
  /** Syntax-highlighting language hint */
  language: 'javascript' | 'go' | 'http' | 'xml' | 'python' | 'typescript'
  /** Human-readable label shown in the UI, e.g. "Go (Server)" */
  label: string
  /** The code string rendered in the <pre> block */
  code: string
}

/** Unified map of backend-flow-id → code example */
export const CODE_EXAMPLES: Record<string, CodeExample> = {
  ...OAUTH2_EXAMPLES,
  ...OIDC_EXAMPLES,
  ...SAML_EXAMPLES,
  ...SPIFFE_EXAMPLES,
  ...SCIM_EXAMPLES,
  ...SSF_EXAMPLES,

  /* Fallback shown when a flow has no dedicated example */
  _default: {
    language: 'javascript',
    label: 'JavaScript',
    code: `// No dedicated example for this flow yet.
// Use the Looking Glass to run the flow and inspect real traffic.`,
  },
}
