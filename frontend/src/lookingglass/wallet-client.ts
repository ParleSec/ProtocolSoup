/**
 * Shared Looking Glass helpers for the hosted wallet harness.
 *
 * OID4VP already posts to the wallet `/submit` surface; OID4VCI pre-authorized
 * flows reuse the same origin for `/api/import` / `/api/issue` so Looking Glass
 * orchestrates and observes while the wallet performs token/proof/credential work.
 */

/**
 * Wallet harness base used for Looking Glass / OID4VP browser calls.
 *
 * Prefer the same-origin `/wallet-harness` Next rewrite so protocol errors are
 * not turned into opaque CORS "Failed to fetch" when the wallet edge rewrites
 * a 502 without Access-Control-Allow-Origin. Path-relative keeps SSR and client
 * evaluation identical.
 */
export function getWalletBaseURL(): string {
  return '/wallet-harness'
}

export function walletAPIURL(path: string): string {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`
  return `${getWalletBaseURL()}${normalizedPath}`
}

export type WalletAPIErrorFields = {
  error?: string
  error_description?: string
  tx_code_required?: boolean
  tx_code_description?: string
  tx_code_length?: number
  tx_code_input_mode?: string
  [key: string]: unknown
}

export function describeWalletAPIError(
  responsePayload: Record<string, unknown> | null,
  fallback: string,
): string {
  const payload = (responsePayload || {}) as WalletAPIErrorFields
  let message = String(payload.error_description || payload.error || fallback).trim() || fallback
  if (payload.tx_code_required) {
    const hints = [
      String(payload.tx_code_description || '').trim(),
      payload.tx_code_length ? `Length: ${String(payload.tx_code_length)}` : '',
      String(payload.tx_code_input_mode || '').trim()
        ? `Input mode: ${String(payload.tx_code_input_mode).trim()}`
        : '',
    ].filter(Boolean)
    if (hints.length > 0) {
      message = `${message} (${hints.join(', ')})`
    }
  }
  return message
}

export type LookingGlassFailureExplanation = {
  title: string
  guidance: string
  specReference: string
}

export const LOOKING_GLASS_HAIP_ATTESTATION_GUIDANCE =
  'HAIP key-attested issuance configurations require client attestation and key attestation (HAIP 1.0 Sections 4.4.1 and 4.5.1; OID4VCI 1.0 Appendix D/E). Looking Glass still executes the real protocol: without WALLET_CLIENT_ATTESTATION_ATTESTER_JWK_JSON and WALLET_CLIENT_ATTESTATION_KEY_ATTESTATION_JWK_JSON (each with an x5c chain), wallet import returns HTTP 400. That rejection is the HAIP issuance gate, not a demo failure. Choose a non-HAIP profile to issue without attestation. OID4VP HAIP presentation (x509_hash) does not use these issuance configurations.'

export const LOOKING_GLASS_X509_HASH_GUIDANCE =
  'x509_hash is HAIP\'s signed-request Client Identifier Prefix (OpenID4VP 1.0 Section 5.9.3; HAIP 1.0 Section 5). The request object is a signed JWT; the wallet validates the x5c chain against its verifier trust store. Roots carried in x5c are never self-trusted. HAIP presentation also requires DCQL and an encrypted response (direct_post.jwt). Client and key attestation are OID4VCI issuance requirements and are not part of this presentation profile. The hosted Looking Glass wallet already trusts the showcase verifier CA via WALLET_VERIFIER_X509_TRUST_ANCHOR_PEM.'

export const LOOKING_GLASS_X509_HASH_COERCION_GUIDANCE =
  'This unencrypted direct_post flow is coerced to encrypted direct_post.jwt when x509_hash is selected, because HAIP 1.0 Section 5.1 requires response encryption.'

export function lookingGlassX509HashGuidance(coerceUnencryptedDirectPost = false): string {
  if (!coerceUnencryptedDirectPost) {
    return LOOKING_GLASS_X509_HASH_GUIDANCE
  }
  return `${LOOKING_GLASS_X509_HASH_GUIDANCE} ${LOOKING_GLASS_X509_HASH_COERCION_GUIDANCE}`
}

type LookingGlassFailureMatcher = {
  test: (normalized: string) => boolean
  title: string
  guidance: string
  specReference: string
}

const LOOKING_GLASS_FAILURE_MATCHERS: LookingGlassFailureMatcher[] = [
  {
    test: (normalized) =>
      normalized.includes('requires haip attestation') ||
      normalized.includes('haip attestation material') ||
      (normalized.includes('key_attestation') && normalized.includes('required')),
    title: 'HAIP issuance needs wallet attestation',
    guidance: LOOKING_GLASS_HAIP_ATTESTATION_GUIDANCE,
    specReference: 'HAIP 1.0 Sections 4.4.1 and 4.5.1; OID4VCI 1.0 Appendix D',
  },
  {
    test: (normalized) =>
      normalized.includes('unknown authority') ||
      normalized.includes('certificate is not trusted') ||
      normalized.includes('validate request object x5c') ||
      normalized.includes('wallet_verifier_x509_trust_anchor_pem') ||
      normalized.includes('x5c chain'),
    title: 'Wallet does not trust this verifier certificate',
    guidance: LOOKING_GLASS_X509_HASH_GUIDANCE,
    specReference: 'HAIP 1.0 Section 5; RFC 5280',
  },
  {
    test: (normalized) =>
      normalized.includes('mso_mdoc iaca') || normalized.includes('no configured mso_mdoc'),
    title: 'Wallet has no mDL IACA trust anchor',
    guidance:
      'mso_mdoc credentials are verified against independently configured IACA roots, not against an x5chain carried in the credential. Set WALLET_MDOC_IACA_ROOT_PEM (or the showcase IACA copy used by CI) before presenting an mDL.',
    specReference: 'ISO/IEC 18013-5',
  },
  {
    test: (normalized) =>
      normalized.includes('haip') &&
      (normalized.includes('dcql') ||
        normalized.includes('scope') ||
        normalized.includes('direct_post') ||
        normalized.includes('profile')),
    title: 'HAIP rejects this request shape',
    guidance: LOOKING_GLASS_X509_HASH_GUIDANCE,
    specReference: 'HAIP 1.0 Section 5; OpenID4VP 1.0',
  },
  {
    test: (normalized) =>
      normalized.includes('invalid_proof') ||
      (normalized.includes('proof') && normalized.includes('not supported')),
    title: 'Issuer rejected the credential proof',
    guidance:
      'invalid_proof means the openid4vci-proof+jwt failed issuer checks. Confirm the holder key algorithm is listed in proof_signing_alg_values_supported, c_nonce matches the latest nonce, and HAIP configurations include a key_attestation JOSE header.',
    specReference: 'OpenID4VCI 1.0 Section 8.2',
  },
  {
    test: (normalized) =>
      normalized.includes('tx_code') || normalized.includes('transaction code'),
    title: 'Transaction code required',
    guidance:
      'This offer includes tx_code (OpenID4VCI pre-authorized grant). Looking Glass pre-authorized+tx_code reads the issuer-returned out-of-band value automatically. If you imported the offer yourself, enter the same tx_code the issuer issued with the offer.',
    specReference: 'OpenID4VCI 1.0 Sections 4.1.1 and 6.1',
  },
  {
    test: (normalized) =>
      normalized.includes('does not map to active request') ||
      normalized.includes('state or request_id'),
    title: 'Encrypted response could not be correlated',
    guidance:
      'direct_post.jwt posts only the response JWE (OpenID4VP §8.3.1). The verifier correlates that JWE through the ECDH-ES key it advertised in client_metadata.jwks. Re-run request creation so the verifier provisions a fresh ephemeral encryption key, then submit again.',
    specReference: 'OpenID4VP 1.0 Section 8.3.1',
  },
  {
    test: (normalized) =>
      normalized.includes('does not have a credential that satisfies') ||
      (normalized.includes('credential format') && normalized.includes('mismatch')) ||
      normalized.includes('no matching credential'),
    title: 'Wallet credential does not match the DCQL query',
    guidance:
      'Select a VC credential profile whose format appears in the DCQL query (mso_mdoc or dc+sd-jwt), or paste a credential_jwt of that format. Looking Glass blocks one-click submit on a hard mismatch so the wallet is not asked to present the wrong evidence.',
    specReference: 'OpenID4VP 1.0; DCQL',
  },
  {
    test: (normalized) =>
      normalized.includes('unsupported media type') ||
      (normalized.includes('content-type') && normalized.includes('jwt')) ||
      normalized.includes('encrypted credential request'),
    title: 'Credential request encryption mismatch',
    guidance:
      'Encrypt the credential or deferred request only when the issuer requires it or the wallet included credential_response_encryption. A JSON body sent as application/jwt, or a JWE sent as application/json, is rejected as a real protocol error.',
    specReference: 'OpenID4VCI 1.0 Section 8.3',
  },
  {
    test: (normalized) =>
      normalized.includes('failed to fetch') ||
      normalized.includes('networkerror') ||
      normalized.includes('load failed') ||
      normalized.includes('network request failed'),
    title: 'Wallet harness is unreachable',
    guidance:
      'Looking Glass calls the wallet through the same-origin /wallet-harness rewrite. Failed to fetch usually means the wallet process is down, WALLET_BACKEND_ORIGIN is wrong, or an edge 502 lost CORS headers. Start the wallet and retry; this is not an OID4VCI/OID4VP protocol error.',
    specReference: 'Looking Glass wallet proxy',
  },
  {
    test: (normalized) =>
      normalized.includes('429') ||
      normalized.includes('too many requests') ||
      normalized.includes('rate limit'),
    title: 'Live rate limit',
    guidance:
      'The hosted environment rejected this run with HTTP 429. Wait and retry; this is the production limiter, not a protocol-validation failure.',
    specReference: 'HTTP 429',
  },
]

/**
 * Map a real protocol or transport error to Looking Glass guidance.
 * Returns null when the message should be shown as-is.
 */
export function explainLookingGlassFailure(message: string): LookingGlassFailureExplanation | null {
  const normalized = message.trim().toLowerCase()
  if (!normalized) {
    return null
  }
  for (const matcher of LOOKING_GLASS_FAILURE_MATCHERS) {
    if (matcher.test(normalized)) {
      return {
        title: matcher.title,
        guidance: matcher.guidance,
        specReference: matcher.specReference,
      }
    }
  }
  return null
}

export type WalletImportRequest = {
  offer?: string
  credential?: string
  tx_code?: string
  credential_format?: string
  credential_configuration_id?: string
  wallet_subject?: string
  looking_glass_session_id?: string
}

export type WalletImportResponse = {
  authorization_required?: boolean
  authorization_url?: string
  credential_jwt?: string
  credential_id?: string
  credential_format?: string
  credential_configuration_id?: string
  credential_source?: string
  credential_issuer?: string
  credential_offer?: Record<string, unknown>
  credential_offer_uri?: string
  credential_offer_transport?: string
  issuer_metadata?: Record<string, unknown>
  authorization_server_metadata?: Record<string, unknown>
  token_endpoint?: string
  credential_endpoint?: string
  nonce_endpoint?: string
  tx_code_required?: boolean
  tx_code_description?: string
  tx_code_length?: number
  tx_code_input_mode?: string
  wallet_subject?: string
  /** Real wallet→issuer HTTP hops for Looking Glass glass-box playback. */
  _protocol_exchanges?: WalletProtocolExchange[]
  _looking_glass_events?: Array<Record<string, unknown>>
  [key: string]: unknown
}

export type WalletProtocolExchange = {
  step?: string
  rfc_reference?: string
  method?: string
  url?: string
  request_headers?: Record<string, string>
  request_body?: unknown
  response_status?: number
  response_headers?: Record<string, string>
  response_body?: unknown
  duration_ms?: number
  actor?: string
  extra?: Record<string, unknown>
}

export type WalletIssueRequest = {
  force_issue?: boolean
  credential_format?: string
  credential_configuration_id?: string
  credential_id?: string
  wallet_subject?: string
  looking_glass_session_id?: string
}

export class WalletAPIRequestError extends Error {
  readonly status: number
  readonly payload: Record<string, unknown> | null

  constructor(message: string, status: number, payload: Record<string, unknown> | null) {
    super(message)
    this.name = 'WalletAPIRequestError'
    this.status = status
    this.payload = payload
  }
}

/**
 * POST JSON to the wallet harness and return the parsed body.
 * Throws WalletAPIRequestError with actionable protocol error text on non-2xx.
 */
export async function postWalletJSON<TResponse>(
  path: string,
  body: Record<string, unknown>,
  init?: { signal?: AbortSignal; headers?: Record<string, string> },
): Promise<{ response: Response; data: TResponse }> {
  const response = await fetch(walletAPIURL(path), {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...(init?.headers || {}),
    },
    body: JSON.stringify(body),
    signal: init?.signal,
  })
  const data = (await response.json().catch(() => null)) as TResponse | null
  if (!response.ok) {
    const payload = data && typeof data === 'object' ? (data as Record<string, unknown>) : null
    throw new WalletAPIRequestError(
      describeWalletAPIError(payload, `Wallet request failed (${response.status})`),
      response.status,
      payload,
    )
  }
  return { response, data: (data || {}) as TResponse }
}

export async function walletImportOffer(
  request: WalletImportRequest,
  init?: { signal?: AbortSignal; headers?: Record<string, string> },
): Promise<WalletImportResponse> {
  const { data } = await postWalletJSON<WalletImportResponse>('/api/import', { ...request }, init)
  return data
}

export async function walletIssueCredential(
  request: WalletIssueRequest,
  init?: { signal?: AbortSignal; headers?: Record<string, string> },
): Promise<WalletImportResponse> {
  const { data } = await postWalletJSON<WalletImportResponse>('/api/issue', { ...request }, init)
  return data
}
