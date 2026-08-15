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
