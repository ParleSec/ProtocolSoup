import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import {
  Wallet, Home, FileSearch, CreditCard, Eye, Send, CheckCircle2,
  QrCode, Search, Download, RefreshCw, Plus, RotateCw,
  X, ChevronDown, ShieldCheck, ShieldAlert,
  XCircle, Info, Camera, ArrowRight, Copy, ExternalLink, FileCode2,
} from 'lucide-react'
import { createWalletScanner } from './scanner'

type WalletView = 'home' | 'review' | 'credentials' | 'disclosure' | 'present' | 'result'
type WalletProtocolMode = 'idle' | 'oid4vci' | 'oid4vp'
type BannerLevel = 'info' | 'success' | 'error'

type CredentialSummary = {
  subject?: string
  expires_at?: string
  is_sd_jwt?: boolean
  format?: string
  vct?: string
  doctype?: string
  credential_types?: string[]
  disclosure_claims?: string[]
  disclosure_count?: number
  key_binding_jwt?: boolean
  claims?: Record<string, unknown>
}

type WalletCredentialEntry = {
  credential_id?: string
  credential_format?: string
  credential_configuration_id?: string
  vct?: string
  doctype?: string
  is_active?: boolean
  issued_at?: string
  updated_at?: string
  credential_summary?: CredentialSummary
}

type SessionPayload = {
  app_title?: string
  wallet_session_id?: string
  wallet_subject?: string
  wallet_scope?: string
  wallet_did_method?: string
  wallet_key_id?: string
  wallet_key_thumbprint?: string
  wallet_session_ttl_seconds?: number
  wallet_session_expires_in?: number
  credential_present?: boolean
  credential_jwt?: string
  credential_id?: string
  credential_format?: string
  credential_configuration_id?: string
  credential_source?: string
  credential_summary?: CredentialSummary
  credentials?: WalletCredentialEntry[]
}

type TrustPayload = {
  trusted_target?: boolean
  requires_external_approval?: boolean
  allow_external_verifiers?: boolean
  client_id_scheme?: string
  did_web?: Record<string, unknown>
  request_object_verification?: {
    verified?: boolean
    error?: string
    key_type?: string
  }
}

type CredentialMatchSummary = {
  query_type?: string
  matched?: boolean
  matched_credential_ids?: string[]
  matched_credential_count?: number
  recommended_credential_id?: string
  reasons?: string[]
}

type ResolveResponse = {
  request_id?: string
  request_uri?: string
  request?: string
  request_uri_source?: string
  response_mode?: string
  response_uri?: string
  client_id?: string
  state?: string
  nonce?: string
  scope?: string
  dcql_query?: unknown
  credential_matches?: CredentialMatchSummary
  request_header?: Record<string, unknown>
  request_payload?: Record<string, unknown>
  trust?: TrustPayload
  inferred_credential_format?: string
  inferred_credential_configuration_id?: string
}

type PreviewResponse = {
  mode?: string
  request_id?: string
  request_uri?: string
  response_mode?: string
  response_uri?: string
  wallet_subject?: string
  wallet_scope?: string
  credential_source?: string
  credential_matches?: CredentialMatchSummary
  credential_id?: string
  credential_format?: string
  credential_configuration_id?: string
  disclosure_claims?: string[]
  vp_token?: string
  vp_header?: Record<string, unknown>
  vp_payload?: Record<string, unknown>
  vp_document?: Record<string, unknown>
  vp_proof?: Record<string, unknown>
  request_header?: Record<string, unknown>
  request_payload?: Record<string, unknown>
  trust?: TrustPayload
}

type PresentResponse = {
  mode?: string
  request_id?: string
  request_uri?: string
  response_mode?: string
  response_uri?: string
  redirect_uri?: string
  wallet_subject?: string
  wallet_scope?: string
  credential_source?: string
  credential_matches?: CredentialMatchSummary
  credential_id?: string
  credential_format?: string
  credential_configuration_id?: string
  disclosure_claims?: string[]
  upstream_status?: number
  upstream_body?: Record<string, unknown>
  trust?: TrustPayload
}

type ImportResponse = SessionPayload & {
  authorization_required?: boolean
  authorization_url?: string
  configuration_selection_required?: boolean
  credential_configurations?: CredentialConfigurationSummary[]
  issuance_requirements?: IssuanceRequirements
  credential_offer?: Record<string, unknown>
  credential_offer_uri?: string
  credential_offer_transport?: string
  credential_issuer?: string
  issuer_metadata?: Record<string, unknown>
  authorization_server_metadata?: Record<string, unknown>
  token_endpoint?: string
  credential_endpoint?: string
  nonce_endpoint?: string
  tx_code_required?: boolean
  tx_code_description?: string
  tx_code_length?: number
  tx_code_input_mode?: string
  error?: string
  error_description?: string
}

type CredentialConfigurationSummary = {
  id?: string
  format?: string
  vct?: string
  doctype?: string
  cryptographic_binding_methods_supported?: string[]
  key_attestation_required?: boolean
  cryptographic_holder_binding?: boolean
  display?: unknown
}

type IssuanceRequirements = {
  par?: boolean
  dpop?: boolean
  client_attestation?: boolean
  key_attestation?: boolean
  cryptographic_holder_binding?: boolean
  credential_request_encryption?: boolean
  credential_response_encryption?: boolean
  format?: string
  vct?: string
  doctype?: string
}

type WalletInputKind = 'empty' | 'offer' | 'issuer' | 'credential' | 'resource' | 'presentation' | 'as_discovery' | 'unknown'

type ProtocolErrorState = {
  source: 'import' | 'issue' | 'resolve' | 'preview' | 'present' | 'session'
  error: string
  errorDescription: string
  txCodeRequired?: boolean
  txCodeDescription?: string
  txCodeLength?: number
  txCodeInputMode?: string
}

type IssuanceProgress =
  | ''
  | 'importing'
  | 'authorization_required'
  | 'issuing'
  | 'deferred'
  | 'validation_failed'
  | 'ready'

const VIEW_TABS: Array<{ id: WalletView; label: string; icon: typeof Home }> = [
  { id: 'home', label: 'Home', icon: Home },
  { id: 'review', label: 'Review', icon: FileSearch },
  { id: 'credentials', label: 'Credentials', icon: CreditCard },
  { id: 'disclosure', label: 'Disclosure', icon: Eye },
  { id: 'present', label: 'Present', icon: Send },
  { id: 'result', label: 'Result', icon: CheckCircle2 },
]

const OID4VCI_VIEW_IDS: WalletView[] = ['home', 'credentials']
const OID4VP_VIEW_IDS: WalletView[] = ['home', 'review', 'credentials', 'disclosure', 'present', 'result']
const IDLE_VIEW_IDS: WalletView[] = ['home', 'credentials']

function viewsForProtocolMode(mode: WalletProtocolMode): WalletView[] {
  if (mode === 'oid4vci') return OID4VCI_VIEW_IDS
  if (mode === 'oid4vp') return OID4VP_VIEW_IDS
  return IDLE_VIEW_IDS
}

function homeTabLabel(mode: WalletProtocolMode): string {
  if (mode === 'oid4vci') return 'Issue'
  if (mode === 'oid4vp') return 'Request'
  return 'Home'
}

const CLAIM_DESCRIPTIONS: Record<string, string> = {
  degree: 'University degree name',
  gpa: 'Grade point average',
  university: 'Issuing institution',
  graduation_year: 'Year of graduation',
  honors: 'Academic honors',
}

const ISSUE_FORMAT_OPTIONS: Array<{ format: string; configurationID: string; label: string }> = [
  { format: 'mso_mdoc', configurationID: 'MobileDrivingLicenceMsoMdoc', label: 'mso_mdoc (mDL)' },
  { format: 'dc+sd-jwt', configurationID: 'UniversityDegreeCredential', label: 'dc+sd-jwt' },
  { format: 'jwt_vc_json', configurationID: 'UniversityDegreeCredentialJWT', label: 'jwt_vc_json' },
  { format: 'jwt_vc_json-ld', configurationID: 'UniversityDegreeCredentialJWTLD', label: 'jwt_vc_json-ld' },
  { format: 'ldp_vc', configurationID: 'UniversityDegreeCredentialLDP', label: 'ldp_vc' },
  // HAIP configuration IDs are real issuer profiles; the wallet rejects them when attestation material is not loaded.
  { format: 'mso_mdoc', configurationID: 'MobileDrivingLicenceMsoMdocHAIP', label: 'mso_mdoc HAIP (attestation)' },
  { format: 'dc+sd-jwt', configurationID: 'UniversityDegreeCredentialSDJWTHAIP', label: 'dc+sd-jwt HAIP (attestation)' },
]

const viewTransition = {
  initial: { opacity: 0, y: 8 },
  animate: { opacity: 1, y: 0 },
  exit: { opacity: 0, y: -8 },
  transition: { duration: 0.15, ease: [0, 0, 0.2, 1] as const },
}

function formatJSON(value: unknown): string {
  if (value === undefined || value === null) return ''
  if (typeof value === 'string') return value
  try { return JSON.stringify(value, null, 2) } catch { return String(value) }
}

function toErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message
  return String(error || 'Unexpected error')
}

function normalizeAuthorizationRedirectTarget(rawURL: string): string {
  let parsedURL: URL
  try { parsedURL = new URL(String(rawURL || '').trim()) } catch { throw new Error('Issuer authorization URL is invalid') }
  if (parsedURL.protocol === 'https:') return parsedURL.toString()
  const isLocalHTTP = parsedURL.protocol === 'http:' && (parsedURL.hostname === 'localhost' || parsedURL.hostname === '127.0.0.1' || parsedURL.hostname === '::1')
  if (isLocalHTTP) return parsedURL.toString()
  throw new Error('Issuer authorization URL must use HTTPS')
}

function tryParseAbsoluteURL(rawURL: unknown): URL | null {
  try {
    const normalized = String(rawURL || '').trim()
    if (!normalized) return null
    return new URL(normalized)
  } catch { return null }
}

function resolveAuthorizationRedirectTarget(response: ImportResponse): string {
  const targetURL = new URL(normalizeAuthorizationRedirectTarget(String(response.authorization_url || '')))
  const authorizationEndpoint = tryParseAbsoluteURL(response.authorization_server_metadata?.authorization_endpoint)
  if (authorizationEndpoint) {
    if (targetURL.origin !== authorizationEndpoint.origin || targetURL.pathname !== authorizationEndpoint.pathname) {
      throw new Error('Issuer authorization URL does not match authorization server metadata')
    }
    return targetURL.toString()
  }
  const trustedOrigins = [
    tryParseAbsoluteURL(response.credential_issuer),
    tryParseAbsoluteURL(response.issuer_metadata?.credential_issuer),
    tryParseAbsoluteURL(response.authorization_server_metadata?.issuer),
    tryParseAbsoluteURL(response.authorization_server_metadata?.authorization_server),
  ].filter((value): value is URL => Boolean(value)).map((value) => value.origin)
  if (trustedOrigins.length > 0 && !trustedOrigins.includes(targetURL.origin)) {
    throw new Error('Issuer authorization URL origin does not match issuer metadata')
  }
  return targetURL.toString()
}

const OID4VCI_PENDING_STORAGE_KEY = 'protocolsoup.wallet.oid4vci.pending'
const OID4VCI_DISCOVERED_ISSUER_STORAGE_KEY = 'protocolsoup.wallet.oid4vci.discovered-issuer'
const OID4VCI_CALLBACK_MESSAGE_TYPE = 'protocolsoup.wallet.oid4vci.callback'

type PendingOID4VCIAuthorizationState = {
  authorizationURL: string
  uriInput: string
  importSnapshot: ImportResponse | null
  savedAt: number
}

type DiscoveredIssuerState = {
  snapshot: ImportResponse
  selectedConfigurationID: string
  savedAt: number
}

function savePendingOID4VCIAuthorization(state: PendingOID4VCIAuthorizationState): void {
  try {
    sessionStorage.setItem(OID4VCI_PENDING_STORAGE_KEY, JSON.stringify(state))
  } catch {
    // sessionStorage may be unavailable; authorize can still proceed.
  }
}

function loadPendingOID4VCIAuthorization(): PendingOID4VCIAuthorizationState | null {
  try {
    const raw = sessionStorage.getItem(OID4VCI_PENDING_STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as PendingOID4VCIAuthorizationState
    if (!parsed || typeof parsed !== 'object' || !String(parsed.authorizationURL || '').trim()) return null
    return parsed
  } catch {
    return null
  }
}

function clearPendingOID4VCIAuthorization(): void {
  try {
    sessionStorage.removeItem(OID4VCI_PENDING_STORAGE_KEY)
  } catch {
    // ignore
  }
}

function saveDiscoveredIssuerState(state: DiscoveredIssuerState): void {
  try {
    sessionStorage.setItem(OID4VCI_DISCOVERED_ISSUER_STORAGE_KEY, JSON.stringify(state))
  } catch {
    // sessionStorage may be unavailable; the in-tab picker still works.
  }
}

function loadDiscoveredIssuerState(): DiscoveredIssuerState | null {
  try {
    const raw = sessionStorage.getItem(OID4VCI_DISCOVERED_ISSUER_STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as DiscoveredIssuerState
    const configurations = parsed?.snapshot?.credential_configurations
    if (!parsed?.snapshot?.credential_issuer || !Array.isArray(configurations) || configurations.length === 0) {
      return null
    }
    return parsed
  } catch {
    return null
  }
}

function clearDiscoveredIssuerState(): void {
  try {
    sessionStorage.removeItem(OID4VCI_DISCOVERED_ISSUER_STORAGE_KEY)
  } catch {
    // ignore
  }
}

function openOID4VCIAuthorizationPopup(authorizationURL: string): Window | null {
  const width = Math.min(560, window.screen.availWidth || 560)
  const height = Math.min(720, window.screen.availHeight || 720)
  const left = Math.max(0, Math.floor(((window.screen.availWidth || width) - width) / 2))
  const top = Math.max(0, Math.floor(((window.screen.availHeight || height) - height) / 2))
  return window.open(
    authorizationURL,
    'protocolsoup_oid4vci_authorize',
    `popup=yes,width=${width},height=${height},left=${left},top=${top}`,
  )
}

function buildResolvePayloadFromInput(rawInput: string, extras?: { clientID?: string; requestURIMethod?: string }): Record<string, string> {
  const trimmed = rawInput.trim()
  if (!trimmed) throw new Error('Provide openid4vp URI or request_uri')
  const payload: Record<string, string> = {}
  if (trimmed.startsWith('openid4vp://')) payload.openid4vp_uri = trimmed
  else if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) payload.request_uri = trimmed
  else payload.request = trimmed
  if (extras?.clientID) payload.client_id = extras.clientID
  if (extras?.requestURIMethod) payload.request_uri_method = extras.requestURIMethod
  return payload
}

function tryParseJSONObject(rawInput: string): Record<string, unknown> | null {
  const trimmed = rawInput.trim()
  if (!trimmed.startsWith('{')) return null
  try {
    const parsed = JSON.parse(trimmed)
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed as Record<string, unknown>
  } catch { return null }
  return null
}

function looksLikeCompactJWT(rawInput: string): boolean {
  const trimmed = rawInput.trim()
  const parts = trimmed.split('.')
  return parts.length === 3 && parts.every((part) => /^[A-Za-z0-9_-]+$/.test(part))
}

function buildImportPayloadFromInput(rawInput: string, txCode: string): Record<string, string> {
  const trimmed = rawInput.trim()
  if (!trimmed) throw new Error('Provide a credential issuer URL, OID4VCI offer, raw VC JWT, or JSON-LD credential')
  const payload: Record<string, string> = {}
  if (looksLikeCredentialIssuerInput(trimmed)) {
    payload.credential_issuer = credentialIssuerFromInput(trimmed)
    return payload
  }
  if (looksLikeCredentialOfferInput(trimmed)) {
    payload.offer = trimmed
    if (txCode.trim()) payload.tx_code = txCode.trim()
    return payload
  }
  if (looksLikeRawCredentialInput(trimmed)) {
    payload.credential = trimmed
    return payload
  }
  throw new Error('Input is not a recognized credential issuer, OID4VCI offer, or verifiable credential')
}

function looksLikeProtectedResourceAuthInput(rawInput: string): boolean {
  try {
    return Boolean(parseProtectedResourceAuthInput(rawInput))
  } catch {
    return false
  }
}

function looksLikeASDiscoveryURL(value: string): boolean {
  const lower = value.toLowerCase()
  return lower.includes('oauth-authorization-server') || lower.includes('openid-configuration')
}

function looksLikeCredentialIssuerMetadataURL(value: string): boolean {
  return value.toLowerCase().includes('/.well-known/openid-credential-issuer')
}

function looksLikeCredentialIssuerInput(rawInput: string): boolean {
  const trimmed = rawInput.trim()
  if (!trimmed) return false
  if (looksLikeCredentialOfferInput(trimmed) || looksLikeProtectedResourceAuthInput(trimmed) || looksLikeRawCredentialInput(trimmed)) {
    return false
  }
  const parsedJSON = tryParseJSONObject(trimmed)
  if (parsedJSON) {
    return Boolean(parsedJSON.credential_issuer) && !parsedJSON.credential_configuration_ids && !parsedJSON.grants
  }
  if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) return false
  if (trimmed.includes('\n')) return false
  try {
    const parsed = new URL(trimmed.split(/\s/)[0])
    const path = parsed.pathname.toLowerCase()
    if (looksLikeCredentialIssuerMetadataURL(parsed.pathname)) return true
    if (looksLikeASDiscoveryURL(parsed.pathname)) return false
    if (parsed.searchParams.has('credential_offer') || parsed.searchParams.has('credential_offer_uri') || parsed.searchParams.has('request_uri') || parsed.searchParams.has('request')) {
      return false
    }
    if (path.includes('credential-offer') || path.includes('/authorize')) return false
    return parsed.search === ''
  } catch {
    return false
  }
}

function looksLikeASDiscoveryOnlyInput(rawInput: string): boolean {
  const trimmed = rawInput.trim()
  if (!trimmed || trimmed.includes('\n') || looksLikeProtectedResourceAuthInput(trimmed) || looksLikeCredentialOfferInput(trimmed)) return false
  if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) return false
  try {
    return looksLikeASDiscoveryURL(new URL(trimmed).pathname)
  } catch {
    return false
  }
}

function credentialIssuerFromInput(rawInput: string): string {
  const trimmed = rawInput.trim()
  const parsedJSON = tryParseJSONObject(trimmed)
  if (parsedJSON && parsedJSON.credential_issuer) return String(parsedJSON.credential_issuer)
  return trimmed
}

function classifyWalletInput(rawInput: string): { kind: WalletInputKind; label: string; detail: string } {
  const trimmed = rawInput.trim()
  if (!trimmed) {
    return { kind: 'empty', label: 'Waiting for input', detail: 'Paste a credential issuer URL, credential offer, presentation request, or issued credential.' }
  }
  if (looksLikeProtectedResourceAuthInput(trimmed)) {
    return { kind: 'resource', label: 'Protected resource', detail: 'Import will authorize with the AS, then GET this resource with DPoP.' }
  }
  if (looksLikeCredentialOfferInput(trimmed)) {
    return { kind: 'offer', label: 'Credential offer', detail: 'Import will redeem this offer with the credential issuer.' }
  }
  if (looksLikeCredentialIssuerInput(trimmed)) {
    return { kind: 'issuer', label: 'Credential issuer', detail: 'Import fetches issuer metadata so you can pick a credential configuration, then authorize.' }
  }
  if (looksLikeASDiscoveryOnlyInput(trimmed)) {
    return { kind: 'as_discovery', label: 'Authorization Server discovery', detail: 'This is not a credential issuer. For issuance, paste credential_issuer. For a protected resource, paste discovery URL plus resource URL.' }
  }
  if (looksLikeRawCredentialInput(trimmed)) {
    return { kind: 'credential', label: 'Issued credential', detail: 'Import will store this credential in the wallet session.' }
  }
  if (looksLikeOID4VPInput(trimmed) || trimmed.startsWith('openid4vp://')) {
    return { kind: 'presentation', label: 'Presentation request', detail: 'Use Resolve to review the verifier request and present.' }
  }
  return { kind: 'unknown', label: 'Unrecognized input', detail: 'Expected a credential issuer URL, offer, presentation request, or credential.' }
}

function issuanceRequirementChips(requirements?: IssuanceRequirements | null): string[] {
  if (!requirements) return []
  const chips: string[] = []
  if (requirements.par) chips.push('PAR')
  if (requirements.dpop) chips.push('DPoP')
  if (requirements.client_attestation) chips.push('Client attestation')
  if (requirements.key_attestation) chips.push('Key attestation')
  if (requirements.cryptographic_holder_binding) chips.push('Holder binding (cnf)')
  if (requirements.credential_request_encryption) chips.push('Request encryption')
  if (requirements.credential_response_encryption) chips.push('Response encryption')
  return chips
}

function parseProtectedResourceAuthInput(rawInput: string): { discovery_url: string; resource_endpoint: string; scope: string } | null {
  const trimmed = rawInput.trim()
  if (!trimmed) return null
  const parsedJSON = tryParseJSONObject(trimmed)
  if (parsedJSON) {
    const discovery = firstNonEmptyString(
      String(parsedJSON.discovery_url || ''),
      String(parsedJSON.discoveryUrl || ''),
    )
    const resource = firstNonEmptyString(
      String(parsedJSON.resource_endpoint || ''),
      String(parsedJSON.resourceEndpoint || ''),
      String(parsedJSON.accounts_endpoint || ''),
      String(parsedJSON.accountsEndpoint || ''),
    )
    const scope = firstNonEmptyString(String(parsedJSON.scope || '')) || (
      resource ? 'accounts' : ''
    )
    if (discovery && resource && scope && looksLikeASDiscoveryURL(discovery)) {
      return { discovery_url: discovery, resource_endpoint: resource, scope }
    }
    return null
  }
  const lines = trimmed.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
  if (lines.length < 2) return null
  let discovery = ''
  let resource = ''
  let scope = ''
  for (const line of lines) {
    const lower = line.toLowerCase()
    if (lower.startsWith('discovery') || looksLikeASDiscoveryURL(line)) {
      const next = line.replace(/^discovery(_url|Url)?\s*[:=]\s*/i, '').trim()
      if (!discovery || (next.includes('openid-configuration') && !discovery.includes('openid-configuration'))) {
        discovery = next
      }
      continue
    }
    if (lower.startsWith('resource') || lower.startsWith('accounts') || lower.includes('open-banking') || lower.includes('/accounts') || lower.includes('userinfo')) {
      const next = line.replace(/^(resource|accounts)(_endpoint|Endpoint)?\s*[:=]\s*/i, '').trim()
      if (next.startsWith('http')) {
        resource = next
      } else if (!scope && next && !next.includes('/')) {
        // Bare "accounts" is the OAuth scope, not a resource URL.
        scope = next
      }
      continue
    }
    if (lower.startsWith('scope')) {
      scope = line.replace(/^scope\s*[:=]\s*/i, '').trim()
      continue
    }
    if (!discovery && line.startsWith('http') && looksLikeASDiscoveryURL(line)) {
      discovery = line
      continue
    }
    if (!resource && line.startsWith('http') && (line.includes('/accounts') || line.includes('open-banking') || line.includes('userinfo'))) {
      resource = line
      continue
    }
    if (!scope && !line.startsWith('http')) {
      scope = line
    }
  }
  // VCI HAIP FAPI client modules use fapi_client_type=plain_oauth, which rejects
  // the openid scope — default to accounts only for Open Banking accounts URLs.
  if (discovery && resource && !scope) {
    scope = 'accounts'
  }
  if (discovery && resource && scope) {
    return { discovery_url: discovery, resource_endpoint: resource, scope }
  }
  return null
}

function looksLikeCredentialOfferInput(rawInput: string): boolean {
  const trimmed = rawInput.trim()
  if (!trimmed) return false
  if (trimmed.startsWith('openid-credential-offer://')) return true
  const parsedJSON = tryParseJSONObject(trimmed)
  if (parsedJSON) return Boolean(parsedJSON.credential_offer || parsedJSON.credential_offer_uri || (parsedJSON.credential_issuer && parsedJSON.credential_configuration_ids))
  if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) return false
  try {
    const parsed = new URL(trimmed)
    return parsed.searchParams.has('credential_offer') || parsed.searchParams.has('credential_offer_uri') || parsed.pathname.toLowerCase().includes('credential-offer')
  } catch { return false }
}

function looksLikeRawCredentialInput(rawInput: string): boolean {
  const trimmed = rawInput.trim()
  if (!trimmed || looksLikeCredentialOfferInput(trimmed)) return false
  if (looksLikeCompactJWT(trimmed)) return true
  const parsedJSON = tryParseJSONObject(trimmed)
  if (!parsedJSON) return false
  return Boolean(parsedJSON['@context'] || parsedJSON.credentialSubject || parsedJSON.proof || parsedJSON.issuer || parsedJSON.vc)
}

function looksLikeOID4VPInput(rawInput: string): boolean {
  const trimmed = rawInput.trim()
  if (!trimmed) return false
  if (trimmed.startsWith('openid4vp://')) return true
  if (looksLikeProtectedResourceAuthInput(trimmed) || looksLikeCredentialOfferInput(trimmed) || looksLikeRawCredentialInput(trimmed)) return false
  if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) return false
  try {
    const parsed = new URL(trimmed)
    if (parsed.searchParams.has('request_uri') || parsed.searchParams.has('request')) return true
    if (parsed.pathname.toLowerCase().includes('authorize')) return true
    return false
  } catch {
    return false
  }
}

function detectWalletProtocolMode(rawInput: string): WalletProtocolMode {
  const trimmed = rawInput.trim()
  if (!trimmed) return 'idle'
  if (looksLikeProtectedResourceAuthInput(trimmed) || looksLikeCredentialOfferInput(trimmed) || looksLikeRawCredentialInput(trimmed) || looksLikeCredentialIssuerInput(trimmed)) return 'oid4vci'
  if (looksLikeASDiscoveryOnlyInput(trimmed)) return 'idle'
  if (looksLikeOID4VPInput(trimmed) || trimmed.startsWith('openid4vp://')) return 'oid4vp'
  // Bare request JWTs / opaque request blobs go through OID4VP resolve.
  return 'oid4vp'
}

function normalizeClaims(rawClaims: unknown): string[] {
  if (!Array.isArray(rawClaims)) return []
  return rawClaims.map((claim) => String(claim).trim()).filter(Boolean)
}

function firstNonEmptyString(...values: Array<string | null | undefined>): string {
  for (const value of values) { if (String(value || '').trim()) return String(value).trim() }
  return ''
}

function mergeCredentialSession(previous: SessionPayload | null, response: SessionPayload): SessionPayload {
  return {
    ...(previous || {}),
    ...response,
    credential_present: true,
    credential_jwt: response.credential_jwt || previous?.credential_jwt,
    credential_summary: response.credential_summary || previous?.credential_summary,
    credential_id: response.credential_id || previous?.credential_id,
    credential_format: response.credential_format || previous?.credential_format,
    credential_configuration_id: response.credential_configuration_id || previous?.credential_configuration_id,
    credentials: response.credentials || previous?.credentials,
  }
}

type IssueFocus = 'input' | 'picker' | 'authorize' | 'request' | 'done'
type IssueStepID = 'input' | 'picker' | 'authorize' | 'offer' | 'request'

function IssueStep({
  title,
  summary,
  open,
  onToggle,
  tone = 'neutral',
  actions,
  children,
}: {
  title: string
  summary?: string
  open: boolean
  onToggle: () => void
  tone?: 'cyan' | 'amber' | 'neutral'
  actions?: React.ReactNode
  children: React.ReactNode
}) {
  const toneClass = tone === 'cyan'
    ? 'border-cyan-500/30 bg-cyan-500/5'
    : tone === 'amber'
      ? 'border-amber-500/30 bg-amber-500/5'
      : 'border-white/10 bg-surface-900/40'
  const titleClass = tone === 'cyan'
    ? 'text-cyan-200'
    : tone === 'amber'
      ? 'text-amber-300'
      : 'text-surface-200'
  return (
    <div className={`rounded-lg border overflow-hidden ${toneClass}`}>
      <div className="flex items-center gap-2 px-3 py-2">
        <button
          type="button"
          className="flex min-w-0 flex-1 items-center gap-2 text-left"
          onClick={onToggle}
          aria-expanded={open}
        >
          <span className={`text-xs sm:text-sm font-medium shrink-0 ${titleClass}`}>{title}</span>
          {!open && summary ? (
            <span className="min-w-0 truncate text-[11px] text-surface-500 font-mono">{summary}</span>
          ) : null}
          <ChevronDown className={`ml-auto w-3.5 h-3.5 shrink-0 text-surface-500 transition-transform duration-200 ${open ? 'rotate-180' : ''}`} />
        </button>
        {actions ? <div className="shrink-0 flex items-center gap-2">{actions}</div> : null}
      </div>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2, ease: 'easeInOut' }}
            className="overflow-hidden"
          >
            <div className="border-t border-white/10 px-3 py-3 space-y-3">
              {children}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function Expandable({ title, icon: Icon, defaultOpen, children }: { title: string; icon?: typeof FileCode2; defaultOpen?: boolean; children: React.ReactNode }) {
  const [open, setOpen] = useState(Boolean(defaultOpen))
  return (
    <div className="rounded-xl border border-white/10 bg-surface-900/50 overflow-hidden">
      <button
        type="button"
        className="flex w-full items-center gap-2.5 px-3 sm:px-4 py-2.5 sm:py-3 text-left text-xs sm:text-sm font-medium text-surface-300 hover:text-white transition-colors"
        onClick={() => setOpen((v) => !v)}
      >
        {Icon && <Icon className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-surface-500 shrink-0" />}
        <span className="flex-1">{title}</span>
        <ChevronDown className={`w-3.5 h-3.5 sm:w-4 sm:h-4 text-surface-500 transition-transform duration-200 ${open ? 'rotate-180' : ''}`} />
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2, ease: 'easeInOut' }}
            className="overflow-hidden"
          >
            <div className="border-t border-white/10 px-3 sm:px-4 py-3">
              <pre className="text-[11px] sm:text-xs leading-relaxed text-surface-400 whitespace-pre-wrap break-all overflow-x-auto font-mono">{children}</pre>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function MetricRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-baseline gap-2 py-1 text-[11px] sm:text-xs">
      <span className="text-surface-500 shrink-0">{label}</span>
      <span className={`text-surface-300 break-all ${mono ? 'font-mono' : ''}`}>{value}</span>
    </div>
  )
}

function ReviewField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-white/10 bg-surface-900/50 p-3">
      <div className="text-[10px] sm:text-[11px] font-medium uppercase tracking-wider text-surface-500 mb-1.5">{label}</div>
      <div className="text-xs sm:text-sm text-surface-300 break-all">{children}</div>
    </div>
  )
}

function SectionHeading({ icon: Icon, title, subtitle }: { icon: typeof Home; title: string; subtitle?: string }) {
  return (
    <div className="flex items-start gap-3 mb-1">
      <div className="rounded-lg bg-gradient-to-br from-cyan-500/15 to-purple-500/15 p-2 mt-0.5">
        <Icon className="w-4 h-4 text-cyan-400" />
      </div>
      <div className="min-w-0">
        <h2 className="text-sm font-semibold text-white">{title}</h2>
        {subtitle && <p className="text-[11px] text-surface-400 mt-0.5 leading-relaxed">{subtitle}</p>}
      </div>
    </div>
  )
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      className="btn-secondary !px-2 !py-1 !text-[10px]"
      onClick={() => { navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) }) }}
    >
      {copied ? <CheckCircle2 className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}

export default function WalletApp() {
  const scanner = useMemo(() => createWalletScanner(), [])
  const scannerViewportRef = useRef<HTMLDivElement | null>(null)
  const resolveInFlightRef = useRef(false)
  const importInFlightRef = useRef(false)
  const bootstrapOfferHandledRef = useRef(false)

  const [activeView, setActiveView] = useState<WalletView>('home')
  const [protocolMode, setProtocolMode] = useState<WalletProtocolMode>('idle')
  const [statusBanner, setStatusBanner] = useState<{ message: string; level: BannerLevel } | null>(null)
  const [session, setSession] = useState<SessionPayload | null>(null)
  const [walletSessionID, setWalletSessionID] = useState('')
  const [selectedCredentialID, setSelectedCredentialID] = useState('')
  const [selectedIssueFormat, setSelectedIssueFormat] = useState(ISSUE_FORMAT_OPTIONS[0]?.configurationID || 'MobileDrivingLicenceMsoMdoc')
  const [uriInput, setURIInput] = useState('')
  const [importTxCodeInput, setImportTxCodeInput] = useState('')
  const [resolved, setResolved] = useState<ResolveResponse | null>(null)
  const [preview, setPreview] = useState<PreviewResponse | null>(null)
  const [result, setResult] = useState<PresentResponse | null>(null)
  const [lastImport, setLastImport] = useState<ImportResponse | null>(null)
  const [discoveredIssuer, setDiscoveredIssuer] = useState<ImportResponse | null>(null)
  const [selectedIssuerConfigurationID, setSelectedIssuerConfigurationID] = useState('')
  const [lastProtocolError, setLastProtocolError] = useState<ProtocolErrorState | null>(null)
  const [issuanceProgress, setIssuanceProgress] = useState<IssuanceProgress>('')
  const [pendingAuthorizationURL, setPendingAuthorizationURL] = useState('')
  const [selectedDisclosureClaims, setSelectedDisclosureClaims] = useState<string[]>([])
  const [externalTrustApproval, setExternalTrustApproval] = useState(false)
  const [scannerOpen, setScannerOpen] = useState(false)
  const [scannerActive, setScannerActive] = useState(false)
  const [scannerStartRequestID, setScannerStartRequestID] = useState(0)
  const [resolveInFlight, setResolveInFlight] = useState(false)
  const [actionPending, setActionPending] = useState<'refresh' | 'issue' | 'import' | 'preview' | 'present' | ''>('')
  const [authorizationContinued, setAuthorizationContinued] = useState(false)
  const [stepExpanded, setStepExpanded] = useState<Partial<Record<IssueStepID, boolean>>>({})

  const inputClassification = useMemo(() => classifyWalletInput(uriInput), [uriInput])
  const discoveredConfigurations = useMemo(
    () => Array.isArray(discoveredIssuer?.credential_configurations) ? discoveredIssuer.credential_configurations : [],
    [discoveredIssuer],
  )
  const canRetryDiscoveredIssuance = Boolean(
    discoveredIssuer?.credential_issuer
    && selectedIssuerConfigurationID
    && (
      pendingAuthorizationURL
      || lastProtocolError?.source === 'import'
      || issuanceProgress === 'authorization_required'
      || issuanceProgress === 'validation_failed'
      || issuanceProgress === 'ready'
    ),
  )
  const issueFocus = useMemo<IssueFocus>(() => {
    if (protocolMode === 'oid4vp') return resolved ? 'request' : 'input'
    if (pendingAuthorizationURL && !authorizationContinued) return 'authorize'
    const pickerActive = discoveredConfigurations.length > 0
      && !pendingAuthorizationURL
      && actionPending !== 'import'
      && issuanceProgress !== 'ready'
      && issuanceProgress !== 'validation_failed'
      && issuanceProgress !== 'authorization_required'
      && !lastProtocolError
    if (pickerActive) return 'picker'
    if (discoveredConfigurations.length > 0 || pendingAuthorizationURL || lastImport || issuanceProgress) return 'done'
    return 'input'
  }, [
    actionPending,
    authorizationContinued,
    discoveredConfigurations.length,
    issuanceProgress,
    lastImport,
    lastProtocolError,
    pendingAuthorizationURL,
    protocolMode,
    resolved,
  ])
  const stepDerivedOpen = useMemo<Record<IssueStepID, boolean>>(() => ({
    input: issueFocus === 'input',
    picker: issueFocus === 'picker',
    authorize: issueFocus === 'authorize',
    offer: false,
    request: issueFocus === 'request',
  }), [issueFocus])
  const stepIsOpen = (id: IssueStepID) => stepExpanded[id] ?? stepDerivedOpen[id]
  const toggleStep = (id: IssueStepID) => {
    setStepExpanded((current) => ({ ...current, [id]: !(current[id] ?? stepDerivedOpen[id]) }))
  }

  const visibleTabs = useMemo(() => {
    const allowed = new Set(viewsForProtocolMode(protocolMode))
    return VIEW_TABS.filter((tab) => allowed.has(tab.id)).map((tab) => (
      tab.id === 'home' ? { ...tab, label: homeTabLabel(protocolMode) } : tab
    ))
  }, [protocolMode])

  const selectedIssueOption = useMemo(
    () => ISSUE_FORMAT_OPTIONS.find((option) => option.configurationID === selectedIssueFormat) || ISSUE_FORMAT_OPTIONS[0],
    [selectedIssueFormat],
  )

  const txCodeGuidance = useMemo(() => {
    if (lastProtocolError?.txCodeRequired) {
      return {
        description: lastProtocolError.txCodeDescription || '',
        length: lastProtocolError.txCodeLength || 0,
        inputMode: lastProtocolError.txCodeInputMode || '',
      }
    }
    if (lastImport?.tx_code_required) {
      return {
        description: String(lastImport.tx_code_description || ''),
        length: Number(lastImport.tx_code_length || 0),
        inputMode: String(lastImport.tx_code_input_mode || ''),
      }
    }
    return null
  }, [lastImport, lastProtocolError])

  const setBanner = useCallback((message: string, level: BannerLevel = 'info') => {
    const normalized = String(message || '').trim()
    if (!normalized) { setStatusBanner(null); return }
    setStatusBanner({ message: normalized, level })
  }, [])

  const recordProtocolError = useCallback((
    source: ProtocolErrorState['source'],
    payloadObject: Record<string, unknown>,
    fallback: string,
  ) => {
    const errorCode = String(payloadObject.error || '').trim()
    const errorDescription = String(payloadObject.error_description || payloadObject.error || fallback).trim() || fallback
    const nextError: ProtocolErrorState = {
      source,
      error: errorCode || 'request_failed',
      errorDescription,
      txCodeRequired: Boolean(payloadObject.tx_code_required),
      txCodeDescription: String(payloadObject.tx_code_description || '').trim() || undefined,
      txCodeLength: Number(payloadObject.tx_code_length || 0) || undefined,
      txCodeInputMode: String(payloadObject.tx_code_input_mode || '').trim() || undefined,
    }
    setLastProtocolError(nextError)
    if (String(payloadObject.error || '').includes('invalid') || String(payloadObject.error || '').includes('validation')) {
      setIssuanceProgress('validation_failed')
    }
    return nextError
  }, [])

  const credentialEntries = useMemo(() => {
    if (!Array.isArray(session?.credentials)) return []
    return session.credentials
  }, [session?.credentials])

  const activeCredentialEntry = useMemo(() => {
    const normalizedSelectedID = selectedCredentialID.trim()
    if (normalizedSelectedID) {
      const explicitSelection = credentialEntries.find((entry) => String(entry.credential_id || '').trim() === normalizedSelectedID)
      if (explicitSelection) return explicitSelection
    }
    if (session?.credential_id) {
      const sessionActive = credentialEntries.find((entry) => String(entry.credential_id || '').trim() === String(session.credential_id || '').trim())
      if (sessionActive) return sessionActive
    }
    const flaggedActive = credentialEntries.find((entry) => Boolean(entry.is_active))
    if (flaggedActive) return flaggedActive
    return credentialEntries[0] || null
  }, [credentialEntries, selectedCredentialID, session?.credential_id])

  const activeCredentialSummary = useMemo(
    () => activeCredentialEntry?.credential_summary || session?.credential_summary || null,
    [activeCredentialEntry?.credential_summary, session?.credential_summary],
  )

  const availableDisclosureClaims = useMemo(() => {
    return normalizeClaims(activeCredentialSummary?.disclosure_claims)
  }, [activeCredentialSummary?.disclosure_claims])

  useEffect(() => {
    setSelectedDisclosureClaims((previous) => previous.filter((claim) => availableDisclosureClaims.includes(claim)))
  }, [availableDisclosureClaims])

  useEffect(() => {
    const preferredID = String(session?.credential_id || '').trim()
    if (preferredID) { setSelectedCredentialID(preferredID); return }
    if (!selectedCredentialID.trim() && credentialEntries.length > 0) {
      setSelectedCredentialID(String(credentialEntries[0]?.credential_id || '').trim())
    }
  }, [credentialEntries, selectedCredentialID, session?.credential_id])

  useEffect(() => {
    if (!resolved?.trust?.requires_external_approval) setExternalTrustApproval(false)
  }, [resolved?.trust?.requires_external_approval])

  useEffect(() => {
    const allowed = viewsForProtocolMode(protocolMode)
    if (!allowed.includes(activeView)) setActiveView(allowed[0] || 'home')
  }, [activeView, protocolMode])

  const clearOID4VPFlowState = useCallback(() => {
    setResolved(null)
    setPreview(null)
    setResult(null)
    setSelectedDisclosureClaims([])
    setExternalTrustApproval(false)
  }, [])

  const clearOID4VCIFlowState = useCallback(() => {
    setPendingAuthorizationURL('')
    setIssuanceProgress('')
    setLastImport(null)
    setDiscoveredIssuer(null)
    setSelectedIssuerConfigurationID('')
    setImportTxCodeInput('')
    setAuthorizationContinued(false)
    setStepExpanded({})
    clearPendingOID4VCIAuthorization()
    clearDiscoveredIssuerState()
  }, [])

  const enterOID4VCIMode = useCallback(() => {
    clearOID4VPFlowState()
    setProtocolMode('oid4vci')
  }, [clearOID4VPFlowState])

  const enterOID4VPMode = useCallback(() => {
    clearOID4VCIFlowState()
    setProtocolMode('oid4vp')
  }, [clearOID4VCIFlowState])

  const resetProtocolMode = useCallback(() => {
    clearOID4VPFlowState()
    clearOID4VCIFlowState()
    setProtocolMode('idle')
    setActiveView('home')
    setBanner('Returned to idle wallet mode')
  }, [clearOID4VCIFlowState, clearOID4VPFlowState, setBanner])

  const apiRequest = useCallback(
    async <TResponse,>(
      endpoint: string,
      method: 'GET' | 'POST',
      payload?: unknown,
      errorSource: ProtocolErrorState['source'] = 'session',
    ): Promise<TResponse> => {
      const headers: Record<string, string> = { Accept: 'application/json' }
      if (walletSessionID.trim()) headers['X-Wallet-Session'] = walletSessionID.trim()
      const requestInit: RequestInit = { method, headers, credentials: 'same-origin' }
      if (payload !== undefined) {
        headers['Content-Type'] = 'application/json'
        requestInit.body = JSON.stringify(payload)
      }
      const response = await fetch(endpoint, requestInit)
      let body: unknown
      try { body = await response.json() } catch { body = {} }
      if (!response.ok) {
        const payloadObject = (body && typeof body === 'object') ? body as Record<string, unknown> : {}
        const protocolError = recordProtocolError(errorSource, payloadObject, `Request failed with HTTP ${response.status}`)
        let errorDescription = protocolError.errorDescription
        if (protocolError.error && protocolError.error !== 'request_failed') {
          errorDescription = `${protocolError.error}: ${errorDescription}`
        }
        if (protocolError.txCodeRequired) {
          const txCodeHints = [
            protocolError.txCodeDescription || '',
            protocolError.txCodeLength ? `Length: ${String(protocolError.txCodeLength)}` : '',
            protocolError.txCodeInputMode ? `Input mode: ${protocolError.txCodeInputMode}` : '',
          ].filter(Boolean)
          if (txCodeHints.length > 0) errorDescription = `${errorDescription} (${txCodeHints.join(', ')})`
        }
        throw new Error(errorDescription)
      }
      setLastProtocolError(null)
      return body as TResponse
    },
    [recordProtocolError, walletSessionID],
  )

  const stopScanner = useCallback(
    async (statusMessage = '') => {
      await scanner.stop()
      setScannerActive(false)
      setScannerOpen(false)
      if (statusMessage) setBanner(statusMessage)
    },
    [scanner, setBanner],
  )

  useEffect(() => {
    document.body.classList.toggle('scanner-modal-open', scannerOpen)
    return () => { document.body.classList.remove('scanner-modal-open') }
  }, [scannerOpen])

  useEffect(() => {
    if (activeView !== 'home' && scannerActive) void stopScanner()
  }, [activeView, scannerActive, stopScanner])

  useEffect(() => {
    return () => { void scanner.stop(); document.body.classList.remove('scanner-modal-open') }
  }, [scanner])

  useEffect(() => {
    if (!scannerOpen) return
    const onKeyDown = (event: KeyboardEvent) => { if (event.key === 'Escape') void stopScanner('Scanner closed') }
    document.addEventListener('keydown', onKeyDown)
    return () => { document.removeEventListener('keydown', onKeyDown) }
  }, [scannerOpen, stopScanner])

  useEffect(() => {
    setStepExpanded({})
  }, [issueFocus])

  const refreshSession = useCallback(async () => {
    setActionPending('refresh')
    setBanner('Loading wallet session')
    try {
      const payload = await apiRequest<SessionPayload>('/api/session', 'GET')
      setSession(payload)
      if (payload.wallet_session_id) setWalletSessionID(String(payload.wallet_session_id))
      if (payload.app_title) document.title = String(payload.app_title)
      setBanner('Wallet session ready', 'success')
    } finally { setActionPending('') }
  }, [apiRequest, setBanner])

  const continueIssuerAuthorization = useCallback(() => {
    const target = String(pendingAuthorizationURL || '').trim()
    if (!target) return
    savePendingOID4VCIAuthorization({
      authorizationURL: target,
      uriInput,
      importSnapshot: lastImport,
      savedAt: Date.now(),
    })
    setAuthorizationContinued(true)
    const popup = openOID4VCIAuthorizationPopup(target)
    if (popup) {
      setBanner('Complete issuer authorization in the popup. This wallet tab will stay on the offer.', 'info')
      return
    }
    // Popup blocked: fall back to same-tab navigation; sessionStorage restores context on return.
    setBanner('Popup blocked — continuing in this tab. Offer context will be restored when you return.', 'info')
    window.location.assign(target)
  }, [lastImport, pendingAuthorizationURL, setBanner, uriInput])

  const applyOID4VCICallbackResult = useCallback(async (status: string, message: string) => {
    clearPendingOID4VCIAuthorization()
    setPendingAuthorizationURL('')
    setProtocolMode('oid4vci')
    await refreshSession()
    if (status === 'success') {
      setIssuanceProgress('ready')
      const normalized = String(message || '').toLowerCase()
      if (normalized.includes('fapi')) {
        setActiveView('home')
        setBanner(firstNonEmptyString(message, 'FAPI resource request completed'), 'success')
        return
      }
      setActiveView('credentials')
      setBanner(firstNonEmptyString(message, 'Credential imported'), 'success')
      return
    }
    setIssuanceProgress('validation_failed')
    setBanner(firstNonEmptyString(message, 'OID4VCI authorization failed'), 'error')
  }, [refreshSession, setBanner])

  const resolveRequest = useCallback(
    async (rawInput: string, extras?: { clientID?: string; requestURIMethod?: string }) => {
      if (resolveInFlightRef.current) return
      resolveInFlightRef.current = true
      setResolveInFlight(true)
      enterOID4VPMode()
      setBanner('Resolving request object')
      try {
        const payload = buildResolvePayloadFromInput(rawInput, extras)
        const response = await apiRequest<ResolveResponse>('/api/resolve', 'POST', payload, 'resolve')
        setResolved(response); setPreview(null); setResult(null)
        setPendingAuthorizationURL('')
        const dcqlClaims: string[] = []
        const credentials = Array.isArray((response.dcql_query as { credentials?: unknown } | undefined)?.credentials)
          ? ((response.dcql_query as { credentials: Array<{ claims?: Array<{ path?: unknown[] }> }> }).credentials)
          : []
        for (const credential of credentials) {
          for (const claim of credential.claims || []) {
            const path = Array.isArray(claim.path) ? claim.path.map((part) => String(part)) : []
            if (path.length === 0) continue
            dcqlClaims.push(path[path.length - 1])
          }
        }
        setSelectedDisclosureClaims(Array.from(new Set(dcqlClaims)))
        setExternalTrustApproval(false)
        if (response.inferred_credential_configuration_id) {
          const match = ISSUE_FORMAT_OPTIONS.find((opt) => opt.configurationID === response.inferred_credential_configuration_id)
            || ISSUE_FORMAT_OPTIONS.find((opt) => opt.format === response.inferred_credential_format)
          if (match) setSelectedIssueFormat(match.configurationID)
        }
        const matched = Boolean(response.credential_matches?.matched)
        if (!matched && response.inferred_credential_format) {
          setBanner('Issuing a credential that matches the presentation request')
          setIssuanceProgress('issuing')
          const issued = await apiRequest<SessionPayload>('/api/issue', 'POST', {
            force_issue: true,
            credential_format: response.inferred_credential_format,
            credential_configuration_id: response.inferred_credential_configuration_id || undefined,
          }, 'issue')
          setSession((previous) => mergeCredentialSession(previous, issued))
          if (issued.credential_id) setSelectedCredentialID(String(issued.credential_id))
          setIssuanceProgress('ready')
        }
        setActiveView('review')
        setBanner('Request object resolved', 'success')
      } finally { resolveInFlightRef.current = false; setResolveInFlight(false) }
    },
    [apiRequest, enterOID4VPMode, setBanner],
  )

  const importCredentialOffer = useCallback(
    async (rawInput: string) => {
      if (importInFlightRef.current) return
      importInFlightRef.current = true
      setActionPending('import')
      enterOID4VCIMode()
      setIssuanceProgress('importing')
      setBanner('Importing credential into wallet')
      try {
        const classification = classifyWalletInput(rawInput)
        if (classification.kind === 'as_discovery') {
          throw new Error(classification.detail)
        }
        if (classification.kind === 'presentation') {
          throw new Error('This looks like a presentation request. Use Resolve, not Import.')
        }
        const resourceAuth = parseProtectedResourceAuthInput(rawInput)
        if (resourceAuth) {
          setBanner('Authorizing with AS, then calling protected resource with DPoP')
          const response = await apiRequest<ImportResponse>('/api/import', 'POST', {
            discovery_url: resourceAuth.discovery_url,
            resource_endpoint: resourceAuth.resource_endpoint,
            scope: resourceAuth.scope,
            wallet_base_url: window.location.origin,
          }, 'import')
          setLastImport(response)
          setDiscoveredIssuer(null)
          clearDiscoveredIssuerState()
          if (response.authorization_required && response.authorization_url) {
            const target = resolveAuthorizationRedirectTarget(response)
            setPendingAuthorizationURL(target)
            setIssuanceProgress('authorization_required')
            setAuthorizationContinued(false)
            setBanner('AS authorization required. Continue in the popup.', 'info')
            setActiveView('home')
            savePendingOID4VCIAuthorization({
              authorizationURL: target,
              uriInput: rawInput,
              importSnapshot: response,
              savedAt: Date.now(),
            })
            return
          }
          throw new Error('Protected resource authorization did not return an authorization URL')
        }
        const payload = buildImportPayloadFromInput(rawInput, importTxCodeInput)
        payload.wallet_base_url = window.location.origin
        const response = await apiRequest<ImportResponse>('/api/import', 'POST', payload, 'import')
        setLastImport(response)
        if (response.configuration_selection_required) {
          const configurations = Array.isArray(response.credential_configurations) ? response.credential_configurations : []
          const nextSelectedID = (() => {
            const currentID = String(selectedIssuerConfigurationID || '').trim()
            if (currentID && configurations.some((configuration) => String(configuration.id || '') === currentID)) {
              return currentID
            }
            return String(configurations[0]?.id || '')
          })()
          setDiscoveredIssuer(response)
          setSelectedIssuerConfigurationID(nextSelectedID)
          saveDiscoveredIssuerState({
            snapshot: response,
            selectedConfigurationID: nextSelectedID,
            savedAt: Date.now(),
          })
          setPendingAuthorizationURL('')
          setIssuanceProgress('')
          setAuthorizationContinued(false)
          setActiveView('home')
          setBanner('Select a credential configuration from this issuer, then request it.', 'info')
          return
        }
        setDiscoveredIssuer(null)
        clearDiscoveredIssuerState()
        if (response.authorization_required && response.authorization_url) {
          const target = resolveAuthorizationRedirectTarget(response)
          setPendingAuthorizationURL(target)
          setIssuanceProgress('authorization_required')
          setAuthorizationContinued(false)
          setBanner('Review issuer authorization below, then continue in the popup so this wallet tab keeps the offer context.', 'info')
          setActiveView('home')
          savePendingOID4VCIAuthorization({
            authorizationURL: target,
            uriInput: rawInput,
            importSnapshot: response,
            savedAt: Date.now(),
          })
          return
        }
        setPendingAuthorizationURL('')
        setSession((previous) => mergeCredentialSession(previous, response))
        setPreview(null); setResult(null); setSelectedDisclosureClaims([])
        if (response.credential_id) setSelectedCredentialID(String(response.credential_id))
        setIssuanceProgress('ready')
        setActiveView('credentials')
        setBanner(`Credential imported from ${String(response.credential_issuer || response.credential_source || 'wallet import')}`, 'success')
      } catch (error) {
        if (String((error as Error)?.message || '').toLowerCase().includes('deferred') || String((error as Error)?.message || '').includes('issuance_pending')) {
          setIssuanceProgress('deferred')
        }
        throw error
      } finally {
        importInFlightRef.current = false
        setActionPending('')
      }
    },
    [apiRequest, enterOID4VCIMode, importTxCodeInput, selectedIssuerConfigurationID, setBanner],
  )

  const requestSelectedIssuerConfiguration = useCallback(async () => {
    const issuer = String(discoveredIssuer?.credential_issuer || '').trim()
    const configurationID = String(selectedIssuerConfigurationID || '').trim()
    if (!issuer) throw new Error('credential_issuer is missing from the discovered issuer')
    if (!configurationID) throw new Error('Select a credential configuration first')
    if (importInFlightRef.current) return
    importInFlightRef.current = true
    setActionPending('import')
    setIssuanceProgress('importing')
    setPendingAuthorizationURL('')
    clearPendingOID4VCIAuthorization()
    setAuthorizationContinued(false)
    setBanner('Starting authorization_code issuance for the selected configuration')
    try {
      const response = await apiRequest<ImportResponse>('/api/import', 'POST', {
        credential_issuer: issuer,
        credential_configuration_id: configurationID,
        wallet_base_url: window.location.origin,
      }, 'import')
      setLastImport(response)
      if (response.authorization_required && response.authorization_url) {
        const target = resolveAuthorizationRedirectTarget(response)
        setPendingAuthorizationURL(target)
        setIssuanceProgress('authorization_required')
        setAuthorizationContinued(false)
        setBanner('Review what this issuer will require, then continue to the authorization server.', 'info')
        savePendingOID4VCIAuthorization({
          authorizationURL: target,
          uriInput,
          importSnapshot: response,
          savedAt: Date.now(),
        })
        return
      }
      throw new Error('Issuer did not return an authorization URL for the selected configuration')
    } catch (error) {
      setIssuanceProgress((current) => (current === 'importing' ? 'validation_failed' : current))
      throw error
    } finally {
      importInFlightRef.current = false
      setActionPending('')
    }
  }, [apiRequest, discoveredIssuer, selectedIssuerConfigurationID, setBanner, uriInput])

  const routeWalletInput = useCallback(
    async (rawInput: string) => {
      const mode = detectWalletProtocolMode(rawInput)
      if (mode === 'oid4vci') { await importCredentialOffer(rawInput); return }
      await resolveRequest(rawInput)
    },
    [importCredentialOffer, resolveRequest],
  )

  const buildWalletPayload = useCallback(() => {
    if (!resolved) throw new Error('Resolve a request first')
    const selectedFormatEntry = selectedIssueOption || ISSUE_FORMAT_OPTIONS[0]
    const inferredFormat = String(resolved.inferred_credential_format || '').trim()
    const inferredConfigID = String(resolved.inferred_credential_configuration_id || '').trim()
    const activeFormat = String(activeCredentialEntry?.credential_format || '').trim()
    const activeConfigID = String(activeCredentialEntry?.credential_configuration_id || '').trim()
    const activeCredentialID = String(activeCredentialEntry?.credential_id || selectedCredentialID || '').trim()

    // Prefer the request-inferred credential profile. A leftover mdoc (or other)
    // active credential must not pin present/preview to the wrong format — that
    // skips HAIP SD-JWT bootstrap and fails DCQL matching.
    const formatMatches = !inferredFormat || !activeFormat || activeFormat === inferredFormat
    const configMatches = !inferredConfigID || !activeConfigID || activeConfigID === inferredConfigID
    const activeMatchesRequest = formatMatches && configMatches
    const credentialID = activeMatchesRequest ? activeCredentialID : ''
    const credentialFormat = activeMatchesRequest
      ? (activeFormat || inferredFormat || selectedFormatEntry?.format || '')
      : (inferredFormat || selectedFormatEntry?.format || '')
    const credentialConfigurationID = activeMatchesRequest
      ? (activeConfigID || inferredConfigID || selectedFormatEntry?.configurationID || '')
      : (inferredConfigID || selectedFormatEntry?.configurationID || '')

    const payload: Record<string, unknown> = {
      request_id: String(resolved.request_id || ''),
      request: String(resolved.request || ''),
      request_uri: String(resolved.request_uri || ''),
      credential_id: credentialID,
      credential_format: credentialFormat,
      credential_configuration_id: credentialConfigurationID,
      disclosure_claims: selectedDisclosureClaims,
      approve_external_trust: externalTrustApproval,
    }
    if (resolved.client_id) payload.client_id = String(resolved.client_id)
    return payload
  }, [activeCredentialEntry, externalTrustApproval, resolved, selectedCredentialID, selectedDisclosureClaims, selectedIssueOption])

  const issueCredential = useCallback(
    async (forceIssue: boolean, overrides?: { format?: string; configurationID?: string }) => {
      setActionPending('issue')
      if (protocolMode === 'idle') setProtocolMode('oid4vci')
      setIssuanceProgress('issuing')
      setBanner('Issuing credential via OID4VCI')
      try {
        const selectedFormatEntry = selectedIssueOption || ISSUE_FORMAT_OPTIONS[0]
        const response = await apiRequest<SessionPayload>('/api/issue', 'POST', {
          force_issue: forceIssue,
          credential_format: overrides?.format || selectedFormatEntry?.format,
          credential_configuration_id: overrides?.configurationID || selectedFormatEntry?.configurationID,
          credential_id: overrides ? undefined : (selectedCredentialID || undefined),
        }, 'issue')
        setSession((previous) => mergeCredentialSession(previous, response))
        if (response.credential_id) setSelectedCredentialID(String(response.credential_id))
        setIssuanceProgress('ready')
        setActiveView('credentials')
        setBanner(`Credential ready from ${String(response.credential_source || 'wallet')}`, 'success')
        return response
      } catch (error) {
        if (String((error as Error)?.message || '').toLowerCase().includes('deferred') || String((error as Error)?.message || '').includes('issuance_pending')) {
          setIssuanceProgress('deferred')
        }
        throw error
      } finally { setActionPending('') }
    },
    [apiRequest, protocolMode, selectedCredentialID, selectedIssueOption, setBanner],
  )

  const hasBlockingVerificationFailure = Boolean(resolved?.trust?.request_object_verification && !resolved?.trust?.request_object_verification?.verified)

  const previewPresentation = useCallback(async () => {
    setActionPending('preview')
    setBanner('Building VP token preview')
    try {
      const payload = buildWalletPayload()
      const response = await apiRequest<PreviewResponse>('/api/preview', 'POST', payload, 'preview')
      setPreview(response); setActiveView('present')
      setBanner('VP preview ready', 'success')
    } finally { setActionPending('') }
  }, [apiRequest, buildWalletPayload, setBanner])

  const presentCredential = useCallback(async () => {
    setActionPending('present')
    setBanner('Submitting presentation to verifier')
    try {
      const payload = buildWalletPayload()
      const response = await apiRequest<PresentResponse>('/api/present', 'POST', payload, 'present')
      setResult(response); setActiveView('result')
      const redirectURI = String(response.redirect_uri || '').trim()
      if (redirectURI) {
        setBanner('Presentation accepted; continuing to verifier redirect', 'success')
        window.location.assign(redirectURI)
        return
      }
      setBanner('Verifier response received', 'success')
    } finally { setActionPending('') }
  }, [apiRequest, buildWalletPayload, setBanner])

  useEffect(() => {
    if (!scannerOpen || scannerStartRequestID === 0) return
    const viewport = scannerViewportRef.current
    if (!viewport) return
    let cancelled = false
    const start = async () => {
      try {
        const started = await scanner.start(
          viewport,
          (decodedText) => {
            if (cancelled) return
            setURIInput(decodedText); setScannerActive(false); setScannerOpen(false)
            void routeWalletInput(decodedText).catch((error: unknown) => { setBanner(toErrorMessage(error), 'error') })
          },
          (message) => { if (!cancelled && message.trim()) setBanner(message) },
        )
        if (cancelled) return
        setScannerActive(started)
        if (!started) setScannerOpen(false)
      } catch (error) {
        if (cancelled) return
        setScannerActive(false); setScannerOpen(false)
        setBanner(toErrorMessage(error), 'error')
      }
    }
    void start()
    return () => { cancelled = true }
  }, [routeWalletInput, scanner, scannerOpen, scannerStartRequestID, setBanner])

  useEffect(() => {
    let cancelled = false
    const init = async () => {
      try {
        await refreshSession()
        if (cancelled) return
        const query = new URLSearchParams(window.location.search)
        const oid4vciStatus = String(query.get('oid4vci_status') || '').trim()
        const oid4vciMessage = String(query.get('oid4vci_message') || '').trim()
        if (oid4vciStatus) {
          const pending = loadPendingOID4VCIAuthorization()
          if (pending?.uriInput) setURIInput(pending.uriInput)
          if (pending?.importSnapshot) setLastImport(pending.importSnapshot)
          const discovered = loadDiscoveredIssuerState()
          if (discovered) {
            setDiscoveredIssuer(discovered.snapshot)
            setSelectedIssuerConfigurationID(String(discovered.selectedConfigurationID || discovered.snapshot.credential_configurations?.[0]?.id || ''))
          }
          // Popup return path: notify the opener wallet tab and close.
          if (window.opener && !window.opener.closed) {
            try {
              window.opener.postMessage(
                {
                  type: OID4VCI_CALLBACK_MESSAGE_TYPE,
                  status: oid4vciStatus,
                  message: oid4vciMessage,
                  pending,
                },
                window.location.origin,
              )
            } catch {
              // opener may be cross-origin after AS hops; fall through to local handling
            }
            window.history.replaceState({}, document.title, window.location.pathname)
            window.close()
            // If the browser ignores close(), still apply locally.
          }
          await applyOID4VCICallbackResult(oid4vciStatus, oid4vciMessage)
          if (cancelled) return
          window.history.replaceState({}, document.title, window.location.pathname)
          return
        }

        const pending = loadPendingOID4VCIAuthorization()
        if (pending) {
          setProtocolMode('oid4vci')
          setURIInput(pending.uriInput || '')
          if (pending.importSnapshot) setLastImport(pending.importSnapshot)
          setPendingAuthorizationURL(pending.authorizationURL)
          setIssuanceProgress('authorization_required')
          setActiveView('home')
        }
        const discovered = loadDiscoveredIssuerState()
        if (discovered) {
          setProtocolMode('oid4vci')
          setDiscoveredIssuer(discovered.snapshot)
          setSelectedIssuerConfigurationID(String(discovered.selectedConfigurationID || discovered.snapshot.credential_configurations?.[0]?.id || ''))
          setActiveView('home')
        }

        const initialOfferURI = String(query.get('credential_offer_uri') || '').trim()
        const initialOffer = String(query.get('credential_offer') || '').trim()
        if (initialOfferURI || initialOffer) {
          if (bootstrapOfferHandledRef.current) return
          bootstrapOfferHandledRef.current = true
          const importInput = window.location.href
          setURIInput(importInput)
          await importCredentialOffer(importInput)
          return
        }
        const initialURI = String(query.get('uri') || query.get('request_uri') || '').trim()
        if (!initialURI) return
        const clientID = String(query.get('client_id') || '').trim()
        const requestURIMethod = String(query.get('request_uri_method') || '').trim()
        setURIInput(initialURI)
        await resolveRequest(initialURI, {
          clientID: clientID || undefined,
          requestURIMethod: requestURIMethod || undefined,
        })
        window.history.replaceState({}, document.title, window.location.pathname)
      } catch (error) { if (!cancelled) setBanner(toErrorMessage(error), 'error') }
    }
    void init()
    return () => { cancelled = true }
  }, [applyOID4VCICallbackResult, importCredentialOffer, refreshSession, resolveRequest, setBanner])

  useEffect(() => {
    const onMessage = (event: MessageEvent) => {
      if (event.origin !== window.location.origin) return
      const data = event.data
      if (!data || typeof data !== 'object' || data.type !== OID4VCI_CALLBACK_MESSAGE_TYPE) return
      const pending = data.pending as PendingOID4VCIAuthorizationState | null | undefined
      if (pending?.uriInput) setURIInput(pending.uriInput)
      if (pending?.importSnapshot) setLastImport(pending.importSnapshot)
      setProtocolMode('oid4vci')
      void applyOID4VCICallbackResult(String(data.status || ''), String(data.message || ''))
    }
    window.addEventListener('message', onMessage)
    return () => window.removeEventListener('message', onMessage)
  }, [applyOID4VCICallbackResult])

  const credentialSummary = activeCredentialSummary
  const supportsSelectiveDisclosure = Boolean(credentialSummary?.is_sd_jwt)
  const policyReasons = useMemo(() => normalizeClaims(result?.upstream_body?.reasons), [result?.upstream_body?.reasons])
  const appTitle = String(session?.app_title || 'Protocol Soup Wallet')

  const bannerConfig = useMemo(() => {
    if (!statusBanner) return null
    if (statusBanner.level === 'error') return { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-300', Icon: XCircle }
    if (statusBanner.level === 'success') return { bg: 'bg-green-500/10', border: 'border-green-500/30', text: 'text-green-300', Icon: CheckCircle2 }
    return { bg: 'bg-surface-900/50', border: 'border-white/10', text: 'text-surface-300', Icon: Info }
  }, [statusBanner])

  // ProtocolSoup Looking Glass returns { result: { policy: { allowed } } }.
  // OID4VP response_uri replies are usually 2xx with { redirect_uri } or an
  // empty body — those are acceptance, not denial.
  const resultAllowed = useMemo(() => {
    if (!result) return false
    const status = Number(result.upstream_status || 0)
    if (status > 0 && (status < 200 || status >= 300)) return false
    const body = result.upstream_body
    if (!body || typeof body !== 'object') return status === 0 || (status >= 200 && status < 300)
    const nestedResult = body.result
    if (nestedResult && typeof nestedResult === 'object') {
      const policy = (nestedResult as Record<string, unknown>).policy
      if (policy && typeof policy === 'object' && 'allowed' in (policy as Record<string, unknown>)) {
        return Boolean((policy as Record<string, unknown>).allowed)
      }
    }
    if (typeof body.error === 'string' && body.error.trim()) return false
    if (typeof body.redirect_uri === 'string' && body.redirect_uri.trim()) return true
    return status === 0 || (status >= 200 && status < 300)
  }, [result])

  const resultTitle = useMemo(() => {
    if (!result) return 'Presentation denied'
    if (resultAllowed) {
      return String(result.redirect_uri || result.upstream_body?.redirect_uri || '').trim()
        ? 'Presentation accepted (verifier redirect)'
        : 'Presentation accepted'
    }
    return 'Presentation denied'
  }, [result, resultAllowed])

  return (
    <main className="min-h-screen bg-[#0a0a0f] relative">
      <div className="fixed inset-0 pointer-events-none opacity-[0.015]" style={{ backgroundImage: 'linear-gradient(rgba(255,255,255,0.07) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.07) 1px, transparent 1px)', backgroundSize: '60px 60px' }} />

      <div className="relative max-w-5xl mx-auto px-4 sm:px-6 py-5 sm:py-8 space-y-4 sm:space-y-6">

        {/* Header */}
        <header className="py-2">
          <div className="flex flex-col gap-3">
            <div className="flex items-center gap-3">
              <div className="rounded-xl bg-gradient-to-br from-cyan-500/20 to-purple-500/20 p-2.5 shrink-0">
                <Wallet className="w-5 h-5 text-cyan-400" />
              </div>
              <div className="min-w-0 flex-1">
                <h1 className="text-base sm:text-lg font-semibold text-white">{appTitle}</h1>
                <p className="text-[11px] sm:text-xs text-surface-400 mt-0.5 leading-relaxed">
                  {protocolMode === 'oid4vci'
                    ? 'OID4VCI issuance — add from a credential issuer, redeem an offer, authorize when required, and store the credential'
                    : protocolMode === 'oid4vp'
                      ? 'OID4VP presentation — review the verifier request, choose disclosures, and submit a real VP'
                      : 'Ephemeral OID4VP and OID4VCI web wallet: add from an issuer, redeem offers, present to verifiers'}
                </p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <span className={`inline-flex items-center rounded-md border px-2 py-1 text-[10px] sm:text-[11px] font-medium tracking-wide ${
                protocolMode === 'oid4vci'
                  ? 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300'
                  : protocolMode === 'oid4vp'
                    ? 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                    : 'border-white/10 bg-surface-900/50 text-surface-400'
              }`}>
                {protocolMode === 'oid4vci' ? 'Mode: OID4VCI' : protocolMode === 'oid4vp' ? 'Mode: OID4VP' : 'Mode: Idle'}
              </span>
              {protocolMode !== 'idle' && (
                <button type="button" className="btn-secondary !px-2 !py-1 text-[10px] sm:text-[11px]" onClick={resetProtocolMode}>
                  Reset mode
                </button>
              )}
              <p className="text-[10px] sm:text-[11px] text-surface-500">No credential data is persisted beyond this wallet session</p>
            </div>
          </div>
        </header>

        {/* Status Banner */}
        <AnimatePresence mode="wait">
          {statusBanner && bannerConfig && (
            <motion.div
              key={statusBanner.message + statusBanner.level}
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.15 }}
              className={`flex items-center gap-2.5 rounded-lg border px-3 sm:px-4 py-2.5 sm:py-3 text-xs sm:text-sm ${bannerConfig.bg} ${bannerConfig.border} ${bannerConfig.text}`}
            >
              <bannerConfig.Icon className="w-4 h-4 shrink-0" />
              <span className="leading-relaxed">{statusBanner.message}</span>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Tab Navigation */}
        <nav className="flex gap-1 p-1 rounded-lg bg-surface-900/50 overflow-x-auto scrollbar-hide" aria-label="Wallet views">
          {visibleTabs.map((tab) => {
            const isActive = activeView === tab.id
            return (
              <button
                key={tab.id}
                type="button"
                className={`flex-1 min-w-0 flex items-center justify-center gap-1.5 sm:gap-2 px-2 sm:px-4 py-2.5 sm:py-2 rounded-md text-sm font-medium transition-colors whitespace-nowrap ${
                  isActive
                    ? 'bg-surface-800 text-white'
                    : 'text-surface-400 hover:text-white active:text-white'
                }`}
                onClick={() => setActiveView(tab.id)}
              >
                <tab.icon className="w-4 h-4 shrink-0" />
                <span className="hidden sm:inline">{tab.label}</span>
              </button>
            )
          })}
        </nav>

        {/* Active View */}
        <AnimatePresence mode="wait">
          {activeView === 'home' && (
            <motion.section key="home" {...viewTransition} className="rounded-xl border border-white/10 bg-surface-900/20 p-3 sm:p-4 space-y-3 sm:space-y-4">
              <SectionHeading
                icon={Home}
                title={protocolMode === 'oid4vci' ? 'Issue' : protocolMode === 'oid4vp' ? 'Presentation Request' : 'Wallet Input'}
                subtitle={
                  protocolMode === 'oid4vci'
                    ? 'Paste a credential issuer URL, credential offer, or an issued credential'
                    : protocolMode === 'oid4vp'
                      ? 'Paste or scan an openid4vp:// URI or https request_uri deeplink'
                      : 'Paste a credential issuer URL, openid-credential-offer:// offer, openid4vp:// request, or an issued credential'
                }
              />
              <IssueStep
                title={protocolMode === 'oid4vp' ? 'Request input' : 'Issuer / offer'}
                summary={String(discoveredIssuer?.credential_issuer || uriInput.trim().split('\n')[0] || '').trim() || undefined}
                open={stepIsOpen('input')}
                onToggle={() => toggleStep('input')}
              >
                <textarea
                  className="glass-input min-h-[120px] resize-y"
                  value={uriInput}
                  onChange={(event) => setURIInput(event.target.value)}
                  placeholder={
                    protocolMode === 'oid4vci'
                      ? 'https://issuer.example/oid4vci/&#10;openid-credential-offer://?credential_offer_uri=...&#10;https://issuer.example/...?credential_offer=...'
                      : protocolMode === 'oid4vp'
                        ? 'openid4vp://authorize?request_uri=...&#10;https://verifier.example/authorize?request_uri=...'
                        : 'https://issuer.example/oid4vci/&#10;openid-credential-offer://?credential_offer_uri=...&#10;openid4vp://authorize?request_uri=...'
                  }
                />
                {inputClassification.kind !== 'empty' && (
                  <div className={`rounded-lg border px-3 py-2 text-[11px] sm:text-xs leading-relaxed ${
                    inputClassification.kind === 'as_discovery' || inputClassification.kind === 'unknown'
                      ? 'border-amber-500/30 bg-amber-500/5 text-amber-200'
                      : 'border-white/10 bg-surface-900/50 text-surface-300'
                  }`}>
                    <span className="font-medium text-surface-100">{inputClassification.label}.</span>{' '}
                    {inputClassification.detail}
                  </div>
                )}
                {protocolMode !== 'oid4vp' && (
                  <input
                    className="glass-input"
                    type="text"
                    value={importTxCodeInput}
                    onChange={(event) => setImportTxCodeInput(event.target.value)}
                    inputMode={txCodeGuidance?.inputMode === 'numeric' ? 'numeric' : undefined}
                    maxLength={txCodeGuidance?.length && txCodeGuidance.length > 0 ? txCodeGuidance.length : undefined}
                    placeholder={txCodeGuidance
                      ? `tx_code required${txCodeGuidance.length ? ` (${txCodeGuidance.length} chars)` : ''}`
                      : 'Optional tx_code for OID4VCI pre-authorized offers'}
                  />
                )}
                {protocolMode !== 'oid4vp' && txCodeGuidance && (
                  <div className="rounded-lg border border-cyan-500/30 bg-cyan-500/5 p-3 space-y-1.5 text-[11px] sm:text-xs text-surface-300">
                    <div className="font-medium text-cyan-300">tx_code guidance from issuer</div>
                    {txCodeGuidance.description && <div>{txCodeGuidance.description}</div>}
                    <div className="text-surface-500">
                      {[
                        txCodeGuidance.length ? `length=${txCodeGuidance.length}` : '',
                        txCodeGuidance.inputMode ? `input_mode=${txCodeGuidance.inputMode}` : '',
                      ].filter(Boolean).join(' · ') || 'Enter the out-of-band transaction code, then Import again'}
                    </div>
                  </div>
                )}
                <div className="flex flex-wrap gap-2">
                  {protocolMode !== 'oid4vci' && (
                    <button className="btn-primary" disabled={resolveInFlight} onClick={() => { void resolveRequest(uriInput).catch((e: unknown) => setBanner(toErrorMessage(e), 'error')) }}>
                      <Search className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Resolve
                    </button>
                  )}
                  {protocolMode !== 'oid4vp' && (
                    <button className={protocolMode === 'oid4vci' ? 'btn-primary' : 'btn-secondary'} disabled={actionPending === 'import'} onClick={() => { void importCredentialOffer(uriInput).catch((e: unknown) => setBanner(toErrorMessage(e), 'error')) }}>
                      <Download className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> {inputClassification.kind === 'issuer' ? 'Discover issuer' : 'Import'}
                    </button>
                  )}
                  {protocolMode === 'idle' && (
                    <button className="btn-secondary" disabled={!uriInput.trim() || resolveInFlight || actionPending === 'import'} onClick={() => { void routeWalletInput(uriInput).catch((e: unknown) => setBanner(toErrorMessage(e), 'error')) }}>
                      <ArrowRight className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Auto-route
                    </button>
                  )}
                  <button className="btn-secondary" disabled={actionPending === 'refresh'} onClick={() => { void refreshSession().catch((e: unknown) => setBanner(toErrorMessage(e), 'error')) }}>
                    <RefreshCw className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Refresh
                  </button>
                  <button className="btn-secondary" disabled={scannerActive} onClick={() => { setScannerOpen(true); setScannerStartRequestID((p) => p + 1) }}>
                    <QrCode className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Scan QR
                  </button>
                </div>
              </IssueStep>
              {protocolMode !== 'oid4vp' && issuanceProgress && (
                <div className="rounded-lg border border-white/10 bg-surface-900/50 px-3 py-2 text-[11px] sm:text-xs text-surface-400">
                  Issuance status:{' '}
                  <span className="text-surface-200 font-medium">
                    {issuanceProgress === 'importing' && 'Importing offer / redeeming with issuer'}
                    {issuanceProgress === 'authorization_required' && 'Authorization required — continue at issuer'}
                    {issuanceProgress === 'issuing' && 'Issuing via OID4VCI bootstrap'}
                    {issuanceProgress === 'deferred' && 'Deferred issuance pending'}
                    {issuanceProgress === 'validation_failed' && 'Credential or offer validation failed'}
                    {issuanceProgress === 'ready' && 'Credential ready in wallet store'}
                  </span>
                </div>
              )}
              {lastProtocolError && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 space-y-1.5">
                  <div className="flex items-center gap-2 text-xs sm:text-sm font-medium text-red-300">
                    <XCircle className="w-4 h-4 shrink-0" /> Protocol error from /api/{lastProtocolError.source}
                  </div>
                  <div className="text-[11px] sm:text-xs font-mono text-red-200/90 break-all">{lastProtocolError.error}</div>
                  <div className="text-[11px] sm:text-xs text-surface-300 leading-relaxed">{lastProtocolError.errorDescription}</div>
                  {lastProtocolError.txCodeRequired && protocolMode !== 'oid4vp' && (
                    <div className="text-[11px] text-amber-300">Provide the required tx_code above and retry Import.</div>
                  )}
                </div>
              )}
              {protocolMode !== 'oid4vp' && discoveredConfigurations.length > 0 && (
                <IssueStep
                  title="Credential configuration"
                  summary={selectedIssuerConfigurationID || String(discoveredIssuer?.credential_issuer || '')}
                  open={stepIsOpen('picker')}
                  onToggle={() => toggleStep('picker')}
                  tone="cyan"
                  actions={(
                    <button
                      type="button"
                      className="btn-primary !inline-flex !px-2 !py-1.5 text-[11px]"
                      disabled={!selectedIssuerConfigurationID || actionPending === 'import'}
                      onClick={() => { void requestSelectedIssuerConfiguration().catch((e: unknown) => setBanner(toErrorMessage(e), 'error')) }}
                    >
                      {canRetryDiscoveredIssuance
                        ? <><RotateCw className="w-3.5 h-3.5" /> Request again</>
                        : <><ShieldCheck className="w-3.5 h-3.5" /> Request this credential</>}
                    </button>
                  )}
                >
                  <div className="text-[11px] sm:text-xs text-surface-400 font-mono break-all">{String(discoveredIssuer?.credential_issuer || '')}</div>
                  {issuanceRequirementChips(discoveredIssuer?.issuance_requirements).length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {issuanceRequirementChips(discoveredIssuer?.issuance_requirements).map((chip) => (
                        <span key={chip} className="rounded-md border border-cyan-500/20 bg-cyan-500/10 px-2 py-0.5 text-[10px] text-cyan-200">{chip}</span>
                      ))}
                    </div>
                  )}
                  <div className="space-y-2">
                    {discoveredConfigurations.map((configuration) => {
                      const configurationID = String(configuration.id || '')
                      const selected = configurationID === selectedIssuerConfigurationID
                      return (
                        <button
                          key={configurationID}
                          type="button"
                          onClick={() => {
                            setSelectedIssuerConfigurationID(configurationID)
                            if (discoveredIssuer) {
                              saveDiscoveredIssuerState({
                                snapshot: discoveredIssuer,
                                selectedConfigurationID: configurationID,
                                savedAt: Date.now(),
                              })
                            }
                          }}
                          className={`w-full text-left rounded-lg border px-3 py-2 space-y-1 transition-colors ${
                            selected
                              ? 'border-cyan-400/50 bg-cyan-500/10'
                              : 'border-white/10 bg-surface-900/40 hover:border-white/20'
                          }`}
                        >
                          <div className="text-xs font-medium text-surface-100 font-mono break-all">{configurationID}</div>
                          <div className="text-[11px] text-surface-400">
                            {[configuration.format, configuration.vct, configuration.doctype].filter(Boolean).join(' · ') || 'credential configuration'}
                          </div>
                          {(configuration.cryptographic_holder_binding || configuration.key_attestation_required) && (
                            <div className="text-[10px] text-cyan-300">
                              {[configuration.cryptographic_holder_binding ? 'holder binding' : '', configuration.key_attestation_required ? 'key attestation' : ''].filter(Boolean).join(' · ')}
                            </div>
                          )}
                        </button>
                      )
                    })}
                  </div>
                </IssueStep>
              )}
              {protocolMode !== 'oid4vp' && pendingAuthorizationURL && (
                <IssueStep
                  title="Issuer authorization"
                  summary={String(lastImport?.credential_configuration_id || lastImport?.credential_format || 'authorization_code')}
                  open={stepIsOpen('authorize')}
                  onToggle={() => toggleStep('authorize')}
                  tone="amber"
                  actions={(
                    <button type="button" className="btn-primary !inline-flex !px-2 !py-1.5 text-[11px]" onClick={continueIssuerAuthorization}>
                      <ExternalLink className="w-3.5 h-3.5" /> Continue to Issuer
                    </button>
                  )}
                >
                  {lastImport?.credential_issuer && (
                    <div className="text-[11px] sm:text-xs text-surface-300">
                      Issuer: <span className="font-mono break-all text-surface-200">{String(lastImport.credential_issuer)}</span>
                    </div>
                  )}
                  {(lastImport?.credential_configuration_id || lastImport?.credential_format || lastImport?.issuance_requirements?.vct) && (
                    <div className="text-[11px] sm:text-xs text-surface-300">
                      {[lastImport.credential_configuration_id, lastImport.credential_format || lastImport.issuance_requirements?.format, lastImport.issuance_requirements?.vct || lastImport.issuance_requirements?.doctype].filter(Boolean).join(' · ')}
                    </div>
                  )}
                  {issuanceRequirementChips(lastImport?.issuance_requirements).length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {issuanceRequirementChips(lastImport?.issuance_requirements).map((chip) => (
                        <span key={chip} className="rounded-md border border-amber-500/20 bg-amber-500/10 px-2 py-0.5 text-[10px] text-amber-100">{chip}</span>
                      ))}
                    </div>
                  )}
                  <div className="text-[11px] sm:text-xs text-surface-400 break-all font-mono">{pendingAuthorizationURL}</div>
                  <p className="text-[11px] text-surface-500 leading-relaxed">
                    This wallet will send an <span className="font-mono">authorization_code</span> request (PAR when the AS requires it).
                    Continue opens the issuer authorization server in a popup so this tab keeps the issuance context.
                  </p>
                </IssueStep>
              )}
              {protocolMode !== 'oid4vp' && !lastImport?.configuration_selection_required && (lastImport?.credential_issuer || lastImport?.credential_offer) && (
                <IssueStep
                  title="Offer review"
                  summary={String(lastImport.credential_issuer || lastImport.credential_offer_transport || '')}
                  open={stepIsOpen('offer')}
                  onToggle={() => toggleStep('offer')}
                >
                  <div className="space-y-0.5">
                    <MetricRow label="credential_issuer" value={String(lastImport.credential_issuer || 'n/a')} mono />
                    <MetricRow label="offer_transport" value={String(lastImport.credential_offer_transport || 'n/a')} />
                    <MetricRow label="credential_offer_uri" value={String(lastImport.credential_offer_uri || 'n/a')} mono />
                    <MetricRow label="tx_code_required" value={String(Boolean(lastImport.tx_code_required))} />
                    {lastImport.tx_code_required && (
                      <>
                        <MetricRow label="tx_code_description" value={String(lastImport.tx_code_description || 'n/a')} />
                        <MetricRow label="tx_code_length" value={String(lastImport.tx_code_length || 'n/a')} />
                        <MetricRow label="tx_code_input_mode" value={String(lastImport.tx_code_input_mode || 'n/a')} />
                      </>
                    )}
                    <MetricRow label="token_endpoint" value={String(lastImport.token_endpoint || 'n/a')} mono />
                    <MetricRow label="credential_endpoint" value={String(lastImport.credential_endpoint || 'n/a')} mono />
                    <MetricRow label="nonce_endpoint" value={String(lastImport.nonce_endpoint || 'n/a')} mono />
                  </div>
                </IssueStep>
              )}
              {protocolMode === 'oid4vp' && resolved && (
                <IssueStep
                  title="Request summary"
                  summary={String(resolved.client_id || resolved.request_id || '')}
                  open={stepIsOpen('request')}
                  onToggle={() => toggleStep('request')}
                  actions={(
                    <button type="button" className="btn-primary !inline-flex !px-2 !py-1.5 text-[11px]" onClick={() => setActiveView('review')}>
                      <ArrowRight className="w-3.5 h-3.5" /> Continue to Review
                    </button>
                  )}
                >
                  <div className="space-y-0.5">
                    <MetricRow label="request_id" value={String(resolved.request_id || 'n/a')} mono />
                    <MetricRow label="client_id" value={String(resolved.client_id || 'n/a')} mono />
                    <MetricRow label="response_mode" value={String(resolved.response_mode || 'n/a')} />
                    <MetricRow label="matched" value={String(Boolean(resolved.credential_matches?.matched))} />
                  </div>
                </IssueStep>
              )}
              {scannerActive && (
                <div className="flex items-center gap-2 text-xs text-cyan-400">
                  <Camera className="w-4 h-4 animate-pulse" /> Camera active — rear camera preferred when available
                </div>
              )}
            </motion.section>
          )}

          {activeView === 'review' && (
            <motion.section key="review" {...viewTransition} className="rounded-xl border border-white/10 bg-surface-900/20 p-3 sm:p-4 space-y-3 sm:space-y-4">
              <SectionHeading icon={FileSearch} title="Review Request" subtitle="Inspect the resolved authorization request before proceeding" />
              {!resolved && (
                <div className="flex flex-col items-center justify-center py-8 sm:py-12 text-center">
                  <FileSearch className="w-10 h-10 sm:w-12 sm:h-12 text-surface-600 mb-3" />
                  <p className="text-surface-400 text-sm">No request resolved</p>
                  <p className="text-surface-400 text-xs sm:text-sm mt-1">Resolve a request from the Home tab to inspect it here</p>
                </div>
              )}
              {resolved && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  <ReviewField label="request_id">{String(resolved.request_id || 'n/a')}</ReviewField>
                  <ReviewField label="client_id">{String(resolved.client_id || 'n/a')}</ReviewField>
                  <ReviewField label="response_mode">{String(resolved.response_mode || 'n/a')}</ReviewField>
                  <ReviewField label="response_uri">{String(resolved.response_uri || 'n/a')}</ReviewField>
                  <ReviewField label="trust">
                    <span className={`inline-flex items-center gap-1.5 ${resolved.trust?.trusted_target ? 'text-green-400' : 'text-amber-400'}`}>
                      {resolved.trust?.trusted_target ? <ShieldCheck className="w-3.5 h-3.5" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                      {resolved.trust?.trusted_target ? 'trusted target' : 'external verifier'}
                    </span>
                  </ReviewField>
                  <ReviewField label="client_id_scheme">{String(resolved.trust?.client_id_scheme || 'n/a')}</ReviewField>
                  <ReviewField label="credential_matches"><pre className="text-[11px] sm:text-xs leading-relaxed whitespace-pre-wrap font-mono">{formatJSON(resolved.credential_matches || {})}</pre></ReviewField>
                  <ReviewField label="dcql_query"><pre className="text-[11px] sm:text-xs leading-relaxed whitespace-pre-wrap font-mono">{formatJSON(resolved.dcql_query || {})}</pre></ReviewField>
                  <ReviewField label="did:web"><pre className="text-[11px] sm:text-xs leading-relaxed whitespace-pre-wrap font-mono">{formatJSON(resolved.trust?.did_web || {})}</pre></ReviewField>
                  <ReviewField label="request_object_verification"><pre className="text-[11px] sm:text-xs leading-relaxed whitespace-pre-wrap font-mono">{formatJSON(resolved.trust?.request_object_verification || {})}</pre></ReviewField>
                </div>
              )}
              {hasBlockingVerificationFailure && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 text-xs sm:text-sm text-red-300 flex items-start gap-2">
                  <XCircle className="w-4 h-4 shrink-0 mt-0.5" />
                  This request failed verifier signature or trust validation and cannot be presented until the verifier fixes it.
                </div>
              )}
              {resolved?.trust?.requires_external_approval && (
                <label className="flex items-center gap-2.5 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 cursor-pointer">
                  <input type="checkbox" checked={externalTrustApproval} onChange={(e) => setExternalTrustApproval(e.target.checked)} className="accent-amber-400 w-4 h-4 shrink-0" />
                  <span className="text-xs sm:text-sm text-amber-300">I trust this external verifier for this session</span>
                </label>
              )}
              {resolved && (
                <div className="flex flex-wrap gap-2">
                  <button className="btn-success" disabled={hasBlockingVerificationFailure} onClick={() => setActiveView('disclosure')}>
                    <ArrowRight className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Continue to Disclosure
                  </button>
                  <button className="btn-secondary" onClick={() => setActiveView('credentials')}>
                    <CreditCard className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Credentials
                  </button>
                  <button className="btn-danger" onClick={() => { resetProtocolMode(); setBanner('Request declined') }}>
                    <X className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Decline
                  </button>
                </div>
              )}
            </motion.section>
          )}

          {activeView === 'credentials' && (
            <motion.section key="credentials" {...viewTransition} className="rounded-xl border border-white/10 bg-surface-900/20 p-3 sm:p-4 space-y-3 sm:space-y-4">
              <SectionHeading
                icon={CreditCard}
                title="Credential Store"
                subtitle={
                  protocolMode === 'oid4vp'
                    ? 'Choose which session credential to present to the verifier'
                    : protocolMode === 'oid4vci'
                      ? 'Credentials imported or issued via OID4VCI in this wallet session'
                      : 'Session-scoped credentials from internal issuance or imported OID4VCI offers'
                }
              />
              {protocolMode !== 'oid4vp' && (
              <div className="flex flex-wrap items-end gap-2">
                <div className="flex flex-col gap-1">
                  <label className="text-[10px] sm:text-[11px] text-surface-500 uppercase tracking-wider" htmlFor="issue-format-select">Format</label>
                  <select id="issue-format-select" className="px-2.5 sm:px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-xs sm:text-sm text-white focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all" value={selectedIssueFormat} onChange={(e) => setSelectedIssueFormat(e.target.value)}>
                    {ISSUE_FORMAT_OPTIONS.map((opt) => <option key={opt.configurationID} value={opt.configurationID}>{opt.label}</option>)}
                  </select>
                </div>
                <button className="btn-primary" disabled={actionPending === 'issue'} onClick={() => { void issueCredential(false).catch((e: unknown) => setBanner(toErrorMessage(e), 'error')) }}>
                  <Plus className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Issue
                </button>
                <button className="btn-secondary" disabled={actionPending === 'issue'} onClick={() => { void issueCredential(true).catch((e: unknown) => setBanner(toErrorMessage(e), 'error')) }}>
                  <RotateCw className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Re-Issue
                </button>
              </div>
              )}

              <div className="rounded-lg border border-white/10 bg-surface-900/50 p-3 space-y-0.5">
                <MetricRow label="credential_count" value={String(credentialEntries.length)} />
                <MetricRow label="active_credential_id" value={String(activeCredentialEntry?.credential_id || session?.credential_id || 'n/a')} mono />
                <MetricRow label="active_format" value={String(activeCredentialEntry?.credential_format || session?.credential_format || credentialSummary?.format || 'n/a')} />
                <MetricRow label="active_configuration" value={String(activeCredentialEntry?.credential_configuration_id || session?.credential_configuration_id || 'n/a')} />
              </div>

              {credentialEntries.length > 0 && (
                <div className="grid grid-cols-1 xs:grid-cols-2 md:grid-cols-3 gap-2">
                  {credentialEntries.map((entry, index) => {
                    const entryID = String(entry.credential_id || '').trim()
                    const isSelected = entryID !== '' && entryID === String(activeCredentialEntry?.credential_id || '').trim()
                    return (
                      <button
                        key={entryID || `credential-${index}`}
                        type="button"
                        className={`flex flex-col gap-1 rounded-lg border p-2.5 text-left transition-all text-[11px] cursor-pointer ${
                          isSelected
                            ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300 ring-1 ring-cyan-500/20'
                            : 'border-white/10 bg-surface-900/40 text-surface-300 hover:border-white/20 hover:bg-surface-900/60'
                        }`}
                        onClick={() => setSelectedCredentialID(entryID)}
                      >
                        <span className="font-medium truncate">{String(entry.credential_format || entry.credential_summary?.format || 'credential')}</span>
                        {entry.credential_configuration_id && <span className="text-[10px] text-surface-500 truncate">{String(entry.credential_configuration_id)}</span>}
                      </button>
                    )
                  })}
                </div>
              )}

              <div className="rounded-lg border border-white/10 bg-surface-900/50 p-3 space-y-0.5">
                <MetricRow label="wallet_subject" value={String(session?.wallet_subject || 'n/a')} mono />
                <MetricRow label="wallet_scope" value={String(session?.wallet_scope || 'n/a')} />
                <MetricRow label="wallet_did_method" value={String(session?.wallet_did_method || 'n/a')} />
                <MetricRow label="credential_present" value={String(Boolean(session?.credential_present))} />
                <MetricRow label="format" value={String(credentialSummary?.format || 'n/a')} />
                <MetricRow label="vct" value={String(credentialSummary?.vct || 'n/a')} mono />
                <MetricRow label="doctype" value={String(credentialSummary?.doctype || 'n/a')} mono />
                <MetricRow label="subject" value={String(credentialSummary?.subject || 'n/a')} mono />
                <MetricRow label="expires_at" value={String(credentialSummary?.expires_at || 'n/a')} />
                <MetricRow label="sd_jwt" value={String(Boolean(credentialSummary?.is_sd_jwt))} />
                <MetricRow label="disclosure_count" value={String(Number(credentialSummary?.disclosure_count || 0))} />
                <MetricRow label="key_binding_jwt" value={String(Boolean(credentialSummary?.key_binding_jwt))} />
                <MetricRow label="disclosure_claims" value={availableDisclosureClaims.length > 0 ? availableDisclosureClaims.join(', ') : 'none'} />
              </div>

              <div className="flex flex-col gap-2">
                <div className="flex items-center gap-2">
                  <Expandable title="Credential JWT" icon={FileCode2}>
                    {String(session?.credential_jwt || '')}
                  </Expandable>
                </div>
                {session?.credential_jwt && <CopyButton text={String(session.credential_jwt)} />}
              </div>

              <Expandable title="Decoded Credential Claims" icon={FileCode2}>
                {formatJSON(credentialSummary?.claims || {})}
              </Expandable>

              {lastImport && (
                <>
                  <Expandable title="Last Imported Offer" icon={Download}>
                    {formatJSON({
                      credential_offer_uri: lastImport.credential_offer_uri || '',
                      credential_offer_transport: lastImport.credential_offer_transport || '',
                      credential_issuer: lastImport.credential_issuer || '',
                      tx_code_required: Boolean(lastImport.tx_code_required),
                      tx_code_description: lastImport.tx_code_description || '',
                      tx_code_length: lastImport.tx_code_length || 0,
                      tx_code_input_mode: lastImport.tx_code_input_mode || '',
                      credential_offer: lastImport.credential_offer || {},
                    })}
                  </Expandable>
                  <Expandable title="Last Imported Issuer Metadata" icon={FileCode2}>
                    {formatJSON({
                      issuer_metadata: lastImport.issuer_metadata || {},
                      authorization_server_metadata: lastImport.authorization_server_metadata || {},
                      token_endpoint: lastImport.token_endpoint || '',
                      credential_endpoint: lastImport.credential_endpoint || '',
                      nonce_endpoint: lastImport.nonce_endpoint || '',
                    })}
                  </Expandable>
                </>
              )}
            </motion.section>
          )}

          {activeView === 'disclosure' && (
            <motion.section key="disclosure" {...viewTransition} className="rounded-xl border border-white/10 bg-surface-900/20 p-3 sm:p-4 space-y-3 sm:space-y-4">
              <SectionHeading
                icon={Eye}
                title="Selective Disclosure"
                subtitle={supportsSelectiveDisclosure
                  ? 'Select SD-JWT claims the wallet should disclose in the VP token'
                  : 'Current credential format does not use selective disclosure and will be presented as-is'}
              />
              {availableDisclosureClaims.length === 0 && (
                <div className="flex flex-col items-center justify-center py-8 sm:py-12 text-center">
                  <Eye className="w-10 h-10 sm:w-12 sm:h-12 text-surface-600 mb-3" />
                  <p className="text-surface-400 text-sm">No selective disclosure claims available</p>
                  <p className="text-surface-400 text-xs sm:text-sm mt-1">Issue or import an SD-JWT credential to select claims</p>
                </div>
              )}
              {supportsSelectiveDisclosure && availableDisclosureClaims.length > 0 && (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                  {availableDisclosureClaims.map((claim) => {
                    const checked = selectedDisclosureClaims.includes(claim)
                    return (
                      <label
                        key={claim}
                        className={`flex items-center gap-2.5 rounded-lg border p-2.5 text-xs cursor-pointer transition-all ${
                          checked
                            ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300'
                            : 'border-white/10 bg-surface-900/40 text-surface-300 hover:border-white/20'
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={(e) => {
                            setSelectedDisclosureClaims((prev) =>
                              e.target.checked ? Array.from(new Set([...prev, claim])).sort() : prev.filter((c) => c !== claim),
                            )
                          }}
                          className="accent-cyan-400 w-3.5 h-3.5 shrink-0"
                        />
                        <div className="min-w-0">
                          <div className="font-medium truncate">{claim}</div>
                          {CLAIM_DESCRIPTIONS[claim] && <div className="text-[10px] text-surface-500 mt-0.5">{CLAIM_DESCRIPTIONS[claim]}</div>}
                        </div>
                      </label>
                    )
                  })}
                </div>
              )}
              <div className="flex flex-wrap gap-2">
                <button className="btn-primary" disabled={actionPending === 'preview'} onClick={() => { void previewPresentation().catch((e: unknown) => setBanner(toErrorMessage(e), 'error')) }}>
                  <Eye className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Build VP Preview
                </button>
                <button className="btn-secondary" onClick={() => setActiveView('present')}>
                  <Send className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Go to Present
                </button>
              </div>
            </motion.section>
          )}

          {activeView === 'present' && (
            <motion.section key="present" {...viewTransition} className="rounded-xl border border-white/10 bg-surface-900/20 p-3 sm:p-4 space-y-3 sm:space-y-4">
              <SectionHeading icon={Send} title="Present Credential" subtitle="Submit a real OID4VP wallet response to the verifier response endpoint" />
              <div className="flex flex-wrap gap-2">
                <button className="btn-success" disabled={actionPending === 'present'} onClick={() => { void presentCredential().catch((e: unknown) => setBanner(toErrorMessage(e), 'error')) }}>
                  <Send className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Submit Presentation
                </button>
                <button className="btn-secondary" disabled={actionPending === 'preview'} onClick={() => { void previewPresentation().catch((e: unknown) => setBanner(toErrorMessage(e), 'error')) }}>
                  <RefreshCw className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Refresh Preview
                </button>
              </div>
              <Expandable title="VP Token Preview" icon={FileCode2} defaultOpen>
                {String(preview?.vp_token || '')}
              </Expandable>
            </motion.section>
          )}

          {activeView === 'result' && (
            <motion.section key="result" {...viewTransition} className="rounded-xl border border-white/10 bg-surface-900/20 p-3 sm:p-4 space-y-3 sm:space-y-4">
              <SectionHeading icon={CheckCircle2} title="Result" subtitle="HTTP outcome from response_uri (verifier redirect or Looking Glass policy)" />
              {!result && (
                <div className="flex flex-col items-center justify-center py-8 sm:py-12 text-center">
                  <CheckCircle2 className="w-10 h-10 sm:w-12 sm:h-12 text-surface-600 mb-3" />
                  <p className="text-surface-400 text-sm">No presentation submitted yet</p>
                  <p className="text-surface-400 text-xs sm:text-sm mt-1">Present a credential to see the verifier&apos;s evaluation</p>
                </div>
              )}
              {result && (
                <>
                  <div className={`rounded-lg border p-3 flex items-center gap-2.5 text-xs sm:text-sm font-medium ${
                    resultAllowed
                      ? 'border-green-500/30 bg-green-500/5 text-green-300'
                      : 'border-red-500/30 bg-red-500/5 text-red-300'
                  }`}>
                    {resultAllowed ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                    {resultTitle}
                    <span className="ml-auto text-surface-400 font-normal font-mono text-xs">HTTP {String(result.upstream_status || 'n/a')}</span>
                  </div>
                  <div className="rounded-lg border border-white/10 bg-surface-900/50 p-3 space-y-0.5">
                    <MetricRow label="request_id" value={String(result.request_id || 'n/a')} mono />
                    <MetricRow label="response_mode" value={String(result.response_mode || 'n/a')} />
                    <MetricRow label="response_uri" value={String(result.response_uri || 'n/a')} mono />
                    <MetricRow label="credential_source" value={String(result.credential_source || 'n/a')} />
                    <MetricRow label="policy_reasons" value={policyReasons.length > 0 ? policyReasons.join(', ') : 'none'} />
                  </div>
                  {result.credential_matches && (
                    <Expandable title="Credential Matching" icon={FileSearch}>
                      {formatJSON(result.credential_matches)}
                    </Expandable>
                  )}
                  <Expandable title="Verifier Response" icon={FileCode2} defaultOpen>
                    {formatJSON(result.upstream_body || {})}
                  </Expandable>
                </>
              )}
            </motion.section>
          )}
        </AnimatePresence>

        {/* Protocol Details */}
        <section className="rounded-xl border border-white/10 bg-surface-900/30 overflow-hidden">
          <div className="px-3 sm:px-5 py-3 sm:py-4 border-b border-white/10">
            <div className="flex items-center gap-2.5">
              <div className="rounded-lg bg-gradient-to-br from-orange-500/15 to-purple-500/15 p-2">
                <FileCode2 className="w-4 h-4 text-orange-400" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-white">Protocol Details</h2>
                <p className="text-[10px] sm:text-xs text-surface-500">
                  {protocolMode === 'oid4vci'
                    ? 'OID4VCI transparency: offer, issuer metadata, and authorization-server discovery'
                    : protocolMode === 'oid4vp'
                      ? 'OID4VP transparency: request objects, trust context, and VP construction artifacts'
                      : 'OID4VP and OID4VCI transparency: request objects, offers, trust context, and VP artifacts'}
                </p>
              </div>
            </div>
          </div>
          <div className="p-3 sm:p-4 space-y-3">
            {protocolMode === 'oid4vci' ? (
              !lastImport ? (
                <div className="flex flex-col items-center justify-center py-8 sm:py-12 text-center">
                  <FileCode2 className="w-10 h-10 sm:w-12 sm:h-12 text-surface-600 mb-3" />
                  <p className="text-surface-400 text-sm">No offer data yet</p>
                  <p className="text-surface-400 text-xs sm:text-sm mt-1">Import a credential offer to inspect issuer and AS metadata</p>
                </div>
              ) : (
                <>
                  <Expandable title="Credential Offer" icon={Download} defaultOpen>
                    {formatJSON({
                      credential_offer_uri: lastImport.credential_offer_uri || '',
                      credential_offer_transport: lastImport.credential_offer_transport || '',
                      credential_issuer: lastImport.credential_issuer || '',
                      credential_offer: lastImport.credential_offer || {},
                    })}
                  </Expandable>
                  <Expandable title="Issuer + AS Metadata" icon={FileCode2}>
                    {formatJSON({
                      issuer_metadata: lastImport.issuer_metadata || {},
                      authorization_server_metadata: lastImport.authorization_server_metadata || {},
                      token_endpoint: lastImport.token_endpoint || '',
                      credential_endpoint: lastImport.credential_endpoint || '',
                      nonce_endpoint: lastImport.nonce_endpoint || '',
                    })}
                  </Expandable>
                </>
              )
            ) : !resolved && !preview ? (
              <div className="flex flex-col items-center justify-center py-8 sm:py-12 text-center">
                <FileCode2 className="w-10 h-10 sm:w-12 sm:h-12 text-surface-600 mb-3" />
                <p className="text-surface-400 text-sm">No protocol data yet</p>
                <p className="text-surface-400 text-xs sm:text-sm mt-1">
                  {protocolMode === 'oid4vp' ? 'Resolve a request to see JWT objects, headers, and payloads' : 'Resolve a request or import an offer to inspect protocol artifacts'}
                </p>
              </div>
            ) : (
              <>
                <Expandable title="Request Object (JWT)" icon={FileCode2} defaultOpen>
                  {String(resolved?.request || '')}
                </Expandable>
                <Expandable title="Request Header + Payload" icon={FileCode2}>
                  {formatJSON({ header: resolved?.request_header || {}, payload: resolved?.request_payload || {}, trust: resolved?.trust || {} })}
                </Expandable>
                <Expandable title={preview?.vp_document ? 'VP Document (Data Integrity)' : 'VP Header + Payload'} icon={FileCode2}>
                  {preview?.vp_document
                    ? formatJSON({ document: preview.vp_document, proof: preview.vp_proof || {} })
                    : formatJSON({ header: preview?.vp_header || {}, payload: preview?.vp_payload || {} })}
                </Expandable>
              </>
            )}
          </div>
        </section>

        {/* Footer */}
        <footer className="border-t border-white/5 pt-4 pb-2 flex items-center justify-between text-[10px] text-surface-600">
          <span>Protocol Soup Wallet</span>
          <a href="https://protocolsoup.com" target="_blank" rel="noopener noreferrer" className="hover:text-surface-400 transition-colors">protocolsoup.com</a>
        </footer>
      </div>

      {/* Scanner Modal */}
      <AnimatePresence>
        {scannerOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
            role="dialog"
            aria-modal="true"
            aria-labelledby="scannerModalTitle"
            onClick={(e) => { if (e.target === e.currentTarget) void stopScanner('Scanner closed') }}
          >
            <motion.div
              initial={{ scale: 0.96, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.96, opacity: 0 }}
              transition={{ duration: 0.16 }}
              className="w-full max-w-lg rounded-xl border border-white/10 bg-surface-900 shadow-2xl flex flex-col gap-3 p-4 max-h-[92vh]"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="rounded-lg bg-gradient-to-br from-cyan-500/20 to-purple-500/20 p-2">
                    <QrCode className="w-4 h-4 text-cyan-400" />
                  </div>
                  <h3 id="scannerModalTitle" className="text-sm font-medium text-white">Scan QR Code</h3>
                </div>
                <button className="btn-secondary !px-2 !py-1.5" onClick={() => { void stopScanner('Scanner closed') }}>
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
              <p className="text-[10px] text-surface-400">Hold the QR inside the frame. Camera stops automatically once a valid payload is detected.</p>
              <div ref={scannerViewportRef} className="rounded-lg border border-white/10 bg-black min-h-[300px] max-h-[60vh] overflow-hidden [&_video]:w-full [&_video]:h-full [&_video]:object-cover [&_canvas]:w-full [&_canvas]:h-full [&_canvas]:object-cover" />
              <div className="flex justify-end">
                <button className="btn-secondary" disabled={!scannerActive} onClick={() => { void stopScanner('Scanner stopped') }}>
                  <Camera className="w-3.5 h-3.5" /> Stop Camera
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </main>
  )
}
