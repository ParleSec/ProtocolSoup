import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import {
  Wallet, Home, FileSearch, CreditCard, Eye, Send, CheckCircle2,
  QrCode, Search, Download, RefreshCw, Plus, RotateCw,
  X, ChevronDown, ShieldCheck, ShieldAlert, AlertTriangle,
  XCircle, Info, Camera, ArrowRight, Copy, ExternalLink, FileCode2,
} from 'lucide-react'
import { createWalletScanner } from './scanner'

type WalletView = 'home' | 'review' | 'credentials' | 'disclosure' | 'present' | 'result'
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
}

const VIEW_TABS: Array<{ id: WalletView; label: string; icon: typeof Home }> = [
  { id: 'home', label: 'Home', icon: Home },
  { id: 'review', label: 'Review', icon: FileSearch },
  { id: 'credentials', label: 'Credentials', icon: CreditCard },
  { id: 'disclosure', label: 'Disclosure', icon: Eye },
  { id: 'present', label: 'Present', icon: Send },
  { id: 'result', label: 'Result', icon: CheckCircle2 },
]

const CLAIM_DESCRIPTIONS: Record<string, string> = {
  degree: 'University degree name',
  gpa: 'Grade point average',
  university: 'Issuing institution',
  graduation_year: 'Year of graduation',
  honors: 'Academic honors',
}

const ISSUE_FORMAT_OPTIONS: Array<{ format: string; configurationID: string; label: string }> = [
  { format: 'dc+sd-jwt', configurationID: 'UniversityDegreeCredential', label: 'dc+sd-jwt' },
  { format: 'jwt_vc_json', configurationID: 'UniversityDegreeCredentialJWT', label: 'jwt_vc_json' },
  { format: 'jwt_vc_json-ld', configurationID: 'UniversityDegreeCredentialJWTLD', label: 'jwt_vc_json-ld' },
  { format: 'ldp_vc', configurationID: 'UniversityDegreeCredentialLDP', label: 'ldp_vc' },
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

function buildResolvePayloadFromInput(rawInput: string): Record<string, string> {
  const trimmed = rawInput.trim()
  if (!trimmed) throw new Error('Provide openid4vp URI or request_uri')
  if (trimmed.startsWith('openid4vp://')) return { openid4vp_uri: trimmed }
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) return { request_uri: trimmed }
  return { request: trimmed }
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
  if (!trimmed) throw new Error('Provide an OID4VCI offer, raw VC JWT, or JSON-LD credential')
  const payload: Record<string, string> = {}
  if (looksLikeCredentialOfferInput(trimmed)) {
    payload.offer = trimmed
    if (txCode.trim()) payload.tx_code = txCode.trim()
    return payload
  }
  if (looksLikeRawCredentialInput(trimmed)) {
    payload.credential = trimmed
    return payload
  }
  throw new Error('Input is not a recognized OID4VCI offer or verifiable credential')
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

  const [activeView, setActiveView] = useState<WalletView>('home')
  const [statusBanner, setStatusBanner] = useState<{ message: string; level: BannerLevel } | null>(null)
  const [session, setSession] = useState<SessionPayload | null>(null)
  const [walletSessionID, setWalletSessionID] = useState('')
  const [selectedCredentialID, setSelectedCredentialID] = useState('')
  const [selectedIssueFormat, setSelectedIssueFormat] = useState(ISSUE_FORMAT_OPTIONS[0]?.format || 'dc+sd-jwt')
  const [uriInput, setURIInput] = useState('')
  const [importTxCodeInput, setImportTxCodeInput] = useState('')
  const [resolved, setResolved] = useState<ResolveResponse | null>(null)
  const [preview, setPreview] = useState<PreviewResponse | null>(null)
  const [result, setResult] = useState<PresentResponse | null>(null)
  const [lastImport, setLastImport] = useState<ImportResponse | null>(null)
  const [pendingAuthorizationURL, setPendingAuthorizationURL] = useState('')
  const [selectedDisclosureClaims, setSelectedDisclosureClaims] = useState<string[]>([])
  const [externalTrustApproval, setExternalTrustApproval] = useState(false)
  const [scannerOpen, setScannerOpen] = useState(false)
  const [scannerActive, setScannerActive] = useState(false)
  const [scannerStartRequestID, setScannerStartRequestID] = useState(0)
  const [resolveInFlight, setResolveInFlight] = useState(false)
  const [actionPending, setActionPending] = useState<'refresh' | 'issue' | 'import' | 'preview' | 'present' | ''>('')

  const setBanner = useCallback((message: string, level: BannerLevel = 'info') => {
    const normalized = String(message || '').trim()
    if (!normalized) { setStatusBanner(null); return }
    setStatusBanner({ message: normalized, level })
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

  const apiRequest = useCallback(
    async <TResponse,>(endpoint: string, method: 'GET' | 'POST', payload?: unknown): Promise<TResponse> => {
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
        let errorDescription = String(payloadObject.error_description || payloadObject.error || `Request failed with HTTP ${response.status}`)
        if (payloadObject.tx_code_required) {
          const txCodeHints = [
            String(payloadObject.tx_code_description || '').trim(),
            payloadObject.tx_code_length ? `Length: ${String(payloadObject.tx_code_length)}` : '',
            String(payloadObject.tx_code_input_mode || '').trim() ? `Input mode: ${String(payloadObject.tx_code_input_mode).trim()}` : '',
          ].filter(Boolean)
          if (txCodeHints.length > 0) errorDescription = `${errorDescription} (${txCodeHints.join(', ')})`
        }
        throw new Error(errorDescription)
      }
      return body as TResponse
    },
    [walletSessionID],
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

  const clearResolvedState = useCallback(() => {
    setResolved(null); setPreview(null); setResult(null)
    setPendingAuthorizationURL(''); setSelectedDisclosureClaims([]); setExternalTrustApproval(false)
  }, [])

  const resolveRequest = useCallback(
    async (rawInput: string) => {
      if (resolveInFlightRef.current) return
      resolveInFlightRef.current = true
      setResolveInFlight(true)
      setBanner('Resolving request object')
      try {
        const payload = buildResolvePayloadFromInput(rawInput)
        const response = await apiRequest<ResolveResponse>('/api/resolve', 'POST', payload)
        setResolved(response); setPreview(null); setResult(null)
        setPendingAuthorizationURL(''); setSelectedDisclosureClaims([]); setExternalTrustApproval(false)
        setActiveView('review')
        setBanner('Request object resolved', 'success')
      } finally { resolveInFlightRef.current = false; setResolveInFlight(false) }
    },
    [apiRequest, setBanner],
  )

  const importCredentialOffer = useCallback(
    async (rawInput: string) => {
      setActionPending('import')
      setBanner('Importing credential into wallet')
      try {
        const payload = buildImportPayloadFromInput(rawInput, importTxCodeInput)
        const response = await apiRequest<ImportResponse>('/api/import', 'POST', payload)
        if (response.authorization_required && response.authorization_url) {
          setPendingAuthorizationURL(resolveAuthorizationRedirectTarget(response))
          setBanner('Issuer authorization required. Review the destination and continue when ready.', 'info')
          return
        }
        setPendingAuthorizationURL('')
        setSession((previous) => mergeCredentialSession(previous, response))
        setLastImport(response); setPreview(null); setResult(null); setSelectedDisclosureClaims([])
        if (response.credential_id) setSelectedCredentialID(String(response.credential_id))
        setActiveView('credentials')
        setBanner(`Credential imported from ${String(response.credential_issuer || response.credential_source || 'wallet import')}`, 'success')
      } finally { setActionPending('') }
    },
    [apiRequest, importTxCodeInput, setBanner],
  )

  const routeWalletInput = useCallback(
    async (rawInput: string) => {
      if (looksLikeCredentialOfferInput(rawInput) || looksLikeRawCredentialInput(rawInput)) { await importCredentialOffer(rawInput); return }
      await resolveRequest(rawInput)
    },
    [importCredentialOffer, resolveRequest],
  )

  const buildWalletPayload = useCallback(() => {
    if (!resolved) throw new Error('Resolve a request first')
    const selectedFormatEntry = ISSUE_FORMAT_OPTIONS.find((option) => option.format === selectedIssueFormat) || ISSUE_FORMAT_OPTIONS[0]
    const activeCredentialID = String(activeCredentialEntry?.credential_id || selectedCredentialID || '').trim()
    return {
      request_id: String(resolved.request_id || ''),
      request: String(resolved.request || ''),
      request_uri: String(resolved.request_uri || ''),
      credential_id: activeCredentialID,
      credential_format: String(activeCredentialEntry?.credential_format || selectedFormatEntry?.format || ''),
      credential_configuration_id: String(activeCredentialEntry?.credential_configuration_id || selectedFormatEntry?.configurationID || ''),
      disclosure_claims: selectedDisclosureClaims,
      approve_external_trust: externalTrustApproval,
    }
  }, [activeCredentialEntry, externalTrustApproval, resolved, selectedCredentialID, selectedDisclosureClaims, selectedIssueFormat])

  const issueCredential = useCallback(
    async (forceIssue: boolean) => {
      setActionPending('issue')
      setBanner('Issuing credential via OID4VCI')
      try {
        const selectedFormatEntry = ISSUE_FORMAT_OPTIONS.find((option) => option.format === selectedIssueFormat) || ISSUE_FORMAT_OPTIONS[0]
        const response = await apiRequest<SessionPayload>('/api/issue', 'POST', {
          force_issue: forceIssue,
          credential_format: selectedFormatEntry?.format,
          credential_configuration_id: selectedFormatEntry?.configurationID,
          credential_id: selectedCredentialID || undefined,
        })
        setSession((previous) => mergeCredentialSession(previous, response))
        if (response.credential_id) setSelectedCredentialID(String(response.credential_id))
        setActiveView('credentials')
        setBanner(`Credential ready from ${String(response.credential_source || 'wallet')}`, 'success')
      } finally { setActionPending('') }
    },
    [apiRequest, selectedCredentialID, selectedIssueFormat, setBanner],
  )

  const hasBlockingVerificationFailure = Boolean(resolved?.trust?.request_object_verification && !resolved?.trust?.request_object_verification?.verified)

  const previewPresentation = useCallback(async () => {
    setActionPending('preview')
    setBanner('Building VP token preview')
    try {
      const payload = buildWalletPayload()
      const response = await apiRequest<PreviewResponse>('/api/preview', 'POST', payload)
      setPreview(response); setActiveView('present')
      setBanner('VP preview ready', 'success')
    } finally { setActionPending('') }
  }, [apiRequest, buildWalletPayload, setBanner])

  const presentCredential = useCallback(async () => {
    setActionPending('present')
    setBanner('Submitting presentation to verifier')
    try {
      const payload = buildWalletPayload()
      const response = await apiRequest<PresentResponse>('/api/present', 'POST', payload)
      setResult(response); setActiveView('result')
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
          setPendingAuthorizationURL('')
          await refreshSession()
          if (cancelled) return
          if (oid4vciStatus === 'success') { setActiveView('credentials'); setBanner(firstNonEmptyString(oid4vciMessage, 'Credential imported'), 'success') }
          else setBanner(firstNonEmptyString(oid4vciMessage, 'OID4VCI authorization failed'), 'error')
          window.history.replaceState({}, document.title, window.location.pathname)
          return
        }
        const initialOfferURI = String(query.get('credential_offer_uri') || '').trim()
        const initialOffer = String(query.get('credential_offer') || '').trim()
        if (initialOfferURI || initialOffer) {
          const importInput = window.location.href
          setURIInput(importInput)
          await importCredentialOffer(importInput)
          return
        }
        const initialURI = String(query.get('uri') || query.get('request_uri') || '').trim()
        if (!initialURI) return
        setURIInput(initialURI)
        await resolveRequest(initialURI)
      } catch (error) { if (!cancelled) setBanner(toErrorMessage(error), 'error') }
    }
    void init()
    return () => { cancelled = true }
  }, [importCredentialOffer, refreshSession, resolveRequest, setBanner])

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

  const resultAllowed = Boolean(result?.upstream_body?.result && typeof result.upstream_body.result === 'object' && (result.upstream_body.result as Record<string, unknown>)?.policy && typeof (result.upstream_body.result as Record<string, unknown>).policy === 'object' && ((result.upstream_body.result as Record<string, unknown>).policy as Record<string, unknown>)?.allowed)

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
                  Ephemeral OID4VP and OID4VCI web wallet with real key material, external offer import, and full protocol visibility
                </p>
              </div>
            </div>
            <p className="text-[10px] sm:text-[11px] text-surface-500">No credential data is persisted beyond this wallet session</p>
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
          {VIEW_TABS.map((tab) => {
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
              <SectionHeading icon={Home} title="Wallet Input" subtitle="Paste an openid4vp:// request, openid-credential-offer:// offer, https:// deeplink, raw VC JWT, or JSON-LD credential" />
              <textarea
                className="glass-input min-h-[120px] resize-y"
                value={uriInput}
                onChange={(event) => setURIInput(event.target.value)}
                placeholder="openid4vp://authorize?request_uri=...&#10;openid-credential-offer://?credential_offer_uri=...&#10;eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK2p3dCJ9..."
              />
              <input
                className="glass-input"
                type="text"
                value={importTxCodeInput}
                onChange={(event) => setImportTxCodeInput(event.target.value)}
                placeholder="Optional tx_code for OID4VCI pre-authorized offers"
              />
              <div className="flex flex-wrap gap-2">
                <button className="btn-primary" disabled={resolveInFlight} onClick={() => { void resolveRequest(uriInput).catch((e: unknown) => setBanner(toErrorMessage(e), 'error')) }}>
                  <Search className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Resolve
                </button>
                <button className="btn-secondary" disabled={actionPending === 'import'} onClick={() => { void importCredentialOffer(uriInput).catch((e: unknown) => setBanner(toErrorMessage(e), 'error')) }}>
                  <Download className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Import
                </button>
                <button className="btn-secondary" disabled={actionPending === 'refresh'} onClick={() => { void refreshSession().catch((e: unknown) => setBanner(toErrorMessage(e), 'error')) }}>
                  <RefreshCw className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Refresh
                </button>
                <button className="btn-secondary" disabled={scannerActive} onClick={() => { setScannerOpen(true); setScannerStartRequestID((p) => p + 1) }}>
                  <QrCode className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Scan QR
                </button>
              </div>
              {pendingAuthorizationURL && (
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 space-y-2">
                  <div className="flex items-center gap-2 text-xs sm:text-sm font-medium text-amber-300">
                    <AlertTriangle className="w-4 h-4 shrink-0" /> Issuer authorization required
                  </div>
                  <div className="text-[11px] sm:text-xs text-surface-400 break-all font-mono">{pendingAuthorizationURL}</div>
                  <a className="btn-primary !inline-flex w-fit" href={pendingAuthorizationURL} rel="noreferrer">
                    <ExternalLink className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Continue to Issuer
                  </a>
                </div>
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
                  <button className="btn-danger" onClick={() => { clearResolvedState(); setActiveView('home'); setBanner('Request declined') }}>
                    <X className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Decline
                  </button>
                </div>
              )}
            </motion.section>
          )}

          {activeView === 'credentials' && (
            <motion.section key="credentials" {...viewTransition} className="rounded-xl border border-white/10 bg-surface-900/20 p-3 sm:p-4 space-y-3 sm:space-y-4">
              <SectionHeading icon={CreditCard} title="Credential Store" subtitle="Session-scoped credentials from internal issuance or imported OID4VCI offers" />
              <div className="flex flex-wrap items-end gap-2">
                <div className="flex flex-col gap-1">
                  <label className="text-[10px] sm:text-[11px] text-surface-500 uppercase tracking-wider" htmlFor="issue-format-select">Format</label>
                  <select id="issue-format-select" className="px-2.5 sm:px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-xs sm:text-sm text-white focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all" value={selectedIssueFormat} onChange={(e) => setSelectedIssueFormat(e.target.value)}>
                    {ISSUE_FORMAT_OPTIONS.map((opt) => <option key={opt.format} value={opt.format}>{opt.label}</option>)}
                  </select>
                </div>
                <button className="btn-primary" disabled={actionPending === 'issue'} onClick={() => { void issueCredential(false).catch((e: unknown) => setBanner(toErrorMessage(e), 'error')) }}>
                  <Plus className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Issue
                </button>
                <button className="btn-secondary" disabled={actionPending === 'issue'} onClick={() => { void issueCredential(true).catch((e: unknown) => setBanner(toErrorMessage(e), 'error')) }}>
                  <RotateCw className="w-3.5 h-3.5 sm:w-4 sm:h-4" /> Re-Issue
                </button>
              </div>

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
              <SectionHeading icon={CheckCircle2} title="Result" subtitle="Verifier evaluation of the submitted presentation" />
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
                    {resultAllowed ? 'Presentation accepted' : 'Presentation denied'}
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
                <p className="text-[10px] sm:text-xs text-surface-500">OID4VP and OID4VCI transparency: request objects, trust context, and VP construction artifacts</p>
              </div>
            </div>
          </div>
          <div className="p-3 sm:p-4 space-y-3">
            {!resolved && !preview ? (
              <div className="flex flex-col items-center justify-center py-8 sm:py-12 text-center">
                <FileCode2 className="w-10 h-10 sm:w-12 sm:h-12 text-surface-600 mb-3" />
                <p className="text-surface-400 text-sm">No protocol data yet</p>
                <p className="text-surface-400 text-xs sm:text-sm mt-1">Resolve a request to see JWT objects, headers, and payloads</p>
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
