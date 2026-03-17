import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createWalletScanner } from './scanner'

type WalletView = 'home' | 'review' | 'credentials' | 'disclosure' | 'present' | 'result'
type BannerLevel = 'info' | 'success' | 'error'

type CredentialSummary = {
  subject?: string
  expires_at?: string
  is_sd_jwt?: boolean
  vct?: string
  disclosure_claims?: string[]
  disclosure_count?: number
  key_binding_jwt?: boolean
  claims?: Record<string, unknown>
}

type SessionPayload = {
  app_title?: string
  wallet_session_id?: string
  wallet_subject?: string
  wallet_scope?: string
  wallet_key_id?: string
  wallet_key_thumbprint?: string
  wallet_session_ttl_seconds?: number
  wallet_session_expires_in?: number
  credential_present?: boolean
  credential_jwt?: string
  credential_source?: string
  credential_summary?: CredentialSummary
}

type TrustPayload = {
  trusted_target?: boolean
  requires_external_approval?: boolean
  allow_external_verifiers?: boolean
  client_id_scheme?: string
  did_web?: Record<string, unknown>
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
  disclosure_claims?: string[]
  vp_token?: string
  vp_header?: Record<string, unknown>
  vp_payload?: Record<string, unknown>
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
  disclosure_claims?: string[]
  upstream_status?: number
  upstream_body?: Record<string, unknown>
  trust?: TrustPayload
}

const VIEW_TABS: Array<{ id: WalletView; label: string }> = [
  { id: 'home', label: 'Home' },
  { id: 'review', label: 'Review' },
  { id: 'credentials', label: 'Credentials' },
  { id: 'disclosure', label: 'Disclosure' },
  { id: 'present', label: 'Present' },
  { id: 'result', label: 'Result' },
]

const CLAIM_DESCRIPTIONS: Record<string, string> = {
  degree: 'University degree name',
  gpa: 'Grade point average',
  university: 'Issuing institution',
  graduation_year: 'Year of graduation',
  honors: 'Academic honors',
}

function formatJSON(value: unknown): string {
  if (value === undefined || value === null) {
    return ''
  }
  if (typeof value === 'string') {
    return value
  }
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

function toErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }
  return String(error || 'Unexpected error')
}

function buildResolvePayloadFromInput(rawInput: string): Record<string, string> {
  const trimmed = rawInput.trim()
  if (!trimmed) {
    throw new Error('Provide openid4vp URI or request_uri')
  }
  if (trimmed.startsWith('openid4vp://')) {
    return { openid4vp_uri: trimmed }
  }
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    return { request_uri: trimmed }
  }
  return { request: trimmed }
}

function normalizeClaims(rawClaims: unknown): string[] {
  if (!Array.isArray(rawClaims)) {
    return []
  }
  return rawClaims.map((claim) => String(claim).trim()).filter(Boolean)
}

export default function WalletApp() {
  const scanner = useMemo(() => createWalletScanner(), [])
  const scannerViewportRef = useRef<HTMLDivElement | null>(null)
  const resolveInFlightRef = useRef(false)

  const [activeView, setActiveView] = useState<WalletView>('home')
  const [statusBanner, setStatusBanner] = useState<{ message: string; level: BannerLevel } | null>(null)
  const [session, setSession] = useState<SessionPayload | null>(null)
  const [walletSessionID, setWalletSessionID] = useState('')
  const [uriInput, setURIInput] = useState('')
  const [resolved, setResolved] = useState<ResolveResponse | null>(null)
  const [preview, setPreview] = useState<PreviewResponse | null>(null)
  const [result, setResult] = useState<PresentResponse | null>(null)
  const [selectedDisclosureClaims, setSelectedDisclosureClaims] = useState<string[]>([])
  const [externalTrustApproval, setExternalTrustApproval] = useState(false)
  const [scannerOpen, setScannerOpen] = useState(false)
  const [scannerActive, setScannerActive] = useState(false)
  const [scannerStartRequestID, setScannerStartRequestID] = useState(0)
  const [resolveInFlight, setResolveInFlight] = useState(false)
  const [actionPending, setActionPending] = useState<'refresh' | 'issue' | 'preview' | 'present' | ''>('')

  const setBanner = useCallback((message: string, level: BannerLevel = 'info') => {
    const normalized = String(message || '').trim()
    if (!normalized) {
      setStatusBanner(null)
      return
    }
    setStatusBanner({ message: normalized, level })
  }, [])

  const availableDisclosureClaims = useMemo(() => {
    const rawClaims = session?.credential_summary?.disclosure_claims
    return normalizeClaims(rawClaims)
  }, [session?.credential_summary?.disclosure_claims])

  useEffect(() => {
    setSelectedDisclosureClaims((previous) => previous.filter((claim) => availableDisclosureClaims.includes(claim)))
  }, [availableDisclosureClaims])

  useEffect(() => {
    if (!resolved?.trust?.requires_external_approval) {
      setExternalTrustApproval(false)
    }
  }, [resolved?.trust?.requires_external_approval])

  const apiRequest = useCallback(
    async <TResponse,>(endpoint: string, method: 'GET' | 'POST', payload?: unknown): Promise<TResponse> => {
      const headers: Record<string, string> = {
        Accept: 'application/json',
      }
      if (walletSessionID.trim()) {
        headers['X-Wallet-Session'] = walletSessionID.trim()
      }
      const requestInit: RequestInit = {
        method,
        headers,
        credentials: 'same-origin',
      }
      if (payload !== undefined) {
        headers['Content-Type'] = 'application/json'
        requestInit.body = JSON.stringify(payload)
      }
      const response = await fetch(endpoint, requestInit)
      let body: unknown
      try {
        body = await response.json()
      } catch {
        body = {}
      }
      if (!response.ok) {
        const payloadObject = (body && typeof body === 'object') ? body as Record<string, unknown> : {}
        const errorDescription = String(payloadObject.error_description || payloadObject.error || `Request failed with HTTP ${response.status}`)
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
      if (statusMessage) {
        setBanner(statusMessage)
      }
    },
    [scanner, setBanner],
  )

  useEffect(() => {
    document.body.classList.toggle('scanner-modal-open', scannerOpen)
    return () => {
      document.body.classList.remove('scanner-modal-open')
    }
  }, [scannerOpen])

  useEffect(() => {
    if (activeView !== 'home' && scannerActive) {
      void stopScanner()
    }
  }, [activeView, scannerActive, stopScanner])

  useEffect(() => {
    return () => {
      void scanner.stop()
      document.body.classList.remove('scanner-modal-open')
    }
  }, [scanner])

  useEffect(() => {
    if (!scannerOpen) {
      return
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        void stopScanner('Scanner closed')
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [scannerOpen, stopScanner])

  const refreshSession = useCallback(async () => {
    setActionPending('refresh')
    setBanner('Loading wallet session')
    try {
      const payload = await apiRequest<SessionPayload>('/api/session', 'GET')
      setSession(payload)
      if (payload.wallet_session_id) {
        setWalletSessionID(String(payload.wallet_session_id))
      }
      if (payload.app_title) {
        document.title = String(payload.app_title)
      }
      setBanner('Wallet session ready', 'success')
    } finally {
      setActionPending('')
    }
  }, [apiRequest, setBanner])

  const clearResolvedState = useCallback(() => {
    setResolved(null)
    setPreview(null)
    setResult(null)
    setSelectedDisclosureClaims([])
    setExternalTrustApproval(false)
  }, [])

  const resolveRequest = useCallback(
    async (rawInput: string) => {
      if (resolveInFlightRef.current) {
        return
      }
      resolveInFlightRef.current = true
      setResolveInFlight(true)
      setBanner('Resolving request object')
      try {
        const payload = buildResolvePayloadFromInput(rawInput)
        const response = await apiRequest<ResolveResponse>('/api/resolve', 'POST', payload)
        setResolved(response)
        setPreview(null)
        setResult(null)
        setSelectedDisclosureClaims([])
        setExternalTrustApproval(false)
        setActiveView('review')
        setBanner('Request object resolved', 'success')
      } finally {
        resolveInFlightRef.current = false
        setResolveInFlight(false)
      }
    },
    [apiRequest, setBanner],
  )

  const buildWalletPayload = useCallback(() => {
    if (!resolved) {
      throw new Error('Resolve a request first')
    }
    return {
      request_id: String(resolved.request_id || ''),
      request: String(resolved.request || ''),
      request_uri: String(resolved.request_uri || ''),
      disclosure_claims: selectedDisclosureClaims,
      approve_external_trust: externalTrustApproval,
    }
  }, [externalTrustApproval, resolved, selectedDisclosureClaims])

  const issueCredential = useCallback(
    async (forceIssue: boolean) => {
      setActionPending('issue')
      setBanner('Issuing credential via OID4VCI')
      try {
        const response = await apiRequest<SessionPayload>('/api/issue', 'POST', { force_issue: forceIssue })
        setSession((previous) => ({
          ...(previous || {}),
          ...response,
          credential_present: true,
          credential_jwt: response.credential_jwt || previous?.credential_jwt,
          credential_summary: response.credential_summary || previous?.credential_summary,
        }))
        setActiveView('credentials')
        setBanner(`Credential ready from ${String(response.credential_source || 'wallet')}`, 'success')
      } finally {
        setActionPending('')
      }
    },
    [apiRequest, setBanner],
  )

  const previewPresentation = useCallback(async () => {
    setActionPending('preview')
    setBanner('Building VP token preview')
    try {
      const payload = buildWalletPayload()
      const response = await apiRequest<PreviewResponse>('/api/preview', 'POST', payload)
      setPreview(response)
      setActiveView('present')
      setBanner('VP preview ready', 'success')
    } finally {
      setActionPending('')
    }
  }, [apiRequest, buildWalletPayload, setBanner])

  const presentCredential = useCallback(async () => {
    setActionPending('present')
    setBanner('Submitting presentation to verifier')
    try {
      const payload = buildWalletPayload()
      const response = await apiRequest<PresentResponse>('/api/present', 'POST', payload)
      setResult(response)
      setActiveView('result')
      setBanner('Verifier response received', 'success')
    } finally {
      setActionPending('')
    }
  }, [apiRequest, buildWalletPayload, setBanner])

  useEffect(() => {
    if (!scannerOpen || scannerStartRequestID === 0) {
      return
    }
    const viewport = scannerViewportRef.current
    if (!viewport) {
      return
    }

    let cancelled = false
    const start = async () => {
      try {
        const started = await scanner.start(
          viewport,
          (decodedText) => {
            if (cancelled) {
              return
            }
            setURIInput(decodedText)
            setScannerActive(false)
            setScannerOpen(false)
            void resolveRequest(decodedText).catch((error: unknown) => {
              setBanner(toErrorMessage(error), 'error')
            })
          },
          (message) => {
            if (!cancelled && message.trim()) {
              setBanner(message)
            }
          },
        )
        if (cancelled) {
          return
        }
        setScannerActive(started)
        if (!started) {
          setScannerOpen(false)
        }
      } catch (error) {
        if (cancelled) {
          return
        }
        setScannerActive(false)
        setScannerOpen(false)
        setBanner(toErrorMessage(error), 'error')
      }
    }

    void start()
    return () => {
      cancelled = true
    }
  }, [resolveRequest, scanner, scannerOpen, scannerStartRequestID, setBanner])

  useEffect(() => {
    let cancelled = false
    const init = async () => {
      try {
        await refreshSession()
        if (cancelled) {
          return
        }
        const query = new URLSearchParams(window.location.search)
        const initialURI = String(query.get('uri') || query.get('request_uri') || '').trim()
        if (!initialURI) {
          return
        }
        setURIInput(initialURI)
        await resolveRequest(initialURI)
      } catch (error) {
        if (!cancelled) {
          setBanner(toErrorMessage(error), 'error')
        }
      }
    }
    void init()
    return () => {
      cancelled = true
    }
  }, [refreshSession, resolveRequest, setBanner])

  const credentialSummary = session?.credential_summary
  const policyReasons = useMemo(
    () => normalizeClaims(result?.upstream_body?.reasons),
    [result?.upstream_body?.reasons],
  )
  const appTitle = String(session?.app_title || 'Protocol Soup Wallet')

  const statusBannerClassName = useMemo(() => {
    if (!statusBanner) {
      return 'banner'
    }
    if (statusBanner.level === 'error') {
      return 'banner error'
    }
    if (statusBanner.level === 'success') {
      return 'banner success'
    }
    return 'banner'
  }, [statusBanner])

  return (
    <main className="wallet-shell">
      <header className="card headline-card">
        <h1>{appTitle}</h1>
        <p className="subtle">
          Ephemeral OID4VP web wallet with real key material, real VP construction, and full protocol visibility
        </p>
        <p className="subtle tiny">No credential data is persisted beyond this wallet session</p>
      </header>

      {statusBanner && <div className={statusBannerClassName}>{statusBanner.message}</div>}

      <nav className="tabs" aria-label="Wallet views">
        {VIEW_TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={`tab ${activeView === tab.id ? 'active' : ''}`}
            onClick={() => setActiveView(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {activeView === 'home' && (
        <section className="card view">
          <h2>Home</h2>
          <p className="subtle">
            Paste an <code className="inline-code">openid4vp://</code> URI, provide a{' '}
            <code className="inline-code">request_uri</code>, or scan a QR code to begin
          </p>
          <div className="grid-two">
            <input
              className="input"
              type="text"
              value={uriInput}
              onChange={(event) => setURIInput(event.target.value)}
              placeholder="openid4vp://authorize?request_uri=https%3A%2F%2Fexample.com%2Foid4vp%2Frequest%2F123"
            />
            <div className="actions">
              <button
                type="button"
                className="action-primary"
                disabled={resolveInFlight}
                onClick={() => {
                  void resolveRequest(uriInput).catch((error: unknown) => {
                    setBanner(toErrorMessage(error), 'error')
                  })
                }}
              >
                Resolve Request
              </button>
              <button
                type="button"
                className="action-secondary"
                disabled={actionPending === 'refresh'}
                onClick={() => {
                  void refreshSession().catch((error: unknown) => {
                    setBanner(toErrorMessage(error), 'error')
                  })
                }}
              >
                Refresh Session
              </button>
            </div>
          </div>
          <div className="actions">
            <button
              type="button"
              className="action-secondary"
              disabled={scannerActive}
              onClick={() => {
                setScannerOpen(true)
                setScannerStartRequestID((previous) => previous + 1)
              }}
            >
              Start QR Scan
            </button>
            <p className="subtle tiny">
              Scan the Looking Glass OID4VP QR with this wallet The camera opens in a popup and closes automatically
              after detection
            </p>
          </div>
          {scannerActive && (
            <p className="tiny" style={{ color: '#67e8f9' }}>
              Camera is active in popup mode and prefers the rear camera when available
            </p>
          )}
        </section>
      )}

      {activeView === 'review' && (
        <section className="card view">
          <h2>Review Request</h2>
          {!resolved && <p className="subtle">No request resolved yet</p>}
          {resolved && (
            <div className="review-grid">
              <div className="review-item">
                <strong>request_id</strong>
                <div>{String(resolved.request_id || 'n/a')}</div>
              </div>
              <div className="review-item">
                <strong>client_id</strong>
                <div>{String(resolved.client_id || 'n/a')}</div>
              </div>
              <div className="review-item">
                <strong>response_mode</strong>
                <div>{String(resolved.response_mode || 'n/a')}</div>
              </div>
              <div className="review-item">
                <strong>response_uri</strong>
                <div>{String(resolved.response_uri || 'n/a')}</div>
              </div>
              <div className="review-item">
                <strong>trust</strong>
                <div>{resolved.trust?.trusted_target ? 'trusted target' : 'external verifier'}</div>
              </div>
              <div className="review-item">
                <strong>client_id_scheme</strong>
                <div>{String(resolved.trust?.client_id_scheme || 'n/a')}</div>
              </div>
              <div className="review-item">
                <strong>dcql_query</strong>
                <pre>{formatJSON(resolved.dcql_query || {})}</pre>
              </div>
              <div className="review-item">
                <strong>did:web</strong>
                <pre>{formatJSON(resolved.trust?.did_web || {})}</pre>
              </div>
            </div>
          )}
          {resolved?.trust?.requires_external_approval && (
            <div className="trust-box">
              <label>
                <input
                  type="checkbox"
                  checked={externalTrustApproval}
                  onChange={(event) => setExternalTrustApproval(event.target.checked)}
                />
                I trust this external verifier for this session
              </label>
            </div>
          )}
          <div className="actions">
            <button type="button" className="action-primary" onClick={() => setActiveView('disclosure')}>
              Continue to Disclosure
            </button>
            <button type="button" className="action-secondary" onClick={() => setActiveView('credentials')}>
              View Credentials
            </button>
            <button
              type="button"
              className="action-danger"
              onClick={() => {
                clearResolvedState()
                setActiveView('home')
                setBanner('Request declined')
              }}
            >
              Decline
            </button>
          </div>
        </section>
      )}

      {activeView === 'credentials' && (
        <section className="card view">
          <h2>Credential Store</h2>
          <p className="subtle">Credentials are session-scoped and may be refreshed via OID4VCI auto-issuance</p>
          <div className="actions">
            <button
              type="button"
              className="action-primary"
              disabled={actionPending === 'issue'}
              onClick={() => {
                void issueCredential(false).catch((error: unknown) => {
                  setBanner(toErrorMessage(error), 'error')
                })
              }}
            >
              Issue Credential
            </button>
            <button
              type="button"
              className="action-secondary"
              disabled={actionPending === 'issue'}
              onClick={() => {
                void issueCredential(true).catch((error: unknown) => {
                  setBanner(toErrorMessage(error), 'error')
                })
              }}
            >
              Force Re-Issue
            </button>
          </div>
          <div className="metric-list">
            <div><strong>wallet_subject</strong>: {String(session?.wallet_subject || 'n/a')}</div>
            <div><strong>wallet_scope</strong>: {String(session?.wallet_scope || 'n/a')}</div>
            <div><strong>credential_present</strong>: {String(Boolean(session?.credential_present))}</div>
            <div><strong>vct</strong>: {String(credentialSummary?.vct || 'n/a')}</div>
            <div><strong>subject</strong>: {String(credentialSummary?.subject || 'n/a')}</div>
            <div><strong>expires_at</strong>: {String(credentialSummary?.expires_at || 'n/a')}</div>
            <div><strong>sd_jwt</strong>: {String(Boolean(credentialSummary?.is_sd_jwt))}</div>
            <div><strong>disclosure_count</strong>: {String(Number(credentialSummary?.disclosure_count || 0))}</div>
            <div><strong>key_binding_jwt</strong>: {String(Boolean(credentialSummary?.key_binding_jwt))}</div>
            <div>
              <strong>disclosure_claims</strong>: {availableDisclosureClaims.length > 0 ? availableDisclosureClaims.join(', ') : 'none'}
            </div>
          </div>
          <details>
            <summary>Credential JWT</summary>
            <pre>{String(session?.credential_jwt || '')}</pre>
          </details>
          <details>
            <summary>Decoded Credential Claims</summary>
            <pre>{formatJSON(credentialSummary?.claims || {})}</pre>
          </details>
        </section>
      )}

      {activeView === 'disclosure' && (
        <section className="card view">
          <h2>Selective Disclosure</h2>
          <p className="subtle">Select SD-JWT claims that the wallet should disclose in the VP token</p>
          {availableDisclosureClaims.length === 0 && (
            <p className="subtle">No selective disclosure claims are currently available</p>
          )}
          {availableDisclosureClaims.length > 0 && (
            <div className="disclosure-grid">
              {availableDisclosureClaims.map((claim) => (
                <label key={claim} className="claim-option">
                  <input
                    type="checkbox"
                    checked={selectedDisclosureClaims.includes(claim)}
                    onChange={(event) => {
                      setSelectedDisclosureClaims((previous) => {
                        if (event.target.checked) {
                          return Array.from(new Set([...previous, claim])).sort()
                        }
                        return previous.filter((item) => item !== claim)
                      })
                    }}
                  />
                  <span>{claim}{CLAIM_DESCRIPTIONS[claim] ? ` - ${CLAIM_DESCRIPTIONS[claim]}` : ''}</span>
                </label>
              ))}
            </div>
          )}
          <div className="actions">
            <button
              type="button"
              className="action-primary"
              disabled={actionPending === 'preview'}
              onClick={() => {
                void previewPresentation().catch((error: unknown) => {
                  setBanner(toErrorMessage(error), 'error')
                })
              }}
            >
              Build VP Preview
            </button>
            <button type="button" className="action-secondary" onClick={() => setActiveView('present')}>
              Go to Present
            </button>
          </div>
        </section>
      )}

      {activeView === 'present' && (
        <section className="card view">
          <h2>Present Credential</h2>
          <p className="subtle">Submit a real OID4VP wallet response to the verifier response endpoint</p>
          <div className="actions">
            <button
              type="button"
              className="action-primary"
              disabled={actionPending === 'present'}
              onClick={() => {
                void presentCredential().catch((error: unknown) => {
                  setBanner(toErrorMessage(error), 'error')
                })
              }}
            >
              Submit Presentation
            </button>
            <button
              type="button"
              className="action-secondary"
              disabled={actionPending === 'preview'}
              onClick={() => {
                void previewPresentation().catch((error: unknown) => {
                  setBanner(toErrorMessage(error), 'error')
                })
              }}
            >
              Refresh Preview
            </button>
          </div>
          <details open>
            <summary>VP Token Preview</summary>
            <pre>{String(preview?.vp_token || '')}</pre>
          </details>
        </section>
      )}

      {activeView === 'result' && (
        <section className="card view">
          <h2>Result</h2>
          {!result && <p className="subtle">No presentation has been submitted yet</p>}
          {result && (
            <div className="metric-list">
              <div><strong>request_id</strong>: {String(result.request_id || 'n/a')}</div>
              <div><strong>response_mode</strong>: {String(result.response_mode || 'n/a')}</div>
              <div><strong>response_uri</strong>: {String(result.response_uri || 'n/a')}</div>
              <div><strong>upstream_status</strong>: {String(result.upstream_status || 'n/a')}</div>
              <div><strong>credential_source</strong>: {String(result.credential_source || 'n/a')}</div>
              <div><strong>policy_reasons</strong>: {policyReasons.length > 0 ? policyReasons.join(', ') : 'none'}</div>
              <div><strong>policy_checks</strong>: {formatJSON(result.upstream_body?.checks || {})}</div>
            </div>
          )}
          <details open>
            <summary>Verifier Response</summary>
            <pre>{formatJSON(result?.upstream_body || {})}</pre>
          </details>
        </section>
      )}

      <section className="card stack">
        <h2>Protocol Details</h2>
        <p className="subtle tiny">
          OpenID4VP and OID4VCI transparency panel request object trust context and VP construction artifacts
        </p>
        <details open>
          <summary>Request Object (JWT)</summary>
          <pre>{String(resolved?.request || '')}</pre>
        </details>
        <details>
          <summary>Request Header + Payload</summary>
          <pre>{formatJSON({
            header: resolved?.request_header || {},
            payload: resolved?.request_payload || {},
            trust: resolved?.trust || {},
          })}</pre>
        </details>
        <details>
          <summary>VP Header + Payload</summary>
          <pre>{formatJSON({
            header: preview?.vp_header || {},
            payload: preview?.vp_payload || {},
          })}</pre>
        </details>
      </section>

      {scannerOpen && (
        <div
          className="scanner-modal"
          role="dialog"
          aria-modal="true"
          aria-labelledby="scannerModalTitle"
          onClick={(event) => {
            if (event.target === event.currentTarget) {
              void stopScanner('Scanner closed')
            }
          }}
        >
          <div className="scanner-modal-card">
            <div className="scanner-modal-header">
              <h3 id="scannerModalTitle">Scan OID4VP QR</h3>
              <button
                type="button"
                className="action-secondary"
                onClick={() => {
                  void stopScanner('Scanner closed')
                }}
              >
                Close
              </button>
            </div>
            <p className="subtle tiny">
              Hold the QR inside the frame The camera stops automatically once a valid payload is detected
            </p>
            <div ref={scannerViewportRef} className="scanner-modal-viewport" />
            <div className="scanner-modal-actions">
              <button
                type="button"
                className="action-secondary"
                disabled={!scannerActive}
                onClick={() => {
                  void stopScanner('Scanner stopped')
                }}
              >
                Stop Camera
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  )
}
