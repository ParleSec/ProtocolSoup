/**
 * Looking Glass - Protocol Execution & Inspection
 */

import React, { useState, useCallback, useMemo, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  Eye, Play, RotateCcw, Key, Terminal, Square,
  ChevronRight, Fingerprint, Shield, Lock, Sparkles,
  RefreshCw, FileKey, KeyRound, Workflow, Search, Trash2, User, QrCode, Copy, Check, X, ExternalLink, Loader2
} from 'lucide-react'

import {
  useProtocols,
  useRealFlowExecutor,
  useLookingGlassSession,
  ProtocolSelector,
  RealFlowPanel,
  type LookingGlassProtocol,
  type LookingGlassFlow,
} from '../lookingglass'

import { TokenInspector } from '../components/lookingglass/TokenInspector'
import { LookingGlassSEO } from '../components/common/SEO'

const OID4VP_WALLET_SUBMIT_URL = 'https://wallet.protocolsoup.com/submit'
const OID4VP_DEFAULT_DISCLOSURE_HINTS = ['degree', 'graduation_year', 'department', 'given_name', 'family_name']
const OID4VP_DCQL_PRESETS: Array<{ id: string; label: string; description: string; query: string }> = [
  {
    id: 'degree-core',
    label: 'Degree core',
    description: 'Requests degree + graduation year from UniversityDegreeCredential.',
    query: JSON.stringify({
      credentials: [
        {
          id: 'university_degree',
          meta: {
            vct_values: ['https://protocolsoup.com/credentials/university_degree'],
          },
          claims: [{ path: ['degree'] }, { path: ['graduation_year'] }],
        },
      ],
    }, null, 2),
  },
  {
    id: 'degree-and-department',
    label: 'Degree + department',
    description: 'Requests academic credential plus department for employer verification.',
    query: JSON.stringify({
      credentials: [
        {
          id: 'university_degree',
          meta: {
            vct_values: ['https://protocolsoup.com/credentials/university_degree'],
          },
          claims: [{ path: ['degree'] }, { path: ['graduation_year'] }, { path: ['department'] }],
        },
      ],
    }, null, 2),
  },
  {
    id: 'multi-credential',
    label: 'Multi-credential query',
    description: 'Demonstrates DCQL with two credential slots and constrained claims.',
    query: JSON.stringify({
      credentials: [
        {
          id: 'degree_credential',
          meta: {
            vct_values: ['https://protocolsoup.com/credentials/university_degree'],
          },
          claims: [{ path: ['degree'] }, { path: ['graduation_year'] }],
        },
        {
          id: 'employment_credential',
          meta: {
            vct_values: ['https://protocolsoup.com/credentials/university_degree'],
          },
          claims: [{ path: ['department'] }],
        },
      ],
    }, null, 2),
  },
]
const DEFAULT_OID4VP_DCQL_PRESET_ID = OID4VP_DCQL_PRESETS[0]?.id || 'degree-core'

export function LookingGlass() {
  useParams<{ sessionId?: string }>()
  const navigate = useNavigate()

  const [selectedProtocol, setSelectedProtocol] = useState<LookingGlassProtocol | null>(null)
  const [selectedFlow, setSelectedFlow] = useState<LookingGlassFlow | null>(null)
  const [inspectedToken, setInspectedToken] = useState('')
  const [refreshTokenInput, setRefreshTokenInput] = useState('')
  const [storedRefreshToken, setStoredRefreshToken] = useState<string | null>(null)
  const [storedAccessToken, setStoredAccessToken] = useState<string | null>(null)
  // Token input for introspection/revocation/userinfo flows
  const [tokenInput, setTokenInput] = useState('')
  const [scimBearerToken, setScimBearerToken] = useState('')
  const [scimTokenLoading, setScimTokenLoading] = useState(false)
  const [scimAuthEnabled, setScimAuthEnabled] = useState(true)
  const [vciTxCodeInput, setVciTxCodeInput] = useState('')
  const [vciTxCodeLoading, setVciTxCodeLoading] = useState(false)
  const [vciTxCodeSource, setVciTxCodeSource] = useState<string | null>(null)
  const [wireSessionId, setWireSessionId] = useState<string | null>(null)
  const [wireSessionError, setWireSessionError] = useState<string | null>(null)
  const [pendingExecute, setPendingExecute] = useState(false)
  const [handoffCopied, setHandoffCopied] = useState(false)
  const [capturedVCWalletSubject, setCapturedVCWalletSubject] = useState('')
  const [capturedVCCredentialJWT, setCapturedVCCredentialJWT] = useState('')
  const [oid4vpWalletModalOpen, setOID4VPWalletModalOpen] = useState(false)
  const [oid4vpWalletSubjectInput, setOID4VPWalletSubjectInput] = useState('')
  const [oid4vpCredentialJWTInput, setOID4VPCredentialJWTInput] = useState('')
  const [oid4vpWalletSubmitPending, setOID4VPWalletSubmitPending] = useState(false)
  const [oid4vpWalletSubmitError, setOID4VPWalletSubmitError] = useState<string | null>(null)
  const [oid4vpWalletSubmitMessage, setOID4VPWalletSubmitMessage] = useState<string | null>(null)
  const [oid4vpLastPromptedRequestID, setOID4VPLastPromptedRequestID] = useState('')
  const [oid4vpQueryMode, setOID4VPQueryMode] = useState<'dcql' | 'scope'>('dcql')
  const [oid4vpDCQLPresetId, setOID4VPDCQLPresetID] = useState(DEFAULT_OID4VP_DCQL_PRESET_ID)
  const [oid4vpDCQLInput, setOID4VPDCQLInput] = useState(
    OID4VP_DCQL_PRESETS.find((preset) => preset.id === DEFAULT_OID4VP_DCQL_PRESET_ID)?.query || '{}',
  )
  const [oid4vpScopeAliasInput, setOID4VPScopeAliasInput] = useState('')
  const [oid4vpWalletMode, setOID4VPWalletMode] = useState<'one_click' | 'stepwise'>('one_click')
  const [oid4vpStepwiseVPToken, setOID4VPStepwiseVPToken] = useState('')
  const [oid4vpStepwiseLastStep, setOID4VPStepwiseLastStep] = useState('')
  const [oid4vpDisclosureClaims, setOID4VPDisclosureClaims] = useState<string[]>([])

  const { protocols, loading: protocolsLoading } = useProtocols()
  const {
    wireExchanges,
    connected: wireConnected,
    clearEvents: clearWireEvents,
  } = useLookingGlassSession(wireSessionId)

  // Fetch SCIM token when SCIM protocol is selected
  useEffect(() => {
    if (selectedProtocol?.id === 'scim' && !scimBearerToken) {
      setScimTokenLoading(true)
      fetch('/scim/internal/token')
        .then(res => res.json())
        .then(data => {
          if (data.token) {
            setScimBearerToken(data.token)
          }
          setScimAuthEnabled(data.authEnabled ?? true)
        })
        .catch(err => {
          console.error('Failed to fetch SCIM token:', err)
        })
        .finally(() => {
          setScimTokenLoading(false)
        })
    }
  }, [selectedProtocol?.id, scimBearerToken])

  const scopes = useMemo(() => {
    // Client credentials flow uses machine-client scopes (api:read, api:write)
    if (selectedFlow?.id?.toLowerCase().replace(/_/g, '-') === 'client-credentials') {
      return ['api:read', 'api:write']
    }
    return selectedProtocol?.id === 'oidc' 
      ? ['openid', 'profile', 'email'] 
      : ['profile', 'email']
  }, [selectedProtocol?.id, selectedFlow?.id])

  const flowId = useMemo(() => 
    selectedFlow?.id?.toLowerCase().replace(/_/g, '-'),
    [selectedFlow?.id]
  )

  const showTLSContext = useMemo(() => {
    const normalizedFlowId = flowId || ''
    const protocolId = selectedProtocol?.id || ''
    return normalizedFlowId.includes('mtls')
      || normalizedFlowId.includes('certificate')
      || protocolId === 'spiffe'
      || (protocolId === 'oauth2' && normalizedFlowId === 'mtls-token-binding')
  }, [flowId, selectedProtocol?.id])

  const isRefreshTokenFlow = flowId === 'refresh-token'
  const isTokenIntrospectionFlow = flowId === 'token-introspection'
  const isTokenRevocationFlow = flowId === 'token-revocation'
  const isUserInfoFlow = flowId === 'oidc-userinfo'
  const isTokenBasedFlow = isTokenIntrospectionFlow || isTokenRevocationFlow || isUserInfoFlow
  const isSCIMFlow = selectedProtocol?.id === 'scim'
  const isOID4VCITxCodeFlow = selectedProtocol?.id === 'oid4vci' && flowId === 'oid4vci-pre-authorized-tx-code'
  const isOID4VPFlow = selectedProtocol?.id === 'oid4vp'
  const showVCTab = selectedProtocol?.id === 'oid4vci' || selectedProtocol?.id === 'oid4vp'

  // Use stored token or user input for flows that need a token
  const activeToken = tokenInput || storedAccessToken || ''

  const [machineClientSecret, setMachineClientSecret] = useState<string | null>(null)

  useEffect(() => {
    if (flowId !== 'client-credentials') {
      setMachineClientSecret(null)
      return
    }

    let cancelled = false
    fetch('/oauth2/demo/clients')
      .then(async (res) => {
        if (!res.ok) {
          throw new Error('Failed to fetch demo clients')
        }
        return res.json()
      })
      .then((data) => {
        if (cancelled) return
        const clients = Array.isArray(data?.clients) ? data.clients : []
        const machineClient = clients.find((client: { id?: string }) => client?.id === 'machine-client')
        setMachineClientSecret(machineClient?.secret || null)
      })
      .catch(() => {
        if (!cancelled) {
          setMachineClientSecret(null)
        }
      })

    return () => {
      cancelled = true
    }
  }, [flowId])

  const clientConfig = useMemo(() => {
    if (flowId === 'client-credentials') {
      return { clientId: 'machine-client', clientSecret: machineClientSecret || undefined }
    }
    // All other flows (including refresh-token) use public-app
    // The refresh token must be used with the same client that obtained it
    return { clientId: 'public-app', clientSecret: undefined }
  }, [flowId, machineClientSecret])

  // Use stored token, input, or empty
  const activeRefreshToken = refreshTokenInput || storedRefreshToken || ''
  const selectedOID4VPPreset = useMemo(
    () => OID4VP_DCQL_PRESETS.find((preset) => preset.id === oid4vpDCQLPresetId) || OID4VP_DCQL_PRESETS[0],
    [oid4vpDCQLPresetId],
  )
  const oid4vpDCQLValidationError = useMemo(() => {
    if (!isOID4VPFlow || oid4vpQueryMode !== 'dcql') {
      return ''
    }
    const normalized = oid4vpDCQLInput.trim()
    if (!normalized) {
      return 'dcql_query JSON is required in DCQL mode.'
    }
    try {
      const parsed = JSON.parse(normalized)
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return 'dcql_query must be a JSON object.'
      }
      return ''
    } catch {
      return 'dcql_query contains invalid JSON.'
    }
  }, [isOID4VPFlow, oid4vpQueryMode, oid4vpDCQLInput])
  const oid4vpScopeAliasValidationError = useMemo(() => {
    if (!isOID4VPFlow || oid4vpQueryMode !== 'scope') {
      return ''
    }
    if (!oid4vpScopeAliasInput.trim()) {
      return 'scope alias is required in scope mode.'
    }
    return ''
  }, [isOID4VPFlow, oid4vpQueryMode, oid4vpScopeAliasInput])
  const canExecuteOID4VPRequest = !isOID4VPFlow || (!oid4vpDCQLValidationError && !oid4vpScopeAliasValidationError)
  const oid4vpDCQLQueryForExecutor = isOID4VPFlow && oid4vpQueryMode === 'dcql'
    ? oid4vpDCQLInput.trim()
    : undefined
  const oid4vpScopeAliasForExecutor = isOID4VPFlow && oid4vpQueryMode === 'scope'
    ? oid4vpScopeAliasInput.trim()
    : undefined

  const realExecutor = useRealFlowExecutor({
    protocolId: selectedProtocol?.id || null,
    flowId: selectedFlow?.id || null,
    clientId: clientConfig.clientId,
    clientSecret: clientConfig.clientSecret,
    redirectUri: `${window.location.origin}/callback`,
    scopes,
    refreshToken: isRefreshTokenFlow ? activeRefreshToken : undefined,
    token: (isTokenIntrospectionFlow || isTokenRevocationFlow) ? activeToken : undefined,
    accessToken: isUserInfoFlow ? activeToken : undefined,
    bearerToken: isSCIMFlow ? scimBearerToken : undefined,
    txCodeValue: isOID4VCITxCodeFlow ? vciTxCodeInput : undefined,
    oid4vpDCQLQueryJSON: oid4vpDCQLQueryForExecutor,
    oid4vpScopeAlias: oid4vpScopeAliasForExecutor,
    lookingGlassSessionId: wireSessionId || undefined,
  })
  const status = realExecutor.state?.status || 'idle'
  const isOID4VPAwaitingResult =
    selectedProtocol?.id === 'oid4vp' &&
    status === 'awaiting_user'

  const executeFlow = realExecutor.execute
  const resetFlow = realExecutor.reset

  const walletHandoffArtifact = useMemo(() => {
    const artifacts = realExecutor.state?.vcArtifacts || []
    for (let i = artifacts.length - 1; i >= 0; i -= 1) {
      if (artifacts[i].type === 'wallet_handoff') {
        return artifacts[i]
      }
    }
    return null
  }, [realExecutor.state?.vcArtifacts])

  const oid4vpRequestObjectArtifact = useMemo(() => {
    const artifacts = realExecutor.state?.vcArtifacts || []
    for (let i = artifacts.length - 1; i >= 0; i -= 1) {
      if (artifacts[i].type === 'request_object') {
        return artifacts[i]
      }
    }
    return null
  }, [realExecutor.state?.vcArtifacts])

  const oid4vpRequestID = useMemo(
    () => String(realExecutor.state?.securityParams.requestId || '').trim(),
    [realExecutor.state?.securityParams.requestId],
  )

  const oid4vpRequestJWT = useMemo(
    () => String(oid4vpRequestObjectArtifact?.raw || '').trim(),
    [oid4vpRequestObjectArtifact],
  )

  const oid4vpRequestURI = useMemo(() => {
    const requestMetadata = (oid4vpRequestObjectArtifact?.metadata || {}) as Record<string, unknown>
    const handoffMetadata = (walletHandoffArtifact?.metadata || {}) as Record<string, unknown>
    return String(requestMetadata.requestURI || handoffMetadata.requestURI || '').trim()
  }, [oid4vpRequestObjectArtifact, walletHandoffArtifact])

  const oid4vpResponseMode = useMemo(() => {
    const requestMetadata = (oid4vpRequestObjectArtifact?.metadata || {}) as Record<string, unknown>
    const handoffMetadata = (walletHandoffArtifact?.metadata || {}) as Record<string, unknown>
    return String(requestMetadata.responseMode || handoffMetadata.responseMode || 'direct_post').trim()
  }, [oid4vpRequestObjectArtifact, walletHandoffArtifact])

  const normalizedOID4VPCredentialJWTInput = useMemo(
    () => oid4vpCredentialJWTInput.trim(),
    [oid4vpCredentialJWTInput],
  )
  const oid4vpTrustMode = useMemo(() => {
    const metadata = (oid4vpRequestObjectArtifact?.metadata || walletHandoffArtifact?.metadata || {}) as Record<string, unknown>
    return String(metadata.trustMode || '').trim()
  }, [oid4vpRequestObjectArtifact, walletHandoffArtifact])
  const oid4vpDidWebAllowedHosts = useMemo(() => {
    const metadata = (oid4vpRequestObjectArtifact?.metadata || walletHandoffArtifact?.metadata || {}) as Record<string, unknown>
    const hosts = metadata.didWebAllowedHosts
    if (!Array.isArray(hosts)) {
      return [] as string[]
    }
    return hosts.map((host) => String(host).trim()).filter(Boolean)
  }, [oid4vpRequestObjectArtifact, walletHandoffArtifact])
  const oid4vpCredentialDisclosureOptions = useMemo(() => {
    const claimsFromCredential = parseSDJWTDisclosureClaimNames(normalizedOID4VPCredentialJWTInput)
    const merged = [...claimsFromCredential, ...OID4VP_DEFAULT_DISCLOSURE_HINTS]
    return Array.from(new Set(merged))
  }, [normalizedOID4VPCredentialJWTInput])

  const canSubmitOID4VPWalletInteraction =
    !!oid4vpRequestID &&
    !!oid4vpRequestJWT

  const oid4vpWalletHandoffPayload = useMemo(
    () => String(walletHandoffArtifact?.metadata?.qrPayload || walletHandoffArtifact?.metadata?.deepLink || walletHandoffArtifact?.raw || '').trim(),
    [walletHandoffArtifact],
  )

  const latestCapturedOID4VCITxCode = useMemo(() => {
    const artifacts = realExecutor.state?.vcArtifacts || []
    for (let i = artifacts.length - 1; i >= 0; i -= 1) {
      const metadata = artifacts[i].metadata || {}
      const txCode = String(metadata.txCodeOOBValue || metadata.txCodeValue || '').trim()
      if (txCode) {
        return txCode
      }
    }
    return ''
  }, [realExecutor.state?.vcArtifacts])

  useEffect(() => {
    if (!isOID4VCITxCodeFlow || vciTxCodeInput.trim() || !latestCapturedOID4VCITxCode) {
      return
    }
    setVciTxCodeInput(latestCapturedOID4VCITxCode)
    setVciTxCodeSource('captured from a previous issuer offer step in this session')
  }, [isOID4VCITxCodeFlow, latestCapturedOID4VCITxCode, vciTxCodeInput])

  useEffect(() => {
    if (!isOID4VCITxCodeFlow || vciTxCodeInput.trim()) {
      return
    }

    let cancelled = false
    setVciTxCodeLoading(true)
    setVciTxCodeSource(null)

    fetch('/oid4vci/offers/pre-authorized', {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tx_code_required: true,
      }),
    })
      .then(async (response) => {
        const payload = await response.json().catch(() => null) as Record<string, unknown> | null
        if (!response.ok) {
          throw new Error(String(payload?.error_description || payload?.error || `Prefill request failed (${response.status})`))
        }
        return payload || {}
      })
      .then((payload) => {
        if (cancelled) return
        const txCode = String(payload.tx_code_oob_value || payload.tx_code_value || '').trim()
        if (!txCode) {
          setVciTxCodeSource('issuer pre-step did not return a tx_code value')
          return
        }
        setVciTxCodeInput(txCode)
        const offerID = String(payload.offer_id || '').trim()
        setVciTxCodeSource(
          offerID
            ? `prefilled from issuer offer pre-step (${offerID})`
            : 'prefilled from issuer offer pre-step',
        )
      })
      .catch((error: unknown) => {
        if (cancelled) return
        const message = error instanceof Error ? error.message : 'Automatic tx_code prefill failed'
        setVciTxCodeSource(message)
      })
      .finally(() => {
        if (!cancelled) {
          setVciTxCodeLoading(false)
        }
      })

    return () => {
      cancelled = true
    }
  }, [isOID4VCITxCodeFlow, vciTxCodeInput])

  // Store tokens from completed flows
  useEffect(() => {
    if (realExecutor.state?.status === 'completed') {
      if (realExecutor.state.tokens.refreshToken) {
        setStoredRefreshToken(realExecutor.state.tokens.refreshToken)
      }
      if (realExecutor.state.tokens.accessToken) {
        setStoredAccessToken(realExecutor.state.tokens.accessToken)
      }
    }
  }, [realExecutor.state?.status, realExecutor.state?.tokens.refreshToken, realExecutor.state?.tokens.accessToken])

  useEffect(() => {
    const artifacts = realExecutor.state?.vcArtifacts || []
    if (artifacts.length === 0) {
      return
    }
    let latestWalletSubject = ''
    let latestCredentialJWT = ''

    for (let i = artifacts.length - 1; i >= 0; i -= 1) {
      const artifact = artifacts[i]
      const metadata = (artifact.metadata || {}) as Record<string, unknown>
      if (!latestWalletSubject) {
        const metadataSubject = String(metadata.walletSubject || metadata.wallet_subject || '').trim()
        if (metadataSubject) {
          latestWalletSubject = metadataSubject
        }
      }
      if (!latestCredentialJWT && artifact.type === 'credential' && typeof artifact.raw === 'string') {
        const normalized = artifact.raw.trim()
        if (normalized) {
          latestCredentialJWT = normalized
        }
      }
      if (latestWalletSubject && latestCredentialJWT) {
        break
      }
    }

    if (latestWalletSubject) {
      setCapturedVCWalletSubject(prev => (prev === latestWalletSubject ? prev : latestWalletSubject))
    }
    if (latestCredentialJWT) {
      setCapturedVCCredentialJWT(prev => (prev === latestCredentialJWT ? prev : latestCredentialJWT))
    }
  }, [realExecutor.state?.vcArtifacts])

  useEffect(() => {
    if (oid4vpWalletSubjectInput.trim() || !capturedVCWalletSubject) {
      return
    }
    setOID4VPWalletSubjectInput(capturedVCWalletSubject)
  }, [capturedVCWalletSubject, oid4vpWalletSubjectInput])

  useEffect(() => {
    if (oid4vpCredentialJWTInput.trim() || !capturedVCCredentialJWT) {
      return
    }
    setOID4VPCredentialJWTInput(capturedVCCredentialJWT)
  }, [capturedVCCredentialJWT, oid4vpCredentialJWTInput])

  useEffect(() => {
    if (oid4vpCredentialDisclosureOptions.length === 0) {
      return
    }
    setOID4VPDisclosureClaims((previous) => {
      const allowedSet = new Set(oid4vpCredentialDisclosureOptions)
      const retained = previous.filter((claimName) => allowedSet.has(claimName))
      if (retained.length > 0) {
        return retained
      }
      return oid4vpCredentialDisclosureOptions
    })
  }, [oid4vpCredentialDisclosureOptions])

  useEffect(() => {
    if (!isOID4VPAwaitingResult || !oid4vpRequestID) {
      return
    }
    if (oid4vpRequestID === oid4vpLastPromptedRequestID) {
      return
    }
    setOID4VPLastPromptedRequestID(oid4vpRequestID)
    setOID4VPWalletSubmitError(null)
    setOID4VPWalletSubmitMessage(null)
    setOID4VPWalletMode('one_click')
    setOID4VPStepwiseVPToken('')
    setOID4VPStepwiseLastStep('')
    setOID4VPWalletModalOpen(true)
  }, [isOID4VPAwaitingResult, oid4vpRequestID, oid4vpLastPromptedRequestID])

  useEffect(() => {
    if (selectedProtocol?.id === 'oid4vp') {
      return
    }
    setOID4VPWalletModalOpen(false)
    setOID4VPLastPromptedRequestID('')
    setOID4VPWalletSubmitPending(false)
    setOID4VPWalletSubmitError(null)
    setOID4VPWalletSubmitMessage(null)
    setOID4VPWalletMode('one_click')
    setOID4VPStepwiseVPToken('')
    setOID4VPStepwiseLastStep('')
  }, [selectedProtocol?.id])

  const openOID4VPWalletModal = useCallback(() => {
    if (!oid4vpWalletSubjectInput.trim() && capturedVCWalletSubject) {
      setOID4VPWalletSubjectInput(capturedVCWalletSubject)
    }
    if (!oid4vpCredentialJWTInput.trim() && capturedVCCredentialJWT) {
      setOID4VPCredentialJWTInput(capturedVCCredentialJWT)
    }
    setOID4VPWalletSubmitError(null)
    setOID4VPWalletSubmitMessage(null)
    setOID4VPWalletModalOpen(true)
  }, [oid4vpWalletSubjectInput, capturedVCWalletSubject, oid4vpCredentialJWTInput, capturedVCCredentialJWT])

  const closeOID4VPWalletModal = useCallback(() => {
    if (oid4vpWalletSubmitPending) {
      return
    }
    setOID4VPWalletModalOpen(false)
  }, [oid4vpWalletSubmitPending])

  const submitOID4VPWalletInteraction = useCallback(async () => {
    const walletSubject = oid4vpWalletSubjectInput.trim()
    const credentialJWT = normalizedOID4VPCredentialJWTInput
    if (!oid4vpRequestID || !oid4vpRequestJWT) {
      setOID4VPWalletSubmitError('Missing request context. Re-run OID4VP request creation.')
      return
    }

    setOID4VPWalletSubmitPending(true)
    setOID4VPWalletSubmitError(null)
    setOID4VPWalletSubmitMessage(null)

    try {
      const payload = {
        mode: 'one_click',
        request_id: oid4vpRequestID,
        request: oid4vpRequestJWT,
        request_uri: oid4vpRequestURI || undefined,
        response_mode: oid4vpResponseMode || undefined,
        wallet_subject: walletSubject || undefined,
        credential_jwt: credentialJWT || undefined,
        disclosure_claims: oid4vpDisclosureClaims,
        looking_glass_session_id: wireSessionId || undefined,
      }

      const response = await fetch(OID4VP_WALLET_SUBMIT_URL, {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      })
      const responsePayload = await response.json().catch(() => null) as Record<string, unknown> | null
      if (!response.ok) {
        throw new Error(
          String(
            responsePayload?.error_description
              || responsePayload?.error
              || `Wallet submission failed (${response.status})`,
          ),
        )
      }
      const upstreamStatus = Number(responsePayload?.upstream_status || 0)
      const credentialSource = String(responsePayload?.credential_source || '').trim()
      const effectiveWalletSubject = String(responsePayload?.wallet_subject || walletSubject || '').trim()
      const disclosureClaims = Array.isArray(responsePayload?.disclosure_claims)
        ? responsePayload?.disclosure_claims.map((claimName) => String(claimName).trim()).filter(Boolean)
        : []
      const sourceMessage = credentialSource === 'auto_issued_oid4vci'
        ? 'Auto-issued a fresh OID4VCI credential in the wallet bootstrap step.'
        : credentialSource === 'auto_refreshed_oid4vci'
          ? 'Refreshed a stale wallet credential via OID4VCI before submission.'
        : credentialSource === 'cached_wallet_store'
          ? 'Used existing wallet credential from wallet harness state.'
          : credentialSource === 'provided'
            ? 'Used credential_jwt provided in the modal.'
            : ''

      setOID4VPWalletModalOpen(false)
      setOID4VPWalletSubmitMessage(
        [
          upstreamStatus > 0
            ? `Wallet response accepted (upstream ${upstreamStatus}).`
            : 'Wallet response accepted.',
          effectiveWalletSubject ? `Wallet subject: ${effectiveWalletSubject}.` : '',
          disclosureClaims.length > 0 ? `Disclosed claims: ${disclosureClaims.join(', ')}.` : '',
          sourceMessage,
          'Checking verifier result...',
        ].filter(Boolean).join(' '),
      )
      setTimeout(() => {
        executeFlow()
      }, 1200)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Wallet submission failed'
      setOID4VPWalletSubmitError(message)
    } finally {
      setOID4VPWalletSubmitPending(false)
    }
  }, [
    oid4vpWalletSubjectInput,
    normalizedOID4VPCredentialJWTInput,
    oid4vpRequestID,
    oid4vpRequestJWT,
    oid4vpRequestURI,
    oid4vpResponseMode,
    oid4vpDisclosureClaims,
    wireSessionId,
    executeFlow,
  ])

  const executeOID4VPWalletStep = useCallback(async (
    step: 'bootstrap' | 'issue_credential' | 'build_presentation' | 'submit_response',
  ) => {
    const walletSubject = oid4vpWalletSubjectInput.trim()
    const credentialJWT = normalizedOID4VPCredentialJWTInput

    if ((step === 'build_presentation' || step === 'submit_response') && (!oid4vpRequestID || !oid4vpRequestJWT)) {
      setOID4VPWalletSubmitError('Missing request context. Re-run OID4VP request creation.')
      return
    }

    setOID4VPWalletSubmitPending(true)
    setOID4VPWalletSubmitError(null)

    try {
      const payload: Record<string, unknown> = {
        mode: 'stepwise',
        step,
        wallet_subject: walletSubject || undefined,
        credential_jwt: credentialJWT || undefined,
        disclosure_claims: oid4vpDisclosureClaims,
        looking_glass_session_id: wireSessionId || undefined,
      }
      if (oid4vpRequestID) {
        payload.request_id = oid4vpRequestID
      }
      if (oid4vpRequestJWT) {
        payload.request = oid4vpRequestJWT
      }
      if (oid4vpRequestURI) {
        payload.request_uri = oid4vpRequestURI
      }
      if (oid4vpResponseMode) {
        payload.response_mode = oid4vpResponseMode
      }
      if (step === 'submit_response' && oid4vpStepwiseVPToken.trim()) {
        payload.vp_token = oid4vpStepwiseVPToken.trim()
      }

      const response = await fetch(OID4VP_WALLET_SUBMIT_URL, {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      })
      const responsePayload = await response.json().catch(() => null) as Record<string, unknown> | null
      if (!response.ok) {
        throw new Error(
          String(
            responsePayload?.error_description
              || responsePayload?.error
              || `Wallet step "${step}" failed (${response.status})`,
          ),
        )
      }

      const nextVPToken = String(responsePayload?.vp_token || '').trim()
      if (step === 'build_presentation' && nextVPToken) {
        setOID4VPStepwiseVPToken(nextVPToken)
      }
      setOID4VPStepwiseLastStep(step)

      const upstreamStatus = Number(responsePayload?.upstream_status || 0)
      const credentialSource = String(responsePayload?.credential_source || '').trim()
      const disclosureClaims = Array.isArray(responsePayload?.disclosure_claims)
        ? responsePayload?.disclosure_claims.map((claimName) => String(claimName).trim()).filter(Boolean)
        : []

      setOID4VPWalletSubmitMessage(
        [
          `Step "${step}" completed.`,
          credentialSource ? `Credential source: ${credentialSource}.` : '',
          disclosureClaims.length > 0 ? `Disclosed claims: ${disclosureClaims.join(', ')}.` : '',
          step === 'build_presentation' && nextVPToken ? 'vp_token generated and cached for submit step.' : '',
          step === 'submit_response' && upstreamStatus > 0 ? `Verifier callback accepted (upstream ${upstreamStatus}).` : '',
        ].filter(Boolean).join(' '),
      )

      if (step === 'submit_response') {
        setOID4VPWalletModalOpen(false)
        setTimeout(() => {
          executeFlow()
        }, 1200)
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : `Wallet step "${step}" failed`
      setOID4VPWalletSubmitError(message)
    } finally {
      setOID4VPWalletSubmitPending(false)
    }
  }, [
    oid4vpWalletSubjectInput,
    normalizedOID4VPCredentialJWTInput,
    oid4vpDisclosureClaims,
    wireSessionId,
    oid4vpRequestID,
    oid4vpRequestJWT,
    oid4vpRequestURI,
    oid4vpResponseMode,
    oid4vpStepwiseVPToken,
    executeFlow,
  ])

  const handleProtocolSelect = useCallback((protocol: LookingGlassProtocol) => {
    // SSF has its own dedicated sandbox - redirect there
    if (protocol.id === 'ssf') {
      navigate('/ssf-sandbox')
      return
    }
    setSelectedProtocol(protocol)
    setSelectedFlow(null)
    resetFlow()
    setWireSessionId(null)
    clearWireEvents()
    setWireSessionError(null)
    setPendingExecute(false)
    setInspectedToken('')
    setVciTxCodeInput('')
    setVciTxCodeLoading(false)
    setVciTxCodeSource(null)
    setOID4VPWalletModalOpen(false)
    setOID4VPLastPromptedRequestID('')
    setOID4VPWalletSubmitPending(false)
    setOID4VPWalletSubmitError(null)
    setOID4VPWalletSubmitMessage(null)
    setOID4VPWalletMode('one_click')
    setOID4VPStepwiseVPToken('')
    setOID4VPStepwiseLastStep('')
    setOID4VPDisclosureClaims([])
    setOID4VPQueryMode('dcql')
    setOID4VPDCQLPresetID(DEFAULT_OID4VP_DCQL_PRESET_ID)
    setOID4VPDCQLInput(
      OID4VP_DCQL_PRESETS.find((preset) => preset.id === DEFAULT_OID4VP_DCQL_PRESET_ID)?.query || '{}',
    )
    setOID4VPScopeAliasInput('')
  }, [resetFlow, clearWireEvents, navigate])

  const handleFlowSelect = useCallback((flow: LookingGlassFlow) => {
    // SSF flows should redirect to the SSF Sandbox
    if (selectedProtocol?.id === 'ssf') {
      navigate('/ssf-sandbox')
      return
    }
    setSelectedFlow(flow)
    resetFlow()
    setWireSessionId(null)
    clearWireEvents()
    setWireSessionError(null)
    setPendingExecute(false)
    setInspectedToken('')
    setVciTxCodeInput('')
    setVciTxCodeLoading(false)
    setVciTxCodeSource(null)
    setOID4VPWalletModalOpen(false)
    setOID4VPLastPromptedRequestID('')
    setOID4VPWalletSubmitPending(false)
    setOID4VPWalletSubmitError(null)
    setOID4VPWalletSubmitMessage(null)
    setOID4VPWalletMode('one_click')
    setOID4VPStepwiseVPToken('')
    setOID4VPStepwiseLastStep('')
    setOID4VPDisclosureClaims([])
    setOID4VPQueryMode('dcql')
    setOID4VPDCQLPresetID(DEFAULT_OID4VP_DCQL_PRESET_ID)
    setOID4VPDCQLInput(
      OID4VP_DCQL_PRESETS.find((preset) => preset.id === DEFAULT_OID4VP_DCQL_PRESET_ID)?.query || '{}',
    )
    setOID4VPScopeAliasInput('')
  }, [resetFlow, clearWireEvents, selectedProtocol, navigate])

  const handleReset = useCallback(() => {
    resetFlow()
    setWireSessionId(null)
    clearWireEvents()
    setWireSessionError(null)
    setPendingExecute(false)
    setInspectedToken('')
    setVciTxCodeLoading(false)
    setOID4VPWalletModalOpen(false)
    setOID4VPLastPromptedRequestID('')
    setOID4VPWalletSubmitPending(false)
    setOID4VPWalletSubmitError(null)
    setOID4VPWalletSubmitMessage(null)
    setOID4VPWalletMode('one_click')
    setOID4VPStepwiseVPToken('')
    setOID4VPStepwiseLastStep('')
    setOID4VPDisclosureClaims([])
  }, [resetFlow, clearWireEvents])

  const copyWalletHandoff = useCallback(async () => {
    if (!walletHandoffArtifact) return
    const metadata = walletHandoffArtifact.metadata || {}
    const payload = String(metadata.qrPayload || metadata.deepLink || walletHandoffArtifact.raw || '')
    if (!payload) return
    await navigator.clipboard.writeText(payload)
    setHandoffCopied(true)
    setTimeout(() => setHandoffCopied(false), 1200)
  }, [walletHandoffArtifact])

  const startWireSession = useCallback(async () => {
    if (!selectedProtocol || !selectedFlow) {
      return null
    }
    setWireSessionError(null)
    try {
      clearWireEvents()
      const response = await fetch(`/api/protocols/${selectedProtocol.id}/demo/${selectedFlow.id}`, {
        method: 'POST',
      })
      if (!response.ok) {
        const errorData = await response.json().catch(() => null) as { error?: string } | null
        throw new Error(errorData?.error || 'Failed to start wire capture session')
      }
      const data = await response.json() as { session_id?: string }
      if (!data.session_id) {
        throw new Error('No session ID returned for wire capture')
      }
      setWireSessionId(data.session_id)
      return data.session_id
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to start wire capture session'
      setWireSessionError(message)
      return null
    }
  }, [selectedProtocol, selectedFlow, clearWireEvents])

  const handleExecute = useCallback(async () => {
    if (isOID4VPFlow && !canExecuteOID4VPRequest) {
      const message = oid4vpDCQLValidationError || oid4vpScopeAliasValidationError || 'OID4VP request configuration is invalid.'
      setOID4VPWalletSubmitError(message)
      return
    }
    if (!wireSessionId) {
      setPendingExecute(true)
      const created = await startWireSession()
      if (!created) {
        setPendingExecute(false)
      }
      return
    }
    executeFlow()
  }, [
    isOID4VPFlow,
    canExecuteOID4VPRequest,
    oid4vpDCQLValidationError,
    oid4vpScopeAliasValidationError,
    wireSessionId,
    startWireSession,
    executeFlow,
  ])

  useEffect(() => {
    if (pendingExecute && wireSessionId) {
      executeFlow()
      setPendingExecute(false)
    }
  }, [pendingExecute, wireSessionId, executeFlow])

  const handleQuickSelect = useCallback((protocolId: string, flowId: string) => {
    const normalizeFlowId = (id: string) => id.toLowerCase().replace(/_/g, '-')

    // SSF flows should redirect to the SSF Sandbox
    if (protocolId === 'ssf') {
      navigate('/ssf-sandbox')
      return
    }
    const protocol = protocols.find(p => p.id === protocolId)
    if (protocol) {
      setSelectedProtocol(protocol)
      const normalizedTarget = normalizeFlowId(flowId)
      const flow = (protocol.flows || []).find(f => normalizeFlowId(f.id) === normalizedTarget)
      if (flow) {
        setSelectedFlow(flow)
        resetFlow()
        setWireSessionId(null)
        clearWireEvents()
        setWireSessionError(null)
        setPendingExecute(false)
        setInspectedToken('')
        setVciTxCodeInput('')
        setOID4VPWalletModalOpen(false)
        setOID4VPLastPromptedRequestID('')
        setOID4VPWalletSubmitPending(false)
        setOID4VPWalletSubmitError(null)
        setOID4VPWalletSubmitMessage(null)
        setOID4VPWalletMode('one_click')
        setOID4VPStepwiseVPToken('')
        setOID4VPStepwiseLastStep('')
        setOID4VPDisclosureClaims([])
      }
    }
  }, [protocols, resetFlow, clearWireEvents, navigate])

  const hasCapturedTokens = realExecutor.state?.decodedTokens && realExecutor.state.decodedTokens.length > 0

  return (
    <>
      <LookingGlassSEO />
      <div className="max-w-5xl mx-auto space-y-4 sm:space-y-6">
      {/* Header */}
      <header className="py-2">
        <div className="flex flex-col gap-3">
          <div className="flex items-start justify-between gap-2">
            <h1 className="text-lg sm:text-2xl font-semibold text-white flex items-center gap-2 sm:gap-3 min-w-0">
              <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-purple-500/20 flex items-center justify-center flex-shrink-0">
                <Eye className="w-4 h-4 sm:w-5 sm:h-5 text-cyan-400" />
              </div>
              <span className="truncate">Looking Glass</span>
            </h1>
            {status !== 'idle' && (
              <StatusBadge status={status} />
            )}
          </div>
          <p className="text-surface-400 text-xs sm:text-base ml-10 sm:ml-[52px] leading-relaxed">
            Execute protocol flows and inspect the traffic
          </p>
        </div>
      </header>

      {/* Quick Select - when nothing selected */}
      {!selectedFlow && !protocolsLoading && (
        <section>
          <div className="flex items-center gap-2 text-surface-400 text-sm mb-3">
            <Sparkles className="w-4 h-4 text-amber-400" />
            <span>Quick start - select a flow to begin</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            <FlowButton
              icon={Workflow}
              label="Interaction Code Flow"
              sublabel="Full OAuth 2.0 + OIDC"
              color="cyan"
              onClick={() => handleQuickSelect('oidc', 'interaction-code')}
            />
            <FlowButton
              icon={Shield}
              label="Authorization Code"
              sublabel="OAuth 2.0"
              color="blue"
              onClick={() => handleQuickSelect('oauth2', 'authorization_code')}
            />
            <FlowButton
              icon={Lock}
              label="Client Credentials"
              sublabel="OAuth 2.0"
              color="green"
              onClick={() => handleQuickSelect('oauth2', 'client_credentials')}
            />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 mt-3">
            <FlowButton
              icon={RefreshCw}
              label="Refresh Token"
              sublabel="OAuth 2.0"
              color="purple"
              onClick={() => handleQuickSelect('oauth2', 'refresh_token')}
            />
            <FlowButton
              icon={Fingerprint}
              label="OIDC Auth Code"
              sublabel="OpenID Connect"
              color="orange"
              onClick={() => handleQuickSelect('oidc', 'oidc_authorization_code')}
            />
            <FlowButton
              icon={FileKey}
              label="SP-Initiated SSO"
              sublabel="SAML 2.0"
              color="blue"
              onClick={() => handleQuickSelect('saml', 'sp_initiated_sso')}
            />
          </div>
        </section>
      )}

      {/* Protocol Selector */}
      <section className="rounded-xl border border-white/10 bg-surface-900/30 p-3 sm:p-5">
        <div className="flex items-center justify-between mb-3 sm:mb-4">
          <div className="flex items-center gap-2">
            <Terminal className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-surface-400" />
            <span className="text-xs sm:text-sm font-medium text-surface-300">Configuration</span>
          </div>
          {selectedFlow && (
            <button
              onClick={handleReset}
              className="flex items-center gap-1 sm:gap-1.5 text-xs sm:text-sm text-surface-400 hover:text-white transition-colors"
            >
              <RotateCcw className="w-3 h-3 sm:w-3.5 sm:h-3.5" />
              Reset
            </button>
          )}
        </div>
        
        <ProtocolSelector
          protocols={protocols}
          selectedProtocol={selectedProtocol}
          selectedFlow={selectedFlow}
          onProtocolSelect={handleProtocolSelect}
          onFlowSelect={handleFlowSelect}
          loading={protocolsLoading}
        />

        {/* Refresh Token Input - shown when refresh token flow is selected */}
        {isRefreshTokenFlow && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="mt-3 sm:mt-4 pt-3 sm:pt-4 border-t border-white/10"
          >
            <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 mb-2">
              <RefreshCw className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-blue-400" />
              <span className="text-xs sm:text-sm font-medium text-surface-300">Refresh Token</span>
              {storedRefreshToken && !refreshTokenInput && (
                <span className="px-1.5 sm:px-2 py-0.5 rounded text-[10px] sm:text-xs bg-green-500/10 text-green-400">
                  Captured ✓
                </span>
              )}
            </div>
            <p className="text-[10px] sm:text-xs text-surface-400 mb-2 sm:mb-3 leading-relaxed">
              Run Authorization Code flow first, or paste a token below.
            </p>
            <div className="flex gap-2">
              <input
                type="text"
                value={refreshTokenInput}
                onChange={(e) => setRefreshTokenInput(e.target.value)}
                placeholder={storedRefreshToken ? "Using captured (or paste new)" : "Paste token here..."}
                className="flex-1 min-w-0 px-2.5 sm:px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-xs sm:text-sm font-mono text-white placeholder-surface-600 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 transition-all"
              />
              {storedRefreshToken && (
                <button
                  onClick={() => setRefreshTokenInput(storedRefreshToken)}
                  className="px-2.5 sm:px-3 py-2 rounded-lg bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs sm:text-sm hover:bg-blue-500/20 transition-colors flex-shrink-0"
                  title="Use captured refresh token"
                >
                  <RefreshCw className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                </button>
              )}
            </div>
            {!activeRefreshToken && (
              <p className="mt-2 text-[10px] sm:text-xs text-amber-400 leading-relaxed">
                ⚠️ No token available. Run Auth Code flow first.
              </p>
            )}
          </motion.div>
        )}

        {/* Access Token Input - shown for introspection, revocation, userinfo flows */}
        {isTokenBasedFlow && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="mt-3 sm:mt-4 pt-3 sm:pt-4 border-t border-white/10"
          >
            <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 mb-2">
              {isTokenIntrospectionFlow && <Search className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-cyan-400" />}
              {isTokenRevocationFlow && <Trash2 className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-red-400" />}
              {isUserInfoFlow && <User className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-green-400" />}
              <span className="text-xs sm:text-sm font-medium text-surface-300">
                {isTokenIntrospectionFlow && 'Token to Introspect'}
                {isTokenRevocationFlow && 'Token to Revoke'}
                {isUserInfoFlow && 'Access Token'}
              </span>
              {storedAccessToken && !tokenInput && (
                <span className="px-1.5 sm:px-2 py-0.5 rounded text-[10px] sm:text-xs bg-green-500/10 text-green-400">
                  Captured ✓
                </span>
              )}
            </div>
            <p className="text-[10px] sm:text-xs text-surface-400 mb-2 sm:mb-3 leading-relaxed">
              {isTokenIntrospectionFlow && 'Run Authorization Code or Client Credentials flow first, or paste a token below.'}
              {isTokenRevocationFlow && 'Run an authorization flow first to get a token, or paste one below.'}
              {isUserInfoFlow && 'Run OIDC Authorization Code flow first (with openid scope), or paste a token below.'}
            </p>
            <div className="flex gap-2">
              <input
                type="text"
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value)}
                placeholder={storedAccessToken ? "Using captured (or paste new)" : "Paste token here..."}
                className={`flex-1 min-w-0 px-2.5 sm:px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-xs sm:text-sm font-mono text-white placeholder-surface-600 focus:outline-none transition-all ${
                  isTokenIntrospectionFlow ? 'focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20' :
                  isTokenRevocationFlow ? 'focus:border-red-500/50 focus:ring-1 focus:ring-red-500/20' :
                  'focus:border-green-500/50 focus:ring-1 focus:ring-green-500/20'
                }`}
              />
              {storedAccessToken && (
                <button
                  onClick={() => setTokenInput(storedAccessToken)}
                  className={`px-2.5 sm:px-3 py-2 rounded-lg text-xs sm:text-sm transition-colors flex-shrink-0 ${
                    isTokenIntrospectionFlow ? 'bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20' :
                    isTokenRevocationFlow ? 'bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20' :
                    'bg-green-500/10 border border-green-500/30 text-green-400 hover:bg-green-500/20'
                  }`}
                  title="Use captured access token"
                >
                  <Key className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                </button>
              )}
            </div>
            {!activeToken && (
              <p className="mt-2 text-[10px] sm:text-xs text-amber-400 leading-relaxed">
                ⚠️ No token available. Run Auth Code flow first.
              </p>
            )}
          </motion.div>
        )}

        {/* SCIM Bearer Token Input - shown when SCIM protocol is selected */}
        {isSCIMFlow && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="mt-3 sm:mt-4 pt-3 sm:pt-4 border-t border-white/10"
          >
            <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 mb-2">
              <KeyRound className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-purple-400" />
              <span className="text-xs sm:text-sm font-medium text-surface-300">SCIM Bearer Token</span>
              {scimTokenLoading && (
                <span className="px-1.5 sm:px-2 py-0.5 rounded text-[10px] sm:text-xs bg-blue-500/10 text-blue-400 animate-pulse">
                  Loading...
                </span>
              )}
              {!scimTokenLoading && scimBearerToken && (
                <span className="px-1.5 sm:px-2 py-0.5 rounded text-[10px] sm:text-xs bg-green-500/10 text-green-400">
                  Auto-configured ✓
                </span>
              )}
              {!scimTokenLoading && !scimAuthEnabled && (
                <span className="px-1.5 sm:px-2 py-0.5 rounded text-[10px] sm:text-xs bg-amber-500/10 text-amber-400">
                  Auth Disabled
                </span>
              )}
            </div>
            {scimAuthEnabled ? (
              <>
                <p className="text-[10px] sm:text-xs text-surface-400 mb-2 sm:mb-3 leading-relaxed">
                  Bearer token for SCIM API authentication. This is the same token configured for external IdPs like Okta.
                </p>
                <input
                  type="password"
                  value={scimBearerToken}
                  onChange={(e) => setScimBearerToken(e.target.value)}
                  placeholder={scimTokenLoading ? "Loading token..." : "Enter your SCIM bearer token..."}
                  disabled={scimTokenLoading}
                  className="w-full px-2.5 sm:px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-xs sm:text-sm font-mono text-white placeholder-surface-600 focus:outline-none focus:border-purple-500/50 focus:ring-1 focus:ring-purple-500/20 transition-all disabled:opacity-50"
                />
                {!scimBearerToken && !scimTokenLoading && (
                  <p className="mt-2 text-[10px] sm:text-xs text-amber-400 leading-relaxed">
                    ⚠️ Bearer token required. Set SCIM_API_TOKEN in production or enter manually.
                  </p>
                )}
              </>
            ) : (
              <p className="text-[10px] sm:text-xs text-surface-400 leading-relaxed">
                SCIM authentication is disabled. Set <code className="text-purple-400">SCIM_API_TOKEN</code> environment variable to enable.
              </p>
            )}
          </motion.div>
        )}

        {isOID4VCITxCodeFlow && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="mt-3 sm:mt-4 pt-3 sm:pt-4 border-t border-white/10"
          >
            <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 mb-2">
              <KeyRound className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-amber-400" />
              <span className="text-xs sm:text-sm font-medium text-surface-300">OID4VCI tx_code</span>
            </div>
            <p className="text-[10px] sm:text-xs text-surface-400 mb-2 sm:mb-3 leading-relaxed">
              This value is prefilled from the issuer out-of-band offer step and reused from prior flow capture when available.
            </p>
            <input
              type="text"
              value={vciTxCodeInput}
              onChange={(e) => setVciTxCodeInput(e.target.value)}
              placeholder={vciTxCodeLoading ? 'Prefilling tx_code from issuer offer...' : 'e.g. 123456'}
              disabled={vciTxCodeLoading}
              className="w-full px-2.5 sm:px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-xs sm:text-sm font-mono text-white placeholder-surface-600 focus:outline-none focus:border-amber-500/50 focus:ring-1 focus:ring-amber-500/20 transition-all"
            />
            {!!vciTxCodeSource && (
              <p className="mt-2 text-[10px] sm:text-xs text-cyan-400 leading-relaxed">
                {vciTxCodeSource}
              </p>
            )}
            {!vciTxCodeLoading && !vciTxCodeInput.trim() && (
              <p className="mt-2 text-[10px] sm:text-xs text-amber-400 leading-relaxed">
                ⚠️ tx_code is required before token exchange for this flow.
              </p>
            )}
          </motion.div>
        )}

        {isOID4VPFlow && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="mt-3 sm:mt-4 pt-3 sm:pt-4 border-t border-white/10"
          >
            <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 mb-2">
              <Workflow className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-violet-400" />
              <span className="text-xs sm:text-sm font-medium text-surface-300">OID4VP request contract</span>
            </div>
            <p className="text-[10px] sm:text-xs text-surface-400 mb-2 sm:mb-3 leading-relaxed">
              Configure either <code className="text-violet-300">dcql_query</code> or a scope alias (mutually exclusive per OpenID4VP).
            </p>

            <div className="grid grid-cols-2 gap-2 mb-3">
              <button
                type="button"
                onClick={() => setOID4VPQueryMode('dcql')}
                className={`px-2.5 py-2 rounded-lg border text-xs transition-colors ${
                  oid4vpQueryMode === 'dcql'
                    ? 'border-violet-500/40 bg-violet-500/15 text-violet-200'
                    : 'border-white/10 bg-surface-900 text-surface-300 hover:text-white'
                }`}
              >
                Use DCQL
              </button>
              <button
                type="button"
                onClick={() => setOID4VPQueryMode('scope')}
                className={`px-2.5 py-2 rounded-lg border text-xs transition-colors ${
                  oid4vpQueryMode === 'scope'
                    ? 'border-violet-500/40 bg-violet-500/15 text-violet-200'
                    : 'border-white/10 bg-surface-900 text-surface-300 hover:text-white'
                }`}
              >
                Use scope alias
              </button>
            </div>

            {oid4vpQueryMode === 'dcql' && (
              <div className="space-y-2">
                <div className="flex flex-wrap items-center gap-2">
                  <label className="text-[11px] sm:text-xs text-surface-400">Preset</label>
                  <select
                    value={oid4vpDCQLPresetId}
                    onChange={(event) => {
                      const nextPresetId = event.target.value
                      const preset = OID4VP_DCQL_PRESETS.find((item) => item.id === nextPresetId)
                      setOID4VPDCQLPresetID(nextPresetId)
                      if (preset) {
                        setOID4VPDCQLInput(preset.query)
                      }
                    }}
                    className="px-2 py-1.5 rounded bg-surface-900 border border-white/10 text-xs text-surface-200 focus:outline-none focus:border-violet-500/40"
                  >
                    {OID4VP_DCQL_PRESETS.map((preset) => (
                      <option key={preset.id} value={preset.id}>{preset.label}</option>
                    ))}
                  </select>
                  <span className="text-[10px] sm:text-xs text-cyan-300">{selectedOID4VPPreset?.description}</span>
                </div>
                <textarea
                  value={oid4vpDCQLInput}
                  onChange={(event) => setOID4VPDCQLInput(event.target.value)}
                  rows={7}
                  className="w-full px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-[11px] sm:text-xs font-mono text-white placeholder-surface-600 focus:outline-none focus:border-violet-500/50 focus:ring-1 focus:ring-violet-500/20 transition-all resize-y"
                  placeholder="Paste dcql_query JSON"
                />
                {!!oid4vpDCQLValidationError && (
                  <p className="text-[11px] sm:text-xs text-amber-400">{oid4vpDCQLValidationError}</p>
                )}
              </div>
            )}

            {oid4vpQueryMode === 'scope' && (
              <div className="space-y-2">
                <input
                  type="text"
                  value={oid4vpScopeAliasInput}
                  onChange={(event) => setOID4VPScopeAliasInput(event.target.value)}
                  placeholder="e.g. openid profile degree_verification"
                  className="w-full px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-xs sm:text-sm font-mono text-white placeholder-surface-600 focus:outline-none focus:border-violet-500/50 focus:ring-1 focus:ring-violet-500/20 transition-all"
                />
                {!!oid4vpScopeAliasValidationError && (
                  <p className="text-[11px] sm:text-xs text-amber-400">{oid4vpScopeAliasValidationError}</p>
                )}
              </div>
            )}
          </motion.div>
        )}
      </section>

      {/* Execution */}
      {selectedFlow && (
        <motion.section
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-xl border border-white/10 bg-surface-900/30 overflow-hidden"
        >
          {/* Flow Header */}
          <div className="px-3 sm:px-5 py-3 sm:py-4 border-b border-white/10">
            <div className="flex items-start justify-between gap-2 mb-2 sm:mb-0">
              <div className="flex items-center gap-2 sm:gap-3 min-w-0 flex-1">
                <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-lg bg-cyan-500/20 flex items-center justify-center flex-shrink-0">
                  <Play className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-cyan-400" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <code className="text-white font-medium text-xs sm:text-base truncate max-w-[160px] sm:max-w-none">{selectedFlow.id}</code>
                    {realExecutor.flowInfo && (
                      <span className="text-[10px] sm:text-xs text-surface-400 font-mono flex-shrink-0">
                        {realExecutor.flowInfo.rfcReference}
                      </span>
                    )}
                  </div>
                </div>
              </div>
              
              <div className="flex items-center gap-1.5 sm:gap-2 flex-shrink-0">
                {status === 'idle' && (
                  <button
                    onClick={handleExecute}
                    disabled={isOID4VPFlow && !canExecuteOID4VPRequest}
                    className={`flex items-center gap-1.5 sm:gap-2 px-2.5 sm:px-4 py-1.5 sm:py-2 rounded-lg border text-xs sm:text-sm font-medium transition-all ${
                      isOID4VPFlow && !canExecuteOID4VPRequest
                        ? 'bg-surface-800/70 border-white/10 text-surface-500 cursor-not-allowed'
                        : 'bg-gradient-to-r from-green-500/20 to-emerald-500/20 border-green-500/30 text-green-400 hover:from-green-500/30 hover:to-emerald-500/30'
                    }`}
                  >
                    <Play className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                    <span className="hidden sm:inline">Execute</span>
                    <span className="sm:hidden">Run</span>
                  </button>
                )}
                {isOID4VPAwaitingResult && (
                  <button
                    onClick={openOID4VPWalletModal}
                    className="flex items-center gap-1.5 sm:gap-2 px-2.5 sm:px-4 py-1.5 sm:py-2 rounded-lg bg-violet-500/10 border border-violet-500/30 text-violet-300 text-xs sm:text-sm font-medium hover:bg-violet-500/20 transition-colors"
                  >
                    <ExternalLink className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                    <span className="hidden sm:inline">Wallet Action</span>
                    <span className="sm:hidden">Wallet</span>
                  </button>
                )}
                {isOID4VPAwaitingResult && (
                  <button
                    onClick={handleExecute}
                    className="flex items-center gap-1.5 sm:gap-2 px-2.5 sm:px-4 py-1.5 sm:py-2 rounded-lg bg-gradient-to-r from-blue-500/20 to-cyan-500/20 border border-blue-500/30 text-blue-300 text-xs sm:text-sm font-medium hover:from-blue-500/30 hover:to-cyan-500/30 transition-all"
                  >
                    <Play className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                    <span className="hidden sm:inline">Check Result</span>
                    <span className="sm:hidden">Check</span>
                  </button>
                )}
                {(status === 'executing' || status === 'awaiting_user') && (
                  <button
                    onClick={realExecutor.abort}
                    className="flex items-center gap-1.5 sm:gap-2 px-2.5 sm:px-4 py-1.5 sm:py-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs sm:text-sm hover:bg-red-500/20 transition-colors"
                  >
                    <Square className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                    <span className="hidden xs:inline">Abort</span>
                  </button>
                )}
                {status === 'completed' && (
                  <button
                    onClick={realExecutor.reset}
                    className="flex items-center gap-1.5 sm:gap-2 px-2.5 sm:px-4 py-1.5 sm:py-2 rounded-lg bg-surface-800 border border-white/10 text-surface-400 text-xs sm:text-sm hover:text-white transition-colors"
                  >
                    <RotateCcw className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                    <span className="hidden sm:inline">Run Again</span>
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Execution Panel */}
          <div className="p-4 sm:p-5">
            {walletHandoffArtifact && (
              <div className="mb-3 p-3 rounded-lg border border-cyan-500/20 bg-cyan-500/5">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 text-cyan-300 mb-1">
                      <QrCode className="w-4 h-4 flex-shrink-0" />
                      <span className="text-sm font-medium">Wallet Handoff Ready</span>
                    </div>
                    <p className="text-xs text-surface-300">
                      Deep-link/QR payload is generated from the live request object and can be used with an external wallet agent.
                    </p>
                  </div>
                  <button
                    onClick={copyWalletHandoff}
                    className="flex items-center gap-1 px-2 py-1 rounded bg-surface-900 text-xs text-surface-300 hover:text-white border border-white/10"
                  >
                    {handoffCopied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                    {handoffCopied ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <pre className="mt-2 p-2 rounded bg-surface-950 text-[11px] text-surface-300 overflow-x-auto">
                  {String(walletHandoffArtifact.metadata?.qrPayload || walletHandoffArtifact.metadata?.deepLink || walletHandoffArtifact.raw || '')}
                </pre>
              </div>
            )}
            {isOID4VPFlow && !!oid4vpTrustMode && (
              <div className="mb-3 p-3 rounded-lg border border-violet-500/30 bg-violet-500/5 text-[11px] sm:text-xs text-violet-200">
                <div className="font-medium mb-1">Verifier trust mode: {humanizeTrustMode(oid4vpTrustMode)}</div>
                {oid4vpDidWebAllowedHosts.length > 0 && (
                  <div className="text-surface-300">
                    did:web host allowlist: <code>{oid4vpDidWebAllowedHosts.join(', ')}</code>
                  </div>
                )}
                {oid4vpDidWebAllowedHosts.length === 0 && (
                  <div className="text-surface-300">No did:web host allowlist is active for this request.</div>
                )}
              </div>
            )}
            {selectedProtocol?.id === 'oid4vp' && (oid4vpWalletSubmitMessage || oid4vpWalletSubmitError) && (
              <div className={`mb-3 p-3 rounded-lg border text-xs ${
                oid4vpWalletSubmitError
                  ? 'border-red-500/30 bg-red-500/5 text-red-300'
                  : 'border-green-500/30 bg-green-500/5 text-green-300'
              }`}>
                {oid4vpWalletSubmitError || oid4vpWalletSubmitMessage}
              </div>
            )}
            <RealFlowPanel
              state={realExecutor.state}
              onExecute={handleExecute}
              onAbort={realExecutor.abort}
              onReset={handleReset}
              isExecuting={realExecutor.isExecuting}
              flowInfo={realExecutor.flowInfo}
              requirements={realExecutor.requirements}
              error={realExecutor.error}
              wireExchanges={wireExchanges}
              wireConnected={wireConnected}
              wireSessionError={wireSessionError}
              showTLSContext={showTLSContext}
              showVCTab={showVCTab}
            />
          </div>
        </motion.section>
      )}

      <AnimatePresence>
        {oid4vpWalletModalOpen && isOID4VPAwaitingResult && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm p-3 sm:p-6 flex items-center justify-center"
            onClick={closeOID4VPWalletModal}
          >
            <motion.div
              initial={{ opacity: 0, y: 12, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 8, scale: 0.98 }}
              transition={{ duration: 0.16 }}
              className="w-full max-w-2xl rounded-xl border border-white/10 bg-surface-900 shadow-2xl overflow-hidden"
              onClick={(event) => event.stopPropagation()}
            >
              <div className="px-4 sm:px-5 py-3 sm:py-4 border-b border-white/10 flex items-center justify-between gap-3">
                <div>
                  <h3 className="text-white text-sm sm:text-base font-medium">OID4VP Wallet Interaction</h3>
                  <p className="text-[11px] sm:text-xs text-surface-400 mt-0.5">
                    Fulfill the wallet step and submit a real presentation callback.
                  </p>
                </div>
                <button
                  onClick={closeOID4VPWalletModal}
                  disabled={oid4vpWalletSubmitPending}
                  className="p-1.5 rounded-lg text-surface-400 hover:text-white hover:bg-white/5 disabled:opacity-50 transition-colors"
                  title="Close"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="p-4 sm:p-5 space-y-4 max-h-[75vh] overflow-y-auto">
                <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3 space-y-2">
                  <div className="text-xs text-cyan-300 font-medium">Request Context</div>
                  <div className="grid gap-1 text-[11px] sm:text-xs text-surface-300">
                    <div><span className="text-surface-400">request_id:</span> <code>{oid4vpRequestID || 'missing'}</code></div>
                    <div><span className="text-surface-400">response_mode:</span> <code>{oid4vpResponseMode || 'direct_post'}</code></div>
                    {oid4vpTrustMode && (
                      <div>
                        <span className="text-surface-400">trust_mode:</span> <code>{humanizeTrustMode(oid4vpTrustMode)}</code>
                      </div>
                    )}
                    {oid4vpRequestURI && (
                      <div className="break-all">
                        <span className="text-surface-400">request_uri:</span> <code>{oid4vpRequestURI}</code>
                      </div>
                    )}
                    {oid4vpDidWebAllowedHosts.length > 0 && (
                      <div className="break-all">
                        <span className="text-surface-400">did:web allowlist:</span> <code>{oid4vpDidWebAllowedHosts.join(', ')}</code>
                      </div>
                    )}
                  </div>
                </div>

                {!!oid4vpWalletHandoffPayload && (
                  <div className="space-y-1">
                    <div className="text-[11px] sm:text-xs text-surface-400">Wallet handoff payload</div>
                    <pre className="p-2 rounded bg-surface-950 text-[11px] text-surface-300 overflow-x-auto">
                      {oid4vpWalletHandoffPayload}
                    </pre>
                  </div>
                )}

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <label className="text-xs sm:text-sm font-medium text-surface-300">wallet_subject (optional)</label>
                    {capturedVCWalletSubject && (
                      <button
                        onClick={() => setOID4VPWalletSubjectInput(capturedVCWalletSubject)}
                        className="text-[11px] sm:text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
                      >
                        Use captured value
                      </button>
                    )}
                  </div>
                  <input
                    type="text"
                    value={oid4vpWalletSubjectInput}
                    onChange={(event) => setOID4VPWalletSubjectInput(event.target.value)}
                    placeholder="Leave blank to use wallet harness default subject"
                    className="w-full px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-xs sm:text-sm font-mono text-white placeholder-surface-600 focus:outline-none focus:border-violet-500/50 focus:ring-1 focus:ring-violet-500/20 transition-all"
                  />
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <label className="text-xs sm:text-sm font-medium text-surface-300">credential_jwt (optional)</label>
                    {capturedVCCredentialJWT && (
                      <button
                        onClick={() => setOID4VPCredentialJWTInput(capturedVCCredentialJWT)}
                        className="text-[11px] sm:text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
                      >
                        Use captured value
                      </button>
                    )}
                  </div>
                  <textarea
                    value={oid4vpCredentialJWTInput}
                    onChange={(event) => setOID4VPCredentialJWTInput(event.target.value)}
                    rows={5}
                    placeholder="Paste SD-JWT VC or issuer credential JWT (or leave blank to auto-issue one)"
                    className="w-full px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-[11px] sm:text-xs font-mono text-white placeholder-surface-600 focus:outline-none focus:border-violet-500/50 focus:ring-1 focus:ring-violet-500/20 transition-all resize-y"
                  />
                </div>

                <div className="space-y-1.5">
                  <div className="text-xs sm:text-sm font-medium text-surface-300">Selective disclosure claims</div>
                  <p className="text-[11px] sm:text-xs text-surface-400">
                    Choose which SD-JWT disclosures to include in the VP response.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {oid4vpCredentialDisclosureOptions.map((claimName) => {
                      const selected = oid4vpDisclosureClaims.includes(claimName)
                      return (
                        <button
                          key={claimName}
                          type="button"
                          onClick={() => {
                            setOID4VPDisclosureClaims((previous) => {
                              if (previous.includes(claimName)) {
                                return previous.filter((item) => item !== claimName)
                              }
                              return [...previous, claimName].sort()
                            })
                          }}
                          className={`px-2 py-1 rounded border text-[11px] sm:text-xs transition-colors ${
                            selected
                              ? 'border-violet-500/40 bg-violet-500/20 text-violet-200'
                              : 'border-white/10 bg-surface-900 text-surface-300 hover:text-white'
                          }`}
                        >
                          {claimName}
                        </button>
                      )
                    })}
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="text-xs sm:text-sm font-medium text-surface-300">Wallet execution mode</div>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => setOID4VPWalletMode('one_click')}
                      className={`px-2.5 py-2 rounded-lg border text-xs transition-colors ${
                        oid4vpWalletMode === 'one_click'
                          ? 'border-violet-500/40 bg-violet-500/15 text-violet-200'
                          : 'border-white/10 bg-surface-900 text-surface-300 hover:text-white'
                      }`}
                    >
                      One-click mode
                    </button>
                    <button
                      type="button"
                      onClick={() => setOID4VPWalletMode('stepwise')}
                      className={`px-2.5 py-2 rounded-lg border text-xs transition-colors ${
                        oid4vpWalletMode === 'stepwise'
                          ? 'border-violet-500/40 bg-violet-500/15 text-violet-200'
                          : 'border-white/10 bg-surface-900 text-surface-300 hover:text-white'
                      }`}
                    >
                      Stepwise mode
                    </button>
                  </div>
                </div>

                {oid4vpWalletMode === 'stepwise' && (
                  <div className="rounded-lg border border-violet-500/20 bg-violet-500/5 p-3 space-y-2">
                    <div className="text-[11px] sm:text-xs text-violet-200 font-medium">Expert stepwise ceremony</div>
                    <div className="grid grid-cols-2 gap-2">
                      <button
                        type="button"
                        onClick={() => executeOID4VPWalletStep('bootstrap')}
                        disabled={oid4vpWalletSubmitPending}
                        className="px-2 py-1.5 rounded border border-white/10 bg-surface-900 text-[11px] sm:text-xs text-surface-200 hover:text-white disabled:opacity-50"
                      >
                        1) Bootstrap wallet
                      </button>
                      <button
                        type="button"
                        onClick={() => executeOID4VPWalletStep('issue_credential')}
                        disabled={oid4vpWalletSubmitPending}
                        className="px-2 py-1.5 rounded border border-white/10 bg-surface-900 text-[11px] sm:text-xs text-surface-200 hover:text-white disabled:opacity-50"
                      >
                        2) Issue credential
                      </button>
                      <button
                        type="button"
                        onClick={() => executeOID4VPWalletStep('build_presentation')}
                        disabled={!canSubmitOID4VPWalletInteraction || oid4vpWalletSubmitPending}
                        className="px-2 py-1.5 rounded border border-white/10 bg-surface-900 text-[11px] sm:text-xs text-surface-200 hover:text-white disabled:opacity-50"
                      >
                        3) Build vp_token
                      </button>
                      <button
                        type="button"
                        onClick={() => executeOID4VPWalletStep('submit_response')}
                        disabled={!canSubmitOID4VPWalletInteraction || oid4vpWalletSubmitPending}
                        className="px-2 py-1.5 rounded border border-white/10 bg-surface-900 text-[11px] sm:text-xs text-surface-200 hover:text-white disabled:opacity-50"
                      >
                        4) Submit response
                      </button>
                    </div>
                    <div className="text-[11px] sm:text-xs text-surface-300">
                      Last step: <code>{oid4vpStepwiseLastStep || 'none'}</code>
                      {oid4vpStepwiseVPToken && ' • vp_token cached'}
                    </div>
                  </div>
                )}

                {oid4vpWalletMode === 'one_click' && !canSubmitOID4VPWalletInteraction && (
                  <p className="text-[11px] sm:text-xs text-amber-400">
                    Missing request context. Re-run OID4VP request creation.
                  </p>
                )}
                {oid4vpWalletMode === 'one_click' && canSubmitOID4VPWalletInteraction && (
                  <p className="text-[11px] sm:text-xs text-cyan-300">
                    This modal can complete OID4VP-only runs end-to-end. If credential_jwt is empty, wallet bootstrap will run a real OID4VCI issuance to obtain one before submission.
                  </p>
                )}
                {oid4vpWalletMode === 'stepwise' && (
                  <p className="text-[11px] sm:text-xs text-cyan-300">
                    Stepwise mode exposes wallet key/bootstrap, credential issuance, presentation build, and verifier callback as separate actions.
                  </p>
                )}
                {!!oid4vpWalletSubmitError && (
                  <p className="text-[11px] sm:text-xs text-red-300">{oid4vpWalletSubmitError}</p>
                )}
              </div>

              <div className="px-4 sm:px-5 py-3 border-t border-white/10 flex items-center justify-end gap-2">
                <button
                  onClick={closeOID4VPWalletModal}
                  disabled={oid4vpWalletSubmitPending}
                  className="px-3 py-2 rounded-lg bg-surface-800 border border-white/10 text-surface-300 text-xs sm:text-sm hover:text-white disabled:opacity-50 transition-colors"
                >
                  Cancel
                </button>
                {oid4vpWalletMode === 'one_click' && (
                  <button
                    onClick={submitOID4VPWalletInteraction}
                    disabled={!canSubmitOID4VPWalletInteraction || oid4vpWalletSubmitPending}
                    className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-violet-500/20 border border-violet-500/30 text-violet-200 text-xs sm:text-sm font-medium hover:bg-violet-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    {oid4vpWalletSubmitPending && <Loader2 className="w-4 h-4 animate-spin" />}
                    <span>{oid4vpWalletSubmitPending ? 'Submitting...' : 'Submit Wallet Response'}</span>
                  </button>
                )}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Token Inspector */}
      <AnimatePresence>
        {(hasCapturedTokens || inspectedToken) && (
          <motion.section
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="rounded-xl border border-white/10 bg-surface-900/30 overflow-hidden"
          >
            <div className="px-3 sm:px-5 py-3 sm:py-4 border-b border-white/10 overflow-hidden">
              <div className="flex items-center gap-2 sm:gap-3 mb-2">
                <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-lg bg-amber-500/20 flex items-center justify-center flex-shrink-0">
                  <Key className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-amber-400" />
                </div>
                <span className="font-medium text-white text-xs sm:text-base">Tokens</span>
              </div>
              
              {hasCapturedTokens && (
                <div className="overflow-x-auto scrollbar-hide -mx-3 px-3 sm:mx-0 sm:px-0">
                  <div className="flex items-center gap-1.5 sm:gap-2 pb-1 min-w-max">
                    {realExecutor.state?.tokens.accessToken && (
                      <TokenButton
                        label="access"
                        color="green"
                        active={inspectedToken === realExecutor.state?.tokens.accessToken}
                        onClick={() => setInspectedToken(realExecutor.state?.tokens.accessToken || '')}
                      />
                    )}
                    {realExecutor.state?.tokens.idToken && (
                      <TokenButton
                        label="id"
                        color="orange"
                        active={inspectedToken === realExecutor.state?.tokens.idToken}
                        onClick={() => setInspectedToken(realExecutor.state?.tokens.idToken || '')}
                      />
                    )}
                    {realExecutor.state?.tokens.refreshToken && (
                      <TokenButton
                        label="refresh"
                        color="blue"
                        active={inspectedToken === realExecutor.state?.tokens.refreshToken}
                        onClick={() => setInspectedToken(realExecutor.state?.tokens.refreshToken || '')}
                      />
                    )}
                  </div>
                </div>
              )}
            </div>

            <div className="p-4 sm:p-5">
              {inspectedToken ? (
                <TokenInspector token={inspectedToken} />
              ) : (
                <div className="text-center py-6 text-surface-400 text-sm">
                  Select a token above to decode
                </div>
              )}
            </div>
          </motion.section>
        )}
      </AnimatePresence>

      {/* Manual JWT Input */}
      <section className="rounded-xl border border-white/10 bg-surface-900/30 p-3 sm:p-5">
        <div className="flex items-center gap-2 mb-2 sm:mb-3">
          <Sparkles className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-purple-400" />
          <span className="text-xs sm:text-sm font-medium text-surface-300">Decode any JWT</span>
        </div>
        <div className="flex gap-2">
          <input
            type="text"
            value={inspectedToken}
            onChange={(e) => setInspectedToken(e.target.value)}
            placeholder="Paste token here..."
            className="flex-1 min-w-0 px-2.5 sm:px-4 py-2 sm:py-2.5 rounded-lg bg-surface-900 border border-white/10 text-xs sm:text-sm font-mono text-white placeholder-surface-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
          />
          {inspectedToken && (
            <button
              onClick={() => setInspectedToken('')}
              className="px-3 sm:px-4 py-2 sm:py-2.5 rounded-lg bg-surface-800 text-surface-400 hover:text-white text-xs sm:text-sm transition-colors flex-shrink-0"
            >
              Clear
            </button>
          )}
        </div>
      </section>
    </div>
    </>
  )
}

function StatusBadge({ status }: { status: string }) {
  const config = {
    completed: { bg: 'bg-green-500/10', border: 'border-green-500/30', text: 'text-green-400', label: 'Completed', shortLabel: 'Done' },
    executing: { bg: 'bg-amber-500/10', border: 'border-amber-500/30', text: 'text-amber-400', label: 'Executing...', shortLabel: 'Running' },
    awaiting_user: { bg: 'bg-blue-500/10', border: 'border-blue-500/30', text: 'text-blue-400', label: 'Awaiting input', shortLabel: 'Waiting' },
    error: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', label: 'Error', shortLabel: 'Error' },
  }[status] || { bg: 'bg-surface-800', border: 'border-white/10', text: 'text-surface-400', label: status, shortLabel: status }

  return (
    <div className={`px-2 sm:px-3 py-1 sm:py-1.5 rounded-full ${config.bg} border ${config.border} flex-shrink-0`}>
      <span className={`text-xs sm:text-sm font-medium ${config.text} whitespace-nowrap`}>
        <span className="hidden sm:inline">{config.label}</span>
        <span className="sm:hidden">{config.shortLabel}</span>
      </span>
    </div>
  )
}

function FlowButton({ 
  icon: Icon, 
  label, 
  sublabel, 
  color,
  onClick 
}: {
  icon: React.ElementType
  label: string
  sublabel: string
  color: 'blue' | 'green' | 'orange' | 'purple' | 'cyan'
  onClick: () => void
}) {
  const colors = {
    blue: { border: 'border-blue-500/20 hover:border-blue-500/40 active:border-blue-500/60', bg: 'bg-blue-500/10', text: 'text-blue-400' },
    green: { border: 'border-green-500/20 hover:border-green-500/40 active:border-green-500/60', bg: 'bg-green-500/10', text: 'text-green-400' },
    orange: { border: 'border-orange-500/20 hover:border-orange-500/40 active:border-orange-500/60', bg: 'bg-orange-500/10', text: 'text-orange-400' },
    purple: { border: 'border-purple-500/20 hover:border-purple-500/40 active:border-purple-500/60', bg: 'bg-purple-500/10', text: 'text-purple-400' },
    cyan: { border: 'border-cyan-500/20 hover:border-cyan-500/40 active:border-cyan-500/60', bg: 'bg-cyan-500/10', text: 'text-cyan-400' },
  }
  const c = colors[color]

  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2.5 sm:gap-4 p-2.5 sm:p-4 rounded-xl border ${c.border} bg-gradient-to-br from-white/[0.02] to-transparent hover:from-white/[0.04] active:from-white/[0.06] transition-all text-left group touch-manipulation`}
    >
      <div className={`w-8 h-8 sm:w-10 sm:h-10 rounded-lg ${c.bg} flex items-center justify-center flex-shrink-0`}>
        <Icon className={`w-4 h-4 sm:w-5 sm:h-5 ${c.text}`} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="font-medium text-white text-xs sm:text-base truncate">{label}</div>
        <div className="text-[10px] sm:text-sm text-surface-400">{sublabel}</div>
      </div>
      <ChevronRight className="w-4 h-4 sm:w-5 sm:h-5 text-surface-600 group-hover:text-surface-400 transition-colors flex-shrink-0" />
    </button>
  )
}

function TokenButton({ 
  label, 
  color,
  active, 
  onClick 
}: {
  label: string
  color: 'green' | 'orange' | 'blue'
  active: boolean
  onClick: () => void
}) {
  const colors = {
    green: active ? 'bg-green-500/20 text-green-400 border-green-500/30' : 'bg-surface-800 text-surface-400 border-transparent hover:text-green-400',
    orange: active ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' : 'bg-surface-800 text-surface-400 border-transparent hover:text-orange-400',
    blue: active ? 'bg-blue-500/20 text-blue-400 border-blue-500/30' : 'bg-surface-800 text-surface-400 border-transparent hover:text-blue-400',
  }

  return (
    <button
      onClick={onClick}
      className={`px-2.5 py-1.5 rounded-md text-xs font-mono border transition-all whitespace-nowrap flex-shrink-0 ${colors[color]}`}
    >
      {label}
    </button>
  )
}

function parseSDJWTDisclosureClaimNames(rawCredential: string): string[] {
  const normalized = rawCredential.trim()
  if (!normalized) {
    return []
  }

  const parts = normalized
    .split('~')
    .map((part) => part.trim())
    .filter(Boolean)
  if (parts.length < 2) {
    return []
  }

  const claimNames = new Set<string>()
  for (const encodedDisclosure of parts.slice(1)) {
    const decodedDisclosure = decodeBase64URLSegment(encodedDisclosure)
    if (!decodedDisclosure) {
      continue
    }
    try {
      const parsedDisclosure = JSON.parse(decodedDisclosure) as unknown
      if (
        Array.isArray(parsedDisclosure) &&
        parsedDisclosure.length >= 3 &&
        typeof parsedDisclosure[1] === 'string'
      ) {
        claimNames.add(parsedDisclosure[1])
      }
    } catch {
      // Ignore malformed segments (for example optional KB-JWT segment).
    }
  }

  return Array.from(claimNames).sort()
}

function decodeBase64URLSegment(value: string): string {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4)
  try {
    return atob(padded)
  } catch {
    return ''
  }
}

function humanizeTrustMode(mode: string): string {
  const normalized = mode.trim().toLowerCase()
  if (normalized === 'controlled_trust_mode') {
    return 'controlled trust mode'
  }
  if (normalized === 'interop_mode') {
    return 'interop mode'
  }
  return mode
}
