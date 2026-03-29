/**
 * Looking Glass - Protocol Execution & Inspection
 */

'use client'

import { useState, useCallback, useMemo, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  Eye, Play, RotateCcw, Key, Square,
  Fingerprint, Shield, Lock, Sparkles,
  RefreshCw, FileKey, KeyRound, Workflow, Search, Trash2, User, QrCode, Copy, Check, ExternalLink
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

import { TokenInspector } from '../lookingglass/components/inspectors/TokenInspector'
import { StatusBadge as SharedStatusBadge, type StatusBadgeVariant } from '../lookingglass/components/shared'
import { FlowButton, TokenButton } from '../lookingglass/components/ActionButtons'
import { OID4VPWalletModal } from '../lookingglass/components/OID4VPWalletModal'
import {
  DEFAULT_OID4VP_DCQL_PRESET_ID,
  OID4VP_DCQL_PRESETS,
  OID4VP_DEFAULT_DISCLOSURE_HINTS,
  parseSDJWTDisclosureClaimNames,
  humanizeOID4VPTrustMode,
} from '../protocols/config/oid4vp'
import { toDataURL as toQRCodeDataURL } from 'qrcode'

const OID4VP_WALLET_SUBMIT_URL = 'https://wallet.protocolsoup.com/submit'
const SAFE_QR_DATA_URL_PREFIX = 'data:image/png;base64,'
const OID4VCI_CREDENTIAL_PROFILES = [
  { id: 'UniversityDegreeCredential', format: 'dc+sd-jwt', label: 'dc+sd-jwt' },
  { id: 'UniversityDegreeCredentialJWT', format: 'jwt_vc_json', label: 'jwt_vc_json' },
  { id: 'UniversityDegreeCredentialJWTLD', format: 'jwt_vc_json-ld', label: 'jwt_vc_json-ld' },
  { id: 'UniversityDegreeCredentialLDP', format: 'ldp_vc', label: 'ldp_vc' },
] as const
const STATUS_BADGE_VARIANTS: Record<string, StatusBadgeVariant> = {
  completed: { bg: 'bg-green-500/10', border: 'border-green-500/30', text: 'text-green-400', label: 'Completed', shortLabel: 'Done' },
  executing: { bg: 'bg-amber-500/10', border: 'border-amber-500/30', text: 'text-amber-400', label: 'Executing...', shortLabel: 'Running' },
  awaiting_user: { bg: 'bg-blue-500/10', border: 'border-blue-500/30', text: 'text-blue-400', label: 'Awaiting input', shortLabel: 'Waiting' },
  error: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', label: 'Error', shortLabel: 'Error' },
}

function sanitizeQRCodeDataURL(raw: string): string {
  const value = raw.trim()
  if (!value.startsWith(SAFE_QR_DATA_URL_PREFIX)) {
    return ''
  }
  const base64Payload = value.slice(SAFE_QR_DATA_URL_PREFIX.length)
  if (!base64Payload || !/^[A-Za-z0-9+/=]+$/.test(base64Payload)) {
    return ''
  }
  return value
}

export function LookingGlass() {
  const router = useRouter()

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
  const [oid4vciCredentialConfigurationID, setOID4VCICredentialConfigurationID] = useState('UniversityDegreeCredential')
  const [wireSessionId, setWireSessionId] = useState<string | null>(null)
  const [wireSessionError, setWireSessionError] = useState<string | null>(null)
  const [pendingExecute, setPendingExecute] = useState(false)
  const [handoffCopied, setHandoffCopied] = useState(false)
  const [oid4vpWalletHandoffQRCodeObjectURL, setOID4VPWalletHandoffQRCodeObjectURL] = useState('')
  const [oid4vpWalletHandoffQRCodeError, setOID4VPWalletHandoffQRCodeError] = useState<string | null>(null)
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
  const [oid4vpClientIDScheme, setOID4VPClientIDScheme] = useState<'redirect_uri' | 'verifier_attestation' | 'x509_san_dns'>('redirect_uri')
  const [oid4vpClientIDInput, setOID4VPClientIDInput] = useState('')
  const [oid4vpWalletMode, setOID4VPWalletMode] = useState<'one_click' | 'stepwise'>('one_click')
  const [oid4vpStepwiseVPToken, setOID4VPStepwiseVPToken] = useState('')
  const [oid4vpStepwiseLastStep, setOID4VPStepwiseLastStep] = useState('')
  const [oid4vpDisclosureClaims, setOID4VPDisclosureClaims] = useState<string[]>([])
  const [oid4vpContractExpanded, setOID4VPContractExpanded] = useState(true)
  const [showAllQuickFlows, setShowAllQuickFlows] = useState(false)

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
  const isOID4VCIFlow = selectedProtocol?.id === 'oid4vci'
  const isOID4VCITxCodeFlow = selectedProtocol?.id === 'oid4vci' && flowId === 'oid4vci-pre-authorized-tx-code'
  const isOID4VPFlow = selectedProtocol?.id === 'oid4vp'
  const hasFlowConfigurationInputs = isRefreshTokenFlow || isTokenBasedFlow || isSCIMFlow || isOID4VCIFlow || isOID4VPFlow
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
  const selectedOID4VCICredentialProfile = useMemo(
    () => OID4VCI_CREDENTIAL_PROFILES.find((profile) => profile.id === oid4vciCredentialConfigurationID) || OID4VCI_CREDENTIAL_PROFILES[0],
    [oid4vciCredentialConfigurationID],
  )
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
  const oid4vpClientIDForExecutor = isOID4VPFlow
    ? oid4vpClientIDInput.trim() || undefined
    : undefined
  const oid4vpClientIDSchemeForExecutor = isOID4VPFlow
    ? oid4vpClientIDScheme
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
    oid4vciCredentialConfigurationID: isOID4VCIFlow ? selectedOID4VCICredentialProfile.id : undefined,
    oid4vciCredentialFormat: isOID4VCIFlow ? selectedOID4VCICredentialProfile.format : undefined,
    oid4vpDCQLQueryJSON: oid4vpDCQLQueryForExecutor,
    oid4vpScopeAlias: oid4vpScopeAliasForExecutor,
    oid4vpClientID: oid4vpClientIDForExecutor,
    oid4vpClientIDScheme: oid4vpClientIDSchemeForExecutor,
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
  const oid4vpRequestClientID = useMemo(() => {
    const requestMetadata = (oid4vpRequestObjectArtifact?.metadata || {}) as Record<string, unknown>
    const handoffMetadata = (walletHandoffArtifact?.metadata || {}) as Record<string, unknown>
    return String(requestMetadata.clientID || handoffMetadata.clientID || '').trim()
  }, [oid4vpRequestObjectArtifact, walletHandoffArtifact])
  const oid4vpRequestClientIDScheme = useMemo(() => {
    const requestMetadata = (oid4vpRequestObjectArtifact?.metadata || {}) as Record<string, unknown>
    const handoffMetadata = (walletHandoffArtifact?.metadata || {}) as Record<string, unknown>
    return String(requestMetadata.clientIDScheme || handoffMetadata.clientIDScheme || '').trim()
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
  useEffect(() => {
    setOID4VPWalletHandoffQRCodeObjectURL((previous) => {
      if (previous) {
        URL.revokeObjectURL(previous)
      }
      return ''
    })

    if (!isOID4VPFlow || !oid4vpWalletHandoffPayload) {
      setOID4VPWalletHandoffQRCodeError(null)
      return
    }

    let cancelled = false
    let generatedObjectURL = ''
    setOID4VPWalletHandoffQRCodeError(null)

    toQRCodeDataURL(oid4vpWalletHandoffPayload, {
      width: 300,
      margin: 1,
      errorCorrectionLevel: 'M',
    })
      .then(async (dataURL) => {
        const safeDataURL = sanitizeQRCodeDataURL(dataURL)
        if (!safeDataURL) {
          if (!cancelled) {
            setOID4VPWalletHandoffQRCodeError('Generated QR payload did not pass safety checks')
          }
          return
        }
        const response = await fetch(safeDataURL)
        const blob = await response.blob()
        if (blob.type !== 'image/png') {
          throw new Error('Generated QR is not a PNG image')
        }
        generatedObjectURL = URL.createObjectURL(blob)
        if (cancelled) {
          URL.revokeObjectURL(generatedObjectURL)
          generatedObjectURL = ''
          return
        }
        if (!cancelled) {
          const nextObjectURL = generatedObjectURL
          generatedObjectURL = ''
          setOID4VPWalletHandoffQRCodeObjectURL(nextObjectURL)
        }
      })
      .catch((error: unknown) => {
        if (cancelled) return
        const message = error instanceof Error ? error.message : 'Failed to generate QR code'
        setOID4VPWalletHandoffQRCodeObjectURL('')
        setOID4VPWalletHandoffQRCodeError(message)
      })

    return () => {
      cancelled = true
      if (generatedObjectURL) {
        URL.revokeObjectURL(generatedObjectURL)
      }
    }
  }, [isOID4VPFlow, oid4vpWalletHandoffPayload])

  useEffect(() => {
    if (!isOID4VPFlow) {
      setOID4VPContractExpanded(true)
      return
    }
    if (walletHandoffArtifact || status !== 'idle') {
      setOID4VPContractExpanded(false)
    }
  }, [isOID4VPFlow, walletHandoffArtifact, status])

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

  const injectWalletLifecycleEvents = useCallback((responsePayload: Record<string, unknown> | null) => {
    if (!responsePayload) return
    const events = responsePayload._looking_glass_events
    if (!Array.isArray(events)) return
    for (const event of events) {
      if (!event || typeof event !== 'object') continue
      const ev = event as Record<string, unknown>
      realExecutor.injectVCArtifact({
        type: 'wallet_lifecycle',
        title: String(ev.title || ev.type || 'Wallet Event'),
        format: String(ev.type || ''),
        json: (ev.data && typeof ev.data === 'object' ? ev.data : {}) as Record<string, unknown>,
      })
    }
  }, [realExecutor])

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
        credential_format: selectedOID4VCICredentialProfile.format,
        credential_configuration_id: selectedOID4VCICredentialProfile.id,
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
      injectWalletLifecycleEvents(responsePayload)
      const upstreamStatus = Number(responsePayload?.upstream_status || 0)
      const credentialSource = String(responsePayload?.credential_source || '').trim()
      const effectiveWalletSubject = String(responsePayload?.wallet_subject || walletSubject || '').trim()
      const disclosureClaims = Array.isArray(responsePayload?.disclosure_claims)
        ? responsePayload?.disclosure_claims.map((claimName) => String(claimName).trim()).filter(Boolean)
        : []
      const sourceMessage = credentialSource === 'auto_issued_oid4vci'
        ? 'Auto-issued a fresh OID4VCI credential in the wallet bootstrap step.'
        : credentialSource === 'auto_refreshed_oid4vci'
          ? 'Auto-refreshed a stale credential via OID4VCI before presentation.'
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
    selectedOID4VCICredentialProfile.format,
    selectedOID4VCICredentialProfile.id,
    wireSessionId,
    executeFlow,
    injectWalletLifecycleEvents,
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
        credential_format: selectedOID4VCICredentialProfile.format,
        credential_configuration_id: selectedOID4VCICredentialProfile.id,
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

      injectWalletLifecycleEvents(responsePayload)
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
    selectedOID4VCICredentialProfile.format,
    selectedOID4VCICredentialProfile.id,
    wireSessionId,
    oid4vpRequestID,
    oid4vpRequestJWT,
    oid4vpRequestURI,
    oid4vpResponseMode,
    oid4vpStepwiseVPToken,
    executeFlow,
    injectWalletLifecycleEvents,
  ])

  const handleProtocolSelect = useCallback((protocol: LookingGlassProtocol) => {
    // SSF has its own dedicated sandbox - redirect there
    if (protocol.id === 'ssf') {
      router.push('/ssf-sandbox')
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
  }, [resetFlow, clearWireEvents, router])

  const handleFlowSelect = useCallback((flow: LookingGlassFlow) => {
    // SSF flows should redirect to the SSF Sandbox
    if (selectedProtocol?.id === 'ssf') {
      router.push('/ssf-sandbox')
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
  }, [resetFlow, clearWireEvents, selectedProtocol, router])

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
      router.push('/ssf-sandbox')
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
  }, [protocols, resetFlow, clearWireEvents, router])

  const hasCapturedTokens = realExecutor.state?.decodedTokens && realExecutor.state.decodedTokens.length > 0
  const quickStartFlows = [
    {
      icon: Workflow,
      label: 'Interaction Code Flow',
      sublabel: 'Full OAuth 2.0 + OIDC',
      color: 'cyan',
      protocolId: 'oidc',
      flowId: 'interaction-code',
    },
    {
      icon: Shield,
      label: 'Authorization Code',
      sublabel: 'OAuth 2.0',
      color: 'blue',
      protocolId: 'oauth2',
      flowId: 'authorization_code',
    },
    {
      icon: Lock,
      label: 'Client Credentials',
      sublabel: 'OAuth 2.0',
      color: 'green',
      protocolId: 'oauth2',
      flowId: 'client_credentials',
    },
    {
      icon: RefreshCw,
      label: 'Refresh Token',
      sublabel: 'OAuth 2.0',
      color: 'purple',
      protocolId: 'oauth2',
      flowId: 'refresh_token',
    },
    {
      icon: Fingerprint,
      label: 'OIDC Auth Code',
      sublabel: 'OpenID Connect',
      color: 'orange',
      protocolId: 'oidc',
      flowId: 'oidc_authorization_code',
    },
    {
      icon: FileKey,
      label: 'SP-Initiated SSO',
      sublabel: 'SAML 2.0',
      color: 'blue',
      protocolId: 'saml',
      flowId: 'sp_initiated_sso',
    },
  ] as const

  return (
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
              <SharedStatusBadge status={status} variants={STATUS_BADGE_VARIANTS} />
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
          <div className="flex items-center justify-between gap-2 text-surface-400 text-sm mb-3">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-amber-400" />
              <span>Quick start - select a flow to begin</span>
            </div>
            <button
              type="button"
              onClick={() => setShowAllQuickFlows((current) => !current)}
              className="sm:hidden text-[11px] font-medium text-surface-500 hover:text-surface-300 transition-colors"
            >
              {showAllQuickFlows ? 'Show less' : `Show all (${quickStartFlows.length})`}
            </button>
          </div>
          <div className="sm:hidden grid grid-cols-2 gap-2">
            {(showAllQuickFlows ? quickStartFlows : quickStartFlows.slice(0, 4)).map((flow) => (
              <FlowButton
                key={`${flow.protocolId}-${flow.flowId}`}
                icon={flow.icon}
                label={flow.label}
                sublabel={flow.sublabel}
                color={flow.color}
                compact
                onClick={() => handleQuickSelect(flow.protocolId, flow.flowId)}
              />
            ))}
          </div>
          <div className="hidden sm:grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {quickStartFlows.map((flow) => (
              <FlowButton
                key={`${flow.protocolId}-${flow.flowId}`}
                icon={flow.icon}
                label={flow.label}
                sublabel={flow.sublabel}
                color={flow.color}
                onClick={() => handleQuickSelect(flow.protocolId, flow.flowId)}
              />
            ))}
          </div>
        </section>
      )}

      {/* Protocol Selector */}
      <section className="flex flex-wrap items-center gap-2 sm:gap-3">
        <ProtocolSelector
          protocols={protocols}
          selectedProtocol={selectedProtocol}
          selectedFlow={selectedFlow}
          onProtocolSelect={handleProtocolSelect}
          onFlowSelect={handleFlowSelect}
          loading={protocolsLoading}
        />
        {selectedFlow && (
          <button
            onClick={handleReset}
            aria-label="Reset selected flow"
            className="flex items-center gap-1.5 px-2 py-1.5 rounded border border-white/10 text-xs sm:text-sm text-surface-400 hover:text-white hover:border-white/20 transition-colors"
          >
            <RotateCcw className="w-3 h-3 sm:w-3.5 sm:h-3.5" />
            <span className="hidden sm:inline">Reset</span>
          </button>
        )}
      </section>

      {hasFlowConfigurationInputs && (
        <section className="rounded-xl border border-white/10 bg-surface-900/20 p-3 sm:p-4">
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

        {showVCTab && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="mt-3 sm:mt-4 pt-3 sm:pt-4 border-t border-white/10"
          >
            <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 mb-2">
              <Fingerprint className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-indigo-400" />
              <span className="text-xs sm:text-sm font-medium text-surface-300">VC credential profile</span>
            </div>
            <p className="text-[10px] sm:text-xs text-surface-400 mb-2 sm:mb-3 leading-relaxed">
              Select the credential profile used for issuance and wallet presentation.
            </p>
            <select
              value={selectedOID4VCICredentialProfile.id}
              onChange={(event) => setOID4VCICredentialConfigurationID(event.target.value)}
              className="w-full px-2.5 sm:px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-xs sm:text-sm text-white focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/20 transition-all"
            >
              {OID4VCI_CREDENTIAL_PROFILES.map((profile) => (
                <option key={profile.id} value={profile.id}>
                  {profile.label} ({profile.id})
                </option>
              ))}
            </select>
          </motion.div>
        )}

        {isOID4VPFlow && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="mt-3 sm:mt-4 pt-3 sm:pt-4 border-t border-white/10"
          >
            <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
              <div className="flex items-center gap-1.5 sm:gap-2">
                <Workflow className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-violet-400" />
                <span className="text-xs sm:text-sm font-medium text-surface-300">OID4VP request contract</span>
                <span className="text-[10px] sm:text-xs text-surface-500">
                  {oid4vpQueryMode === 'dcql' ? 'DCQL mode' : 'Scope alias mode'}
                </span>
              </div>
              <button
                type="button"
                onClick={() => setOID4VPContractExpanded((previous) => !previous)}
                className="px-2 py-1 rounded border border-white/10 bg-surface-900 text-[10px] sm:text-xs text-surface-300 hover:text-white transition-colors"
              >
                {oid4vpContractExpanded ? 'Collapse' : 'Expand'}
              </button>
            </div>
            {oid4vpContractExpanded && (
              <>
                <p className="text-[10px] sm:text-xs text-surface-400 mb-2 sm:mb-3 leading-relaxed">
                  Configure either <code className="text-violet-300">dcql_query</code> or a scope alias (mutually exclusive per OpenID4VP).
                </p>

                <div className="mb-3 space-y-2 rounded-lg border border-white/10 bg-surface-950/60 p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <label className="text-[11px] sm:text-xs text-surface-400">Verifier trust profile</label>
                    <select
                      value={oid4vpClientIDScheme}
                      onChange={(event) => setOID4VPClientIDScheme(event.target.value as 'redirect_uri' | 'verifier_attestation' | 'x509_san_dns')}
                      className="px-2 py-1.5 rounded bg-surface-900 border border-white/10 text-xs text-surface-200 focus:outline-none focus:border-violet-500/40"
                    >
                      <option value="redirect_uri">redirect_uri</option>
                      <option value="verifier_attestation">verifier_attestation</option>
                      <option value="x509_san_dns">x509_san_dns</option>
                    </select>
                  </div>
                  <input
                    type="text"
                    value={oid4vpClientIDInput}
                    onChange={(event) => setOID4VPClientIDInput(event.target.value)}
                    placeholder="Optional client_id override. Leave blank to use the verifier default for the selected scheme."
                    className="w-full px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-[11px] sm:text-xs font-mono text-white placeholder-surface-600 focus:outline-none focus:border-violet-500/50 focus:ring-1 focus:ring-violet-500/20 transition-all"
                  />
                  <p className="text-[10px] sm:text-xs text-surface-500 leading-relaxed">
                    <code className="text-violet-300">verifier_attestation</code> uses a live attestation issuer and JWKS. <code className="text-violet-300">x509_san_dns</code> binds verifier identity to a DNS name via X.509 certificate SAN — auto-provisions an ephemeral CA + leaf chain when no external certificates are configured.
                  </p>
                </div>

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
              </>
            )}
          </motion.div>
        )}
        </section>
      )}

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
                <details className="mt-2 rounded border border-white/10 bg-surface-950/70">
                  <summary className="cursor-pointer px-2 py-1.5 text-[11px] text-surface-400 hover:text-white">
                    Show raw handoff payload
                  </summary>
                  <pre className="px-2 pb-2 text-[11px] text-surface-300 overflow-x-auto">
                    {oid4vpWalletHandoffPayload}
                  </pre>
                </details>
                {oid4vpWalletHandoffQRCodeObjectURL && (
                  <div className="mt-3 flex flex-col items-center gap-2">
                    <img
                      src={oid4vpWalletHandoffQRCodeObjectURL}
                      alt="OID4VP wallet handoff QR"
                      className="w-44 h-44 rounded-lg border border-white/10 bg-white p-2"
                    />
                    <p className="text-[11px] text-surface-400 text-center max-w-[260px]">
                      Open wallet.protocolsoup.com on your wallet device and scan to complete the presentation
                    </p>
                  </div>
                )}
                {!oid4vpWalletHandoffQRCodeObjectURL && oid4vpWalletHandoffQRCodeError && (
                  <p className="mt-2 text-[11px] text-amber-300">
                    QR generation failed: {oid4vpWalletHandoffQRCodeError}
                  </p>
                )}
              </div>
            )}
            {isOID4VPFlow && !!oid4vpTrustMode && (
              <details className="mb-3 p-3 rounded-lg border border-violet-500/30 bg-violet-500/5 text-[11px] sm:text-xs text-violet-200">
                <summary className="cursor-pointer font-medium">
                  Verifier trust mode: {humanizeOID4VPTrustMode(oid4vpTrustMode)}
                </summary>
                {!!oid4vpRequestClientIDScheme && (
                  <div className="text-surface-300 mt-2">
                    client_id_scheme: <code>{oid4vpRequestClientIDScheme}</code>
                  </div>
                )}
                {!!oid4vpRequestClientID && (
                  <div className="text-surface-300 mt-2">
                    client_id: <code>{oid4vpRequestClientID}</code>
                  </div>
                )}
                {oid4vpDidWebAllowedHosts.length > 0 && (
                  <div className="text-surface-300 mt-2">
                    did:web host allowlist: <code>{oid4vpDidWebAllowedHosts.join(', ')}</code>
                  </div>
                )}
                {oid4vpDidWebAllowedHosts.length === 0 && (
                  <div className="text-surface-300 mt-2">No did:web host allowlist is active for this request.</div>
                )}
              </details>
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
          <OID4VPWalletModal
            onClose={closeOID4VPWalletModal}
            submitPending={oid4vpWalletSubmitPending}
            requestID={oid4vpRequestID}
            responseMode={oid4vpResponseMode}
            trustMode={oid4vpTrustMode}
            requestURI={oid4vpRequestURI}
            didWebAllowedHosts={oid4vpDidWebAllowedHosts}
            walletHandoffPayload={oid4vpWalletHandoffPayload}
            walletHandoffQRCodeDataURL={oid4vpWalletHandoffQRCodeObjectURL}
            walletHandoffQRCodeError={oid4vpWalletHandoffQRCodeError}
            capturedWalletSubject={capturedVCWalletSubject}
            walletSubjectInput={oid4vpWalletSubjectInput}
            onWalletSubjectInputChange={setOID4VPWalletSubjectInput}
            onUseCapturedWalletSubject={() => setOID4VPWalletSubjectInput(capturedVCWalletSubject)}
            capturedCredentialJWT={capturedVCCredentialJWT}
            credentialJWTInput={oid4vpCredentialJWTInput}
            onCredentialJWTInputChange={setOID4VPCredentialJWTInput}
            onUseCapturedCredentialJWT={() => setOID4VPCredentialJWTInput(capturedVCCredentialJWT)}
            disclosureOptions={oid4vpCredentialDisclosureOptions}
            selectedDisclosureClaims={oid4vpDisclosureClaims}
            onToggleDisclosureClaim={(claimName) => {
              setOID4VPDisclosureClaims((previous) => {
                if (previous.includes(claimName)) {
                  return previous.filter((item) => item !== claimName)
                }
                return [...previous, claimName].sort()
              })
            }}
            walletMode={oid4vpWalletMode}
            onWalletModeChange={setOID4VPWalletMode}
            onExecuteWalletStep={executeOID4VPWalletStep}
            canSubmitWalletInteraction={canSubmitOID4VPWalletInteraction}
            stepwiseLastStep={oid4vpStepwiseLastStep}
            stepwiseVPToken={oid4vpStepwiseVPToken}
            submitError={oid4vpWalletSubmitError}
            submitMessage={oid4vpWalletSubmitMessage}
            onSubmitWalletResponse={submitOID4VPWalletInteraction}
          />
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
  )
}

export default LookingGlass

