/**
 * Looking Glass - Protocol Execution & Inspection
 */

'use client'

import { useState, useCallback, useMemo, useEffect, useRef } from 'react'
import Link from 'next/link'
import { useRouter, usePathname, useSearchParams } from 'next/navigation'

import { parseFlowDeepLink, buildLookingGlassPath } from '@/components/palette/runDispatch'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  Eye, Play, RotateCcw, Key, Square,
  Fingerprint, Shield, Lock, Sparkles,
  RefreshCw, FileKey, KeyRound, Workflow, Search, Trash2, User, QrCode, Copy, Check, ExternalLink,
  Share2, XCircle, BookOpen, ChevronRight
} from 'lucide-react'

import {
  useProtocols,
  useRealFlowExecutor,
  useLookingGlassSession,
  ProtocolSelector,
  RealFlowPanel,
  type ClientCredentialsAccessTokenMode,
  type ClientCredentialsAuthMethod,
  type LookingGlassProtocol,
  type LookingGlassFlow,
} from '../lookingglass'
import { getLookingGlassSurface } from '../lookingglass/surfaces'
import { SecurityStatePanel } from '../lookingglass/components/ssf/SecurityStatePanel'
import { SETOverlay } from '../lookingglass/components/ssf/SETOverlay'
import { mapLookingGlassEventsToFlowEvents, setsFromLookingGlassEvents } from '../lookingglass/ssf/mapEvents'
import { getSSFLab, subscribeSSFLab, updateSSFLab } from '../lookingglass/ssf/lab-store'
import type { SecurityState } from '../lookingglass/ssf/types'

import { TokenInspector } from '../lookingglass/components/inspectors/TokenInspector'
import { StatusBadge as SharedStatusBadge, ProtocolNotice, SegmentedChoice, type StatusBadgeVariant } from '../lookingglass/components/shared'
import { FlowButton, TokenButton } from '../lookingglass/components/ActionButtons'
import { OID4VPWalletModal } from '../lookingglass/components/OID4VPWalletModal'
import {
  DEFAULT_OID4VP_DCQL_PRESET_ID,
  OID4VP_DCQL_PRESETS,
  OID4VP_DEFAULT_DISCLOSURE_HINTS,
  getOID4VPDCQLCredentialFormats,
  parseSDJWTDisclosureClaimNames,
  humanizeOID4VPTrustMode,
  withHAIPUniversityDegreeVCT,
} from '../protocols/config/oid4vp'
import {
  getCatalogFlow,
  getCatalogProtocol,
  getFlowRouteId,
} from '../protocols/presentation/protocol-catalog-data'
import { toDataURL as toQRCodeDataURL } from 'qrcode'

import { describeWalletAPIError, walletAPIURL, LOOKING_GLASS_X509_HASH_COERCION_GUIDANCE } from '../lookingglass/wallet-client'

const OID4VP_WALLET_SUBMIT_URL = walletAPIURL('/submit')
const SAFE_QR_DATA_URL_PREFIX = 'data:image/png;base64,'
// Profiles advertised in Credential Issuer Metadata (HAIP-aligned: dc+sd-jwt + mso_mdoc).
const OID4VCI_CREDENTIAL_PROFILES = [
  { id: 'MobileDrivingLicenceMsoMdoc', format: 'mso_mdoc', label: 'mso_mdoc (mDL)', haip: false },
  { id: 'UniversityDegreeCredential', format: 'dc+sd-jwt', label: 'dc+sd-jwt', haip: false },
  // HAIP key-attested configurations. Looking Glass pre-authorized redemption
  // goes through the wallet harness, which supplies client/key attestation when
  // WALLET_* attestation material is configured.
  { id: 'MobileDrivingLicenceMsoMdocHAIP', format: 'mso_mdoc', label: 'mso_mdoc (mDL, HAIP key-attested)', haip: true },
  { id: 'UniversityDegreeCredentialSDJWTHAIP', format: 'dc+sd-jwt', label: 'dc+sd-jwt (HAIP key-attested)', haip: true },
] as const
type OID4VCICredentialFormat = (typeof OID4VCI_CREDENTIAL_PROFILES)[number]['format']
type OID4VPClientIDScheme = 'redirect_uri' | 'verifier_attestation' | 'x509_san_dns' | 'x509_hash'

function oid4vciProfileFor(format: OID4VCICredentialFormat, haip: boolean) {
  return OID4VCI_CREDENTIAL_PROFILES.find((profile) => profile.format === format && profile.haip === haip)
    || OID4VCI_CREDENTIAL_PROFILES[0]
}
const LOOKING_GLASS_ISSUABLE_FORMATS = new Set<string>(
  OID4VCI_CREDENTIAL_PROFILES.map((profile) => profile.format),
)
const LOOKING_GLASS_OID4VP_DCQL_PRESETS = OID4VP_DCQL_PRESETS.filter((preset) => {
  try {
    const formats = getOID4VPDCQLCredentialFormats(preset.query)
    return formats.length > 0 && formats.every((format) => LOOKING_GLASS_ISSUABLE_FORMATS.has(format))
  } catch {
    return false
  }
})

function oid4vpDCQLPresetForFormat(format: OID4VCICredentialFormat) {
  return LOOKING_GLASS_OID4VP_DCQL_PRESETS.find((preset) => {
    try {
      return getOID4VPDCQLCredentialFormats(preset.query).includes(format)
    } catch {
      return false
    }
  })
}

function oid4vpDCQLQueryForSelection(format: OID4VCICredentialFormat, haip: boolean, issuerOrigin: string): string {
  const preset = oid4vpDCQLPresetForFormat(format)
  if (!preset) {
    return ''
  }
  if (!haip || format !== 'dc+sd-jwt') {
    return preset.query
  }
  try {
    return withHAIPUniversityDegreeVCT(preset.query, issuerOrigin)
  } catch {
    return preset.query
  }
}

const STATUS_BADGE_VARIANTS: Record<string, StatusBadgeVariant> = {
  completed: { bg: 'bg-green-500/10', border: 'border-green-500/30', text: 'text-green-400', label: 'Completed', shortLabel: 'Done' },
  executing: { bg: 'bg-amber-500/10', border: 'border-amber-500/30', text: 'text-amber-400', label: 'Executing...', shortLabel: 'Running' },
  awaiting_user: { bg: 'bg-blue-500/10', border: 'border-blue-500/30', text: 'text-blue-400', label: 'Awaiting input', shortLabel: 'Waiting' },
  error: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', label: 'Error', shortLabel: 'Error' },
}

function formatOID4VPList(values: string[]): string {
  if (values.length === 0) {
    return ''
  }
  return values.map((value) => `"${value}"`).join(', ')
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

function describeWalletSubmitError(responsePayload: Record<string, unknown> | null, fallback: string): string {
  const baseMessage = describeWalletAPIError(responsePayload, fallback)
  const credentialMatches = responsePayload?.credential_matches
  if (!credentialMatches || typeof credentialMatches !== 'object' || Array.isArray(credentialMatches)) {
    return baseMessage
  }

  const reasons = (credentialMatches as Record<string, unknown>).reasons
  if (!Array.isArray(reasons) || reasons.length === 0) {
    return baseMessage
  }

  const details = reasons
    .map((reason) => String(reason).trim())
    .filter(Boolean)
    .slice(0, 3)

  if (details.length === 0) {
    return baseMessage
  }
  return `${baseMessage}. Match details: ${details.join('; ')}.`
}

function pickSSFLabFlow(protocol: LookingGlassProtocol): LookingGlassFlow | undefined {
  const flows = protocol.flows || []
  return flows.find((flow) => flow.id === 'ssf-stream-lab') || flows[0]
}

export function LookingGlass() {
  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()
  const [shareCopied, setShareCopied] = useState(false)
  const lastHandledPairRef = useRef<string | null>(null)

  const [selectedProtocol, setSelectedProtocol] = useState<LookingGlassProtocol | null>(null)
  const [selectedFlow, setSelectedFlow] = useState<LookingGlassFlow | null>(null)
  const [inspectedToken, setInspectedToken] = useState('')
  const [refreshTokenInput, setRefreshTokenInput] = useState('')
  const [storedRefreshToken, setStoredRefreshToken] = useState<string | null>(null)
  const [storedAccessToken, setStoredAccessToken] = useState<string | null>(null)
  const [clientCredentialsAuthMethod, setClientCredentialsAuthMethod] = useState<ClientCredentialsAuthMethod>('client_secret_basic')
  const [clientCredentialsAccessTokenMode, setClientCredentialsAccessTokenMode] = useState<ClientCredentialsAccessTokenMode>('bearer')
  // Token input for introspection/revocation/userinfo flows
  const [tokenInput, setTokenInput] = useState('')
  const [scimBearerToken, setScimBearerToken] = useState('')
  const [scimTokenLoading, setScimTokenLoading] = useState(false)
  const [scimAuthEnabled, setScimAuthEnabled] = useState(true)
  const [oid4vciCredentialFormat, setOID4VCICredentialFormat] = useState<OID4VCICredentialFormat>('mso_mdoc')
  const [oid4vciHaip, setOID4VCIHaip] = useState(false)
  const [oid4vciWalletOfferEndpoint, setOID4VCIWalletOfferEndpoint] = useState('')
  const [oid4vciAdvancedExpanded, setOID4VCIAdvancedExpanded] = useState(false)
  const [wireSessionId, setWireSessionId] = useState<string | null>(null)
  const [wireSessionToken, setWireSessionToken] = useState<string | null>(null)
  const [wireSessionError, setWireSessionError] = useState<string | null>(null)
  const [pendingExecute, setPendingExecute] = useState(false)
  const [handoffCopied, setHandoffCopied] = useState(false)
  const [oid4vpWalletHandoffQRCodeObjectURL, setOID4VPWalletHandoffQRCodeObjectURL] = useState('')
  const [oid4vpWalletHandoffQRCodeError, setOID4VPWalletHandoffQRCodeError] = useState<string | null>(null)
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
  const [oid4vpClientIDScheme, setOID4VPClientIDScheme] = useState<OID4VPClientIDScheme>('redirect_uri')
  const [oid4vpClientIDInput, setOID4VPClientIDInput] = useState('')
  const [oid4vpRequestURIMethod, setOID4VPRequestURIMethod] = useState<'get' | 'post'>('get')
  const [oid4vpWalletMode, setOID4VPWalletMode] = useState<'one_click' | 'stepwise'>('one_click')
  const [oid4vpStepwiseVPToken, setOID4VPStepwiseVPToken] = useState('')
  const [oid4vpStepwiseLastStep, setOID4VPStepwiseLastStep] = useState('')
  const [oid4vpDisclosureClaims, setOID4VPDisclosureClaims] = useState<string[]>([])
  const [oid4vpContractExpanded, setOID4VPContractExpanded] = useState(false)
  const [showAllQuickFlows, setShowAllQuickFlows] = useState(false)
  const [ssfReady, setSsfReady] = useState(false)
  const [ssfSecurityState, setSsfSecurityState] = useState<SecurityState | null>(null)
  const [ssfEventId, setSsfEventId] = useState('')

  const { protocols, loading: protocolsLoading } = useProtocols()
  const {
    wireExchanges,
    events: lookingGlassEvents,
    connected: wireConnected,
    clearEvents: clearWireEvents,
  } = useLookingGlassSession(wireSessionId, wireSessionToken)

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
    // Client Credentials uses machine-client scopes regardless of the
    // independently selected authentication and access-token modes.
    const normalizedId = selectedFlow?.id?.toLowerCase().replace(/_/g, '-')
    if (normalizedId === 'client-credentials') {
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

  const referenceNavigation = useMemo(() => {
    if (!selectedProtocol || !selectedFlow) {
      return null
    }

    const protocol = getCatalogProtocol(selectedProtocol.id)
    if (!protocol) {
      return null
    }

    const flowRouteId = getFlowRouteId(selectedProtocol.id, selectedFlow.id)
    const flow = getCatalogFlow(selectedProtocol.id, flowRouteId)

    return {
      protocol: {
        name: protocol.name,
        href: `/protocol/${protocol.id}`,
      },
      flow: flow
        ? {
            name: flow.name,
            href: `/protocol/${protocol.id}/flow/${flow.id}`,
          }
        : null,
    }
  }, [selectedProtocol, selectedFlow])

  const showTLSContext = useMemo(() => {
    const normalizedFlowId = flowId || ''
    const protocolId = selectedProtocol?.id || ''
    return normalizedFlowId.includes('mtls')
      || normalizedFlowId.includes('certificate')
      || protocolId === 'spiffe'
      || (protocolId === 'oauth2' && normalizedFlowId === 'mtls-token-binding')
  }, [flowId, selectedProtocol?.id])

  const isRefreshTokenFlow = flowId === 'refresh-token'
  const isClientCredentialsFlow = flowId === 'client-credentials'
  const isTokenIntrospectionFlow = flowId === 'token-introspection'
  const isTokenRevocationFlow = flowId === 'token-revocation'
  const isUserInfoFlow = flowId === 'oidc-userinfo'
  const isTokenBasedFlow = isTokenIntrospectionFlow || isTokenRevocationFlow || isUserInfoFlow
  const isSCIMFlow = selectedProtocol?.id === 'scim'
  const isOID4VCIFlow = selectedProtocol?.id === 'oid4vci'
  const isOID4VCIIssuerInitiatedFlow = isOID4VCIFlow && flowId === 'oid4vci-issuer-initiated'

  const isOID4VPFlow = selectedProtocol?.id === 'oid4vp'
  const surface = useMemo(() => getLookingGlassSurface(selectedProtocol?.id), [selectedProtocol?.id])
  const SurfaceChrome = surface?.chrome
  const hasFlowConfigurationInputs = isClientCredentialsFlow || isRefreshTokenFlow || isTokenBasedFlow || isSCIMFlow || isOID4VCIFlow || isOID4VPFlow || Boolean(SurfaceChrome)
  const showVCTab = selectedProtocol?.id === 'oid4vci' || selectedProtocol?.id === 'oid4vp'
  const wasOID4VCIIssuerInitiatedFlowRef = useRef(false)

  useEffect(() => {
    const entering = isOID4VCIIssuerInitiatedFlow && !wasOID4VCIIssuerInitiatedFlowRef.current
    wasOID4VCIIssuerInitiatedFlowRef.current = isOID4VCIIssuerInitiatedFlow
    if (!entering || oid4vciCredentialFormat !== 'mso_mdoc') {
      return
    }
    setOID4VCIHaip(true)
  }, [isOID4VCIIssuerInitiatedFlow, oid4vciCredentialFormat])

  // Use stored token or user input for flows that need a token
  const activeToken = tokenInput || storedAccessToken || ''

  const [machineClientSecret, setMachineClientSecret] = useState<string | null>(null)
  const [machineTokenEndpoint, setMachineTokenEndpoint] = useState<string | null>(null)

  useEffect(() => {
    if (!isClientCredentialsFlow || clientCredentialsAuthMethod !== 'client_secret_basic') {
      setMachineClientSecret(null)
      setMachineTokenEndpoint(null)
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
        setMachineTokenEndpoint(
          typeof data?.token_endpoint === 'string' && data.token_endpoint.length > 0
            ? data.token_endpoint
            : null,
        )
      })
      .catch(() => {
        if (!cancelled) {
          setMachineClientSecret(null)
          setMachineTokenEndpoint(null)
        }
      })

    return () => {
      cancelled = true
    }
  }, [isClientCredentialsFlow, clientCredentialsAuthMethod])

  const clientConfig = useMemo(() => {
    if (isClientCredentialsFlow) {
      if (clientCredentialsAuthMethod === 'private_key_jwt') {
        return { clientId: '', clientSecret: undefined }
      }
      return { clientId: 'machine-client', clientSecret: machineClientSecret || undefined }
    }
    // All other flows (including refresh-token) use public-app
    // The refresh token must be used with the same client that obtained it
    return { clientId: 'public-app', clientSecret: undefined }
  }, [isClientCredentialsFlow, clientCredentialsAuthMethod, machineClientSecret])

  // Use stored token, input, or empty
  const activeRefreshToken = refreshTokenInput || storedRefreshToken || ''
  const selectedOID4VCICredentialProfile = useMemo(
    () => oid4vciProfileFor(oid4vciCredentialFormat, oid4vciHaip),
    [oid4vciCredentialFormat, oid4vciHaip],
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
  const oid4vpRequestURIMethodForExecutor = isOID4VPFlow
    ? oid4vpRequestURIMethod
    : undefined
  const oid4vpClientIDOverride = useMemo(() => {
    if (oid4vciHaip || oid4vpClientIDScheme === 'x509_hash') {
      return {
        label: 'client_id',
        placeholder: 'Optional x509_hash client_id override. Leave blank for the leaf-hash default.',
        helper: 'HAIP binds client_id to the SHA-256 of the request-signer leaf (OpenID4VP 1.0 Section 5.9.3).',
      }
    }
    if (oid4vpClientIDScheme === 'redirect_uri') {
      return {
        label: 'redirect_uri',
        placeholder: 'Optional redirect_uri override. Leave blank to use Looking Glass /oid4vp/response.',
        helper: 'For redirect_uri, client_id MUST equal response_uri (OpenID4VP 1.0 Section 5.9.3). The wallet posts vp_token to that URI.',
      }
    }
    if (oid4vpClientIDScheme === 'x509_san_dns') {
      return {
        label: 'client_id',
        placeholder: 'Optional x509_san_dns client_id override. Must match a DNS SAN on the leaf.',
        helper: 'Leave blank to use the provisioned x509_san_dns identifier.',
      }
    }
    return {
      label: 'client_id',
      placeholder: 'Optional verifier_attestation client_id override. Leave blank for the provisioned profile.',
      helper: 'Leave blank to use the provisioned verifier_attestation identifier.',
    }
  }, [oid4vciHaip, oid4vpClientIDScheme])

  const realExecutor = useRealFlowExecutor({
    protocolId: selectedProtocol?.id || null,
    flowId: selectedProtocol?.id === 'ssf' ? 'ssf-lab' : (selectedFlow?.id || null),
    clientId: clientConfig.clientId,
    clientSecret: clientConfig.clientSecret,
    clientCredentialsAuthMethod: isClientCredentialsFlow ? clientCredentialsAuthMethod : undefined,
    clientCredentialsAccessTokenMode: isClientCredentialsFlow ? clientCredentialsAccessTokenMode : undefined,
    clientCredentialsTokenEndpoint: isClientCredentialsFlow ? machineTokenEndpoint || undefined : undefined,
    redirectUri: `${window.location.origin}/callback`,
    scopes,
    refreshToken: isRefreshTokenFlow ? activeRefreshToken : undefined,
    token: (isTokenIntrospectionFlow || isTokenRevocationFlow) ? activeToken : undefined,
    accessToken: isUserInfoFlow ? activeToken : undefined,
    bearerToken: isSCIMFlow ? scimBearerToken : undefined,
    oid4vciCredentialConfigurationID: isOID4VCIFlow ? selectedOID4VCICredentialProfile.id : undefined,
    oid4vciCredentialFormat: isOID4VCIFlow ? selectedOID4VCICredentialProfile.format : undefined,
    oid4vciWalletOfferEndpoint: isOID4VCIIssuerInitiatedFlow ? oid4vciWalletOfferEndpoint.trim() || undefined : undefined,
    oid4vpDCQLQueryJSON: oid4vpDCQLQueryForExecutor,
    oid4vpScopeAlias: oid4vpScopeAliasForExecutor,
    oid4vpClientID: oid4vpClientIDForExecutor,
    oid4vpClientIDScheme: oid4vpClientIDSchemeForExecutor,
    oid4vpRequestURIMethod: oid4vpRequestURIMethodForExecutor,
    lookingGlassSessionId: wireSessionId || undefined,
    lookingGlassSessionToken: wireSessionToken || undefined,
  })
  const mergedExecutorState = useMemo(() => {
    if (!realExecutor.state) return null
    if (!surface) return realExecutor.state
    // SSF Flow/Tokens are Looking Glass bus only — never executor-local makeRequest steps.
    const sessionEvents = mapLookingGlassEventsToFlowEvents(lookingGlassEvents)
    const sessionTokens = setsFromLookingGlassEvents(lookingGlassEvents)
    return {
      ...realExecutor.state,
      events: sessionEvents,
      decodedTokens: sessionTokens,
    }
  }, [lookingGlassEvents, realExecutor.state, surface])
  const status = mergedExecutorState?.status || 'idle'
  const isOID4VPAwaitingResult =
    selectedProtocol?.id === 'oid4vp' &&
    status === 'awaiting_user'
  // Issuer-initiated OID4VCI reuses the OID4VP awaiting_user chrome
  // (Check Result + shared Wallet Handoff Ready panel). Deferred issuance
  // keeps its own amber Check Status control.
  const isOID4VCIIssuerInitiatedAwaiting =
    isOID4VCIIssuerInitiatedFlow &&
    status === 'awaiting_user'
  const isOID4VCIDeferredAwaiting =
    selectedProtocol?.id === 'oid4vci' &&
    !isOID4VCIIssuerInitiatedFlow &&
    status === 'awaiting_user'
  const showWalletHandoffCheckResult =
    isOID4VPAwaitingResult || isOID4VCIIssuerInitiatedAwaiting

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
  const selectedOID4VPCredentialProfileLabel = `${selectedOID4VCICredentialProfile.label} (${selectedOID4VCICredentialProfile.id})`
  const oid4vpWalletCredentialCompatibility = useMemo(() => {
    if (!isOID4VPFlow || oid4vpQueryMode !== 'dcql' || oid4vpDCQLValidationError) {
      return { requestedFormats: [] as string[], error: null as string | null, warning: null as string | null }
    }

    const requestedFormats = getOID4VPDCQLCredentialFormats(oid4vpDCQLInput)
    if (requestedFormats.length === 0) {
      return { requestedFormats, error: null as string | null, warning: null as string | null }
    }

    const selectedFormat = selectedOID4VCICredentialProfile.format
    if (requestedFormats.includes(selectedFormat)) {
      return { requestedFormats, error: null as string | null, warning: null as string | null }
    }

    const mismatchMessage = [
      `The selected credential ${selectedOID4VPCredentialProfileLabel} issues "${selectedFormat}",`,
      `but the presentation query requests format ${formatOID4VPList(requestedFormats)}.`,
    ].join(' ')

    if (normalizedOID4VPCredentialJWTInput) {
      return {
        requestedFormats,
        error: null as string | null,
        warning: `${mismatchMessage} The pasted credential_jwt will be tried instead; if it is not one of those formats, the wallet will reject the presentation.`,
      }
    }

    return {
      requestedFormats,
      error: `${mismatchMessage} Select a matching format or paste a matching credential_jwt before submitting the wallet response.`,
      warning: null as string | null,
    }
  }, [
    isOID4VPFlow,
    oid4vpQueryMode,
    oid4vpDCQLValidationError,
    oid4vpDCQLInput,
    selectedOID4VCICredentialProfile.format,
    selectedOID4VPCredentialProfileLabel,
    normalizedOID4VPCredentialJWTInput,
  ])

  useEffect(() => {
    if (!isOID4VPFlow) {
      return
    }
    const preset = oid4vpDCQLPresetForFormat(oid4vciCredentialFormat)
    if (!preset) {
      return
    }
    setOID4VPDCQLPresetID(preset.id)
    const issuerOrigin = typeof window !== 'undefined' ? window.location.origin : 'https://protocolsoup.com'
    setOID4VPDCQLInput(oid4vpDCQLQueryForSelection(oid4vciCredentialFormat, oid4vciHaip, issuerOrigin))
  }, [isOID4VPFlow, oid4vciCredentialFormat, oid4vciHaip])

  useEffect(() => {
    if (!isOID4VPFlow) {
      return
    }
    if (oid4vciHaip) {
      setOID4VPClientIDScheme('x509_hash')
      setOID4VPQueryMode('dcql')
      return
    }
    setOID4VPClientIDScheme((current) => (current === 'x509_hash' ? 'redirect_uri' : current))
  }, [isOID4VPFlow, oid4vciHaip])
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
    !!oid4vpRequestJWT &&
    !oid4vpWalletCredentialCompatibility.error

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

    if ((!isOID4VPFlow && !isOID4VCIIssuerInitiatedFlow) || !oid4vpWalletHandoffPayload) {
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
  }, [isOID4VPFlow, isOID4VCIIssuerInitiatedFlow, oid4vpWalletHandoffPayload])

  useEffect(() => {
    if (!isOID4VPFlow) {
      setOID4VPContractExpanded(true)
      return
    }
    if (walletHandoffArtifact || status !== 'idle') {
      setOID4VPContractExpanded(false)
    }
  }, [isOID4VPFlow, walletHandoffArtifact, status])

  useEffect(() => {
    if (!isOID4VCIIssuerInitiatedFlow) {
      setOID4VCIAdvancedExpanded(false)
    }
  }, [isOID4VCIIssuerInitiatedFlow])


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
    setOID4VPWalletSubmitError(null)
    setOID4VPWalletSubmitMessage(null)
    setOID4VPWalletModalOpen(true)
  }, [])

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
    if (oid4vpWalletCredentialCompatibility.error) {
      setOID4VPWalletSubmitError(oid4vpWalletCredentialCompatibility.error)
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
        throw new Error(describeWalletSubmitError(responsePayload, `Wallet submission failed (${response.status})`))
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
    oid4vpWalletCredentialCompatibility.error,
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
    if (step !== 'bootstrap' && oid4vpWalletCredentialCompatibility.error) {
      setOID4VPWalletSubmitError(oid4vpWalletCredentialCompatibility.error)
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
        throw new Error(describeWalletSubmitError(responsePayload, `Wallet step "${step}" failed (${response.status})`))
      }

      injectWalletLifecycleEvents(responsePayload)
      const nextVPToken = String(responsePayload?.vp_token || '').trim()
      if (step === 'build_presentation' && !nextVPToken) {
        throw new Error('Wallet build_presentation completed without returning a vp_token. Check the credential format/profile selected for this request.')
      }
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
    oid4vpWalletCredentialCompatibility.error,
    wireSessionId,
    oid4vpRequestID,
    oid4vpRequestJWT,
    oid4vpRequestURI,
    oid4vpResponseMode,
    oid4vpStepwiseVPToken,
    executeFlow,
    injectWalletLifecycleEvents,
  ])

  const syncUrlToSelection = useCallback(
    (protocolId: string | null, flowId: string | null) => {
      if (protocolId && flowId) {
        const deepLink = buildLookingGlassPath({ protocolId, flowId })
        router.replace(deepLink, { scroll: false })
      } else {
        router.replace(pathname || '/looking-glass', { scroll: false })
      }
    },
    [router, pathname],
  )

  const clearUrlState = useCallback(() => {
    router.replace(pathname || '/looking-glass', { scroll: false })
  }, [router, pathname])

  const resetClientCredentialsCapture = useCallback(() => {
    resetFlow()
    setWireSessionId(null)
    setWireSessionToken(null)
    clearWireEvents()
    setWireSessionError(null)
    setPendingExecute(false)
    setInspectedToken('')
  }, [resetFlow, clearWireEvents])

  const handleClientCredentialsAuthMethodChange = useCallback(
    (method: ClientCredentialsAuthMethod) => {
      if (method === clientCredentialsAuthMethod) return
      resetClientCredentialsCapture()
      setClientCredentialsAuthMethod(method)
    },
    [clientCredentialsAuthMethod, resetClientCredentialsCapture],
  )

  const handleClientCredentialsAccessTokenModeChange = useCallback(
    (mode: ClientCredentialsAccessTokenMode) => {
      if (mode === clientCredentialsAccessTokenMode) return
      resetClientCredentialsCapture()
      setClientCredentialsAccessTokenMode(mode)
    },
    [clientCredentialsAccessTokenMode, resetClientCredentialsCapture],
  )

  const handleClearAll = useCallback(() => {
    setSelectedProtocol(null)
    setSelectedFlow(null)
    resetFlow()
    setWireSessionId(null)
    setWireSessionToken(null)
    clearWireEvents()
    setWireSessionError(null)
    setPendingExecute(false)
    setInspectedToken('')
    setStoredRefreshToken(null)
    setStoredAccessToken(null)
    setClientCredentialsAuthMethod('client_secret_basic')
    setClientCredentialsAccessTokenMode('bearer')
    setRefreshTokenInput('')
    setTokenInput('')
    setScimBearerToken('')
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
    setOID4VPClientIDInput('')
    setOID4VPClientIDScheme('redirect_uri')
    setOID4VPRequestURIMethod('get')
    setOID4VCICredentialFormat('mso_mdoc')
    setOID4VCIHaip(false)
    setOID4VCIWalletOfferEndpoint('')
    setOID4VCIAdvancedExpanded(false)
    setOID4VPContractExpanded(false)
    lastHandledPairRef.current = null
    clearUrlState()
  }, [resetFlow, clearWireEvents, clearUrlState])

  const handleProtocolSelect = useCallback((protocol: LookingGlassProtocol) => {
    setSelectedProtocol(protocol)
    const labFlow = protocol.id === 'ssf' ? pickSSFLabFlow(protocol) : undefined
    setSelectedFlow(labFlow || null)
    resetFlow()
    setWireSessionId(null)
    setWireSessionToken(null)
    clearWireEvents()
    setWireSessionError(null)
    setPendingExecute(false)
    setInspectedToken('')
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
    syncUrlToSelection(protocol.id, labFlow?.id || null)
  }, [resetFlow, clearWireEvents, syncUrlToSelection])

  const handleFlowSelect = useCallback((flow: LookingGlassFlow) => {
    const keepSession = getLookingGlassSurface(selectedProtocol?.id)?.session.resetOnFlowChange === false
    setSelectedFlow(flow)
    if (!keepSession) {
      resetFlow()
      setWireSessionId(null)
      setWireSessionToken(null)
      clearWireEvents()
      setWireSessionError(null)
      setPendingExecute(false)
      setInspectedToken('')
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
    syncUrlToSelection(selectedProtocol?.id || null, flow.id)
  }, [resetFlow, clearWireEvents, selectedProtocol, syncUrlToSelection])

  const handleReset = useCallback(() => {
    const keepSession = surface?.session.accumulateWire
    resetFlow()
    if (!keepSession) {
      setWireSessionId(null)
      setWireSessionToken(null)
      clearUrlState()
    }
    clearWireEvents()
    setWireSessionError(null)
    setPendingExecute(false)
    setInspectedToken('')
    setOID4VPWalletModalOpen(false)
    setOID4VPLastPromptedRequestID('')
    setOID4VPWalletSubmitPending(false)
    setOID4VPWalletSubmitError(null)
    setOID4VPWalletSubmitMessage(null)
    setOID4VPWalletMode('one_click')
    setOID4VPStepwiseVPToken('')
    setOID4VPStepwiseLastStep('')
    setOID4VPDisclosureClaims([])
  }, [resetFlow, clearWireEvents, clearUrlState, surface])

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
      if (!surface?.session.accumulateWire) {
        clearWireEvents()
      }
      const response = await fetch(`/api/protocols/${selectedProtocol.id}/demo/${selectedFlow.id}`, {
        method: 'POST',
      })
      if (!response.ok) {
        const errorData = await response.json().catch(() => null) as { error?: string } | null
        throw new Error(errorData?.error || 'Failed to start wire capture session')
      }
      const data = await response.json() as { session_id?: string; session_token?: string }
      if (!data.session_id || !data.session_token) {
        throw new Error('No owned session returned for wire capture')
      }
      setWireSessionToken(data.session_token)
      setWireSessionId(data.session_id)
      return data.session_id
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to start wire capture session'
      setWireSessionError(message)
      return null
    }
  }, [selectedProtocol, selectedFlow, clearWireEvents, surface])

  const handleExecute = useCallback(async () => {
    if (isOID4VPFlow && !canExecuteOID4VPRequest) {
      const message = oid4vpDCQLValidationError || oid4vpScopeAliasValidationError || 'OID4VP request configuration is invalid.'
      setOID4VPWalletSubmitError(message)
      return
    }
    if (surface && !ssfReady && selectedProtocol?.id === 'ssf') {
      return
    }
    if (selectedProtocol?.id === 'ssf') {
      updateSSFLab({ intent: 'fire' })
    }
    // Client Credentials private-key registration is intentionally one-shot
    // per owned Looking Glass session. Start every execution in a fresh
    // session so reruns and all four auth/token-mode combinations remain
    // isolated and reproducible without weakening that registration guard.
    if (isClientCredentialsFlow) {
      resetClientCredentialsCapture()
      setPendingExecute(true)
      const created = await startWireSession()
      if (!created) {
        setPendingExecute(false)
      }
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
    isClientCredentialsFlow,
    wireSessionId,
    resetClientCredentialsCapture,
    startWireSession,
    executeFlow,
    surface,
    ssfReady,
    selectedProtocol?.id,
  ])

  const handleVerifyStream = useCallback(async () => {
    if (status !== 'idle') {
      return
    }
    updateSSFLab({ intent: 'verify' })
    if (!wireSessionId) {
      setPendingExecute(true)
      const created = await startWireSession()
      if (!created) {
        setPendingExecute(false)
        updateSSFLab({ intent: 'fire' })
      }
      return
    }
    executeFlow()
  }, [status, wireSessionId, startWireSession, executeFlow])

  useEffect(() => {
    if (!surface?.session.accumulateWire) return
    if (!selectedProtocol || !selectedFlow || wireSessionId) return
    void startWireSession()
  }, [surface, selectedProtocol, selectedFlow, wireSessionId, startWireSession])

  useEffect(() => {
    if (pendingExecute && wireSessionId) {
      executeFlow()
      setPendingExecute(false)
    }
  }, [pendingExecute, wireSessionId, executeFlow])

  const handleQuickSelect = useCallback((protocolId: string, flowId: string) => {
    const normalizeFlowId = (id: string) => id.toLowerCase().replace(/_/g, '-')

    const protocol = protocols.find(p => p.id === protocolId)
    if (protocol) {
      setSelectedProtocol(protocol)
      const normalizedTarget = normalizeFlowId(flowId)
      const flow = (protocol.flows || []).find(f => normalizeFlowId(f.id) === normalizedTarget)
      if (flow) {
        setSelectedFlow(flow)
        resetFlow()
        setWireSessionId(null)
        setWireSessionToken(null)
        clearWireEvents()
        setWireSessionError(null)
        setPendingExecute(false)
        setInspectedToken('')
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
  }, [protocols, resetFlow, clearWireEvents])

  // Honour ?protocol=X&flow=Y from deep-links (palette run dispatch, shared
  // URLs, browser bookmarks). After consuming the deep-link, replace the
  // URL with a clean pathname so the query params don't persist across
  // navigation, protocol changes, or tab-session lifetime.
  useEffect(() => {
    if (protocolsLoading || protocols.length === 0) return
    const pair = parseFlowDeepLink(searchParams)
    if (!pair) return
    const key = [
      pair.protocolId,
      pair.flowId,
      pair.clientAuth || '',
      pair.accessTokenMode || '',
      pair.credentialFormat || '',
      pair.haip ? '1' : '',
    ].join('\u0000')
    if (lastHandledPairRef.current === key) return
    lastHandledPairRef.current = key
    if (
      pair.protocolId === 'oauth2' &&
      pair.flowId.toLowerCase().replace(/_/g, '-') === 'client-credentials'
    ) {
      setClientCredentialsAuthMethod(pair.clientAuth || 'client_secret_basic')
      setClientCredentialsAccessTokenMode(pair.accessTokenMode || 'bearer')
    }
    if (pair.protocolId === 'oid4vci' || pair.protocolId === 'oid4vp') {
      setOID4VCICredentialFormat(pair.credentialFormat || 'mso_mdoc')
      setOID4VCIHaip(Boolean(pair.haip))
    }
    handleQuickSelect(pair.protocolId, pair.flowId)

    // Consume-and-clear: strip the deep-link params so they don't
    // re-trigger on remount after navigating away and back.
    router.replace(pathname || '/looking-glass', { scroll: false })
  }, [searchParams, protocols, protocolsLoading, handleQuickSelect, router, pathname])

  const copyShareableLink = useCallback(() => {
    if (!selectedProtocol || !selectedFlow) return
    const deepLink = buildLookingGlassPath({
      protocolId: selectedProtocol.id,
      flowId: selectedFlow.id,
      clientAuth: isClientCredentialsFlow ? clientCredentialsAuthMethod : undefined,
      accessTokenMode: isClientCredentialsFlow ? clientCredentialsAccessTokenMode : undefined,
      credentialFormat: showVCTab ? oid4vciCredentialFormat : undefined,
      haip: showVCTab ? oid4vciHaip : undefined,
    })
    const url = `${window.location.origin}${deepLink}`
    navigator.clipboard.writeText(url).then(() => {
      setShareCopied(true)
      setTimeout(() => setShareCopied(false), 1500)
    })
  }, [
    selectedProtocol,
    selectedFlow,
    isClientCredentialsFlow,
    clientCredentialsAuthMethod,
    clientCredentialsAccessTokenMode,
    showVCTab,
    oid4vciCredentialFormat,
    oid4vciHaip,
  ])

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

  useEffect(() => {
    return subscribeSSFLab(() => {
      setSsfSecurityState(getSSFLab().securityState)
      setSsfReady(getSSFLab().ready)
      setSsfEventId(getSSFLab().eventId)
    })
  }, [])

  const handleResetRpState = useCallback(async () => {
    const lab = getSSFLab()
    if (!lab.subjectIdentifier || !wireSessionId) return
    await fetch(`/ssf/security-state/${encodeURIComponent(lab.subjectIdentifier)}/reset`, {
      method: 'POST',
      headers: { 'X-Looking-Glass-Session': wireSessionId },
    })
    const res = await fetch(`/ssf/security-state/${encodeURIComponent(lab.subjectIdentifier)}`, {
      headers: { 'X-Looking-Glass-Session': wireSessionId },
    })
    if (!res.ok) return
    const state = await res.json() as SecurityState
    updateSSFLab({ securityState: state })
    setSsfSecurityState(state)
  }, [wireSessionId])

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
            {surface?.copy.subtitle || 'Execute protocol flows and inspect the traffic'}
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
                onClick={() => {
                  handleQuickSelect(flow.protocolId, flow.flowId)
                  syncUrlToSelection(flow.protocolId, flow.flowId)
                }}
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
                onClick={() => {
                  handleQuickSelect(flow.protocolId, flow.flowId)
                  syncUrlToSelection(flow.protocolId, flow.flowId)
                }}
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
          flowNoun={surface?.copy.flowNoun}
          hideFlowSelector={surface?.hideFlowSelector}
        />
        {selectedFlow && (
          <div className="flex items-center rounded bg-surface-900 border border-white/10 overflow-hidden">
            <button
              onClick={copyShareableLink}
              aria-label="Copy shareable link for this flow"
              title="Copy shareable deep-link"
              className="flex items-center gap-1.5 px-2.5 sm:px-3 py-2 sm:py-1.5 text-xs font-mono text-surface-300 hover:text-accent-cyan hover:bg-white/5 transition-colors border-r border-white/10"
            >
              {shareCopied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-green-400" />
                  <span className="hidden sm:inline text-green-400">copied</span>
                </>
              ) : (
                <>
                  <Share2 className="w-3.5 h-3.5" />
                  <span className="hidden sm:inline">share</span>
                </>
              )}
            </button>
            <button
              onClick={handleReset}
              aria-label="Reset selected flow"
              title="Reset flow execution"
              className="flex items-center gap-1.5 px-2.5 sm:px-3 py-2 sm:py-1.5 text-xs font-mono text-surface-300 hover:text-white hover:bg-white/5 transition-colors border-r border-white/10"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">reset</span>
            </button>
            <button
              onClick={handleClearAll}
              aria-label="Clear selection and URL"
              title="Clear all"
              className="flex items-center gap-1.5 px-2.5 sm:px-3 py-2 sm:py-1.5 text-xs font-mono text-surface-300 hover:text-red-400 hover:bg-white/5 transition-colors"
            >
              <XCircle className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">clear</span>
            </button>
          </div>
        )}
      </section>

      {hasFlowConfigurationInputs && (
        <section className="rounded-xl border border-white/10 bg-surface-900/20 p-3 sm:p-4">
        {isClientCredentialsFlow && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
          >
            <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 mb-2">
              <KeyRound className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-cyan-400" />
              <span className="text-xs sm:text-sm font-medium text-surface-300">Client authentication</span>
            </div>
            <p className="text-[10px] sm:text-xs text-surface-400 mb-2 sm:mb-3 leading-relaxed">
              Choose how the confidential client authenticates to the token endpoint.
            </p>
            <SegmentedChoice
              aria-label="Client authentication"
              value={clientCredentialsAuthMethod}
              onChange={handleClientCredentialsAuthMethodChange}
              options={[
                { id: 'client_secret_basic', label: 'client_secret_basic' },
                { id: 'private_key_jwt', label: 'private_key_jwt' },
              ]}
            />
            <p className="mt-2 text-[10px] sm:text-xs text-surface-500 leading-relaxed">
              {clientCredentialsAuthMethod === 'private_key_jwt'
                ? 'A non-extractable WebCrypto private key signs the assertion in this browser. An owned session registration assigns the real client ID after its public JWK is accepted.'
                : 'The demo client authenticates with an HTTP Basic client secret.'}
            </p>

            <div className="mt-4 pt-4 border-t border-white/10">
              <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 mb-2">
                <Shield className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-amber-400" />
                <span className="text-xs sm:text-sm font-medium text-surface-300">Access-token protection</span>
              </div>
              <p className="text-[10px] sm:text-xs text-surface-400 mb-2 sm:mb-3 leading-relaxed">
                Choose whether the issued access token is a regular Bearer token or sender-constrained with DPoP.
              </p>
              <SegmentedChoice
                aria-label="Access-token protection"
                value={clientCredentialsAccessTokenMode}
                onChange={handleClientCredentialsAccessTokenModeChange}
                options={[
                  { id: 'bearer', label: 'Bearer' },
                  { id: 'dpop', label: 'DPoP', accent: 'amber' },
                ]}
              />
              <p className="mt-2 text-[10px] sm:text-xs text-surface-500 leading-relaxed">
                {clientCredentialsAccessTokenMode === 'dpop'
                  ? 'A separate non-extractable ES256 key signs a fresh RFC 9449 proof. The resulting token carries cnf.jkt and is returned with token_type=DPoP.'
                  : 'No DPoP proof is sent. The authorization server returns the standard token_type=Bearer response.'}
              </p>
            </div>
          </motion.div>
        )}

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


        {showVCTab && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
          >
            <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 mb-2">
              <Fingerprint className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-indigo-400" />
              <span className="text-xs sm:text-sm font-medium text-surface-300">Credential</span>
            </div>
            <p className="text-[10px] sm:text-xs text-surface-400 mb-2 sm:mb-3 leading-relaxed">
              {isOID4VPFlow
                ? 'Choose the credential to auto-issue, then whether HAIP presentation is on.'
                : 'Choose the credential format, then whether HAIP key-attested issuance is on.'}
            </p>
            <SegmentedChoice
              aria-label="Credential format"
              value={oid4vciCredentialFormat}
              onChange={setOID4VCICredentialFormat}
              options={[
                { id: 'mso_mdoc', label: 'mso_mdoc' },
                { id: 'dc+sd-jwt', label: 'dc+sd-jwt' },
              ]}
            />
            <p className="mt-2 text-[10px] sm:text-xs text-surface-500 leading-relaxed">
              {oid4vciCredentialFormat === 'mso_mdoc'
                ? 'ISO/IEC 18013-5 mobile driving licence (mDL).'
                : 'University Degree SD-JWT VC.'}
            </p>

            <div className="mt-4 pt-4 border-t border-white/10">
              <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 mb-2">
                <Shield className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-amber-400" />
                <span className="text-xs sm:text-sm font-medium text-surface-300">HAIP</span>
              </div>
              <p className="text-[10px] sm:text-xs text-surface-400 mb-2 sm:mb-3 leading-relaxed">
                {isOID4VPFlow
                  ? 'General uses the selected verifier trust profile. HAIP uses x509_hash, DCQL, and encrypted direct_post.jwt.'
                  : 'General issues without wallet attestation. HAIP issues with client and key attestation.'}
              </p>
              <SegmentedChoice
                aria-label="HAIP"
                value={oid4vciHaip ? 'on' : 'off'}
                onChange={(value) => setOID4VCIHaip(value === 'on')}
                options={[
                  { id: 'off', label: 'general' },
                  { id: 'on', label: 'HAIP', accent: 'amber' },
                ]}
              />
              <p className="mt-2 text-[10px] sm:text-xs text-surface-500 leading-relaxed">
                {oid4vciHaip
                  ? isOID4VPFlow
                    ? `Issues ${selectedOID4VCICredentialProfile.id} with client and key attestation (HAIP 1.0 Sections 4.4.1 and 4.5.1), then presents with x509_hash, DCQL, and encrypted direct_post.jwt (HAIP 1.0 Section 5).`
                    : `Issues ${selectedOID4VCICredentialProfile.id} with client and key attestation (HAIP 1.0 Sections 4.4.1 and 4.5.1). The hosted wallet supplies that material. Self-hosted import returns HTTP 400 without WALLET_CLIENT_ATTESTATION_* JWKs.`
                  : `Issues ${selectedOID4VCICredentialProfile.id} without HAIP attestation.`}
              </p>
            </div>
            {isOID4VPFlow && oid4vciHaip && flowId === 'oid4vp-direct-post' && (
              <div className="mt-2">
                <ProtocolNotice
                  tone="info"
                  title="HAIP will coerce this unencrypted flow to direct_post.jwt"
                  specReference="HAIP 1.0 Section 5.1"
                >
                  {LOOKING_GLASS_X509_HASH_COERCION_GUIDANCE}
                </ProtocolNotice>
              </div>
            )}
            {isOID4VCIFlow && flowId === 'oid4vci-pre-authorized-tx-code' && (
              <div className="mt-2">
                <ProtocolNotice
                  tone="info"
                  title="tx_code is required on the token request"
                  specReference="OpenID4VCI 1.0 Sections 4.1.1 and 6.1"
                >
                  Looking Glass reads the issuer-returned out-of-band tx_code from the Credential Offer and sends it with wallet import. If import fails with tx_code_required, the offer was created without that value — re-run this flow rather than a plain pre-authorized run.
                </ProtocolNotice>
              </div>
            )}
            {isOID4VPFlow && (oid4vpWalletCredentialCompatibility.error || oid4vpWalletCredentialCompatibility.warning) && (
              <div className="mt-2">
                <ProtocolNotice
                  tone={oid4vpWalletCredentialCompatibility.error ? 'error' : 'warning'}
                  title={oid4vpWalletCredentialCompatibility.error ? 'Credential format mismatch' : 'Credential format warning'}
                >
                  {oid4vpWalletCredentialCompatibility.error || oid4vpWalletCredentialCompatibility.warning}
                </ProtocolNotice>
              </div>
            )}
          </motion.div>
        )}

        {isOID4VCIIssuerInitiatedFlow && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="mt-3 sm:mt-4 pt-3 sm:pt-4 border-t border-white/10"
          >
            <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
              <div className="flex items-center gap-1.5 sm:gap-2 min-w-0">
                <Share2 className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-cyan-400 flex-shrink-0" />
                <span className="text-xs sm:text-sm font-medium text-surface-300">Offer delivery</span>
              </div>
              <button
                type="button"
                onClick={() => setOID4VCIAdvancedExpanded((previous) => !previous)}
                className="px-2 py-1 rounded border border-white/10 bg-surface-900 text-[10px] sm:text-xs text-surface-300 hover:text-white transition-colors flex-shrink-0"
              >
                {oid4vciAdvancedExpanded ? 'Hide advanced' : 'Advanced'}
              </button>
            </div>
            <p className="text-[10px] sm:text-xs text-surface-500 leading-relaxed font-mono break-all">
              {oid4vciWalletOfferEndpoint.trim() || 'openid-credential-offer:// QR'}
            </p>
            {oid4vciAdvancedExpanded && (
              <div className="mt-3 space-y-2">
                <p className="text-[10px] sm:text-xs text-surface-400 leading-relaxed">
                  Optional. Paste an external wallet&apos;s OID4VCI 1.0 §4.1.2 Credential Offer Endpoint
                  (<code className="text-cyan-300">credential_offer_endpoint</code>).
                  When set, Execute has the issuer deliver the live <code className="text-cyan-300">credential_offer</code> to that endpoint
                  over HTTPS. When blank, Looking Glass creates an
                  <code className="text-cyan-300"> openid-credential-offer://</code> invocation URI and QR code instead. After delivery,
                  click <code className="text-cyan-300">Check Result</code> once the wallet has driven PAR, token exchange, and credential request.
                </p>
                <input
                  type="text"
                  value={oid4vciWalletOfferEndpoint}
                  onChange={(event) => setOID4VCIWalletOfferEndpoint(event.target.value)}
                  placeholder="https://wallet.example/credential_offer"
                  className="w-full px-2.5 sm:px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-xs sm:text-sm font-mono text-white placeholder-surface-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                />
              </div>
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
            <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
              <div className="flex items-center gap-1.5 sm:gap-2 min-w-0">
                <Workflow className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-violet-400 flex-shrink-0" />
                <span className="text-xs sm:text-sm font-medium text-surface-300">Presentation request</span>
              </div>
              <button
                type="button"
                onClick={() => setOID4VPContractExpanded((previous) => !previous)}
                className="px-2 py-1 rounded border border-white/10 bg-surface-900 text-[10px] sm:text-xs text-surface-300 hover:text-white transition-colors flex-shrink-0"
              >
                {oid4vpContractExpanded ? 'Hide advanced' : 'Advanced'}
              </button>
            </div>
            <p className="text-[10px] sm:text-xs text-surface-500 leading-relaxed font-mono">
              {[
                oid4vciCredentialFormat,
                oid4vciHaip ? 'HAIP' : 'general',
                oid4vpQueryMode === 'dcql' ? 'DCQL' : 'scope',
                oid4vpClientIDScheme,
                oid4vpRequestURIMethod === 'post' ? 'request_uri POST' : null,
              ].filter(Boolean).join(' · ')}
            </p>
            {(!!oid4vpDCQLValidationError || !!oid4vpScopeAliasValidationError) && (
              <div className="mt-2">
                <ProtocolNotice
                  tone="error"
                  title={oid4vpDCQLValidationError ? 'DCQL is invalid — Execute is disabled' : 'Scope alias is invalid — Execute is disabled'}
                >
                  {oid4vpDCQLValidationError || oid4vpScopeAliasValidationError}
                </ProtocolNotice>
              </div>
            )}
            {oid4vpContractExpanded && (
              <div className="mt-3 space-y-4">
                <p className="text-[10px] sm:text-xs text-surface-400 leading-relaxed">
                  DCQL and scope alias are mutually exclusive per OpenID4VP. Format already selects the matching DCQL preset; edit the JSON only to customize the query.
                </p>

                <div className="space-y-2">
                  <span className="text-[11px] sm:text-xs text-surface-400">Query</span>
                  <SegmentedChoice
                    aria-label="Presentation query"
                    value={oid4vpQueryMode}
                    onChange={setOID4VPQueryMode}
                    options={[
                      { id: 'dcql', label: 'DCQL', accent: 'violet' },
                      { id: 'scope', label: 'scope alias', accent: 'violet', disabled: oid4vciHaip },
                    ]}
                  />
                </div>

                {oid4vpQueryMode === 'dcql' && (
                  <div className="space-y-2">
                    <p className="text-[10px] sm:text-xs text-cyan-300">
                      {oid4vpDCQLInput === oid4vpDCQLQueryForSelection(
                        oid4vciCredentialFormat,
                        oid4vciHaip,
                        typeof window !== 'undefined' ? window.location.origin : 'https://protocolsoup.com',
                      )
                        ? oid4vciHaip && oid4vciCredentialFormat === 'dc+sd-jwt'
                          ? 'Requests degree + graduation_year from an SD-JWT VC. HAIP also accepts the type-metadata vct used by UniversityDegreeCredentialSDJWTHAIP.'
                          : selectedOID4VPPreset?.description
                        : 'Custom DCQL query. Changing format restores the matching preset.'}
                    </p>
                    <textarea
                      value={oid4vpDCQLInput}
                      onChange={(event) => setOID4VPDCQLInput(event.target.value)}
                      rows={7}
                      className="w-full px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-[11px] sm:text-xs font-mono text-white placeholder-surface-600 focus:outline-none focus:border-violet-500/50 focus:ring-1 focus:ring-violet-500/20 transition-all resize-y"
                      placeholder="Paste dcql_query JSON"
                    />
                  </div>
                )}

                {oid4vpQueryMode === 'scope' && (
                  <input
                    type="text"
                    value={oid4vpScopeAliasInput}
                    onChange={(event) => setOID4VPScopeAliasInput(event.target.value)}
                    placeholder="e.g. openid profile degree_verification"
                    className="w-full px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-xs sm:text-sm font-mono text-white placeholder-surface-600 focus:outline-none focus:border-violet-500/50 focus:ring-1 focus:ring-violet-500/20 transition-all"
                  />
                )}

                {!oid4vciHaip && (
                  <div className="space-y-2">
                    <span className="text-[11px] sm:text-xs text-surface-400">Verifier trust</span>
                    <SegmentedChoice
                      aria-label="Verifier trust"
                      columns={3}
                      value={oid4vpClientIDScheme === 'x509_hash' ? 'redirect_uri' : oid4vpClientIDScheme}
                      onChange={(scheme) => setOID4VPClientIDScheme(scheme)}
                      options={[
                        { id: 'redirect_uri', label: 'redirect_uri', accent: 'violet' },
                        { id: 'verifier_attestation', label: 'verifier_attestation', accent: 'violet' },
                        { id: 'x509_san_dns', label: 'x509_san_dns', accent: 'violet' },
                      ]}
                    />
                    <p className="text-[10px] sm:text-xs text-surface-500 leading-relaxed">
                      <code className="text-violet-300">verifier_attestation</code> uses a live attestation issuer and JWKS.
                      {' '}<code className="text-violet-300">x509_san_dns</code> binds verifier identity to a DNS SAN.
                      HAIP presentation is the HAIP selector above, not a separate trust dropdown.
                    </p>
                  </div>
                )}

                <div className="space-y-2">
                  <span className="text-[11px] sm:text-xs text-surface-400">Request URI method</span>
                  <SegmentedChoice
                    aria-label="Request URI method"
                    value={oid4vpRequestURIMethod}
                    onChange={setOID4VPRequestURIMethod}
                    options={[
                      { id: 'get', label: 'GET', accent: 'violet' },
                      { id: 'post', label: 'POST', accent: 'violet' },
                    ]}
                  />
                  <p className="text-[10px] sm:text-xs text-surface-500 leading-relaxed">
                    POST <code className="text-violet-300">request_uri_method</code> (OpenID4VP 1.0 Section 5.10) has the wallet fetch the request object with an HTTP POST carrying <code className="text-violet-300">wallet_nonce</code>.
                  </p>
                </div>

                <div className="space-y-2">
                  <span className="text-[11px] sm:text-xs text-surface-400">{oid4vpClientIDOverride.label}</span>
                  <input
                    type="text"
                    value={oid4vpClientIDInput}
                    onChange={(event) => setOID4VPClientIDInput(event.target.value)}
                    placeholder={oid4vpClientIDOverride.placeholder}
                    className="w-full px-3 py-2 rounded-lg bg-surface-900 border border-white/10 text-[11px] sm:text-xs font-mono text-white placeholder-surface-600 focus:outline-none focus:border-violet-500/50 focus:ring-1 focus:ring-violet-500/20 transition-all"
                  />
                  <p className="text-[10px] sm:text-xs text-surface-500 leading-relaxed">
                    {oid4vpClientIDOverride.helper}
                  </p>
                </div>
              </div>
            )}
          </motion.div>
        )}
        {SurfaceChrome && (
          <SurfaceChrome
            flowId={selectedFlow?.id || null}
            sessionId={wireSessionId}
            sessionToken={wireSessionToken}
            onReadyChange={setSsfReady}
            onSecurityStateChange={setSsfSecurityState}
            onVerifyStream={status === 'idle' ? handleVerifyStream : undefined}
          />
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
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2 sm:gap-3 min-w-0 flex-1">
                <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-lg bg-cyan-500/20 flex items-center justify-center flex-shrink-0">
                  <Play className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-cyan-400" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <code className="text-white font-medium text-xs sm:text-base truncate max-w-[160px] sm:max-w-none">{surface ? (ssfEventId || 'ssf-stream-lab') : selectedFlow.id}</code>
                    {realExecutor.flowInfo && (
                      <span className="text-[10px] sm:text-xs text-surface-400 font-mono flex-shrink-0">
                        {realExecutor.flowInfo.rfcReference}
                      </span>
                    )}
                  </div>
                  {referenceNavigation && (
                    <nav
                      aria-label={`Protocol reference breadcrumb for ${selectedFlow.name}`}
                      className="mt-1.5 text-[10px] sm:text-xs text-surface-500"
                    >
                      <ol className="flex flex-wrap items-center gap-1">
                        <li className="hidden sm:flex items-center gap-1">
                          <BookOpen aria-hidden="true" className="w-3 h-3 text-purple-400 flex-shrink-0" />
                          <Link
                            href="/protocols"
                            target="_blank"
                            rel="noopener noreferrer"
                            aria-label="Open Protocol Reference in a new tab"
                            className="hover:text-purple-300 transition-colors"
                          >
                            Protocol Reference
                          </Link>
                        </li>
                        <li className="hidden sm:flex items-center gap-1">
                          <ChevronRight aria-hidden="true" className="w-3 h-3 text-surface-600 flex-shrink-0" />
                          <Link
                            href={referenceNavigation.protocol.href}
                            target="_blank"
                            rel="noopener noreferrer"
                            aria-label={`Open ${referenceNavigation.protocol.name} overview in a new tab`}
                            aria-current={referenceNavigation.flow ? undefined : 'true'}
                            className="hover:text-purple-300 transition-colors"
                          >
                            {referenceNavigation.protocol.name}
                          </Link>
                        </li>
                        {referenceNavigation.flow ? (
                          <li className="flex items-center gap-1">
                            <ChevronRight aria-hidden="true" className="hidden sm:block w-3 h-3 text-surface-600 flex-shrink-0" />
                            <Link
                              href={referenceNavigation.flow.href}
                              target="_blank"
                              rel="noopener noreferrer"
                              aria-label={`Open ${referenceNavigation.flow.name} flow guide in a new tab`}
                              aria-current="true"
                              className="inline-flex items-center gap-1 hover:text-purple-300 transition-colors"
                            >
                              <span className="hidden sm:inline">{referenceNavigation.flow.name}</span>
                              <span className="sm:hidden">{referenceNavigation.flow.name} guide</span>
                              <ExternalLink aria-hidden="true" className="w-2.5 h-2.5 flex-shrink-0" />
                            </Link>
                          </li>
                        ) : (
                          <li className="sm:hidden">
                            <Link
                              href={referenceNavigation.protocol.href}
                              target="_blank"
                              rel="noopener noreferrer"
                              aria-label={`Open ${referenceNavigation.protocol.name} overview in a new tab`}
                              aria-current="true"
                              className="inline-flex items-center gap-1 hover:text-purple-300 transition-colors"
                            >
                              {referenceNavigation.protocol.name} overview
                              <ExternalLink aria-hidden="true" className="w-2.5 h-2.5 flex-shrink-0" />
                            </Link>
                          </li>
                        )}
                      </ol>
                    </nav>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-1.5 sm:gap-2 flex-shrink-0">
                {status === 'idle' && (
                  <button
                    onClick={handleExecute}
                    disabled={(isOID4VPFlow && !canExecuteOID4VPRequest) || (Boolean(surface) && !ssfReady)}
                    title={
                      isOID4VPFlow && !canExecuteOID4VPRequest
                        ? (oid4vpDCQLValidationError || oid4vpScopeAliasValidationError || 'OID4VP request configuration is invalid.')
                        : (Boolean(surface) && !ssfReady)
                          ? 'Select a subject and event before firing'
                          : undefined
                    }
                    className={`flex items-center gap-1.5 sm:gap-2 px-2.5 sm:px-4 py-1.5 sm:py-2 rounded-lg border text-xs sm:text-sm font-medium transition-all ${
                      (isOID4VPFlow && !canExecuteOID4VPRequest) || (Boolean(surface) && !ssfReady)
                        ? 'bg-surface-800/70 border-white/10 text-surface-500 cursor-not-allowed'
                        : 'bg-gradient-to-r from-green-500/20 to-emerald-500/20 border-green-500/30 text-green-400 hover:from-green-500/30 hover:to-emerald-500/30'
                    }`}
                  >
                    <Play className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                    <span className="hidden sm:inline">{surface?.copy.executeLabel || 'Execute'}</span>
                    <span className="sm:hidden">{surface ? 'Fire' : 'Run'}</span>
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
                {showWalletHandoffCheckResult && (
                  <button
                    onClick={handleExecute}
                    className="flex items-center gap-1.5 sm:gap-2 px-2.5 sm:px-4 py-1.5 sm:py-2 rounded-lg bg-gradient-to-r from-blue-500/20 to-cyan-500/20 border border-blue-500/30 text-blue-300 text-xs sm:text-sm font-medium hover:from-blue-500/30 hover:to-cyan-500/30 transition-all"
                  >
                    <Play className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                    <span className="hidden sm:inline">Check Result</span>
                    <span className="sm:hidden">Check</span>
                  </button>
                )}
                {isOID4VCIDeferredAwaiting && (
                  <button
                    onClick={handleExecute}
                    className="flex items-center gap-1.5 sm:gap-2 px-2.5 sm:px-4 py-1.5 sm:py-2 rounded-lg bg-gradient-to-r from-amber-500/20 to-orange-500/20 border border-amber-500/30 text-amber-300 text-xs sm:text-sm font-medium hover:from-amber-500/30 hover:to-orange-500/30 transition-all"
                  >
                    <RefreshCw className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                    <span className="hidden sm:inline">Check Status</span>
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
                  <div className="flex items-center gap-2">
                    <button
                      onClick={copyWalletHandoff}
                      className="flex items-center gap-1 px-2 py-1 rounded bg-surface-900 text-xs text-surface-300 hover:text-white border border-white/10"
                    >
                      {handoffCopied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                      {handoffCopied ? 'Copied' : 'Copy'}
                    </button>
                  </div>
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
                      alt="Wallet handoff QR"
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
            {selectedProtocol?.id === 'oid4vp' && oid4vpWalletSubmitError && (
              <div className="mb-3">
                <ProtocolNotice tone="error" protocolError={oid4vpWalletSubmitError} />
              </div>
            )}
            {selectedProtocol?.id === 'oid4vp' && oid4vpWalletSubmitMessage && !oid4vpWalletSubmitError && (
              <div className="mb-3 p-3 rounded-lg border border-green-500/30 bg-green-500/5 text-xs text-green-300">
                {oid4vpWalletSubmitMessage}
              </div>
            )}
            <RealFlowPanel
              state={mergedExecutorState}
              flowInfo={realExecutor.flowInfo}
              requirements={realExecutor.requirements}
              error={realExecutor.error}
              wireExchanges={wireExchanges}
              wireConnected={wireConnected}
              wireSessionError={wireSessionError}
              showTLSContext={showTLSContext}
              showVCTab={showVCTab}
              extraTabs={surface?.panel.extraTabs}
              extraTabContent={surface ? {
                state: (
                  <SecurityStatePanel
                    state={ssfSecurityState}
                    onReset={handleResetRpState}
                  />
                ),
                set: <SETOverlay tokens={mergedExecutorState?.decodedTokens || []} />,
              } : undefined}
              emptyCopy={surface ? { title: surface.copy.emptyTitle, subtitle: surface.copy.emptySubtitle } : undefined}
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
            clientIDScheme={oid4vpClientIDScheme}
            requestURI={oid4vpRequestURI}
            didWebAllowedHosts={oid4vpDidWebAllowedHosts}
            walletHandoffPayload={oid4vpWalletHandoffPayload}
            walletHandoffQRCodeDataURL={oid4vpWalletHandoffQRCodeObjectURL}
            walletHandoffQRCodeError={oid4vpWalletHandoffQRCodeError}
            walletSubjectInput={oid4vpWalletSubjectInput}
            onWalletSubjectInputChange={setOID4VPWalletSubjectInput}
            credentialProfileLabel={selectedOID4VPCredentialProfileLabel}
            walletCompatibilityError={oid4vpWalletCredentialCompatibility.error}
            walletCompatibilityWarning={oid4vpWalletCredentialCompatibility.warning}
            credentialJWTInput={oid4vpCredentialJWTInput}
            onCredentialJWTInputChange={setOID4VPCredentialJWTInput}
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
                    {realExecutor.state?.tokens.clientAssertion && (
                      <TokenButton
                        label="client assertion"
                        color="cyan"
                        active={inspectedToken === realExecutor.state?.tokens.clientAssertion}
                        onClick={() => setInspectedToken(realExecutor.state?.tokens.clientAssertion || '')}
                      />
                    )}
                    {realExecutor.state?.tokens.dpopProof && (
                      <TokenButton
                        label="DPoP proof"
                        color="amber"
                        active={inspectedToken === realExecutor.state?.tokens.dpopProof}
                        onClick={() => setInspectedToken(realExecutor.state?.tokens.dpopProof || '')}
                      />
                    )}
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
                <TokenInspector
                  token={inspectedToken}
                  tokenType={
                    // token_type (RFC 6749 Section 5.1) describes the access
                    // token specifically, so it is only passed when the
                    // token currently being inspected is that access token --
                    // not for id_token/refresh_token/client_assertion or a
                    // manually-pasted token, none of which have a token_type.
                    inspectedToken === realExecutor.state?.tokens.accessToken
                      ? realExecutor.state?.tokens.tokenType
                      : undefined
                  }
                />
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

