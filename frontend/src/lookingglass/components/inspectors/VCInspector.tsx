import { useMemo, useState, type ElementType, type JSX } from 'react'
import {
  Activity,
  AlertTriangle,
  Check,
  Clock,
  Copy,
  ExternalLink,
  Eye,
  FileText,
  KeyRound,
  QrCode,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
} from 'lucide-react'
import type { CredentialInspectionMetadata, VCArtifact } from '../../flows/base'
import { decodeJWTWithoutValidation } from '../../../utils/crypto'
import type { DecodeCredentialEvidence, DecodeCredentialSelectiveDisclosure } from '../../../utils/api'

interface VCInspectorProps {
  artifacts: VCArtifact[]
}

export function VCInspector({ artifacts }: VCInspectorProps) {
  const [copiedId, setCopiedId] = useState<string | null>(null)

  const sortedArtifacts = useMemo(
    () => [...artifacts].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime()),
    [artifacts]
  )

  if (sortedArtifacts.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-10 text-center">
        <Eye className="w-10 h-10 text-surface-600 mb-2" />
        <p className="text-surface-400 text-sm">No VC artifacts captured yet</p>
        <p className="text-surface-400 text-xs">Run an OID4VCI or OID4VP flow to inspect artifacts</p>
      </div>
    )
  }

  const copyText = async (value: string, id: string) => {
    await navigator.clipboard.writeText(value)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 1500)
  }

  return (
    <div className="space-y-3">
      {sortedArtifacts.map((artifact) => {
        const icon = artifactIcon(artifact.type)
        const Icon = icon.icon
        const metadata = artifact.metadata || {}
        const jwtDecoded = artifact.raw ? decodeJWTWithoutValidation(artifact.raw) : null
        const checks = getCheckList(metadata)
        const reasons = getReasonList(metadata)
        const reasonCodes = getReasonCodeList(metadata)
        const credentialEvidenceDisplay = getCredentialEvidence(metadata)
        const deferredIssuance = getDeferredIssuance(metadata)
        const deferredStatus = deferredIssuance ? deferredStatusConfig(deferredIssuance.status) : null

        return (
          <div key={artifact.id} className="rounded-lg bg-surface-900/50 border border-white/5 overflow-hidden">
            <div className="p-3 border-b border-white/5 flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0">
                <div className={`p-1.5 rounded ${icon.bg}`}>
                  <Icon className={`w-4 h-4 ${icon.fg}`} />
                </div>
                <div className="min-w-0">
                  <div className="text-sm font-medium text-white truncate">{artifact.title}</div>
                  <div className="text-[11px] text-surface-400">
                    {artifact.type}
                    {artifact.format ? ` • ${artifact.format}` : ''}
                  </div>
                </div>
              </div>
              <div className="text-[11px] text-surface-500 shrink-0">
                {artifact.timestamp.toLocaleTimeString()}
              </div>
            </div>

            <div className="p-3 space-y-2">
              {artifact.rfcReference && (
                <div className="text-[11px] text-indigo-400 font-mono">{artifact.rfcReference}</div>
              )}

              {deferredIssuance && deferredStatus && (
                <div className={`p-2 rounded border ${deferredStatus.background}`}>
                  <div className={`text-xs font-medium ${deferredStatus.text}`}>
                    Deferred issuance {deferredStatus.label}
                  </div>
                  <div className="mt-1 text-[11px] text-surface-300">
                    Transaction ID: <code className="text-surface-200">{deferredIssuance.transactionId || 'n/a'}</code>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-2 text-[11px] text-surface-300">
                    {deferredIssuance.pollAttempt !== undefined && (
                      <span>
                        Poll attempt: {deferredIssuance.pollAttempt}
                        {deferredIssuance.maxPollAttempts !== undefined ? `/${deferredIssuance.maxPollAttempts}` : ''}
                      </span>
                    )}
                    {deferredIssuance.retryAfterSeconds !== undefined && (
                      <span>Retry after: {deferredIssuance.retryAfterSeconds}s</span>
                    )}
                  </div>
                </div>
              )}

              {artifact.type === 'wallet_lifecycle' && artifact.json && typeof artifact.json === 'object' && !Array.isArray(artifact.json) && (
                <div className="p-2 rounded bg-teal-500/5 border border-teal-500/20 space-y-1.5">
                  <div className="text-xs text-teal-300 font-medium">Wallet Internal Event</div>
                  <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-[11px]">
                    {Object.entries(artifact.json as Record<string, unknown>).map(([key, value]) => (
                      <div key={key} className="flex items-baseline gap-1.5">
                        <span className="text-surface-400 shrink-0">{key}:</span>
                        <span className="text-surface-200 font-mono break-all">
                          {typeof value === 'object' && value !== null
                            ? JSON.stringify(value)
                            : String(value ?? 'n/a')}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {checks.length > 0 && (
                <div className="p-2 rounded bg-surface-950 border border-white/5">
                  <div className="text-xs text-surface-300 mb-1">Verifier checks</div>
                  <div className="grid grid-cols-2 gap-1 text-xs">
                    {checks.map((check) => (
                      <div key={check.label} className="flex items-center gap-1.5">
                        {check.value ? (
                          <ShieldCheck className="w-3.5 h-3.5 text-green-400" />
                        ) : (
                          <ShieldX className="w-3.5 h-3.5 text-red-400" />
                        )}
                        <span className="text-surface-300">{check.label}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {reasons.length > 0 && (
                <div className="p-2 rounded bg-red-500/5 border border-red-500/20">
                  <div className="text-xs text-red-300">Policy reasons: {reasons.join(', ')}</div>
                </div>
              )}

              {reasonCodes.length > 0 && (
                <div className="p-2 rounded bg-amber-500/5 border border-amber-500/20">
                  <div className="text-xs text-amber-200">Reason codes: {reasonCodes.join(', ')}</div>
                </div>
              )}

              {credentialEvidenceDisplay && renderCredentialEvidenceDisplay(credentialEvidenceDisplay)}

              {Object.keys(metadata).length > 0 && (
                <pre className="p-2 rounded bg-surface-950 text-[11px] text-surface-300 overflow-x-auto">
                  {JSON.stringify(metadata, null, 2)}
                </pre>
              )}

              {jwtDecoded && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  <pre className="p-2 rounded bg-surface-950 text-[11px] text-surface-300 overflow-x-auto">
                    {JSON.stringify(jwtDecoded.header, null, 2)}
                  </pre>
                  <pre className="p-2 rounded bg-surface-950 text-[11px] text-surface-300 overflow-x-auto">
                    {JSON.stringify(jwtDecoded.payload, null, 2)}
                  </pre>
                </div>
              )}

              {artifact.raw && (
                <div className="space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs text-surface-400">Raw artifact</span>
                    <div className="flex items-center gap-3">
                      {artifact.type === 'wallet_handoff' && isHTTPURL(artifact.raw) && (
                        <a
                          href={artifact.raw}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-1 text-xs text-cyan-300 hover:text-cyan-200"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                          Open
                        </a>
                      )}
                      <button
                        onClick={() => copyText(artifact.raw || '', artifact.id)}
                        className="flex items-center gap-1 text-xs text-surface-300 hover:text-white"
                      >
                        {copiedId === artifact.id ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                        {copiedId === artifact.id ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                  </div>
                  <pre className="p-2 rounded bg-surface-950 text-[11px] text-surface-300 overflow-x-auto">
                    {artifact.raw}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}

// isHTTPURL gates the "Open" link to wallet_handoff artifacts that are
// actually a navigable https:// (or http:// for local dev) URL, e.g. the
// issuer-initiated offer delivery URL -- never an openid4vp:// deep link
// or other non-navigable payload, which a browser cannot open directly.
function isHTTPURL(value: string): boolean {
  try {
    const parsed = new URL(value)
    return parsed.protocol === 'https:' || parsed.protocol === 'http:'
  } catch {
    return false
  }
}

function artifactIcon(type: VCArtifact['type']): { icon: ElementType; fg: string; bg: string } {
  switch (type) {
    case 'wallet_handoff':
      return { icon: QrCode, fg: 'text-cyan-400', bg: 'bg-cyan-500/10' }
    case 'wallet_lifecycle':
      return { icon: Activity, fg: 'text-teal-400', bg: 'bg-teal-500/10' }
    case 'credential':
      return { icon: KeyRound, fg: 'text-emerald-400', bg: 'bg-emerald-500/10' }
    case 'verification_result':
      return { icon: ShieldCheck, fg: 'text-violet-400', bg: 'bg-violet-500/10' }
    case 'deferred_status':
      return { icon: Clock, fg: 'text-blue-400', bg: 'bg-blue-500/10' }
    default:
      return { icon: FileText, fg: 'text-amber-400', bg: 'bg-amber-500/10' }
  }
}

function getCheckList(metadata: Record<string, unknown>): Array<{ label: string; value: boolean }> {
  const checks = metadata.checks as Record<string, unknown> | undefined
  if (!checks || typeof checks !== 'object') {
    return []
  }
  return [
    { label: 'Nonce', value: Boolean(checks.nonceValidated) },
    { label: 'Audience', value: Boolean(checks.audienceValidated) },
    { label: 'Expiry', value: Boolean(checks.expiryValidated) },
    { label: 'Holder Binding', value: Boolean(checks.holderBindingVerified) },
  ]
}

function getReasonList(metadata: Record<string, unknown>): string[] {
  const reasons = metadata.reasons
  if (!Array.isArray(reasons)) {
    return []
  }
  return reasons.map((reason) => String(reason))
}

function getReasonCodeList(metadata: Record<string, unknown>): string[] {
  const reasonCodes = metadata.reasonCodes
  if (!Array.isArray(reasonCodes)) {
    return []
  }
  return reasonCodes.map((code) => String(code))
}

// CredentialEvidenceView is the one shape both evidence sources render
// through. metadata.credentialEvidence (post-verification, set by
// oid4vp-direct-post) and metadata.credentialInspection (the decode
// endpoint, set by oid4vci-pre-authorized's captureCredential) are
// different backend DTOs with only partial field overlap -- subject,
// issuer, requiredClaimPaths and credentialConfigurationID exist only on
// the verification-path DTO (models.OID4VPCredentialEvidence), because
// InspectCredential has no presentation-exchange or DCQL context for a
// pasted/freshly-issued credential; selectiveDisclosure, issuedAt and
// expiresAt exist on both but are populated from vc.CredentialEvidence
// either way. Fields absent from a given source are '' / [] / undefined
// here, never fabricated, and render as "n/a" or are omitted entirely.
interface CredentialEvidenceView {
  subject: string
  format: string
  vct: string
  doctype: string
  credentialTypes: string[]
  issuer: string
  requiredClaimPaths: string[]
  disclosedClaims: Record<string, unknown>
  fullClaims: Record<string, unknown>
  selectiveDisclosure?: DecodeCredentialSelectiveDisclosure
  issuedAt?: string
  expiresAt?: string
}

// CredentialEvidenceDisplay is the structural enforcement for "unverified
// evidence must render in the unverified register": there is no frontend
// test runner (confirmed alongside the Node-script fallback used for
// verify-jwk-thumbprint.mjs), so this guarantee is carried by the type
// checker instead of a test. kind is derived exactly once, in
// getCredentialEvidence, from vc.IssuerTrustStatus -- never from format,
// and never re-derived downstream. renderCredentialEvidenceDisplay is the
// only function that reads `kind`, and each of VerifiedRegister /
// UnverifiedRegister's prop types is narrowed with Extract<> so passing a
// mismatched variant into either is a compile error, not a runtime
// styling choice that can silently drift.
type CredentialEvidenceDisplay =
  | { kind: 'verified'; evidence: CredentialEvidenceView; note: string }
  | {
      kind: 'unverified'
      evidence: CredentialEvidenceView
      issuerTrust: 'failed' | 'not_evaluated'
      issuerTrustDetail?: string
      digestsConsistentWithMSO?: boolean
      digestConsistencyDetail?: string
    }
  | { kind: 'decode_failed'; reason: string }

interface DeferredIssuanceView {
  transactionId: string
  status: string
  pollAttempt?: number
  maxPollAttempts?: number
  retryAfterSeconds?: number
}

function deferredStatusConfig(status: string): { label: string; text: string; background: string } {
  switch (status) {
    case 'transaction_created':
      return {
        label: 'started',
        text: 'text-blue-300',
        background: 'bg-blue-500/5 border-blue-500/20',
      }
    case 'pending':
      return {
        label: 'pending',
        text: 'text-amber-200',
        background: 'bg-amber-500/5 border-amber-500/20',
      }
    case 'completed':
      return {
        label: 'completed',
        text: 'text-green-300',
        background: 'bg-green-500/5 border-green-500/20',
      }
    case 'timeout':
      return {
        label: 'timed out',
        text: 'text-red-300',
        background: 'bg-red-500/5 border-red-500/20',
      }
    default:
      return {
        label: status || 'unknown',
        text: 'text-surface-300',
        background: 'bg-surface-950 border-white/10',
      }
  }
}

function getDeferredIssuance(metadata: Record<string, unknown>): DeferredIssuanceView | null {
  const hasDeferredFlag = Boolean(metadata.deferredFlow || metadata.deferred)
  const transactionId = String(
    metadata.transactionId || metadata.transaction_id || metadata.deferredTransactionId || '',
  ).trim()

  if (!hasDeferredFlag && !transactionId) {
    return null
  }

  const status = String(metadata.deferredStatus || '').trim() || (metadata.deferred ? 'transaction_created' : '')
  return {
    transactionId,
    status,
    pollAttempt: toOptionalInt(metadata.pollAttempt ?? metadata.deferredPollAttempts),
    maxPollAttempts: toOptionalInt(metadata.maxPollAttempts ?? metadata.deferredMaxPollAttempts),
    retryAfterSeconds: toOptionalInt(metadata.retryAfterSeconds ?? metadata.deferredRetryAfterSeconds),
  }
}

function toOptionalInt(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.floor(value)
  }
  if (typeof value === 'string') {
    const parsed = Number.parseInt(value.trim(), 10)
    if (Number.isFinite(parsed)) {
      return parsed
    }
  }
  return undefined
}

// getCredentialEvidence reads whichever of the two evidence sources is
// present and returns one shared display shape. There is deliberately no
// `if (format === 'mso_mdoc')` branch anywhere in this file: mso_mdoc goes
// through vc.MSOMdocFormat into the same vc.CredentialEvidence /
// vc.SelectiveDisclosureSummary shape as every other registered format, so
// the same code path renders it.
function getCredentialEvidence(metadata: Record<string, unknown>): CredentialEvidenceDisplay | null {
  const inspection = metadata.credentialInspection
  if (inspection && typeof inspection === 'object' && typeof (inspection as { status?: unknown }).status === 'string') {
    return credentialEvidenceDisplayFromInspection(inspection as CredentialInspectionMetadata)
  }

  // metadata.credentialEvidence is the OID4VP verification-path DTO
  // (models.OID4VPCredentialEvidence). validatePresentedCredentialEnvelopes
  // hard-fails the whole request on any IssuerTrustStatus other than
  // Verified (see its ValidateIssuerSignature call) before this evidence is
  // ever constructed, so reaching this branch at all is itself proof of a
  // verified issuer signature -- 'verified' is not inferred here, it is a
  // fact already established upstream.
  const legacyEvidence = metadata.credentialEvidence
  if (legacyEvidence && typeof legacyEvidence === 'object') {
    return {
      kind: 'verified',
      evidence: credentialEvidenceViewFromLegacy(legacyEvidence as Record<string, unknown>),
      note: 'Issuer signature verified against stored issuance lineage',
    }
  }

  return null
}

function credentialEvidenceViewFromLegacy(evidenceMap: Record<string, unknown>): CredentialEvidenceView {
  const requiredClaimPaths = Array.isArray(evidenceMap.required_claim_paths)
    ? evidenceMap.required_claim_paths.map((path) => String(path))
    : []
  const disclosedClaims =
    evidenceMap.disclosed_claims && typeof evidenceMap.disclosed_claims === 'object'
      ? (evidenceMap.disclosed_claims as Record<string, unknown>)
      : {}
  const fullClaims =
    evidenceMap.full_claims && typeof evidenceMap.full_claims === 'object'
      ? (evidenceMap.full_claims as Record<string, unknown>)
      : {}

  return {
    subject: typeof evidenceMap.subject === 'string' ? evidenceMap.subject : '',
    format: typeof evidenceMap.format === 'string' ? evidenceMap.format : '',
    vct: typeof evidenceMap.vct === 'string' ? evidenceMap.vct : '',
    doctype: typeof evidenceMap.doctype === 'string' ? evidenceMap.doctype : '',
    credentialTypes: Array.isArray(evidenceMap.credential_types)
      ? evidenceMap.credential_types.map((item) => String(item))
      : [],
    issuer: typeof evidenceMap.issuer === 'string' ? evidenceMap.issuer : '',
    requiredClaimPaths,
    disclosedClaims,
    fullClaims,
    // The verification-path DTO carries no selective-disclosure summary or
    // validity timestamps today (models.OID4VPCredentialEvidence predates
    // both). Leaving these undefined renders as "not shown", never a
    // fabricated zero or "n/a" count.
  }
}

function credentialEvidenceViewFromDecoded(evidence: DecodeCredentialEvidence): CredentialEvidenceView {
  return {
    subject: '',
    format: evidence.format || '',
    vct: evidence.vct || '',
    doctype: evidence.doctype || '',
    credentialTypes: evidence.credential_types || [],
    issuer: '',
    requiredClaimPaths: [],
    disclosedClaims: evidence.disclosed_claims || {},
    fullClaims: evidence.full_claims || {},
    selectiveDisclosure: evidence.selective_disclosure,
    issuedAt: evidence.issued_at,
    expiresAt: evidence.expires_at,
  }
}

// credentialEvidenceDisplayFromInspection is the one place `kind` gets
// decided for decode-endpoint evidence, straight from
// vc.IssuerTrustStatus's tri-state via assurance.issuer_trust -- 'verified'
// only when the backend actually verified a signature against real trust
// material, which InspectCredential today never supplies (see its doc
// comment), so every decode-endpoint result renders unverified in
// practice. digestsConsistentWithMSO/digestConsistencyDetail are carried
// through untouched either way: they prove internal consistency between
// presented items and the credential's own MSO, never authenticity, and
// must keep that wording downstream.
function credentialEvidenceDisplayFromInspection(inspection: CredentialInspectionMetadata): CredentialEvidenceDisplay {
  if (inspection.status === 'decode_failed') {
    return { kind: 'decode_failed', reason: inspection.reason }
  }

  const evidence = credentialEvidenceViewFromDecoded(inspection.evidence)
  const { assurance } = inspection
  if (assurance.issuer_trust === 'verified') {
    return { kind: 'verified', evidence, note: 'Issuer signature verified against supplied trust material' }
  }
  return {
    kind: 'unverified',
    evidence,
    issuerTrust: assurance.issuer_trust,
    issuerTrustDetail: assurance.issuer_trust_detail,
    digestsConsistentWithMSO: assurance.digests_consistent_with_mso,
    digestConsistencyDetail: assurance.digest_consistency_detail,
  }
}

// renderCredentialEvidenceDisplay is the only function in this file that
// reads CredentialEvidenceDisplay.kind. The switch is exhaustive over the
// three variants with a `never`-typed default: adding a fourth kind to the
// union without adding a case here is a compile error, not a silently
// unhandled state. Every case returns a real element (never null/undefined
// implicitly) because the declared return type is JSX.Element rather than
// ReactNode -- there is no arm that can quietly render nothing.
function renderCredentialEvidenceDisplay(display: CredentialEvidenceDisplay): JSX.Element {
  switch (display.kind) {
    case 'verified':
      return <VerifiedRegister display={display} />
    case 'unverified':
      return <UnverifiedRegister display={display} />
    case 'decode_failed':
      return <DecodeFailedPanel reason={display.reason} />
    default: {
      const unhandled: never = display
      throw new Error(`VCInspector: unhandled credential evidence display kind: ${JSON.stringify(unhandled)}`)
    }
  }
}

// EvidenceAssurance is CredentialEvidenceRegister's required `assurance`
// prop -- deliberately its own type rather than a boolean, and with no
// default value anywhere in this file, so a new call site is forced to
// state which register applies rather than silently inheriting "verified"
// by omission.
type EvidenceAssurance =
  | { kind: 'verified'; note: string }
  | {
      kind: 'unverified'
      issuerTrust: 'failed' | 'not_evaluated'
      issuerTrustDetail?: string
      digestsConsistentWithMSO?: boolean
      digestConsistencyDetail?: string
    }

// VerifiedRegister is the counterpart to UnverifiedRegister below, kept as
// its own component (rather than a shared component with an internal
// verified/unverified if-branch) so the register is chosen by which
// component the exhaustive switch above selects, not by a condition
// evaluated inside a shared render path.
function VerifiedRegister({ display }: { display: Extract<CredentialEvidenceDisplay, { kind: 'verified' }> }): JSX.Element {
  return <CredentialEvidenceRegister evidence={display.evidence} assurance={{ kind: 'verified', note: display.note }} />
}

// UnverifiedRegister is the only component in this file that can produce a
// rendered unverified value: its prop type is narrowed with Extract<> to
// exactly `{ kind: 'unverified' }`, so there is no way to obtain a
// renderable unverified value that is not already inside it, and no other
// function constructs an EvidenceAssurance with kind: 'unverified'.
function UnverifiedRegister({ display }: { display: Extract<CredentialEvidenceDisplay, { kind: 'unverified' }> }): JSX.Element {
  return (
    <CredentialEvidenceRegister
      evidence={display.evidence}
      assurance={{
        kind: 'unverified',
        issuerTrust: display.issuerTrust,
        issuerTrustDetail: display.issuerTrustDetail,
        digestsConsistentWithMSO: display.digestsConsistentWithMSO,
        digestConsistencyDetail: display.digestConsistencyDetail,
      }}
    />
  )
}

function DecodeFailedPanel({ reason }: { reason: string }): JSX.Element {
  return (
    <div className="p-2 rounded bg-surface-950 border border-red-500/30 space-y-1">
      <div className="flex items-center gap-1.5 text-xs text-red-300 font-medium">
        <AlertTriangle className="w-3.5 h-3.5" />
        Credential decode failed
      </div>
      <div className="text-[11px] text-surface-400">{reason}</div>
    </div>
  )
}

// CredentialEvidenceRegister is "the evidence renderer": assurance is
// required with no default, so border colour, badge icon and label are
// always derived from assurance.kind rather than from a caller-supplied
// style choice. VerifiedRegister and UnverifiedRegister are its only
// callers, each already committed to its own register before calling in.
function CredentialEvidenceRegister({
  evidence,
  assurance,
}: {
  evidence: CredentialEvidenceView
  assurance: EvidenceAssurance
}): JSX.Element {
  const verified = assurance.kind === 'verified'
  const failed = assurance.kind === 'unverified' && assurance.issuerTrust === 'failed'
  const borderClass = verified ? 'border-emerald-500/20' : failed ? 'border-red-500/30' : 'border-amber-500/30'
  const BadgeIcon = verified ? ShieldCheck : failed ? ShieldX : ShieldAlert
  const badgeTextClass = verified ? 'text-emerald-300' : failed ? 'text-red-300' : 'text-amber-200'
  const badgeLabel = verified
    ? `Verified — ${assurance.note}`
    : failed
      ? 'Signature verification failed'
      : 'Not verified — no issuer trust material evaluated'

  return (
    <div className={`p-2 rounded bg-surface-950 border space-y-2 ${borderClass}`}>
      <div className={`flex items-center gap-1.5 text-xs font-medium ${badgeTextClass}`}>
        <BadgeIcon className="w-3.5 h-3.5" />
        {badgeLabel}
      </div>
      {assurance.kind === 'unverified' && assurance.issuerTrustDetail && (
        <div className="text-[11px] text-surface-400">{assurance.issuerTrustDetail}</div>
      )}
      {assurance.kind === 'unverified' && assurance.digestsConsistentWithMSO !== undefined && (
        <div className="text-[11px] text-surface-400">
          Digests consistent with MSO (internal consistency, not authenticity):{' '}
          <span className={assurance.digestsConsistentWithMSO ? 'text-surface-200' : 'text-red-300'}>
            {assurance.digestsConsistentWithMSO ? 'yes' : 'no'}
          </span>
          {assurance.digestConsistencyDetail ? ` — ${assurance.digestConsistencyDetail}` : ''}
        </div>
      )}
      {!verified && (
        <div className="text-[11px] text-amber-200/80">
          Everything below is what this artifact contains, unverified. Do not treat it as authenticated.
        </div>
      )}
      <CredentialEvidenceFields evidence={evidence} />
    </div>
  )
}

// CredentialEvidenceFields is a private detail of CredentialEvidenceRegister
// (not called from anywhere else in this file): the neutral claims/counts
// grid that looks the same regardless of register, with all register
// chrome -- border, badge, warning copy -- owned by its one caller above.
function CredentialEvidenceFields({ evidence }: { evidence: CredentialEvidenceView }) {
  const validityLine = formatValidityLine(evidence.issuedAt, evidence.expiresAt)
  return (
    <div className="space-y-2">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-[11px]">
        <EvidenceField label="Subject" value={evidence.subject} />
        <EvidenceField label="Format" value={evidence.format} />
        <EvidenceField label="Issuer" value={evidence.issuer} />
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-[11px]">
        <EvidenceField label="VCT" value={evidence.vct} />
        <EvidenceField label="doctype" value={evidence.doctype} />
        <EvidenceField label="credential types" value={evidence.credentialTypes.join(', ')} />
      </div>
      {validityLine && <div className="text-[11px] text-surface-400">{validityLine}</div>}
      {evidence.requiredClaimPaths.length > 0 && (
        <div className="space-y-1">
          <div className="text-[11px] text-surface-400">Required claim paths</div>
          <div className="flex flex-wrap gap-1">
            {evidence.requiredClaimPaths.map((path) => (
              <code key={path} className="px-1.5 py-0.5 rounded bg-surface-900 border border-white/10 text-[10px] text-surface-300">
                {path}
              </code>
            ))}
          </div>
        </div>
      )}
      {evidence.selectiveDisclosure && <SelectiveDisclosureBlock summary={evidence.selectiveDisclosure} />}
      {Object.keys(evidence.disclosedClaims).length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          <div className="space-y-1">
            <div className="text-[11px] text-cyan-300">Disclosed claims</div>
            <pre className="p-2 rounded bg-surface-900 text-[11px] text-surface-300 overflow-x-auto">
              {JSON.stringify(evidence.disclosedClaims, null, 2)}
            </pre>
          </div>
          <div className="space-y-1">
            <div className="text-[11px] text-violet-300">Full reconstructed claims</div>
            <pre className="p-2 rounded bg-surface-900 text-[11px] text-surface-300 overflow-x-auto">
              {JSON.stringify(evidence.fullClaims, null, 2)}
            </pre>
          </div>
        </div>
      ) : (
        // disclosedClaims vs fullClaims is only a meaningful distinction for
        // dc+sd-jwt, where a holder can present a proper subset of the
        // issuer's disclosures. BuildCredentialEvidence never populates
        // DisclosedClaims for mso_mdoc (there is no equivalent split there --
        // CollectDisclosedElements' output is what SelectiveDisclosureBlock
        // above already renders), and an issued-but-not-yet-presented
        // dc+sd-jwt can legitimately carry none either. Rendering an empty
        // "Disclosed claims: {}" panel next to a fully-populated "Full
        // reconstructed claims" one in either case would assert a disclosure
        // state the artifact never claimed -- the same failure shape this
        // component exists to avoid -- so fall back to one plain claims
        // panel instead of a split that has nothing real on one side.
        <div className="space-y-1">
          <div className="text-[11px] text-violet-300">Claims</div>
          <pre className="p-2 rounded bg-surface-900 text-[11px] text-surface-300 overflow-x-auto">
            {JSON.stringify(evidence.fullClaims, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}

function EvidenceField({ label, value }: { label: string; value: string }) {
  return (
    <div className="p-2 rounded bg-surface-900 border border-white/5">
      <div className="text-surface-400 mb-1">{label}</div>
      <div className="text-surface-200 font-mono break-all">{value || 'n/a'}</div>
    </div>
  )
}

// SelectiveDisclosureBlock is the mdoc/SD-JWT-agnostic rendering of A4's
// disclosure summary: committed-count wording branches on
// committed_count_is_exact (mdoc's valueDigests count is genuine; SD-JWT's
// _sd count is a decoy-inclusive upper bound and must never be shown with
// the same confidence), and present-count wording branches on
// lifecycle_stage so an issued credential is never described as though a
// holder had made a disclosure decision about it.
function SelectiveDisclosureBlock({ summary }: { summary: DecodeCredentialSelectiveDisclosure }) {
  const namespaceEntries = Object.entries(summary.per_namespace || {})
  return (
    <div className="p-2 rounded bg-surface-900 border border-white/5 space-y-1.5">
      <div className="text-[11px] text-surface-300">Selective disclosure — {describeMechanism(summary.mechanism)}</div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-1 text-[11px] text-surface-300">
        <div>{describeCommittedCount(summary)}</div>
        <div>{describePresentCount(summary)}</div>
      </div>
      {summary.digest_algorithm && (
        <div className="text-[11px] text-surface-400">
          Digest algorithm: <span className="text-surface-200 font-mono">{summary.digest_algorithm}</span>
        </div>
      )}
      {namespaceEntries.length > 0 && (
        <div className="space-y-1">
          <div className="text-[11px] text-surface-400">Per namespace (present / committed)</div>
          <div className="flex flex-wrap gap-1">
            {namespaceEntries.map(([namespace, counts]) => (
              <code
                key={namespace}
                className="px-1.5 py-0.5 rounded bg-surface-950 border border-white/10 text-[10px] text-surface-300"
              >
                {namespace}: {counts.present_count}/{counts.committed_count}
              </code>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function describeMechanism(mechanism: string): string {
  switch (mechanism) {
    case 'mso_valuedigests':
      return 'ISO/IEC 18013-5 MSO valueDigests'
    case 'sd_jwt_disclosures':
      return 'SD-JWT disclosures (draft-ietf-oauth-selective-disclosure-jwt)'
    default:
      return mechanism || 'unknown mechanism'
  }
}

function describeCommittedCount(summary: DecodeCredentialSelectiveDisclosure): string {
  if (summary.committed_count_is_exact) {
    return `Committed: ${summary.committed_count} (exact)`
  }
  const caveats = ['may include decoy digests']
  if (summary.has_unrepresented_disclosure_forms) {
    caveats.push('may undercount nested or array-element disclosures')
  }
  return `Committed: ≤${summary.committed_count} (upper bound — ${caveats.join('; ')})`
}

function describePresentCount(summary: DecodeCredentialSelectiveDisclosure): string {
  if (summary.lifecycle_stage === 'issued') {
    return `Present at issuance: ${summary.present_count} of ${summary.committed_count} committed elements`
  }
  return `Disclosed: ${summary.present_count} of ${summary.committed_count} committed elements`
}

function formatValidityLine(issuedAt?: string, expiresAt?: string): string {
  const parts: string[] = []
  if (issuedAt) {
    parts.push(`Issued ${formatTimestamp(issuedAt)}`)
  }
  if (expiresAt) {
    parts.push(`Expires ${formatTimestamp(expiresAt)}`)
  }
  return parts.join(' · ')
}

function formatTimestamp(iso: string): string {
  const parsed = new Date(iso)
  return Number.isNaN(parsed.getTime()) ? iso : parsed.toLocaleString()
}
