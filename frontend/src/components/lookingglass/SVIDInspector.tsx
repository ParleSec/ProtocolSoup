import { useMemo, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  AlertTriangle, CheckCircle, XCircle, Clock,
  Key, Lock, Globe, ChevronDown, Copy, Check,
  FileText, Fingerprint, Calendar, Server,
  Award, Layers, RefreshCw, ShieldCheck
} from 'lucide-react'

// ============================================================================
// Types
// ============================================================================

interface X509SVIDData {
  spiffe_id: string
  certificate: string
  chain: string[]
  not_before: string
  not_after: string
  serial_number: string
  issuer: string
  subject: string
  dns_names?: string[]
  uris: string[]
  public_key: {
    algorithm: string
    size?: number
    curve?: string
  }
  signature: {
    algorithm: string
    value: string
  }
  extensions?: Array<{
    oid: string
    critical: boolean
    name?: string
  }>
}

interface JWTSVIDData {
  token: string
  spiffe_id: string
  audience: string[]
  expires_at: string
  issued_at: string
  header: Record<string, unknown>
  claims: Record<string, unknown>
}

interface TrustBundleData {
  trust_domain: string
  num_roots: number
  roots: Array<{
    subject: string
    issuer: string
    not_before: string
    not_after: string
    serial_number: string
    is_ca: boolean
  }>
}

interface SVIDInspectorProps {
  type: 'x509' | 'jwt' | 'bundle' | 'spiffe-id'
  data: X509SVIDData | JWTSVIDData | TrustBundleData | string
}

// SPIFFE-specific claim explanations
const spiffeClaimInfo: Record<string, { label: string; description: string; icon: React.ElementType }> = {
  sub: { label: 'SPIFFE ID', description: 'The unique workload identity in SPIFFE URI format', icon: Fingerprint },
  aud: { label: 'Audience', description: 'Intended recipient service(s) for this JWT-SVID', icon: Server },
  exp: { label: 'Expiration', description: 'JWT-SVIDs are short-lived (typically 5 minutes)', icon: Clock },
  iat: { label: 'Issued At', description: 'When the SPIRE Server issued this token', icon: Calendar },
}

// ============================================================================
// Main Component
// ============================================================================

export function SVIDInspector({ type, data }: SVIDInspectorProps) {
  if (type === 'x509') {
    return <X509SVIDInspector data={data as X509SVIDData} />
  }
  if (type === 'jwt') {
    return <JWTSVIDInspector data={data as JWTSVIDData} />
  }
  if (type === 'bundle') {
    return <TrustBundleInspector data={data as TrustBundleData} />
  }
  if (type === 'spiffe-id') {
    return <SPIFFEIDInspector spiffeId={data as string} />
  }
  return null
}

// ============================================================================
// X.509-SVID Inspector
// ============================================================================

function X509SVIDInspector({ data }: { data: X509SVIDData }) {
  const [expandedSection, setExpandedSection] = useState<string | null>('identity')
  const [copiedField, setCopiedField] = useState<string | null>(null)

  const validityStatus = useMemo(() => {
    const now = new Date()
    const notBefore = new Date(data.not_before)
    const notAfter = new Date(data.not_after)

    if (now < notBefore) {
      return { status: 'not_yet_valid', message: 'Certificate not yet valid' }
    }
    if (now > notAfter) {
      return { status: 'expired', message: 'Certificate has expired' }
    }

    const timeLeft = notAfter.getTime() - now.getTime()
    const hoursLeft = Math.floor(timeLeft / (1000 * 60 * 60))
    const minutesLeft = Math.floor((timeLeft % (1000 * 60 * 60)) / (1000 * 60))

    if (hoursLeft < 1) {
      return { status: 'expiring', message: `Expires in ${minutesLeft} minutes` }
    }
    return { status: 'valid', message: `Valid for ${hoursLeft}h ${minutesLeft}m` }
  }, [data.not_before, data.not_after])

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text)
    setCopiedField(field)
    setTimeout(() => setCopiedField(null), 2000)
  }

  // Parse SPIFFE ID components
  const spiffeComponents = useMemo(() => {
    try {
      const url = new URL(data.spiffe_id)
      return {
        scheme: url.protocol.replace(':', ''),
        trustDomain: url.host,
        path: url.pathname,
      }
    } catch {
      return null
    }
  }, [data.spiffe_id])

  return (
    <div className="space-y-3 sm:space-y-4">
      {/* Status Banner */}
      <div className={`flex items-start sm:items-center gap-3 p-3 sm:p-4 rounded-xl border ${
        validityStatus.status === 'expired' || validityStatus.status === 'not_yet_valid'
          ? 'bg-red-500/10 border-red-500/30'
          : validityStatus.status === 'expiring'
          ? 'bg-yellow-500/10 border-yellow-500/30'
          : 'bg-green-500/10 border-green-500/30'
      }`}>
        {validityStatus.status === 'expired' || validityStatus.status === 'not_yet_valid' ? (
          <XCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
        ) : validityStatus.status === 'expiring' ? (
          <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0" />
        ) : (
          <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0" />
        )}
        <div className="flex-1 min-w-0">
          <p className="font-medium text-sm sm:text-base text-white">X.509-SVID Certificate</p>
          <p className={`text-xs sm:text-sm ${
            validityStatus.status === 'expired' || validityStatus.status === 'not_yet_valid'
              ? 'text-red-300'
              : validityStatus.status === 'expiring'
              ? 'text-yellow-300'
              : 'text-green-300'
          }`}>
            {validityStatus.message}
          </p>
        </div>
        <span className="px-2 sm:px-3 py-1 rounded-full bg-white/10 text-xs font-medium text-white flex-shrink-0">
          {data.public_key.algorithm}
        </span>
      </div>

      {/* SPIFFE ID Display */}
      <div className="p-3 sm:p-4 rounded-xl bg-gradient-to-r from-purple-500/10 to-blue-500/10 border border-purple-500/20">
        <div className="flex items-center gap-2 mb-2">
          <Fingerprint className="w-4 h-4 text-purple-400" />
          <span className="text-xs font-semibold text-purple-300 uppercase tracking-wider">SPIFFE ID</span>
        </div>
        <div className="font-mono text-sm text-white break-all">{data.spiffe_id}</div>
        {spiffeComponents && (
          <div className="flex flex-wrap gap-2 mt-3">
            <span className="px-2 py-1 rounded bg-purple-500/20 text-xs text-purple-300">
              {spiffeComponents.scheme}://
            </span>
            <span className="px-2 py-1 rounded bg-blue-500/20 text-xs text-blue-300">
              {spiffeComponents.trustDomain}
            </span>
            <span className="px-2 py-1 rounded bg-cyan-500/20 text-xs text-cyan-300">
              {spiffeComponents.path}
            </span>
          </div>
        )}
      </div>

      {/* Certificate Details Sections */}
      <div className="space-y-3">
        {/* Identity Section */}
        <SVIDSection
          title="Identity"
          subtitle="SPIFFE ID and certificate subject"
          icon={Fingerprint}
          color="purple"
          isExpanded={expandedSection === 'identity'}
          onToggle={() => setExpandedSection(expandedSection === 'identity' ? null : 'identity')}
        >
          <div className="space-y-2">
            <FieldRow
              label="SPIFFE ID"
              value={data.spiffe_id}
              description="Workload identity in URI format (in SAN extension)"
              onCopy={() => copyToClipboard(data.spiffe_id, 'spiffe_id')}
              isCopied={copiedField === 'spiffe_id'}
            />
            <FieldRow
              label="Subject"
              value={data.subject}
              description="X.509 certificate subject DN"
              onCopy={() => copyToClipboard(data.subject, 'subject')}
              isCopied={copiedField === 'subject'}
            />
            <FieldRow
              label="Issuer"
              value={data.issuer}
              description="Certificate authority that signed this SVID"
              onCopy={() => copyToClipboard(data.issuer, 'issuer')}
              isCopied={copiedField === 'issuer'}
            />
            {data.dns_names && data.dns_names.length > 0 && (
              <FieldRow
                label="DNS Names"
                value={data.dns_names.join(', ')}
                description="Additional DNS SANs for service discovery"
                onCopy={() => copyToClipboard(data.dns_names!.join(', '), 'dns')}
                isCopied={copiedField === 'dns'}
              />
            )}
          </div>
        </SVIDSection>

        {/* Validity Section */}
        <SVIDSection
          title="Validity Period"
          subtitle="Certificate lifetime and rotation"
          icon={Clock}
          color="cyan"
          isExpanded={expandedSection === 'validity'}
          onToggle={() => setExpandedSection(expandedSection === 'validity' ? null : 'validity')}
        >
          <div className="space-y-2">
            <FieldRow
              label="Not Before"
              value={new Date(data.not_before).toLocaleString()}
              description="Certificate becomes valid"
            />
            <FieldRow
              label="Not After"
              value={new Date(data.not_after).toLocaleString()}
              description="Certificate expires (auto-rotated before this)"
              isHighlighted={validityStatus.status === 'expiring'}
            />
            <FieldRow
              label="Serial Number"
              value={data.serial_number.length > 32 ? `${data.serial_number.slice(0, 32)}...` : data.serial_number}
              description="Unique certificate identifier"
              onCopy={() => copyToClipboard(data.serial_number, 'serial')}
              isCopied={copiedField === 'serial'}
            />
          </div>
          <div className="mt-3 p-3 rounded-lg bg-blue-500/10 border border-blue-500/20">
            <div className="flex items-start gap-2">
              <RefreshCw className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" />
              <div>
                <p className="text-sm text-blue-300 font-medium">Automatic Rotation</p>
                <p className="text-xs text-blue-300/70 mt-1">
                  SPIRE Agent automatically rotates this certificate before expiration,
                  typically at 50% of the TTL. No service restart required.
                </p>
              </div>
            </div>
          </div>
        </SVIDSection>

        {/* Cryptography Section */}
        <SVIDSection
          title="Cryptography"
          subtitle="Public key and signature"
          icon={Key}
          color="green"
          isExpanded={expandedSection === 'crypto'}
          onToggle={() => setExpandedSection(expandedSection === 'crypto' ? null : 'crypto')}
        >
          <div className="space-y-2">
            <FieldRow
              label="Public Key Algorithm"
              value={data.public_key.algorithm}
              description="Key type used for this certificate"
            />
            {data.public_key.curve && (
              <FieldRow
                label="Curve"
                value={data.public_key.curve}
                description="Elliptic curve for ECDSA keys"
              />
            )}
            {data.public_key.size && (
              <FieldRow
                label="Key Size"
                value={`${data.public_key.size} bits`}
                description="Key length for RSA keys"
              />
            )}
            <FieldRow
              label="Signature Algorithm"
              value={data.signature.algorithm}
              description="Algorithm used by CA to sign this certificate"
            />
            <div className="p-3 rounded-lg bg-surface-800">
              <p className="text-xs text-surface-400 mb-1">Signature (truncated)</p>
              <p className="font-mono text-xs text-green-400 break-all">
                {data.signature.value}
              </p>
            </div>
          </div>
        </SVIDSection>

        {/* Extensions Section */}
        {data.extensions && data.extensions.length > 0 && (
          <SVIDSection
            title="X.509 Extensions"
            subtitle="Certificate extensions and constraints"
            icon={Layers}
            color="orange"
            isExpanded={expandedSection === 'extensions'}
            onToggle={() => setExpandedSection(expandedSection === 'extensions' ? null : 'extensions')}
          >
            <div className="space-y-2">
              {data.extensions.map((ext, idx) => (
                <div key={idx} className="flex items-start gap-3 p-3 rounded-lg bg-surface-900/50">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-white">
                        {ext.name || ext.oid}
                      </span>
                      {ext.critical && (
                        <span className="px-1.5 py-0.5 rounded text-xs bg-red-500/20 text-red-400">
                          CRITICAL
                        </span>
                      )}
                    </div>
                    <code className="text-xs text-surface-400">{ext.oid}</code>
                  </div>
                </div>
              ))}
            </div>
          </SVIDSection>
        )}
      </div>
    </div>
  )
}

// ============================================================================
// JWT-SVID Inspector
// ============================================================================

function JWTSVIDInspector({ data }: { data: JWTSVIDData }) {
  const [expandedSection, setExpandedSection] = useState<string | null>('claims')
  const [copiedField, setCopiedField] = useState<string | null>(null)

  const validityStatus = useMemo(() => {
    const now = new Date()
    const expiresAt = new Date(data.expires_at)

    if (now > expiresAt) {
      return { status: 'expired', message: 'Token has expired' }
    }

    const timeLeft = expiresAt.getTime() - now.getTime()
    const minutesLeft = Math.floor(timeLeft / (1000 * 60))
    const secondsLeft = Math.floor((timeLeft % (1000 * 60)) / 1000)

    if (minutesLeft < 1) {
      return { status: 'expiring', message: `Expires in ${secondsLeft} seconds` }
    }
    return { status: 'valid', message: `Valid for ${minutesLeft}m ${secondsLeft}s` }
  }, [data.expires_at])

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text)
    setCopiedField(field)
    setTimeout(() => setCopiedField(null), 2000)
  }

  return (
    <div className="space-y-3 sm:space-y-4">
      {/* Status Banner */}
      <div className={`flex items-start sm:items-center gap-3 p-3 sm:p-4 rounded-xl border ${
        validityStatus.status === 'expired'
          ? 'bg-red-500/10 border-red-500/30'
          : validityStatus.status === 'expiring'
          ? 'bg-yellow-500/10 border-yellow-500/30'
          : 'bg-green-500/10 border-green-500/30'
      }`}>
        {validityStatus.status === 'expired' ? (
          <XCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
        ) : validityStatus.status === 'expiring' ? (
          <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0" />
        ) : (
          <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0" />
        )}
        <div className="flex-1 min-w-0">
          <p className="font-medium text-sm sm:text-base text-white">JWT-SVID Token</p>
          <p className={`text-xs sm:text-sm ${
            validityStatus.status === 'expired'
              ? 'text-red-300'
              : validityStatus.status === 'expiring'
              ? 'text-yellow-300'
              : 'text-green-300'
          }`}>
            {validityStatus.message}
          </p>
        </div>
        <span className="px-2 sm:px-3 py-1 rounded-full bg-white/10 text-xs font-medium text-white flex-shrink-0">
          {String(data.header.alg || 'JWT')}
        </span>
      </div>

      {/* Token Structure Visual */}
      <div className="p-3 sm:p-4 rounded-xl bg-surface-900/50 border border-white/5">
        <h4 className="text-xs font-semibold text-surface-400 uppercase tracking-wider mb-3">JWT Structure</h4>
        <div className="flex flex-wrap gap-1 font-mono text-xs">
          <span className="px-3 py-2 rounded-lg bg-red-500/20 text-red-400">Header</span>
          <span className="text-surface-600 self-center">.</span>
          <span className="px-3 py-2 rounded-lg bg-purple-500/20 text-purple-400">Claims</span>
          <span className="text-surface-600 self-center">.</span>
          <span className="px-3 py-2 rounded-lg bg-cyan-500/20 text-cyan-400">Signature</span>
        </div>
      </div>

      {/* SPIFFE ID Display */}
      <div className="p-3 sm:p-4 rounded-xl bg-gradient-to-r from-purple-500/10 to-blue-500/10 border border-purple-500/20">
        <div className="flex items-center gap-2 mb-2">
          <Fingerprint className="w-4 h-4 text-purple-400" />
          <span className="text-xs font-semibold text-purple-300 uppercase tracking-wider">SPIFFE ID (sub claim)</span>
        </div>
        <div className="font-mono text-sm text-white break-all">{data.spiffe_id}</div>
        <div className="flex flex-wrap gap-2 mt-3">
          <span className="px-2 py-1 rounded bg-blue-500/20 text-xs text-blue-300 flex items-center gap-1">
            <Server className="w-3 h-3" />
            Audience: {data.audience.join(', ')}
          </span>
        </div>
      </div>

      {/* Sections */}
      <div className="space-y-3">
        {/* Header Section */}
        <SVIDSection
          title="Header"
          subtitle="Algorithm and key identifier"
          icon={Key}
          color="red"
          isExpanded={expandedSection === 'header'}
          onToggle={() => setExpandedSection(expandedSection === 'header' ? null : 'header')}
        >
          <div className="space-y-2">
            {Object.entries(data.header).map(([key, value]) => (
              <FieldRow
                key={key}
                label={key}
                value={String(value)}
                onCopy={() => copyToClipboard(String(value), key)}
                isCopied={copiedField === key}
              />
            ))}
          </div>
        </SVIDSection>

        {/* Claims Section */}
        <SVIDSection
          title="Claims"
          subtitle="SPIFFE identity and metadata"
          icon={FileText}
          color="purple"
          isExpanded={expandedSection === 'claims'}
          onToggle={() => setExpandedSection(expandedSection === 'claims' ? null : 'claims')}
        >
          <div className="space-y-2">
            {Object.entries(data.claims).map(([key, value]) => {
              const info = spiffeClaimInfo[key]
              const displayValue = typeof value === 'object' ? JSON.stringify(value) : String(value)
              const isTimestamp = ['exp', 'iat', 'nbf'].includes(key)
              const formattedValue = isTimestamp && typeof value === 'number'
                ? new Date(value * 1000).toLocaleString()
                : displayValue

              return (
                <FieldRow
                  key={key}
                  label={info?.label || key}
                  value={formattedValue}
                  description={info?.description}
                  onCopy={() => copyToClipboard(displayValue, key)}
                  isCopied={copiedField === key}
                  isHighlighted={key === 'exp' && validityStatus.status === 'expiring'}
                />
              )
            })}
          </div>
        </SVIDSection>

        {/* Token Section */}
        <SVIDSection
          title="Raw Token"
          subtitle="Complete JWT-SVID"
          icon={Lock}
          color="cyan"
          isExpanded={expandedSection === 'token'}
          onToggle={() => setExpandedSection(expandedSection === 'token' ? null : 'token')}
        >
          <div className="p-3 rounded-lg bg-surface-800">
            <p className="font-mono text-xs text-cyan-400 break-all">
              {data.token.length > 100 ? `${data.token.slice(0, 100)}...` : data.token}
            </p>
          </div>
          <button
            onClick={() => copyToClipboard(data.token, 'full_token')}
            className="mt-2 flex items-center gap-2 px-3 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-sm text-surface-300"
          >
            {copiedField === 'full_token' ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
            Copy Full Token
          </button>
        </SVIDSection>
      </div>
    </div>
  )
}

// ============================================================================
// Trust Bundle Inspector
// ============================================================================

function TrustBundleInspector({ data }: { data: TrustBundleData }) {
  const [expandedRoot, setExpandedRoot] = useState<number | null>(0)

  return (
    <div className="space-y-3 sm:space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3 p-3 sm:p-4 rounded-xl bg-green-500/10 border border-green-500/30">
        <ShieldCheck className="w-5 h-5 text-green-400" />
        <div className="flex-1">
          <p className="font-medium text-white">Trust Bundle</p>
          <p className="text-sm text-green-300">{data.num_roots} root certificate(s)</p>
        </div>
        <span className="px-3 py-1 rounded-full bg-white/10 text-xs font-medium text-white">
          {data.trust_domain}
        </span>
      </div>

      {/* Trust Domain */}
      <div className="p-3 sm:p-4 rounded-xl bg-gradient-to-r from-green-500/10 to-cyan-500/10 border border-green-500/20">
        <div className="flex items-center gap-2 mb-2">
          <Globe className="w-4 h-4 text-green-400" />
          <span className="text-xs font-semibold text-green-300 uppercase tracking-wider">Trust Domain</span>
        </div>
        <div className="font-mono text-sm text-white">{data.trust_domain}</div>
        <p className="text-xs text-surface-400 mt-2">
          All SPIFFE IDs in this bundle start with spiffe://{data.trust_domain}/
        </p>
      </div>

      {/* Root Certificates */}
      <div className="space-y-2">
        <h4 className="text-xs font-semibold text-surface-400 uppercase tracking-wider px-1">
          Root CA Certificates
        </h4>
        {data.roots.map((root, index) => (
          <div
            key={index}
            className="rounded-xl bg-surface-900/50 border border-white/5 overflow-hidden"
          >
            <button
              onClick={() => setExpandedRoot(expandedRoot === index ? null : index)}
              className="w-full flex items-center gap-3 p-3 sm:p-4 text-left"
            >
              <Award className={`w-5 h-5 ${root.is_ca ? 'text-yellow-400' : 'text-surface-400'}`} />
              <div className="flex-1 min-w-0">
                <p className="font-medium text-sm text-white truncate">{root.subject}</p>
                <p className="text-xs text-surface-400">
                  Expires: {new Date(root.not_after).toLocaleDateString()}
                </p>
              </div>
              {root.is_ca && (
                <span className="px-2 py-1 rounded text-xs bg-yellow-500/20 text-yellow-400">CA</span>
              )}
              <ChevronDown className={`w-4 h-4 text-surface-400 transition-transform ${expandedRoot === index ? 'rotate-180' : ''}`} />
            </button>
            <AnimatePresence>
              {expandedRoot === index && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  className="overflow-hidden"
                >
                  <div className="px-4 pb-4 space-y-2">
                    <FieldRow label="Subject" value={root.subject} />
                    <FieldRow label="Issuer" value={root.issuer} />
                    <FieldRow label="Not Before" value={new Date(root.not_before).toLocaleString()} />
                    <FieldRow label="Not After" value={new Date(root.not_after).toLocaleString()} />
                    <FieldRow label="Serial Number" value={root.serial_number} />
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        ))}
      </div>
    </div>
  )
}

// ============================================================================
// SPIFFE ID Parser
// ============================================================================

function SPIFFEIDInspector({ spiffeId }: { spiffeId: string }) {
  const parsed = useMemo(() => {
    try {
      if (!spiffeId.startsWith('spiffe://')) {
        return { valid: false, error: 'Must start with spiffe://' }
      }
      const url = new URL(spiffeId)
      const pathParts = url.pathname.split('/').filter(Boolean)
      
      return {
        valid: true,
        scheme: 'spiffe',
        trustDomain: url.host,
        path: url.pathname,
        pathComponents: pathParts,
      }
    } catch {
      return { valid: false, error: 'Invalid SPIFFE ID format' }
    }
  }, [spiffeId])

  if (!parsed.valid) {
    return (
      <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30">
        <div className="flex items-center gap-2 text-red-400">
          <XCircle className="w-5 h-5" />
          <span className="font-medium">Invalid SPIFFE ID</span>
        </div>
        <p className="text-sm text-red-300 mt-2">{parsed.error}</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="p-4 rounded-xl bg-green-500/10 border border-green-500/30">
        <div className="flex items-center gap-2 text-green-400 mb-3">
          <CheckCircle className="w-5 h-5" />
          <span className="font-medium">Valid SPIFFE ID</span>
        </div>
        <div className="font-mono text-sm text-white break-all">{spiffeId}</div>
      </div>

      <div className="space-y-2">
        <FieldRow
          label="Scheme"
          value={parsed.scheme!}
          description="SPIFFE URI scheme (always 'spiffe')"
        />
        <FieldRow
          label="Trust Domain"
          value={parsed.trustDomain!}
          description="Administrative domain that issued this identity"
        />
        <FieldRow
          label="Path"
          value={parsed.path!}
          description="Workload identifier within the trust domain"
        />
        {parsed.pathComponents!.length > 0 && (
          <div className="p-3 rounded-lg bg-surface-900/50">
            <p className="text-xs text-surface-400 mb-2">Path Components</p>
            <div className="flex flex-wrap gap-2">
              {parsed.pathComponents!.map((component, idx) => (
                <span key={idx} className="px-2 py-1 rounded bg-purple-500/20 text-xs text-purple-300">
                  {component}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ============================================================================
// Shared Components
// ============================================================================

function SVIDSection({
  title,
  subtitle,
  icon: Icon,
  color,
  isExpanded,
  onToggle,
  children,
}: {
  title: string
  subtitle: string
  icon: React.ElementType
  color: string
  isExpanded: boolean
  onToggle: () => void
  children: React.ReactNode
}) {
  const colorClasses: Record<string, string> = {
    red: 'text-red-400 bg-red-500/10 border-red-500/20',
    purple: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
    cyan: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
    green: 'text-green-400 bg-green-500/10 border-green-500/20',
    orange: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  }

  return (
    <div className={`rounded-xl border overflow-hidden transition-all ${
      isExpanded ? colorClasses[color] : 'bg-surface-900/30 border-white/5'
    }`}>
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 p-3 sm:p-4 text-left"
      >
        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
          isExpanded ? colorClasses[color] : 'bg-surface-800'
        }`}>
          <Icon className={`w-5 h-5 ${isExpanded ? colorClasses[color].split(' ')[0] : 'text-surface-400'}`} />
        </div>
        <div className="flex-1 min-w-0">
          <h3 className={`font-medium ${isExpanded ? 'text-white' : 'text-surface-300'}`}>{title}</h3>
          <p className="text-xs text-surface-400">{subtitle}</p>
        </div>
        <ChevronDown className={`w-5 h-5 text-surface-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
      </button>
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4">{children}</div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function FieldRow({
  label,
  value,
  description,
  onCopy,
  isCopied,
  isHighlighted,
}: {
  label: string
  value: string
  description?: string
  onCopy?: () => void
  isCopied?: boolean
  isHighlighted?: boolean
}) {
  return (
    <div className={`flex items-start gap-3 p-3 rounded-lg transition-colors group ${
      isHighlighted ? 'bg-yellow-500/10' : 'bg-surface-900/50 hover:bg-surface-800/50'
    }`}>
      <div className="flex-1 min-w-0">
        <p className={`text-xs font-medium ${isHighlighted ? 'text-yellow-400' : 'text-surface-400'}`}>
          {label}
        </p>
        <p className="text-sm text-white break-all mt-0.5">{value}</p>
        {description && <p className="text-xs text-surface-400 mt-1">{description}</p>}
      </div>
      {onCopy && (
        <button
          onClick={onCopy}
          className="opacity-0 group-hover:opacity-100 p-1.5 rounded-md hover:bg-white/10 transition-all"
        >
          {isCopied ? (
            <Check className="w-3.5 h-3.5 text-green-400" />
          ) : (
            <Copy className="w-3.5 h-3.5 text-surface-400" />
          )}
        </button>
      )}
    </div>
  )
}

