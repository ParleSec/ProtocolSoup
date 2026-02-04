import { useMemo, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Lock,
  User,
  Server,
  Link2,
  Fingerprint,
  Layers,
  CheckCircle,
  XCircle,
  AlertTriangle,
  ChevronDown,
  Copy,
  Check,
} from 'lucide-react'
import type { WireCapturedExchange, WireCertificateInfo } from '../../lookingglass/types'

interface TLSInspectorProps {
  exchange: WireCapturedExchange
}

interface TokenBindingInfo {
  token?: string
  tokenThumbprint?: string
  clientThumbprint?: string
  status: 'match' | 'mismatch' | 'missing'
}

const parseBearerToken = (headers?: Record<string, string[]>): string | undefined => {
  if (!headers) return undefined
  const authHeader = Object.entries(headers).find(([key]) => key.toLowerCase() === 'authorization')
  if (!authHeader) return undefined
  const values = authHeader[1] || []
  for (const value of values) {
    const match = value.match(/^Bearer\s+(.+)$/i)
    if (match) {
      return match[1]
    }
  }
  return undefined
}

const decodeJwtPayload = (token?: string): Record<string, unknown> | undefined => {
  if (!token) return undefined
  const parts = token.split('.')
  if (parts.length < 2) return undefined
  try {
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const padding = '='.repeat((4 - (base64.length % 4)) % 4)
    const json = atob(base64 + padding)
    return JSON.parse(json) as Record<string, unknown>
  } catch {
    return undefined
  }
}

const formatDate = (value?: string): string => {
  if (!value) return 'unknown'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return date.toLocaleString()
}

const formatShort = (value?: string, max = 48): string => {
  if (!value) return 'unknown'
  if (value.length <= max) return value
  return `${value.slice(0, max / 2)}…${value.slice(-max / 2)}`
}

const getCertStatus = (cert?: WireCertificateInfo): { label: string; tone: 'green' | 'yellow' | 'red' } => {
  if (!cert?.notAfter) {
    return { label: 'Validity unknown', tone: 'yellow' }
  }
  const now = Date.now()
  const notBefore = cert.notBefore ? Date.parse(cert.notBefore) : NaN
  const notAfter = cert.notAfter ? Date.parse(cert.notAfter) : NaN
  if (!Number.isNaN(notAfter) && now > notAfter) {
    return { label: 'Expired', tone: 'red' }
  }
  if (!Number.isNaN(notBefore) && now < notBefore) {
    return { label: 'Not yet valid', tone: 'yellow' }
  }
  return { label: 'Valid', tone: 'green' }
}

export function TLSInspector({ exchange }: TLSInspectorProps) {
  const tls = exchange.tls
  const [expandedSection, setExpandedSection] = useState<'tls' | 'client' | 'server' | 'binding' | null>('tls')
  const [copiedField, setCopiedField] = useState<string | null>(null)
  const clientCert = tls?.clientCert
  const serverCert = tls?.serverCert

  const bindingInfo = useMemo<TokenBindingInfo>(() => {
    if (!tls) {
      return { status: 'missing' }
    }
    const token = parseBearerToken(exchange.request.headers)
    const payload = decodeJwtPayload(token)
    const cnf = payload?.cnf as Record<string, unknown> | undefined
    const tokenThumbprint = typeof cnf?.['x5t#S256'] === 'string' ? cnf['x5t#S256'] : undefined
    const clientThumbprint = tls.clientCert?.thumbprint
    if (!tokenThumbprint || !clientThumbprint) {
      return { token, tokenThumbprint, clientThumbprint, status: 'missing' }
    }
    return {
      token,
      tokenThumbprint,
      clientThumbprint,
      status: tokenThumbprint === clientThumbprint ? 'match' : 'mismatch',
    }
  }, [exchange.request.headers, tls])

  if (!tls) {
    return null
  }

  const bindingConfig = {
    match: { icon: CheckCircle, color: 'text-green-400', label: 'Thumbprint matches cnf.x5t#S256' },
    mismatch: { icon: XCircle, color: 'text-red-400', label: 'Thumbprint mismatch' },
    missing: { icon: AlertTriangle, color: 'text-yellow-400', label: 'Binding data incomplete' },
  }[bindingInfo.status]
  const BindingIcon = bindingConfig.icon

  const clientStatus = getCertStatus(clientCert)
  const serverStatus = getCertStatus(serverCert)
  const isOutbound = tls.source === 'outbound'
  const sourceLabel = tls.source === 'outbound'
    ? 'Outbound TLS (mTLS client)'
    : tls.source === 'inbound'
    ? 'Inbound TLS'
    : 'TLS Source Unknown'
  const clientChainDisplay = tls.clientChain && tls.clientChain.length > 0
    ? tls.clientChain.map(cert => cert.subject)
    : (!isOutbound ? (tls.peerCertSubjects || []) : [])
  const serverChainDisplay = tls.serverChain && tls.serverChain.length > 0
    ? tls.serverChain.map(cert => cert.subject)
    : (isOutbound ? (tls.peerCertSubjects || []) : [])
  const chainLength = Math.max(clientChainDisplay.length, serverChainDisplay.length)
  const chainStatus = tls.verifiedChainLength && tls.verifiedChainLength > 0
    ? `Verified chain length: ${tls.verifiedChainLength}`
    : chainLength > 0
    ? `Chain presented (unverified, length ${chainLength})`
    : 'No chain data'

  const copyToClipboard = (value: string, key: string) => {
    if (!value) return
    navigator.clipboard.writeText(value)
    setCopiedField(key)
    setTimeout(() => setCopiedField(null), 1500)
  }

  return (
    <div className="space-y-3 sm:space-y-4">
      <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-surface-400">
        <Lock className="w-3.5 h-3.5 text-cyan-400" />
        <span>TLS Context · {sourceLabel}</span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        <SummaryCard label="Version" value={tls.version || 'unknown'} />
        <SummaryCard label="Cipher Suite" value={tls.cipherSuite || 'unknown'} />
        <SummaryCard label="SNI" value={tls.serverName || 'none'} />
        <SummaryCard label="ALPN" value={tls.negotiatedProtocol || 'none'} />
        <SummaryCard
          label="mTLS"
          value={tls.mutualTLS === undefined ? 'unknown' : (tls.mutualTLS ? 'client cert presented' : 'no client cert')}
        />
        <SummaryCard label="Source" value={sourceLabel} />
        <SummaryCard label="Chain Status" value={chainStatus} />
      </div>

      <TLSSection
        title="TLS Negotiation"
        subtitle="Handshake parameters captured on the wire"
        icon={Lock}
        color="cyan"
        isExpanded={expandedSection === 'tls'}
        onToggle={() => setExpandedSection(expandedSection === 'tls' ? null : 'tls')}
      >
        <div className="space-y-2">
          <FieldRow label="TLS Version" value={tls.version || 'unknown'} />
          <FieldRow label="Cipher Suite" value={tls.cipherSuite || 'unknown'} />
          <FieldRow label="SNI" value={tls.serverName || 'none'} />
          <FieldRow label="ALPN" value={tls.negotiatedProtocol || 'none'} />
          <FieldRow label="Mutual TLS" value={tls.mutualTLS ? 'yes' : 'no'} />
          <FieldRow label="Chain Validation" value={chainStatus} />
        </div>
      </TLSSection>

      <TLSSection
        title="Client Certificate"
        subtitle={clientCert ? `${clientStatus.label} certificate` : 'No client certificate presented'}
        icon={User}
        color={clientStatus.tone === 'red' ? 'red' : clientStatus.tone === 'yellow' ? 'orange' : 'green'}
        isExpanded={expandedSection === 'client'}
        onToggle={() => setExpandedSection(expandedSection === 'client' ? null : 'client')}
      >
        {clientCert ? (
          <div className="space-y-2">
            <FieldRow label="Subject" value={clientCert.subject} />
            <FieldRow label="Issuer" value={clientCert.issuer} />
            <FieldRow label="Serial Number" value={clientCert.serialNumber} />
            <FieldRow label="Not Before" value={formatDate(clientCert.notBefore)} />
            <FieldRow label="Not After" value={formatDate(clientCert.notAfter)} />
            {clientCert.spiffeId && (
              <FieldRow label="SPIFFE ID (SAN URI)" value={clientCert.spiffeId} />
            )}
            <FieldRow
              label="Thumbprint (SHA-256)"
              value={clientCert.thumbprint || 'unknown'}
              onCopy={() => copyToClipboard(clientCert.thumbprint, 'client-thumbprint')}
              isCopied={copiedField === 'client-thumbprint'}
            />
            {clientChainDisplay.length > 0 && (
              <div className="p-3 rounded-lg bg-surface-900/50">
                <p className="text-xs text-surface-400 mb-2 flex items-center gap-2">
                  <Layers className="w-3.5 h-3.5 text-surface-500" />
                  Certificate Chain
                </p>
                <div className="space-y-1 text-xs text-surface-300">
                  {clientChainDisplay.map((subject, idx) => (
                    <div key={`${subject}-${idx}`} className="flex items-start gap-2">
                      <span className="text-surface-500">{idx + 1}.</span>
                      <span className="break-all">{subject}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="text-xs text-surface-400">
            Client certificates were not presented during the handshake.
          </div>
        )}
      </TLSSection>

      <TLSSection
        title="Server Certificate"
        subtitle={serverCert ? `${serverStatus.label} certificate` : (isOutbound ? 'Server certificate not available' : 'Not captured on inbound TLS')}
        icon={Server}
        color={serverStatus.tone === 'red' ? 'red' : serverStatus.tone === 'yellow' ? 'orange' : 'green'}
        isExpanded={expandedSection === 'server'}
        onToggle={() => setExpandedSection(expandedSection === 'server' ? null : 'server')}
      >
        {serverCert ? (
          <div className="space-y-2">
            <FieldRow label="Subject" value={serverCert.subject} />
            <FieldRow label="Issuer" value={serverCert.issuer} />
            <FieldRow label="Serial Number" value={serverCert.serialNumber} />
            <FieldRow label="Not Before" value={formatDate(serverCert.notBefore)} />
            <FieldRow label="Not After" value={formatDate(serverCert.notAfter)} />
            {serverCert.spiffeId && (
              <FieldRow label="SPIFFE ID (SAN URI)" value={serverCert.spiffeId} />
            )}
            <FieldRow
              label="Thumbprint (SHA-256)"
              value={serverCert.thumbprint || 'unknown'}
              onCopy={() => copyToClipboard(serverCert.thumbprint, 'server-thumbprint')}
              isCopied={copiedField === 'server-thumbprint'}
            />
            {serverChainDisplay.length > 0 && (
              <div className="p-3 rounded-lg bg-surface-900/50">
                <p className="text-xs text-surface-400 mb-2 flex items-center gap-2">
                  <Layers className="w-3.5 h-3.5 text-surface-500" />
                  Certificate Chain
                </p>
                <div className="space-y-1 text-xs text-surface-300">
                  {serverChainDisplay.map((subject, idx) => (
                    <div key={`${subject}-${idx}`} className="flex items-start gap-2">
                      <span className="text-surface-500">{idx + 1}.</span>
                      <span className="break-all">{subject}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="text-xs text-surface-400">
            Server certificate details are not available from server-side TLS capture.
          </div>
        )}
      </TLSSection>

      <TLSSection
        title="Certificate Binding (RFC 8705)"
        subtitle="x5t#S256 ↔ cnf claim match"
        icon={Link2}
        color={bindingInfo.status === 'match' ? 'green' : bindingInfo.status === 'mismatch' ? 'red' : 'orange'}
        isExpanded={expandedSection === 'binding'}
        onToggle={() => setExpandedSection(expandedSection === 'binding' ? null : 'binding')}
      >
        <div className="space-y-3">
          <div className="flex items-start gap-2 text-xs text-surface-300">
            <BindingIcon className={`w-4 h-4 flex-shrink-0 ${bindingConfig.color}`} />
            <span>{bindingConfig.label}</span>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-[11px] text-surface-400">
            <span className="px-2 py-1 rounded bg-surface-900/60 text-surface-200">Client Cert</span>
            <motion.span
              animate={{ opacity: [0.3, 1, 0.3], x: [0, 4, 0] }}
              transition={{ duration: 1.6, repeat: Infinity }}
            >
              →
            </motion.span>
            <span className="px-2 py-1 rounded bg-surface-900/60 text-surface-200">SHA-256</span>
            <motion.span
              animate={{ opacity: [0.3, 1, 0.3], x: [0, 4, 0] }}
              transition={{ duration: 1.6, repeat: Infinity, delay: 0.2 }}
            >
              →
            </motion.span>
            <span className="px-2 py-1 rounded bg-surface-900/60 text-surface-200 flex items-center gap-1">
              <Fingerprint className="w-3 h-3" />
              Thumbprint
            </span>
            <span className="px-2 py-1 rounded bg-surface-900/60 text-surface-200">cnf.x5t#S256</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <FieldRow
              label="Client Cert Thumbprint"
              value={bindingInfo.clientThumbprint || 'unknown'}
              onCopy={() => copyToClipboard(bindingInfo.clientThumbprint || '', 'binding-client')}
              isCopied={copiedField === 'binding-client'}
            />
            <FieldRow
              label="Token cnf.x5t#S256"
              value={bindingInfo.tokenThumbprint || 'missing'}
              onCopy={() => copyToClipboard(bindingInfo.tokenThumbprint || '', 'binding-token')}
              isCopied={copiedField === 'binding-token'}
            />
          </div>

          {bindingInfo.token && (
            <div className="p-2.5 rounded-lg bg-surface-900/50 text-xs text-surface-400">
              Authorization token detected: <span className="text-surface-200 font-mono">{formatShort(bindingInfo.token, 60)}</span>
            </div>
          )}
        </div>
      </TLSSection>
    </div>
  )
}

function SummaryCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="p-2.5 rounded-lg bg-surface-900/40 border border-white/5">
      <p className="text-[10px] uppercase tracking-wide text-surface-500">{label}</p>
      <p className="text-xs sm:text-sm text-surface-200 mt-1 break-words">{value}</p>
    </div>
  )
}

function TLSSection({
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
    orange: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
    cyan: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
    green: 'text-green-400 bg-green-500/10 border-green-500/20',
  }
  const selectedColor = colorClasses[color] || colorClasses.cyan

  return (
    <div className={`rounded-xl border overflow-hidden transition-all ${
      isExpanded ? selectedColor : 'bg-surface-900/30 border-white/5'
    }`}>
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 p-3 sm:p-4 text-left"
      >
        <div className={`w-9 h-9 sm:w-10 sm:h-10 rounded-lg flex items-center justify-center ${
          isExpanded ? selectedColor : 'bg-surface-800'
        }`}>
          <Icon className={`w-4 h-4 sm:w-5 sm:h-5 ${isExpanded ? selectedColor.split(' ')[0] : 'text-surface-400'}`} />
        </div>
        <div className="flex-1 min-w-0">
          <h3 className={`font-medium text-sm sm:text-base ${isExpanded ? 'text-white' : 'text-surface-300'}`}>{title}</h3>
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
  onCopy,
  isCopied,
}: {
  label: string
  value: string
  onCopy?: () => void
  isCopied?: boolean
}) {
  return (
    <div className="flex items-start gap-3 p-3 rounded-lg bg-surface-900/50 hover:bg-surface-800/50 transition-colors group">
      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium text-surface-400">{label}</p>
        <p className="text-sm text-white break-all mt-0.5">{value}</p>
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
