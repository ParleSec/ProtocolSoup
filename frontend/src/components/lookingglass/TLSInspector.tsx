import { useMemo } from 'react'
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

  const isOutbound = tls.source === 'outbound'
  const sourceLabel = tls.source === 'outbound'
    ? 'Outbound TLS (mTLS client)'
    : tls.source === 'inbound'
    ? 'Inbound TLS'
    : 'TLS Source Unknown'
  const clientStatus = getCertStatus(clientCert)
  const serverStatus = getCertStatus(serverCert)
  const statusTone = (tone: 'green' | 'yellow' | 'red') =>
    tone === 'green' ? 'text-green-300' : tone === 'red' ? 'text-red-300' : 'text-yellow-300'
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

  const bindingStatus = bindingInfo.status === 'match'
    ? { label: 'Match', tone: 'text-green-300' }
    : bindingInfo.status === 'mismatch'
    ? { label: 'Mismatch', tone: 'text-red-300' }
    : { label: 'Missing data', tone: 'text-yellow-300' }

  return (
    <div className="space-y-3">
      <h4 className="text-xs font-medium text-surface-400 mb-2">TLS (Wire)</h4>

      <InfoBlock title={`Context · ${sourceLabel}`}>
        <KeyValueRow label="Version" value={tls.version || 'unknown'} />
        <KeyValueRow label="Cipher Suite" value={tls.cipherSuite || 'unknown'} />
        <KeyValueRow label="SNI" value={tls.serverName || 'none'} />
        <KeyValueRow label="ALPN" value={tls.negotiatedProtocol || 'none'} />
        <KeyValueRow label="mTLS" value={tls.mutualTLS === undefined ? 'unknown' : (tls.mutualTLS ? 'yes' : 'no')} />
        <KeyValueRow label="Chain Status" value={chainStatus} />
      </InfoBlock>

      <InfoBlock title="Client Certificate">
        {clientCert ? (
          <>
            <KeyValueRow label="Status" value={clientStatus.label} valueClassName={statusTone(clientStatus.tone)} />
            <KeyValueRow label="Subject" value={clientCert.subject} />
            <KeyValueRow label="Issuer" value={clientCert.issuer} />
            <KeyValueRow label="Serial Number" value={clientCert.serialNumber} mono />
            <KeyValueRow label="Not Before" value={formatDate(clientCert.notBefore)} />
            <KeyValueRow label="Not After" value={formatDate(clientCert.notAfter)} />
            {clientCert.spiffeId && (
              <KeyValueRow label="SPIFFE ID (SAN URI)" value={clientCert.spiffeId} />
            )}
            <KeyValueRow label="Thumbprint (SHA-256)" value={clientCert.thumbprint || 'unknown'} mono />
            {clientChainDisplay.length > 0 && <ChainList subjects={clientChainDisplay} />}
          </>
        ) : (
          <KeyValueRow label="Status" value="No client certificate presented" />
        )}
      </InfoBlock>

      <InfoBlock title="Server Certificate">
        {serverCert ? (
          <>
            <KeyValueRow label="Status" value={serverStatus.label} valueClassName={statusTone(serverStatus.tone)} />
            <KeyValueRow label="Subject" value={serverCert.subject} />
            <KeyValueRow label="Issuer" value={serverCert.issuer} />
            <KeyValueRow label="Serial Number" value={serverCert.serialNumber} mono />
            <KeyValueRow label="Not Before" value={formatDate(serverCert.notBefore)} />
            <KeyValueRow label="Not After" value={formatDate(serverCert.notAfter)} />
            {serverCert.spiffeId && (
              <KeyValueRow label="SPIFFE ID (SAN URI)" value={serverCert.spiffeId} />
            )}
            <KeyValueRow label="Thumbprint (SHA-256)" value={serverCert.thumbprint || 'unknown'} mono />
            {serverChainDisplay.length > 0 && <ChainList subjects={serverChainDisplay} />}
          </>
        ) : (
          <KeyValueRow label="Status" value={isOutbound ? 'Server certificate not available' : 'Not captured on inbound TLS'} />
        )}
      </InfoBlock>

      <InfoBlock title="Certificate Binding (RFC 8705)">
        <KeyValueRow label="Status" value={bindingStatus.label} valueClassName={bindingStatus.tone} />
        <KeyValueRow label="Client thumbprint" value={bindingInfo.clientThumbprint || 'unknown'} mono />
        <KeyValueRow label="Token cnf.x5t#S256" value={bindingInfo.tokenThumbprint || 'missing'} mono />
        {bindingInfo.token && (
          <KeyValueRow label="Authorization token" value={formatShort(bindingInfo.token, 60)} mono />
        )}
      </InfoBlock>
    </div>
  )
}

function InfoBlock({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs font-medium text-surface-400 mb-2">{title}</div>
      <div className="rounded-lg bg-surface-950 p-2 text-xs text-surface-400 space-y-1">
        {children}
      </div>
    </div>
  )
}

function KeyValueRow({
  label,
  value,
  mono,
  valueClassName,
}: {
  label: string
  value: string
  mono?: boolean
  valueClassName?: string
}) {
  return (
    <div className="flex flex-wrap gap-1">
      <span className="text-surface-500">{label}:</span>
      <span className={`${mono ? 'font-mono text-[10px]' : ''} ${valueClassName || 'text-surface-300'}`.trim()}>
        {value}
      </span>
    </div>
  )
}

function ChainList({ subjects }: { subjects: string[] }) {
  return (
    <div className="pt-2">
      <div className="text-[10px] uppercase tracking-wide text-surface-500 mb-1">Chain</div>
      <div className="space-y-1 text-[10px] text-surface-300 font-mono">
        {subjects.map((subject, idx) => (
          <div key={`${subject}-${idx}`} className="flex items-start gap-2">
            <span className="text-surface-500">{idx + 1}.</span>
            <span className="break-all">{subject}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
