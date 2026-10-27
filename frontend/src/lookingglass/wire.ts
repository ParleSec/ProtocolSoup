/**
 * Normalises a captured HTTP exchange from the backend's snake_case JSON
 * (lookingglass.CapturedExchange) into WireCapturedExchange. Pure, so Looking
 * Glass hooks and server-rendered pages share one implementation.
 */
import type { WireCapturedExchange, WireCertificateInfo } from './types'

export function normalizeWireExchange(raw: unknown): WireCapturedExchange | null {
  if (!raw || typeof raw !== 'object') {
    return null
  }
  const data = raw as Record<string, unknown>
  const request = normalizeWireMessage(data.request)
  const response = normalizeWireMessage(data.response)
  if (!request || !response) {
    return null
  }

  return {
    id: String(data.id || crypto.randomUUID()),
    sessionId: data.session_id ? String(data.session_id) : undefined,
    request,
    response,
    timing: normalizeWireTiming(data.timing),
    tls: normalizeWireTLS(data.tls),
    meta: normalizeWireMeta(data.meta),
  }
}

function normalizeWireMessage(raw: unknown): WireCapturedExchange['request'] | null {
  if (!raw || typeof raw !== 'object') {
    return null
  }
  const data = raw as Record<string, unknown>
  return {
    method: data.method ? String(data.method) : undefined,
    url: data.url ? String(data.url) : undefined,
    host: data.host ? String(data.host) : undefined,
    proto: data.proto ? String(data.proto) : undefined,
    headers: normalizeWireHeaders(data.headers),
    body: normalizeWirePayload(data.body),
    raw: normalizeWirePayload(data.raw),
    status: typeof data.status === 'number' ? data.status : undefined,
    statusText: data.status_text ? String(data.status_text) : undefined,
  }
}

function normalizeWireHeaders(raw: unknown): Record<string, string[]> | undefined {
  if (!raw || typeof raw !== 'object') {
    return undefined
  }
  const headers = raw as Record<string, unknown>
  const normalized: Record<string, string[]> = {}
  for (const [key, value] of Object.entries(headers)) {
    if (Array.isArray(value)) {
      normalized[key] = value.map(item => String(item))
    } else if (value != null) {
      normalized[key] = [String(value)]
    }
  }
  return normalized
}

function normalizeWirePayload(raw: unknown): WireCapturedExchange['request']['body'] | undefined {
  if (!raw || typeof raw !== 'object') {
    return undefined
  }
  const payload = raw as Record<string, unknown>
  const encoding = payload.encoding === 'base64' ? 'base64' : 'utf-8'
  return {
    encoding,
    data: typeof payload.data === 'string' ? payload.data : undefined,
    size: typeof payload.size === 'number' ? payload.size : 0,
    truncated: Boolean(payload.truncated),
    contentType: typeof payload.content_type === 'string' ? payload.content_type : undefined,
  }
}

function normalizeWireTiming(raw: unknown): WireCapturedExchange['timing'] {
  if (!raw || typeof raw !== 'object') {
    return { startUnixMicro: 0, endUnixMicro: 0, durationMicro: 0 }
  }
  const timing = raw as Record<string, unknown>
  return {
    startUnixMicro: Number(timing.start_unix_micro || 0),
    endUnixMicro: Number(timing.end_unix_micro || 0),
    durationMicro: Number(timing.duration_micro || 0),
  }
}

function normalizeWireCertificate(raw: unknown): WireCertificateInfo | undefined {
  if (!raw || typeof raw !== 'object') {
    return undefined
  }
  const cert = raw as Record<string, unknown>
  const subject = cert.subject ? String(cert.subject) : ''
  const issuer = cert.issuer ? String(cert.issuer) : ''
  const thumbprint = cert.thumbprint ? String(cert.thumbprint) : ''
  if (!subject && !issuer && !thumbprint) {
    return undefined
  }
  return {
    subject,
    issuer,
    spiffeId: cert.spiffe_id ? String(cert.spiffe_id) : undefined,
    thumbprint,
    notBefore: cert.not_before ? String(cert.not_before) : '',
    notAfter: cert.not_after ? String(cert.not_after) : '',
    serialNumber: cert.serial_number ? String(cert.serial_number) : '',
  }
}

function normalizeWireCertificateChain(raw: unknown): WireCertificateInfo[] | undefined {
  if (!Array.isArray(raw)) {
    return undefined
  }
  const chain = raw
    .map(item => normalizeWireCertificate(item))
    .filter((item): item is WireCertificateInfo => Boolean(item))
  return chain.length > 0 ? chain : undefined
}

function normalizeWireTLS(raw: unknown): WireCapturedExchange['tls'] | undefined {
  if (!raw || typeof raw !== 'object') {
    return undefined
  }
  const tls = raw as Record<string, unknown>
  return {
    version: tls.version ? String(tls.version) : undefined,
    cipherSuite: tls.cipher_suite ? String(tls.cipher_suite) : undefined,
    serverName: tls.server_name ? String(tls.server_name) : undefined,
    negotiatedProtocol: tls.negotiated_protocol ? String(tls.negotiated_protocol) : undefined,
    peerCertSubjects: Array.isArray(tls.peer_cert_subjects)
      ? tls.peer_cert_subjects.map(item => String(item))
      : undefined,
    clientCert: normalizeWireCertificate(tls.client_cert),
    serverCert: normalizeWireCertificate(tls.server_cert),
    clientChain: normalizeWireCertificateChain(tls.client_chain),
    serverChain: normalizeWireCertificateChain(tls.server_chain),
    mutualTLS: typeof tls.mutual_tls === 'boolean' ? tls.mutual_tls : undefined,
    verifiedChainLength: typeof tls.verified_chain_length === 'number'
      ? tls.verified_chain_length
      : undefined,
    source: tls.source ? String(tls.source) : undefined,
  }
}

function normalizeWireMeta(raw: unknown): WireCapturedExchange['meta'] {
  if (!raw || typeof raw !== 'object') {
    return {
      captureSource: 'unknown',
      headerOrderPreserved: false,
      bodyLimitBytes: 0,
      requestBodyReadBytes: 0,
      responseBodyWrittenBytes: 0,
      rawReconstructed: false,
    }
  }
  const meta = raw as Record<string, unknown>
  return {
    captureSource: String(meta.capture_source || 'middleware'),
    headerOrderPreserved: Boolean(meta.header_order_preserved),
    bodyLimitBytes: Number(meta.body_limit_bytes || 0),
    requestBodyReadBytes: Number(meta.request_body_read_bytes || 0),
    responseBodyWrittenBytes: Number(meta.response_body_written_bytes || 0),
    rawReconstructed: Boolean(meta.raw_reconstructed),
  }
}
