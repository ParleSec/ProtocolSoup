import { NextResponse } from 'next/server'

/**
 * Same-origin forwarding to the Go backend and the wallet harness.
 *
 * Upstream origins are read per request rather than from `next.config.ts`
 * rewrites, which `next build` freezes into the image. Published images are
 * then pointed at a deployment's own backend and wallet with runtime env.
 */

/** Forwarded to BACKEND_ORIGIN with the path unchanged. */
const BACKEND_PROXY_PREFIXES = [
  '/api',
  '/agentauth',
  '/mcp',
  '/oauth2',
  '/oidc',
  '/oid4vci',
  '/oid4vp',
  '/saml',
  '/spiffe',
  '/scim',
  '/ssf',
] as const

/** Stripped before forwarding to WALLET_BACKEND_ORIGIN. */
const WALLET_PROXY_PREFIX = '/wallet-harness'

const DEFAULT_BACKEND_ORIGIN = 'http://localhost:8080'

function hasPrefix(pathname: string, prefix: string): boolean {
  return pathname === prefix || pathname.startsWith(`${prefix}/`)
}

function configured(name: string): string {
  return String(process.env[name] || '').trim()
}

function configurationError(variable: string, description: string): NextResponse {
  return NextResponse.json(
    { error: 'upstream_not_configured', error_description: `${variable} ${description}` },
    { status: 502, headers: { 'Cache-Control': 'no-store' } },
  )
}

/**
 * Builds the upstream URL by assigning the pathname rather than resolving it
 * against the origin, so a request path such as `//other.example` cannot
 * change the upstream host.
 */
function upstreamURL(origin: string, pathname: string, search: string): URL | null {
  let target: URL
  try {
    target = new URL(origin)
  } catch {
    return null
  }
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    return null
  }
  target.pathname = `${target.pathname.replace(/\/+$/, '')}${pathname}`
  target.search = search
  target.hash = ''
  return target
}

/**
 * Returns the response for a backend or wallet path, or null when the path is
 * served by the Next.js app.
 */
export function upstreamResponse(pathname: string, search: string): NextResponse | null {
  if (hasPrefix(pathname, WALLET_PROXY_PREFIX)) {
    const origin = configured('WALLET_BACKEND_ORIGIN') || configured('WALLET_SITE_URL')
    if (!origin) {
      return configurationError(
        'WALLET_BACKEND_ORIGIN',
        'is not set. Point it at the wallet harness this deployment uses; Looking Glass OID4VCI and OID4VP wallet steps are unavailable until it is set.',
      )
    }
    const target = upstreamURL(origin, pathname.slice(WALLET_PROXY_PREFIX.length) || '/', search)
    if (!target) {
      return configurationError('WALLET_BACKEND_ORIGIN', 'must be an absolute http(s) URL.')
    }
    return NextResponse.rewrite(target)
  }

  if (BACKEND_PROXY_PREFIXES.some((prefix) => hasPrefix(pathname, prefix))) {
    const target = upstreamURL(configured('BACKEND_ORIGIN') || DEFAULT_BACKEND_ORIGIN, pathname, search)
    if (!target) {
      return configurationError('BACKEND_ORIGIN', 'must be an absolute http(s) URL.')
    }
    return NextResponse.rewrite(target)
  }

  return null
}
