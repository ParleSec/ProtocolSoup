import { NextResponse, type NextRequest } from 'next/server'
import { AGENT_LINK_HEADER, isBackendPath } from '@/lib/agent-discovery'
import {
  MARKDOWN_ROUTE,
  MARKDOWN_TARGET_HEADER,
  prefersMarkdown,
} from '@/lib/markdown-negotiation'

/**
 * Applies the agent-facing behaviour that has to sit in front of every page
 * response: RFC 8288 Link headers pointing at the machine-readable surfaces,
 * and `Accept: text/markdown` content negotiation.
 */

/**
 * Documents that are already machine-readable. They need neither a markdown
 * representation nor a Link header advertising the set they belong to.
 */
const AGENT_DOCUMENTS = new Set([
  '/robots.txt',
  '/llms.txt',
  '/llms-full.txt',
  '/auth.md',
  '/sitemap.xml',
  '/sitemap-index.xml',
])

function isExcluded(pathname: string): boolean {
  return (
    isBackendPath(pathname) ||
    AGENT_DOCUMENTS.has(pathname) ||
    pathname.startsWith('/.well-known') ||
    pathname.startsWith(MARKDOWN_ROUTE) ||
    // Generated images are responses, not documents.
    pathname.endsWith('opengraph-image') ||
    pathname.endsWith('twitter-image')
  )
}

export function proxy(request: NextRequest): NextResponse {
  const { pathname, search } = request.nextUrl

  if (isExcluded(pathname)) {
    return NextResponse.next()
  }

  if (prefersMarkdown(request.headers.get('accept'))) {
    const url = request.nextUrl.clone()
    url.pathname = MARKDOWN_ROUTE
    url.search = ''

    // Overwrites any client-supplied value, so the target cannot be spoofed
    // through this path.
    const headers = new Headers(request.headers)
    headers.set(MARKDOWN_TARGET_HEADER, `${pathname}${search}`)

    return NextResponse.rewrite(url, { request: { headers } })
  }

  const response = NextResponse.next()
  response.headers.set('Link', AGENT_LINK_HEADER)
  // The same URL can answer with HTML or markdown, so caches must key on it.
  response.headers.append('Vary', 'Accept')
  return response
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon\\.svg|manifest\\.json|sw\\.js|icons/).*)',
  ],
}
