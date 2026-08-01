import TurndownService from 'turndown'
import { isBackendPath } from '@/lib/agent-discovery'
import {
  MARKDOWN_TARGET_HEADER,
  isSafeRenderTarget,
} from '@/lib/markdown-negotiation'

/**
 * Renders the markdown representation of a page for `Accept: text/markdown`
 * (Markdown for Agents).
 *
 * The markdown is derived from the HTML the site actually serves for the same
 * URL rather than from a separately maintained copy, so it cannot drift out of
 * sync with the page an interactive visitor sees.
 */

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

/**
 * The page is fetched back from this process over the loopback interface. In
 * production the public origin terminates on the Go runtime, which would send
 * the request out and back through the internet.
 */
function loopbackOrigin(): string {
  if (process.env.MARKDOWN_RENDER_ORIGIN) {
    return process.env.MARKDOWN_RENDER_ORIGIN.replace(/\/+$/, '')
  }
  return `http://127.0.0.1:${process.env.PORT || '3000'}`
}

/**
 * Elements that carry no text once the page is markdown. Site chrome is not
 * listed: extracting `<main>` already excludes it, and `<header>` is also used
 * for section headings inside the content.
 */
const STRIPPED_ELEMENTS = new Set(['script', 'style', 'noscript', 'template', 'svg'])

function extractMainContent(html: string): string {
  const main = html.match(/<main[^>]*>([\s\S]*)<\/main>/i)
  if (main) {
    return main[1]
  }
  const body = html.match(/<body[^>]*>([\s\S]*)<\/body>/i)
  return body ? body[1] : html
}

function toMarkdown(html: string): string {
  const turndown = new TurndownService({
    headingStyle: 'atx',
    codeBlockStyle: 'fenced',
    bulletListMarker: '-',
  })
  turndown.remove((node) => STRIPPED_ELEMENTS.has(node.nodeName.toLowerCase()))

  return turndown
    .turndown(extractMainContent(html))
    .replace(/\n{3,}/g, '\n\n')
    .trim()
}

export async function GET(request: Request) {
  const target = request.headers.get(MARKDOWN_TARGET_HEADER) ?? '/'

  // proxy.ts never points this route at a backend path, but the route is
  // directly addressable, so the target is re-checked here rather than trusted.
  // Rendering a rewritten upstream path would make this process issue requests
  // to the protocol runtime on a caller's behalf.
  if (!isSafeRenderTarget(target) || isBackendPath(target.split('?')[0])) {
    return new Response('Invalid render target\n', {
      status: 400,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    })
  }

  let upstream: Response
  try {
    upstream = await fetch(`${loopbackOrigin()}${target}`, {
      headers: {
        Accept: 'text/html',
        // Keep server-rendered absolute URLs on the public host.
        'x-forwarded-host': request.headers.get('host') ?? '',
        'x-forwarded-proto': 'https',
      },
      cache: 'no-store',
    })
  } catch {
    return new Response('Unable to render markdown for this page\n', {
      status: 502,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    })
  }

  if (!upstream.ok) {
    return new Response(`No markdown representation available (upstream ${upstream.status})\n`, {
      status: upstream.status,
      headers: { 'Content-Type': 'text/plain; charset=utf-8', Vary: 'Accept' },
    })
  }

  const contentType = upstream.headers.get('content-type') ?? ''
  if (!contentType.includes('text/html')) {
    return new Response('This resource has no markdown representation\n', {
      status: 406,
      headers: { 'Content-Type': 'text/plain; charset=utf-8', Vary: 'Accept' },
    })
  }

  const markdown = `${toMarkdown(await upstream.text())}\n`

  return new Response(markdown, {
    headers: {
      'Content-Type': 'text/markdown; charset=utf-8',
      'Cache-Control': 'public, max-age=300, s-maxage=300',
      Vary: 'Accept',
      'Content-Location': target,
    },
  })
}
