/**
 * Proactive content negotiation for `Accept: text/markdown`
 * (Markdown for Agents). HTML stays the default: markdown is only served when
 * a client asks for it explicitly and ranks it at least as highly as HTML.
 */

export const MARKDOWN_MEDIA_TYPE = 'text/markdown'
/**
 * Internal render endpoint. It must not start with an underscore: Next treats
 * such folders as private and excludes them from routing.
 */
export const MARKDOWN_ROUTE = '/agent/markdown'

/**
 * The path to render is handed to the route on a request header rather than a
 * query parameter: after a rewrite the route handler still sees the original
 * request URL, so a query string added during the rewrite would be lost.
 */
export const MARKDOWN_TARGET_HEADER = 'x-markdown-target'

interface AcceptEntry {
  type: string
  quality: number
}

function parseAccept(header: string): AcceptEntry[] {
  return header
    .split(',')
    .map((part) => {
      const [rawType, ...parameters] = part.split(';')
      const type = rawType.trim().toLowerCase()
      if (!type) {
        return null
      }

      // RFC 9110 Section 12.4.2: a weight outside 0..1 or an unparseable one
      // leaves the default of 1.
      let quality = 1
      for (const parameter of parameters) {
        const [name, value] = parameter.split('=')
        if (name?.trim().toLowerCase() !== 'q') {
          continue
        }
        const parsed = Number.parseFloat(value ?? '')
        if (Number.isFinite(parsed) && parsed >= 0 && parsed <= 1) {
          quality = parsed
        }
      }

      return { type, quality }
    })
    .filter((entry): entry is AcceptEntry => entry !== null)
}

function qualityOf(entries: AcceptEntry[], candidates: string[]): number {
  let best = 0
  for (const entry of entries) {
    if (candidates.includes(entry.type) && entry.quality > best) {
      best = entry.quality
    }
  }
  return best
}

/**
 * Browsers never list `text/markdown`, so the trailing catch-all wildcard in a
 * browser Accept header must not select markdown. Only an explicit
 * `text/markdown` counts for markdown, while HTML may be matched by wildcards.
 */
export function prefersMarkdown(acceptHeader: string | null | undefined): boolean {
  if (!acceptHeader) {
    return false
  }

  const entries = parseAccept(acceptHeader)
  const markdown = qualityOf(entries, [MARKDOWN_MEDIA_TYPE, 'text/x-markdown'])
  if (markdown <= 0) {
    return false
  }

  const html = qualityOf(entries, ['text/html', 'application/xhtml+xml', 'text/*', '*/*'])
  return markdown >= html
}

/**
 * Guards the internal render target. The value is set by middleware from the
 * incoming pathname, but the route is directly addressable, so it is validated
 * before being used to build a fetch URL.
 */
export function isSafeRenderTarget(target: string): boolean {
  return (
    target.startsWith('/') &&
    !target.startsWith('//') &&
    !target.startsWith('/\\') &&
    !target.includes('\\') &&
    !target.includes('..')
  )
}
