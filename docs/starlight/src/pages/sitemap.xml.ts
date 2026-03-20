import type { APIRoute } from 'astro'
import { getCollection } from 'astro:content'

export const prerender = true

function escapeXml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, '')
}

function normalizeDocsPath(entryId: string): string {
  const normalized = entryId.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '')
  if (!normalized || normalized === 'index') {
    return '/'
  }
  return `/${normalized}/`
}

function resolveLastmodDate(): string {
  const raw = String(
    import.meta.env.DOCS_SITEMAP_LASTMOD ||
      import.meta.env.NEXT_PUBLIC_DEPLOYED_AT ||
      '',
  ).trim()

  if (raw) {
    const parsed = new Date(raw)
    if (!Number.isNaN(parsed.getTime())) {
      return parsed.toISOString().slice(0, 10)
    }
  }

  return new Date().toISOString().slice(0, 10)
}

export const GET: APIRoute = async () => {
  const docsOrigin = trimTrailingSlash(
    String(
      import.meta.env.PUBLIC_DOCS_SITE_URL ||
        import.meta.env.DOCS_SITE_URL ||
        'https://docs.protocolsoup.com',
    ),
  )
  const lastmod = resolveLastmodDate()

  const docsEntries = await getCollection('docs')
  const staticPaths = ['/api/reference/']
  const allPaths = [
    ...docsEntries.map((entry) => normalizeDocsPath(entry.id)),
    ...staticPaths,
  ]

  const uniquePaths = Array.from(new Set(allPaths)).sort()

  const entriesXml = uniquePaths
    .map((path) => {
      const url = `${docsOrigin}${path}`
      return [
        '<url>',
        `  <loc>${escapeXml(url)}</loc>`,
        `  <lastmod>${lastmod}</lastmod>`,
        '  <changefreq>weekly</changefreq>',
        `  <priority>${path === '/' ? '1.0' : '0.7'}</priority>`,
        '</url>',
      ].join('\n')
    })
    .join('\n')

  const xml = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    entriesXml,
    '</urlset>',
  ].join('\n')

  return new Response(xml, {
    headers: {
      'Content-Type': 'application/xml; charset=utf-8',
      'Cache-Control': 'public, max-age=3600, s-maxage=3600, stale-while-revalidate=3600',
    },
  })
}

