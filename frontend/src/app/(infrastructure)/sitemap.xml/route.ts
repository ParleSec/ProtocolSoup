import { PROTOCOL_CATALOG_DATA } from '@/protocols/presentation/protocol-catalog-data'
import { PAGE_SEO } from '@/config/seo'
import { SITE_ORIGIN, SITEMAP_LASTMOD, absoluteUrl } from '@/lib/seo'

function escapeXml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

function createUrlEntry({
  loc,
  title,
  changefreq,
  priority,
  image,
  lastmod,
}: {
  loc: string
  title: string
  changefreq: 'weekly' | 'monthly'
  priority: number
  image: string
  lastmod: string
}): string {
  return [
    '<url>',
    `  <loc>${escapeXml(loc)}</loc>`,
    `  <xhtml:link rel="alternate" hreflang="x-default" href="${escapeXml(loc)}" />`,
    `  <lastmod>${lastmod}</lastmod>`,
    `  <changefreq>${changefreq}</changefreq>`,
    `  <priority>${priority.toFixed(1)}</priority>`,
    '  <image:image>',
    `    <image:loc>${escapeXml(image)}</image:loc>`,
    `    <image:title>${escapeXml(title)}</image:title>`,
    '  </image:image>',
    '</url>',
  ].join('\n')
}

export async function GET() {
  const siteUrl = SITE_ORIGIN
  const image = absoluteUrl('/opengraph-image')
  const lastmod = SITEMAP_LASTMOD

  const entries: string[] = []
  const staticRoutes: Array<{ path: string; changefreq: 'weekly' | 'monthly'; priority: number; title: string }> = [
    { path: '', changefreq: 'weekly', priority: 1.0, title: PAGE_SEO['/'].title },
    { path: '/protocols', changefreq: 'weekly', priority: 0.9, title: PAGE_SEO['/protocols'].title },
    { path: '/looking-glass', changefreq: 'weekly', priority: 0.9, title: PAGE_SEO['/looking-glass'].title },
    { path: '/ssf-sandbox', changefreq: 'weekly', priority: 0.9, title: PAGE_SEO['/ssf-sandbox'].title },
  ]

  for (const route of staticRoutes) {
    entries.push(
      createUrlEntry({
        loc: `${siteUrl}${route.path}`,
        title: route.title,
        changefreq: route.changefreq,
        priority: route.priority,
        image,
        lastmod,
      }),
    )
  }

  for (const protocol of PROTOCOL_CATALOG_DATA) {
    entries.push(
      createUrlEntry({
        loc: `${siteUrl}/protocol/${protocol.id}`,
        title: PAGE_SEO[`/protocol/${protocol.id}`]?.title || `${protocol.name} Tutorial`,
        changefreq: 'monthly',
        priority: 0.8,
        image,
        lastmod,
      }),
    )
    for (const flow of protocol.flows) {
      entries.push(
        createUrlEntry({
          loc: `${siteUrl}/protocol/${protocol.id}/flow/${flow.id}`,
          title: `${flow.name} - ${protocol.name} Flow Guide`,
          changefreq: 'monthly',
          priority: 0.7,
          image,
          lastmod,
        }),
      )
    }
  }

  const xml = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"',
    '        xmlns:image="http://www.google.com/schemas/sitemap-image/1.1"',
    '        xmlns:xhtml="http://www.w3.org/1999/xhtml"',
    '        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
    '        xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9',
    '        http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd',
    '        http://www.google.com/schemas/sitemap-image/1.1',
    '        http://www.google.com/schemas/sitemap-image/1.1/sitemap-image.xsd">',
    ...entries,
    '</urlset>',
  ].join('\n')

  return new Response(xml, {
    headers: {
      'Content-Type': 'application/xml; charset=utf-8',
      'Cache-Control': 'public, max-age=86400, s-maxage=86400, stale-while-revalidate=86400',
    },
  })
}

