import { DOCS_ORIGIN, SITE_ORIGIN, SITEMAP_LASTMOD } from '@/lib/seo'

function escapeXml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

export async function GET() {
  const lastmod = SITEMAP_LASTMOD
  const sitemapUrls: string[] = [
    `${SITE_ORIGIN}/sitemap.xml`,
    `${DOCS_ORIGIN}/sitemap.xml`,
  ]

  const walletSitemap = String(process.env.WALLET_SITEMAP_URL || '').trim()
  if (walletSitemap) {
    sitemapUrls.push(walletSitemap)
  }

  const sitemapEntries = sitemapUrls.flatMap((url) => [
    '  <sitemap>',
    `    <loc>${escapeXml(url)}</loc>`,
    `    <lastmod>${lastmod}</lastmod>`,
    '  </sitemap>',
  ])

  const xml = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ...sitemapEntries,
    '</sitemapindex>',
  ].join('\n')

  return new Response(xml, {
    headers: {
      'Content-Type': 'application/xml; charset=utf-8',
      'Cache-Control': 'public, max-age=86400, s-maxage=86400, stale-while-revalidate=86400',
    },
  })
}

