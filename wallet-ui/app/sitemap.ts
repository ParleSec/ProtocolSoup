import type { MetadataRoute } from 'next'

const WALLET_ORIGIN = (process.env.WALLET_SITE_URL || 'https://wallet.protocolsoup.com').replace(/\/+$/, '')

export const dynamic = 'force-static'
export const revalidate = false

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    {
      url: `${WALLET_ORIGIN}/`,
      lastModified: new Date(),
      changeFrequency: 'weekly',
      priority: 0.9,
    },
    {
      url: `${WALLET_ORIGIN}/llms.txt`,
      lastModified: new Date(),
      changeFrequency: 'weekly',
      priority: 0.8,
    },
  ]
}
