import type { Metadata } from 'next'
import { SITE_CONFIG } from '@/config/seo'

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, '')
}

function normalizePath(pathname: string): string {
  if (!pathname) {
    return '/'
  }
  return pathname.startsWith('/') ? pathname : `/${pathname}`
}

export const SITE_ORIGIN = trimTrailingSlash(
  process.env.NEXT_PUBLIC_SITE_URL || SITE_CONFIG.baseUrl,
)

export const DOCS_ORIGIN = trimTrailingSlash(
  process.env.DOCS_SITE_URL || SITE_CONFIG.docsUrl || 'https://docs.protocolsoup.com',
)

export const WALLET_ORIGIN = trimTrailingSlash(
  process.env.WALLET_SITE_URL || SITE_CONFIG.walletUrl || 'https://wallet.protocolsoup.com',
)

export function absoluteUrl(pathname: string): string {
  if (/^https?:\/\//i.test(pathname)) {
    return pathname
  }
  return `${SITE_ORIGIN}${normalizePath(pathname)}`
}

function resolveSitemapDate(input: string | undefined): string {
  if (input) {
    const parsed = new Date(input)
    if (!Number.isNaN(parsed.getTime())) {
      return parsed.toISOString().slice(0, 10)
    }
  }
  return new Date().toISOString().slice(0, 10)
}

export const SITEMAP_LASTMOD = resolveSitemapDate(
  process.env.SITEMAP_LASTMOD || process.env.NEXT_PUBLIC_DEPLOYED_AT,
)

interface CreatePageMetadataInput {
  title: string
  description: string
  path: string
  keywords?: string[]
  type?: 'website' | 'article'
  noIndex?: boolean
  imagePath?: string
  imageAlt?: string
}

export function createPageMetadata({
  title,
  description,
  path,
  keywords,
  type = 'website',
  noIndex = false,
  imagePath = '/opengraph-image',
  imageAlt,
}: CreatePageMetadataInput): Metadata {
  const canonicalUrl = absoluteUrl(path)
  const openGraphImage = absoluteUrl(imagePath)

  return {
    title,
    description,
    keywords,
    alternates: { canonical: canonicalUrl },
    openGraph: {
      type,
      siteName: SITE_CONFIG.name,
      title,
      description,
      url: canonicalUrl,
      locale: SITE_CONFIG.locale,
      images: [
        {
          url: openGraphImage,
          width: 1200,
          height: 630,
          alt: imageAlt || `${title} | ${SITE_CONFIG.name}`,
        },
      ],
    },
    twitter: {
      card: 'summary_large_image',
      title,
      description,
      images: [openGraphImage],
      site: SITE_CONFIG.twitterHandle,
      creator: SITE_CONFIG.twitterHandle,
    },
    robots: noIndex
      ? {
          index: false,
          follow: false,
          googleBot: {
            index: false,
            follow: false,
            'max-image-preview': 'none',
            'max-snippet': -1,
            'max-video-preview': -1,
          },
        }
      : undefined,
  }
}

