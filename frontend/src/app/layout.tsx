import type { Metadata } from 'next'
import { Layout } from '@/components/common/Layout'
import { SITE_CONFIG } from '@/config/seo'
import { SITE_ORIGIN, absoluteUrl } from '@/lib/seo'
import { generateOrganizationSchema, generateWebsiteSchema } from '@/utils/schema'
import '../index.css'

export const metadata: Metadata = {
  metadataBase: new URL(SITE_ORIGIN),
  title: {
    default: `${SITE_CONFIG.name} - ${SITE_CONFIG.tagline}`,
    template: `%s | ${SITE_CONFIG.name}`,
  },
  applicationName: SITE_CONFIG.name,
  description: SITE_CONFIG.tagline,
  alternates: { canonical: '/' },
  category: 'Technology',
  creator: SITE_CONFIG.author,
  publisher: SITE_CONFIG.name,
  referrer: 'origin-when-cross-origin',
  openGraph: {
    type: 'website',
    siteName: SITE_CONFIG.name,
    title: SITE_CONFIG.name,
    description: SITE_CONFIG.tagline,
    url: SITE_ORIGIN,
    locale: SITE_CONFIG.locale,
    images: [
      {
        url: absoluteUrl('/opengraph-image'),
        width: 1200,
        height: 630,
        alt: `${SITE_CONFIG.name} Open Graph`,
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: SITE_CONFIG.name,
    description: SITE_CONFIG.tagline,
    images: [absoluteUrl('/twitter-image')],
    site: SITE_CONFIG.twitterHandle,
    creator: SITE_CONFIG.twitterHandle,
  },
  manifest: '/manifest.json',
  icons: {
    icon: [
      { url: '/favicon.svg', type: 'image/svg+xml' },
      { url: '/icons/icon-192.svg', sizes: '192x192', type: 'image/svg+xml' },
      { url: '/icons/icon-512.svg', sizes: '512x512', type: 'image/svg+xml' },
    ],
    apple: [{ url: '/icons/icon-192.svg', type: 'image/svg+xml' }],
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-image-preview': 'large',
      'max-snippet': -1,
      'max-video-preview': -1,
    },
  },
  verification: {
    google: process.env.NEXT_PUBLIC_GOOGLE_SITE_VERIFICATION || undefined,
  },
}

const baseSchemas = [generateWebsiteSchema(), generateOrganizationSchema()]

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en">
      <body>
        {baseSchemas.map((schema, index) => (
          <script
            key={`base-schema-${index}`}
            type="application/ld+json"
            dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }}
          />
        ))}
        <Layout>{children}</Layout>
      </body>
    </html>
  )
}
