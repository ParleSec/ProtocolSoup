import type { Metadata, Viewport } from 'next'
import '@fontsource/jetbrains-mono/latin-400.css'
import '@fontsource/jetbrains-mono/latin-500.css'
import '@fontsource/jetbrains-mono/latin-600.css'
import '@fontsource/jetbrains-mono/latin-700.css'
import '@fontsource/space-grotesk/latin-400.css'
import '@fontsource/space-grotesk/latin-500.css'
import '@fontsource/space-grotesk/latin-600.css'
import '@fontsource/space-grotesk/latin-700.css'
import '../src/index.css'

const WALLET_ORIGIN = (process.env.WALLET_SITE_URL || 'https://wallet.protocolsoup.com').replace(/\/+$/, '')
const SITE_ORIGIN = 'https://protocolsoup.com'
const TITLE = 'ProtocolSoup Wallet Harness — OID4VCI Issuance & OID4VP Presentation'
const DESCRIPTION =
  'Hosted OID4VCI and OID4VP wallet for ProtocolSoup. Issue and present mdoc and SD-JWT verifiable credentials, complete QR and deeplink handoffs, and exercise HAIP client and key attestation against live issuer and verifier traffic.'
const OG_IMAGE = {
  url: '/opengraph-image.png',
  width: 1200,
  height: 630,
  alt: 'ProtocolSoup Wallet Harness - OID4VCI issuance and OID4VP presentation',
  type: 'image/png' as const,
}

export const metadata: Metadata = {
  metadataBase: new URL(WALLET_ORIGIN),
  title: {
    default: TITLE,
    template: '%s | ProtocolSoup Wallet',
  },
  applicationName: 'ProtocolSoup Wallet Harness',
  description: DESCRIPTION,
  category: 'Technology',
  creator: 'Mason Parle',
  publisher: 'ProtocolSoup',
  authors: [{ name: 'Mason Parle' }],
  referrer: 'origin-when-cross-origin',
  keywords: [
    'oid4vci wallet',
    'oid4vp wallet',
    'openid4vc wallet',
    'verifiable credential wallet',
    'mdoc wallet',
    'mDL wallet',
    'sd-jwt vc wallet',
    'haip wallet',
    'credential presentation',
    'wallet harness',
    'protocol soup wallet',
  ],
  alternates: {
    canonical: '/',
    types: {
      'text/plain': [
        { url: '/llms.txt', title: 'llms.txt' },
        { url: '/llms-full.txt', title: 'llms-full.txt' },
      ],
      'text/markdown': [
        {
          url: '/.well-known/agent-skills/use-wallet-harness/SKILL.md',
          title: 'Agent skill',
        },
      ],
    },
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
  openGraph: {
    type: 'website',
    siteName: 'ProtocolSoup Wallet Harness',
    title: TITLE,
    description: DESCRIPTION,
    url: WALLET_ORIGIN,
    locale: 'en_US',
    images: [OG_IMAGE],
  },
  twitter: {
    card: 'summary_large_image',
    title: TITLE,
    description: DESCRIPTION,
    images: [
      {
        url: '/twitter-image.png',
        width: 1200,
        height: 630,
        alt: OG_IMAGE.alt,
      },
    ],
    site: '@protocolsoup',
    creator: '@protocolsoup',
  },
  manifest: '/manifest.json',
  appleWebApp: {
    capable: true,
    title: 'ProtocolSoup Wallet',
    statusBarStyle: 'black-translucent',
  },
  icons: {
    icon: [
      { url: '/favicon.ico', sizes: '48x48', type: 'image/x-icon' },
      { url: '/favicon.svg', type: 'image/svg+xml' },
      { url: '/icons/icon-192.svg', sizes: '192x192', type: 'image/svg+xml' },
      { url: '/icons/icon-512.svg', sizes: '512x512', type: 'image/svg+xml' },
    ],
    apple: [{ url: '/apple-touch-icon.png', sizes: '180x180', type: 'image/png' }],
  },
}

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  themeColor: '#0a0a0f',
}

const walletSchema = {
  '@context': 'https://schema.org',
  '@type': 'WebApplication',
  '@id': `${WALLET_ORIGIN}#wallet`,
  name: 'ProtocolSoup Wallet Harness',
  url: WALLET_ORIGIN,
  description: DESCRIPTION,
  applicationCategory: 'DeveloperApplication',
  operatingSystem: 'Web Browser',
  inLanguage: 'en-US',
  image: {
    '@type': 'ImageObject',
    url: `${WALLET_ORIGIN}/opengraph-image.png`,
    width: 1200,
    height: 630,
  },
  logo: {
    '@type': 'ImageObject',
    url: `${WALLET_ORIGIN}/icons/icon-512.svg`,
  },
  screenshot: `${WALLET_ORIGIN}/opengraph-image.png`,
  featureList: [
    'OID4VCI credential issuance',
    'OID4VP presentation',
    'mdoc and SD-JWT VC',
    'HAIP client and key attestation',
    'QR and deeplink handoffs',
  ],
  author: {
    '@type': 'Person',
    name: 'Mason Parle',
  },
  publisher: {
    '@type': 'Organization',
    name: 'ProtocolSoup',
    alternateName: 'Protocol Soup',
    url: SITE_ORIGIN,
    logo: {
      '@type': 'ImageObject',
      url: `${SITE_ORIGIN}/icons/icon-512.svg`,
    },
  },
  sameAs: [
    'https://twitter.com/protocolsoup',
    'https://github.com/ParleSec/ProtocolSoup',
  ],
  isPartOf: {
    '@type': 'WebSite',
    name: 'ProtocolSoup',
    alternateName: 'Protocol Soup',
    url: SITE_ORIGIN,
  },
  significantLink: [
    `${WALLET_ORIGIN}/llms.txt`,
    `${WALLET_ORIGIN}/.well-known/agent-skills/use-wallet-harness/SKILL.md`,
  ],
  offers: {
    '@type': 'Offer',
    price: '0',
    priceCurrency: 'USD',
  },
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en">
      <body>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(walletSchema) }}
        />
        <noscript>
          <main>
            <h1>ProtocolSoup Wallet Harness</h1>
            <p>
              Real OID4VCI issuance and OID4VP presentation wallet. This host is
              the holder, not Looking Glass and not an MCP server.
            </p>
            <ul>
              <li>
                <a href="/llms.txt">llms.txt</a> — start here if you are an agent
              </li>
              <li>
                <a href="/.well-known/agent-skills/use-wallet-harness/SKILL.md">
                  Agent skill
                </a>
              </li>
              <li>
                <a href="/.well-known/api-catalog">API catalog</a>
              </li>
              <li>
                <a href="https://docs.protocolsoup.com/deploy/services/wallet/">
                  Runtime docs
                </a>
              </li>
            </ul>
            <p>
              Request <code>Accept: text/markdown</code> on this URL for the
              same recipes without JavaScript.
            </p>
          </main>
        </noscript>
        {children}
      </body>
    </html>
  )
}
