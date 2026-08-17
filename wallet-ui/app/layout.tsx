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
const TITLE = 'Protocol Soup Wallet Harness — OID4VCI Issuance & OID4VP Presentation'
const DESCRIPTION =
  'Hosted OID4VCI and OID4VP wallet for Protocol Soup. Issue and present mdoc and SD-JWT verifiable credentials, complete QR and deeplink handoffs, and exercise HAIP client and key attestation against live issuer and verifier traffic.'

export const metadata: Metadata = {
  metadataBase: new URL(WALLET_ORIGIN),
  title: {
    default: TITLE,
    template: '%s | Protocol Soup Wallet',
  },
  applicationName: 'Protocol Soup Wallet Harness',
  description: DESCRIPTION,
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
  alternates: { canonical: '/' },
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
    siteName: 'Protocol Soup Wallet Harness',
    title: TITLE,
    description: DESCRIPTION,
    url: WALLET_ORIGIN,
    locale: 'en_US',
    images: [
      {
        url: `${SITE_ORIGIN}/opengraph-image`,
        width: 1200,
        height: 630,
        alt: 'Protocol Soup Wallet Harness',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: TITLE,
    description: DESCRIPTION,
    images: [`${SITE_ORIGIN}/opengraph-image`],
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
  name: 'Protocol Soup Wallet Harness',
  url: WALLET_ORIGIN,
  description: DESCRIPTION,
  applicationCategory: 'DeveloperApplication',
  operatingSystem: 'Web Browser',
  isPartOf: {
    '@type': 'WebSite',
    name: 'Protocol Soup',
    url: SITE_ORIGIN,
  },
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
            <h1>Protocol Soup Wallet Harness</h1>
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
