import type { NextConfig } from 'next'

const canonicalSiteOrigin = (process.env.NEXT_PUBLIC_SITE_URL || 'https://protocolsoup.com').replace(/\/+$/, '')
const canonicalHost = new URL(canonicalSiteOrigin).host
const wwwHost = canonicalHost.startsWith('www.') ? canonicalHost : `www.${canonicalHost}`

const nextConfig: NextConfig = {
  output: 'standalone',
  reactStrictMode: true,
  poweredByHeader: false,
  async redirects() {
    const redirects: Array<{
      source: string
      has: Array<{ type: 'host'; value: string }>
      destination: string
      permanent: boolean
    }> = []
    if (wwwHost !== canonicalHost) {
      redirects.push({
        source: '/:path*',
        has: [{ type: 'host', value: wwwHost }],
        destination: `${canonicalSiteOrigin}/:path*`,
        permanent: true,
      })
    }
    return redirects
  },
  // Backend and /wallet-harness forwarding lives in src/proxy.ts so upstream
  // origins are read at runtime instead of being frozen into the build.
}

export default nextConfig
