import type { NextConfig } from 'next'

const backendOrigin = process.env.BACKEND_ORIGIN || 'http://localhost:8080'
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
  async rewrites() {
    return [
      { source: '/api/:path*', destination: `${backendOrigin}/api/:path*` },
      { source: '/oauth2/:path*', destination: `${backendOrigin}/oauth2/:path*` },
      { source: '/oidc/:path*', destination: `${backendOrigin}/oidc/:path*` },
      { source: '/oid4vci/:path*', destination: `${backendOrigin}/oid4vci/:path*` },
      { source: '/oid4vp/:path*', destination: `${backendOrigin}/oid4vp/:path*` },
      { source: '/saml/:path*', destination: `${backendOrigin}/saml/:path*` },
      { source: '/spiffe/:path*', destination: `${backendOrigin}/spiffe/:path*` },
      { source: '/scim/:path*', destination: `${backendOrigin}/scim/:path*` },
      { source: '/ssf/:path*', destination: `${backendOrigin}/ssf/:path*` },
    ]
  },
}

export default nextConfig
