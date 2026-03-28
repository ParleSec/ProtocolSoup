import type { NextConfig } from 'next'

const walletBackendOrigin = process.env.WALLET_BACKEND_ORIGIN || 'http://localhost:8080'
const isStaticExport = process.env.NODE_ENV === 'production'

const nextConfig: NextConfig = {
  ...(isStaticExport ? { output: 'export' } : {}),
  reactStrictMode: true,
  poweredByHeader: false,
  ...(!isStaticExport
    ? {
        async rewrites() {
          return [
            { source: '/api/:path*', destination: `${walletBackendOrigin}/api/:path*` },
            { source: '/submit', destination: `${walletBackendOrigin}/submit` },
            { source: '/health', destination: `${walletBackendOrigin}/health` },
          ]
        },
      }
    : {}),
}

export default nextConfig
