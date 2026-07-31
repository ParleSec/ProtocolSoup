import type { NextConfig } from 'next'

const walletBackendOrigin = process.env.WALLET_BACKEND_ORIGIN || 'http://localhost:8080'
const isStaticExport = process.env.NODE_ENV === 'production'

const nextConfig: NextConfig = {
  ...(isStaticExport ? { output: 'export' } : {}),
  reactStrictMode: true,
  poweredByHeader: false,
  experimental: {
    // TypeScript 7's native compiler does not expose the JS compiler API
    // Next.js uses by default, so it must run the project-local `tsc` CLI
    // instead. See https://nextjs.org/docs/app/api-reference/config/next-config-js/useTypeScriptCli
    useTypeScriptCli: true,
  },
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
