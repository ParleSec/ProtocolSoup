import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = fileURLToPath(new URL('.', import.meta.url))

/**
 * SEO Note: This app uses react-helmet-async for dynamic meta tags.
 * Modern Googlebot renders JavaScript and will see all SEO tags.
 * 
 * For additional SEO improvements, consider:
 * - Using a CDN that supports edge-side rendering (Cloudflare Workers, Vercel Edge)
 * - Implementing server-side rendering with Vite SSR
 * - Using prerender.io or similar service for bot-specific rendering
 */

export default defineConfig({
  plugins: [react()],
  build: {
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          'animation': ['framer-motion'],
        },
      },
    },
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:8080',
        ws: true,
      },
      '/oauth2': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/oidc': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/saml': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/spiffe': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/scim': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/ssf': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
})

