import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = fileURLToPath(new URL('.', import.meta.url))

export default defineConfig({
  plugins: [react()],
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

