import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = fileURLToPath(new URL('.', import.meta.url))

export default defineConfig({
  plugins: [react()],
  build: {
    // Disable sourcemaps in production for smaller files
    sourcemap: false,
    // Target modern browsers for smaller bundles
    target: 'es2020',
    // Inline small assets
    assetsInlineLimit: 4096,
    // Use esbuild (default, built-in, fast)
    minify: 'esbuild',
    rollupOptions: {
      output: {
        // Better chunk splitting for caching
        manualChunks: {
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          'animation': ['framer-motion'],
          'icons': ['lucide-react'],
        },
        // Smaller chunk names
        chunkFileNames: 'assets/[name]-[hash:8].js',
        entryFileNames: 'assets/[name]-[hash:8].js',
        assetFileNames: 'assets/[name]-[hash:8].[ext]',
      },
    },
    chunkSizeWarningLimit: 500,
  },
  // esbuild options for better minification
  esbuild: {
    drop: ['console', 'debugger'],
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/api': { target: 'http://localhost:8080', changeOrigin: true },
      '/ws': { target: 'ws://localhost:8080', ws: true },
      '/oauth2': { target: 'http://localhost:8080', changeOrigin: true },
      '/oidc': { target: 'http://localhost:8080', changeOrigin: true },
      '/saml': { target: 'http://localhost:8080', changeOrigin: true },
      '/spiffe': { target: 'http://localhost:8080', changeOrigin: true },
      '/scim': { target: 'http://localhost:8080', changeOrigin: true },
      '/ssf': { target: 'http://localhost:8080', changeOrigin: true },
    },
  },
})
