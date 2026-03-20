import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = fileURLToPath(new URL('.', import.meta.url))

export default defineConfig({
  plugins: [react()],
  build: {
    sourcemap: false,
    target: 'es2020',
    minify: 'esbuild',
    emptyOutDir: true,
    outDir: resolve(__dirname, '../backend/cmd/walletharness/static'),
    rollupOptions: {
      input: resolve(__dirname, 'index.html'),
      output: {
        chunkFileNames: 'assets/[name]-[hash:8].js',
        entryFileNames: 'assets/[name]-[hash:8].js',
        assetFileNames: 'assets/[name]-[hash:8].[ext]',
      },
    },
  },
  server: {
    port: 4174,
    fs: {
      allow: [resolve(__dirname, '..')],
    },
    proxy: {
      '/api': { target: 'http://localhost:8080', changeOrigin: true },
      '/submit': { target: 'http://localhost:8080', changeOrigin: true },
      '/health': { target: 'http://localhost:8080', changeOrigin: true },
    },
  },
})
