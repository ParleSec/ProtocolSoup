import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { HelmetProvider } from 'react-helmet-async'
import App from './App'
import { ErrorBoundary } from './components/common/ErrorBoundary'
import './index.css'

// Global error handler for uncaught errors
window.addEventListener('error', (event) => {
  console.error('Global error:', event.error)
  const root = document.getElementById('root')
  if (root && !root.querySelector('[data-react-mounted]')) {
    showFallbackError(event.error?.message || 'Unknown error')
  }
})

// Handle unhandled promise rejections
window.addEventListener('unhandledrejection', (event) => {
  console.error('Unhandled rejection:', event.reason)
})

function showFallbackError(message: string) {
  const root = document.getElementById('root')
  if (!root) return
  
  root.innerHTML = `
    <div style="min-height: 100vh; background: #020617; display: flex; align-items: center; justify-content: center; padding: 1rem;">
      <div style="max-width: 400px; width: 100%; background: #0f172a; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 24px; text-align: center;">
        <div style="font-size: 2rem; margin-bottom: 1rem;">🍜</div>
        <h1 style="font-size: 1.25rem; font-weight: 600; color: white; margin-bottom: 0.5rem;">Failed to Load</h1>
        <p style="color: #94a3b8; font-size: 0.875rem; margin-bottom: 1.5rem;">The app failed to start. This might be due to a cached version.</p>
        <p style="color: #64748b; font-size: 0.75rem; margin-bottom: 1.5rem; font-family: monospace;">${message}</p>
        <button onclick="clearCacheAndReload()" style="width: 100%; padding: 12px 16px; background: #f97316; color: white; font-weight: 500; border: none; border-radius: 8px; cursor: pointer;">Clear Cache and Reload</button>
      </div>
    </div>
  `
}

// Make clearCacheAndReload available globally
declare global {
  interface Window {
    clearCacheAndReload: () => Promise<void>
  }
}

window.clearCacheAndReload = async () => {
  try {
    if ('serviceWorker' in navigator) {
      const registrations = await navigator.serviceWorker.getRegistrations()
      await Promise.all(registrations.map(r => r.unregister()))
    }
    if ('caches' in window) {
      const names = await caches.keys()
      await Promise.all(names.map(name => caches.delete(name)))
    }
    localStorage.clear()
    sessionStorage.clear()
    window.location.href = window.location.origin + '?cache_bust=' + Date.now()
  } catch (e) {
    console.error('Failed to clear cache:', e)
    window.location.reload()
  }
}

// Render the app
try {
  const rootElement = document.getElementById('root')
  if (!rootElement) throw new Error('Root element not found')
  
  const root = ReactDOM.createRoot(rootElement)
  
  root.render(
    <React.StrictMode>
      <ErrorBoundary>
        <HelmetProvider>
          <BrowserRouter>
            <div data-react-mounted="true">
              <App />
            </div>
          </BrowserRouter>
        </HelmetProvider>
      </ErrorBoundary>
    </React.StrictMode>,
  )
} catch (error) {
  console.error('Failed to render app:', error)
  showFallbackError((error as Error)?.message || 'Failed to initialize app')
}

// Signal to pre-renderer that the page is ready for capture
document.dispatchEvent(new Event('render-ready'))
