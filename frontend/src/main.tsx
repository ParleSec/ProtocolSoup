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
  
  root.innerHTML = ''

  const wrapper = document.createElement('div')
  wrapper.style.minHeight = '100vh'
  wrapper.style.background = '#020617'
  wrapper.style.display = 'flex'
  wrapper.style.alignItems = 'center'
  wrapper.style.justifyContent = 'center'
  wrapper.style.padding = '1rem'

  const card = document.createElement('div')
  card.style.maxWidth = '400px'
  card.style.width = '100%'
  card.style.background = '#0f172a'
  card.style.border = '1px solid rgba(255,255,255,0.1)'
  card.style.borderRadius = '12px'
  card.style.padding = '24px'
  card.style.textAlign = 'center'

  const icon = document.createElement('div')
  icon.style.fontSize = '2rem'
  icon.style.marginBottom = '1rem'
  icon.textContent = '🍜'

  const title = document.createElement('h1')
  title.style.fontSize = '1.25rem'
  title.style.fontWeight = '600'
  title.style.color = 'white'
  title.style.marginBottom = '0.5rem'
  title.textContent = 'Failed to Load'

  const description = document.createElement('p')
  description.style.color = '#94a3b8'
  description.style.fontSize = '0.875rem'
  description.style.marginBottom = '1.5rem'
  description.textContent = 'The app failed to start. This might be due to a cached version.'

  const details = document.createElement('p')
  details.style.color = '#64748b'
  details.style.fontSize = '0.75rem'
  details.style.marginBottom = '1.5rem'
  details.style.fontFamily = 'monospace'
  details.textContent = message

  const button = document.createElement('button')
  button.style.width = '100%'
  button.style.padding = '12px 16px'
  button.style.background = '#f97316'
  button.style.color = 'white'
  button.style.fontWeight = '500'
  button.style.border = 'none'
  button.style.borderRadius = '8px'
  button.style.cursor = 'pointer'
  button.textContent = 'Clear Cache and Reload'
  button.addEventListener('click', () => {
    void window.clearCacheAndReload()
  })

  card.append(icon, title, description, details, button)
  wrapper.appendChild(card)
  root.appendChild(wrapper)
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
  
  // Mark as mounted before render attempt
  rootElement.setAttribute('data-react-mounted', 'true')
  
  const root = ReactDOM.createRoot(rootElement)
  
  root.render(
    <React.StrictMode>
      <ErrorBoundary>
        <HelmetProvider>
          <BrowserRouter>
            <App />
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
