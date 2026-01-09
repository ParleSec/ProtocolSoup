import { Routes, Route } from 'react-router-dom'
import { Suspense, lazy, useState, useEffect } from 'react'
import { Layout } from './components/common/Layout'

// Retry wrapper for lazy imports - handles chunk loading failures
function lazyWithRetry<T extends React.ComponentType<unknown>>(
  importFn: () => Promise<{ default: T }>,
  retries = 2
): React.LazyExoticComponent<T> {
  return lazy(async () => {
    for (let i = 0; i <= retries; i++) {
      try {
        return await importFn()
      } catch (error) {
        if (i === retries) {
          // On final failure, return an error component
          console.error('Failed to load chunk after retries:', error)
          return {
            default: (() => <ChunkLoadError />) as unknown as T
          }
        }
        // Wait before retry
        await new Promise(r => setTimeout(r, 1000 * (i + 1)))
      }
    }
    return { default: (() => <ChunkLoadError />) as unknown as T }
  })
}

// Lazy load pages with retry logic
const Dashboard = lazyWithRetry(() => import('./pages/Dashboard').then(m => ({ default: m.Dashboard })))
const Protocols = lazyWithRetry(() => import('./pages/Protocols').then(m => ({ default: m.Protocols })))
const ProtocolDemo = lazyWithRetry(() => import('./pages/ProtocolDemo').then(m => ({ default: m.ProtocolDemo })))
const FlowDetail = lazyWithRetry(() => import('./pages/FlowDetail').then(m => ({ default: m.FlowDetail })))
const LookingGlass = lazyWithRetry(() => import('./pages/LookingGlass').then(m => ({ default: m.LookingGlass })))
const SSFSandbox = lazyWithRetry(() => import('./pages/SSFSandbox').then(m => ({ default: m.SSFSandbox })))
const Callback = lazyWithRetry(() => import('./pages/Callback').then(m => ({ default: m.Callback })))
const NotFound = lazyWithRetry(() => import('./pages/NotFound').then(m => ({ default: m.NotFound })))

// Error component for failed chunk loads
function ChunkLoadError() {
  const handleClearAndReload = async () => {
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
      window.location.href = window.location.origin + '?cache_bust=' + Date.now()
    } catch {
      window.location.reload()
    }
  }

  return (
    <div className="flex flex-col items-center justify-center min-h-[50vh] text-center px-4">
      <div className="text-4xl mb-4">⚠️</div>
      <h2 className="text-lg font-semibold text-white mb-2">Failed to Load Page</h2>
      <p className="text-surface-400 text-sm mb-6 max-w-sm">
        This might be due to a network issue or cached version mismatch.
      </p>
      <button
        onClick={handleClearAndReload}
        className="px-4 py-2 bg-amber-500 hover:bg-amber-600 text-white font-medium rounded-lg transition-colors"
      >
        Clear Cache & Reload
      </button>
    </div>
  )
}

// Loading fallback component with timeout
function PageLoader() {
  const [showTimeout, setShowTimeout] = useState(false)

  useEffect(() => {
    const timer = setTimeout(() => setShowTimeout(true), 10000) // 10 second timeout
    return () => clearTimeout(timer)
  }, [])

  if (showTimeout) {
    return <ChunkLoadError />
  }

  return (
    <div className="flex items-center justify-center min-h-[50vh]">
      <div className="w-8 h-8 border-2 border-amber-400 border-t-transparent rounded-full animate-spin" />
    </div>
  )
}

function App() {
  return (
    <Layout>
      <Suspense fallback={<PageLoader />}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/protocols" element={<Protocols />} />
          <Route path="/protocol/:protocolId" element={<ProtocolDemo />} />
          <Route path="/protocol/:protocolId/flow/:flowId" element={<FlowDetail />} />
          <Route path="/looking-glass" element={<LookingGlass />} />
          <Route path="/looking-glass/:sessionId" element={<LookingGlass />} />
          <Route path="/ssf-sandbox" element={<SSFSandbox />} />
          <Route path="/callback" element={<Callback />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Suspense>
    </Layout>
  )
}

export default App
