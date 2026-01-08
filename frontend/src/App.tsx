import { Routes, Route } from 'react-router-dom'
import { Suspense, lazy } from 'react'
import { Layout } from './components/common/Layout'

// Lazy load pages for code splitting
const Dashboard = lazy(() => import('./pages/Dashboard').then(m => ({ default: m.Dashboard })))
const Protocols = lazy(() => import('./pages/Protocols').then(m => ({ default: m.Protocols })))
const ProtocolDemo = lazy(() => import('./pages/ProtocolDemo').then(m => ({ default: m.ProtocolDemo })))
const FlowDetail = lazy(() => import('./pages/FlowDetail').then(m => ({ default: m.FlowDetail })))
const LookingGlass = lazy(() => import('./pages/LookingGlass').then(m => ({ default: m.LookingGlass })))
const SSFSandbox = lazy(() => import('./pages/SSFSandbox').then(m => ({ default: m.SSFSandbox })))
const Callback = lazy(() => import('./pages/Callback').then(m => ({ default: m.Callback })))
const NotFound = lazy(() => import('./pages/NotFound').then(m => ({ default: m.NotFound })))

// Loading fallback component
function PageLoader() {
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
