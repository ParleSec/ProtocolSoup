import { Routes, Route } from 'react-router-dom'
import { Layout } from './components/common/Layout'
import { Dashboard } from './pages/Dashboard'
import { Protocols } from './pages/Protocols'
import { ProtocolDemo } from './pages/ProtocolDemo'
import { FlowDetail } from './pages/FlowDetail'
import { LookingGlass } from './pages/LookingGlass'
import { Callback } from './pages/Callback'

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/protocols" element={<Protocols />} />
        <Route path="/protocol/:protocolId" element={<ProtocolDemo />} />
        <Route path="/protocol/:protocolId/flow/:flowId" element={<FlowDetail />} />
        <Route path="/looking-glass" element={<LookingGlass />} />
        <Route path="/looking-glass/:sessionId" element={<LookingGlass />} />
        <Route path="/callback" element={<Callback />} />
      </Routes>
    </Layout>
  )
}

export default App
