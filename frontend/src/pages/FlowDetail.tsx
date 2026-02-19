import { useEffect, useState, useMemo } from 'react'
import { useParams, Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  ArrowLeft, Eye, ChevronDown, ChevronRight,
  Lock, Key, AlertTriangle, Copy, Check,
  Code, ExternalLink, Loader2, ArrowRight,
  Fingerprint, Server, Globe, FileKey, Shield, Users, Radio
} from 'lucide-react'
import { TokenInspector } from '../components/lookingglass/TokenInspector'
import { FlowDiagram } from '../components/lookingglass/FlowDiagram'
import { useProtocolFlows, FlowStep } from '../protocols'
import { SEO } from '../components/common/SEO'
import { getFlowSEO } from '../config/seo'
import { generateFlowPageSchema } from '../utils/schema'
import { SITE_CONFIG } from '../config/seo'
import { CODE_EXAMPLES } from '../protocols/examples'

const FLOW_ALIASES: Record<string, Record<string, string>> = {
  oidc: { hybrid: 'oidc_hybrid', userinfo: 'oidc_userinfo', discovery: 'oidc_discovery' },
  scim: { 'group-management': 'group-membership', 'filter-queries': 'user-discovery' },
}

export function FlowDetail() {
  const { protocolId, flowId } = useParams()
  const [activeStep, setActiveStep] = useState<number>(-1)
  const [token, setToken] = useState<string>('')
  const [copied, setCopied] = useState(false)
  const [showCode, setShowCode] = useState(false)

  const { flows, loading, error } = useProtocolFlows(protocolId)

  const mappedFlowId = useMemo(() => {
    if (!flowId) return ''
    const normalized = flowId.replace(/-/g, '_')
    // Check alias map first
    const aliased = protocolId ? FLOW_ALIASES[protocolId]?.[flowId] : undefined
    const match = flows.find(f =>
      f.id === flowId ||
      f.id === normalized ||
      f.id.replace(/_/g, '-') === flowId ||
      (aliased && f.id === aliased)
    )
    return match?.id || aliased || normalized || flowId
  }, [flowId, flows, protocolId])

  const flow = useMemo(() => {
    if (!mappedFlowId) return null
    const apiFlow = flows.find(f => f.id === mappedFlowId)
    if (!apiFlow) return null
    return {
      title: apiFlow.name,
      description: apiFlow.description,
      steps: apiFlow.steps,
    }
  }, [flows, mappedFlowId])

  useEffect(() => {
    setActiveStep(-1)
  }, [flowId])

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[50vh]">
        <Loader2 className="w-6 h-6 text-surface-400 animate-spin" />
      </div>
    )
  }

  if (error) {
    return (
      <>
        <SEO title="Flow Data Unavailable" noIndex={true} />
        <div className="text-center py-20">
          <h1 className="text-xl font-semibold text-white mb-3">Flow Data Unavailable</h1>
          <p className="text-sm text-surface-400 mb-6">{error.message}</p>
          <Link to={`/protocol/${protocolId}`} className="text-cyan-400 hover:underline">
            Back to {getProtocolName(protocolId)}
          </Link>
        </div>
      </>
    )
  }

  const copyCode = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const codeExample = CODE_EXAMPLES[mappedFlowId] || CODE_EXAMPLES['_default']
  const getCodeExample = () => codeExample?.code || ''

  // Get flow badges — keyed by actual backend flow IDs
  const getBadges = () => {
    const badges = []
    if (mappedFlowId.includes('pkce')) {
      badges.push({ label: 'PKCE Protected', color: 'green', icon: Lock })
    }
    if (mappedFlowId === 'authorization_code') {
      badges.push({ label: 'Server-side', color: 'yellow', icon: Key })
    }
    if (mappedFlowId === 'client_credentials') {
      badges.push({ label: 'Machine-to-Machine', color: 'blue', icon: Server })
    }
    if (protocolId === 'oidc') {
      badges.push({ label: 'ID Token', color: 'purple', icon: Fingerprint })
    }
    // SAML badges — backend IDs: sp_initiated_sso, idp_initiated_sso, single_logout, metadata
    if (protocolId === 'saml') {
      badges.push({ label: 'XML-Based', color: 'cyan', icon: FileKey })
    }
    if (mappedFlowId === 'sp_initiated_sso' || mappedFlowId === 'idp_initiated_sso') {
      badges.push({ label: 'SSO', color: 'green', icon: Shield })
    }
    if (mappedFlowId === 'single_logout') {
      badges.push({ label: 'Federated Logout', color: 'yellow', icon: Globe })
    }
    // SPIFFE/SPIRE badges
    if (mappedFlowId === 'x509-svid-issuance') {
      badges.push({ label: 'X.509 Certificate', color: 'green', icon: Shield })
      badges.push({ label: 'Workload API', color: 'cyan', icon: Server })
    }
    if (mappedFlowId === 'jwt-svid-issuance') {
      badges.push({ label: 'JWT Token', color: 'purple', icon: Key })
      badges.push({ label: 'Short-Lived', color: 'yellow', icon: Lock })
    }
    if (mappedFlowId === 'mtls-handshake') {
      badges.push({ label: 'Mutual TLS', color: 'green', icon: Lock })
      badges.push({ label: 'Zero Trust', color: 'blue', icon: Shield })
    }
    if (mappedFlowId === 'certificate-rotation') {
      badges.push({ label: 'Auto-Rotation', color: 'cyan', icon: Shield })
      badges.push({ label: 'Zero Downtime', color: 'green', icon: Lock })
    }
    // SCIM 2.0 badges — backend IDs: user-lifecycle, group-membership, user-discovery, schema-discovery, bulk-operations
    if (protocolId === 'scim') {
      badges.push({ label: 'Provisioning', color: 'purple', icon: Users })
    }
    if (mappedFlowId === 'user-lifecycle') {
      badges.push({ label: 'User CRUD', color: 'blue', icon: Server })
      badges.push({ label: 'IdP Integration', color: 'cyan', icon: Globe })
    }
    if (mappedFlowId === 'group-membership') {
      badges.push({ label: 'Group Sync', color: 'green', icon: Users })
    }
    if (mappedFlowId === 'user-discovery') {
      badges.push({ label: 'RFC 7644', color: 'yellow', icon: Code })
    }
    if (mappedFlowId === 'schema-discovery') {
      badges.push({ label: 'Auto-Config', color: 'cyan', icon: Server })
    }
    if (mappedFlowId === 'bulk-operations') {
      badges.push({ label: 'Batch Processing', color: 'blue', icon: Server })
    }
    // SSF badges — backend IDs use dashes: ssf-stream-configuration, caep-session-revoked, etc.
    if (protocolId === 'ssf') {
      badges.push({ label: 'Security Events', color: 'amber', icon: Radio })
    }
    if (mappedFlowId === 'ssf-stream-configuration') {
      badges.push({ label: 'Stream Setup', color: 'blue', icon: Server })
    }
    if (mappedFlowId === 'ssf-push-delivery') {
      badges.push({ label: 'Real-time Push', color: 'green', icon: Server })
      badges.push({ label: 'RFC 8935', color: 'cyan', icon: Code })
    }
    if (mappedFlowId === 'ssf-poll-delivery') {
      badges.push({ label: 'Poll-based', color: 'purple', icon: Server })
      badges.push({ label: 'RFC 8936', color: 'cyan', icon: Code })
    }
    if (mappedFlowId.includes('caep')) {
      badges.push({ label: 'CAEP', color: 'blue', icon: Shield })
      badges.push({ label: 'Continuous Eval', color: 'green', icon: Lock })
    }
    if (mappedFlowId.includes('risc')) {
      badges.push({ label: 'RISC', color: 'amber', icon: AlertTriangle })
      badges.push({ label: 'High Severity', color: 'purple', icon: Shield })
    }
    if (mappedFlowId === 'risc-credential-compromise') {
      badges.push({ label: 'CRITICAL', color: 'purple', icon: AlertTriangle })
    }
    return badges
  }

  function getProtocolName(id: string | undefined) {
    switch (id) {
      case 'oauth2': return 'OAuth 2.0'
      case 'oidc': return 'OpenID Connect'
      case 'saml': return 'SAML 2.0'
      case 'spiffe': return 'SPIFFE/SPIRE'
      case 'scim': return 'SCIM 2.0'
      case 'ssf': return 'Shared Signals (SSF)'
      default: return id || 'Protocol'
    }
  }

  if (!flow) {
    return (
      <>
        <SEO title="Flow Not Found" noIndex={true} />
        <div className="text-center py-20">
          <h1 className="text-xl font-semibold text-white mb-4">Flow Not Found</h1>
          <Link to={`/protocol/${protocolId}`} className="text-cyan-400 hover:underline">
            Back to {getProtocolName(protocolId)}
          </Link>
        </div>
      </>
    )
  }

  const badges = getBadges()

  // Generate SEO data
  const protocolName = getProtocolName(protocolId)
  const seoData = getFlowSEO(protocolId || '', flowId || '', flow.title)
  const structuredData = generateFlowPageSchema(
    protocolId || '',
    protocolName,
    flow.title,
    flow.description,
    `${SITE_CONFIG.baseUrl}/protocol/${protocolId}/flow/${flowId}`,
    flow.steps.map(s => ({ name: s.name, description: s.description }))
  )

  return (
    <>
      <SEO
        title={seoData.title}
        description={seoData.description}
        canonical={`/protocol/${protocolId}/flow/${flowId}`}
        ogType="article"
        keywords={seoData.keywords}
        structuredData={structuredData}
      />
      <div className="max-w-4xl mx-auto space-y-4 sm:space-y-6 px-1 sm:px-0">
      {/* Breadcrumb & Title */}
      <header>
        {/* Mobile breadcrumb - simplified */}
        <nav className="sm:hidden text-xs text-surface-400 mb-3">
          <Link to="/protocols" className="hover:text-white transition-colors">Protocols</Link>
          <span className="mx-1.5">›</span>
          <Link to={`/protocol/${protocolId}`} className="hover:text-white transition-colors">
            {getProtocolName(protocolId)}
          </Link>
        </nav>
        
        {/* Desktop breadcrumb - full */}
        <div className="hidden sm:flex items-center gap-2 text-sm text-surface-400 mb-2">
          <Link to="/protocols" className="hover:text-white transition-colors">Protocols</Link>
          <ChevronRight className="w-4 h-4" />
          <Link to={`/protocol/${protocolId}`} className="hover:text-white transition-colors">
            {getProtocolName(protocolId)}
          </Link>
          <ChevronRight className="w-4 h-4" />
          <span className="text-surface-300">{flow.title}</span>
        </div>
        
        {/* Mobile layout - stacked */}
        <div className="flex flex-col gap-3 sm:hidden">
          <div>
            <h1 className="text-xl font-semibold text-white mb-1.5">{flow.title}</h1>
            <p className="text-sm text-surface-400">{flow.description}</p>
          </div>
          
          <Link
            to={protocolId === 'ssf' ? '/ssf-sandbox' : '/looking-glass'}
            className={`inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-gradient-to-r ${
              protocolId === 'ssf' 
                ? 'from-amber-500/20 to-orange-500/20 border-amber-500/30 text-amber-400 hover:from-amber-500/30 hover:to-orange-500/30' 
                : 'from-cyan-500/20 to-purple-500/20 border-cyan-500/30 text-cyan-400 hover:from-cyan-500/30 hover:to-purple-500/30'
            } border text-sm font-medium transition-all w-full`}
          >
            {protocolId === 'ssf' ? <Radio className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            {protocolId === 'ssf' ? 'Try in SSF Sandbox' : 'Try in Looking Glass'}
          </Link>
        </div>
        
        {/* Desktop layout - side by side */}
        <div className="hidden sm:flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold text-white mb-2">{flow.title}</h1>
            <p className="text-surface-400">{flow.description}</p>
          </div>
          
          <Link
            to={protocolId === 'ssf' ? '/ssf-sandbox' : '/looking-glass'}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r ${
              protocolId === 'ssf' 
                ? 'from-amber-500/20 to-orange-500/20 border-amber-500/30 text-amber-400 hover:from-amber-500/30 hover:to-orange-500/30' 
                : 'from-cyan-500/20 to-purple-500/20 border-cyan-500/30 text-cyan-400 hover:from-cyan-500/30 hover:to-purple-500/30'
            } border text-sm font-medium transition-all flex-shrink-0`}
          >
            {protocolId === 'ssf' ? <Radio className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            {protocolId === 'ssf' ? 'Try in SSF Sandbox' : 'Try in Looking Glass'}
          </Link>
        </div>

        {/* Badges */}
        {badges.length > 0 && (
          <div className="flex flex-wrap gap-1.5 sm:gap-2 mt-3 sm:mt-4">
            {badges.map(badge => (
              <span 
                key={badge.label}
                className={`inline-flex items-center gap-1 sm:gap-1.5 px-2 sm:px-2.5 py-0.5 sm:py-1 rounded-full text-[10px] sm:text-xs font-medium border
                  ${badge.color === 'green' ? 'bg-green-500/10 text-green-400 border-green-500/20' : ''}
                  ${badge.color === 'yellow' ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20' : ''}
                  ${badge.color === 'blue' ? 'bg-blue-500/10 text-blue-400 border-blue-500/20' : ''}
                  ${badge.color === 'purple' ? 'bg-purple-500/10 text-purple-400 border-purple-500/20' : ''}
                  ${badge.color === 'cyan' ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20' : ''}
                  ${badge.color === 'amber' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' : ''}
                `}
              >
                <badge.icon className="w-2.5 h-2.5 sm:w-3 sm:h-3" />
                {badge.label}
              </span>
            ))}
          </div>
        )}
      </header>

      {/* Sequence Diagram */}
      <section className="rounded-xl border border-white/10 bg-surface-900/30 overflow-hidden">
        <div className="px-3 sm:px-5 py-3 sm:py-4 border-b border-white/10">
          <h2 className="font-medium text-white text-sm sm:text-base">Sequence Diagram</h2>
          <p className="text-xs sm:text-sm text-surface-400 mt-0.5 sm:mt-1">Click any step for details</p>
        </div>
        <div className="p-3 sm:p-5">
          <FlowDiagram 
            steps={flow.steps}
            activeStep={activeStep}
            onStepClick={setActiveStep}
          />
        </div>
      </section>

      {/* Code Example */}
      <section className="rounded-xl border border-white/10 bg-surface-900/30 overflow-hidden">
        <button
          onClick={() => setShowCode(!showCode)}
          className="w-full px-3 sm:px-5 py-3 sm:py-4 flex items-center justify-between hover:bg-white/[0.02] transition-colors"
        >
          <h2 className="font-medium text-white flex items-center gap-2 text-sm sm:text-base">
            <Code className="w-4 h-4 text-surface-400" />
            Implementation Example
            {codeExample?.label && (
              <span className="text-xs font-normal text-surface-400">— {codeExample.label}</span>
            )}
          </h2>
          <ChevronDown className={`w-4 h-4 text-surface-400 transition-transform ${showCode ? 'rotate-180' : ''}`} />
        </button>

        <AnimatePresence>
          {showCode && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="overflow-hidden"
            >
              <div className="relative border-t border-white/10">
                <button
                  onClick={() => copyCode(getCodeExample())}
                  className="absolute top-2 right-2 sm:top-3 sm:right-3 flex items-center gap-1.5 px-2 sm:px-2.5 py-1 sm:py-1.5 rounded-lg text-xs text-surface-400 hover:text-white hover:bg-white/10 transition-colors"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copied ? 'Copied!' : 'Copy'}
                </button>
                <pre className="p-3 sm:p-5 overflow-x-auto text-xs sm:text-sm">
                  <code className="text-surface-300 font-mono leading-relaxed">{getCodeExample()}</code>
                </pre>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </section>

      {/* Step-by-Step Breakdown */}
      <section className="rounded-xl border border-white/10 bg-surface-900/30 overflow-hidden">
        <div className="px-3 sm:px-5 py-3 sm:py-4 border-b border-white/10">
          <h2 className="font-medium text-white text-sm sm:text-base">Step-by-Step Breakdown</h2>
        </div>
        <div className="p-3 sm:p-5">
          <div className="space-y-2 sm:space-y-3">
            {flow.steps.map((step, index) => (
              <StepRow
                key={step.order}
                step={step}
                index={index}
                isActive={activeStep === step.order}
                isLast={index === flow.steps.length - 1}
                onClick={() => setActiveStep(activeStep === step.order ? -1 : step.order)}
              />
            ))}
          </div>
        </div>
      </section>

      {/* Token Inspector */}
      <section className="rounded-xl border border-white/10 bg-surface-900/30 overflow-hidden">
        <div className="px-3 sm:px-5 py-3 sm:py-4 border-b border-white/10">
          <h2 className="font-medium text-white flex items-center gap-2 text-sm sm:text-base">
            <Key className="w-4 h-4 text-amber-400" />
            Token Inspector
          </h2>
        </div>
        <div className="p-3 sm:p-5">
          <input
            type="text"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="Paste a JWT to decode..."
            className="w-full px-3 sm:px-4 py-2 sm:py-2.5 rounded-lg bg-surface-900 border border-white/10 text-xs sm:text-sm font-mono text-white placeholder-surface-600 focus:outline-none focus:border-cyan-500/50 mb-3 sm:mb-4"
          />
          {token && <TokenInspector token={token} />}
        </div>
      </section>

      {/* Navigation */}
      <div className="flex items-center justify-between pt-2 pb-4 sm:pb-0">
        <Link
          to={`/protocols`}
          className="flex items-center gap-1.5 sm:gap-2 text-xs sm:text-sm text-surface-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
          <span className="hidden sm:inline">All Protocols</span>
          <span className="sm:hidden">Back</span>
        </Link>
        <Link
          to={protocolId === 'ssf' ? '/ssf-sandbox' : '/looking-glass'}
          className="flex items-center gap-1.5 sm:gap-2 text-xs sm:text-sm text-surface-400 hover:text-white transition-colors"
        >
          <span className="hidden sm:inline">{protocolId === 'ssf' ? 'Open SSF Sandbox' : 'Open Looking Glass'}</span>
          <span className="sm:hidden">{protocolId === 'ssf' ? 'SSF Sandbox' : 'Looking Glass'}</span>
          <ExternalLink className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
        </Link>
      </div>
    </div>
    </>
  )
}

// Step Row Component
function StepRow({ step, index, isActive, isLast, onClick }: { 
  step: FlowStep & { security?: string[] }
  index: number
  isActive: boolean
  isLast: boolean
  onClick: () => void 
}) {
  const typeConfig: Record<string, { color: string; icon: React.ElementType }> = {
    request: { color: 'text-blue-400 bg-blue-500/10 border-blue-500/20', icon: ArrowRight },
    response: { color: 'text-green-400 bg-green-500/10 border-green-500/20', icon: ArrowLeft },
    redirect: { color: 'text-amber-400 bg-amber-500/10 border-amber-500/20', icon: Globe },
    internal: { color: 'text-surface-400 bg-surface-800 border-white/10', icon: Server },
  }
  
  const config = typeConfig[step.type] || typeConfig.request
  const TypeIcon = config.icon

  return (
    <div className="relative">
      {/* Connector line */}
      {!isLast && (
        <div className="absolute left-4 sm:left-5 top-9 sm:top-10 bottom-0 w-px bg-white/10" />
      )}
      
      <motion.div
        initial={{ opacity: 0, x: -10 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ delay: index * 0.03 }}
        onClick={onClick}
        className={`relative rounded-lg border cursor-pointer transition-all ${
          isActive 
            ? 'bg-white/5 border-white/20' 
            : 'border-transparent hover:bg-white/[0.02] hover:border-white/10'
        }`}
      >
        <div className="p-2 sm:p-3 flex items-start gap-2 sm:gap-3">
          {/* Step number */}
          <div className={`w-8 h-8 sm:w-10 sm:h-10 rounded-full flex items-center justify-center text-xs sm:text-sm font-medium flex-shrink-0 border ${config.color}`}>
            {step.order}
          </div>
          
          {/* Content */}
          <div className="flex-1 min-w-0 pt-0.5 sm:pt-1">
            <div className="flex items-center gap-1.5 sm:gap-2 mb-0.5">
              <span className="font-medium text-white text-sm sm:text-base truncate">{step.name}</span>
              <TypeIcon className={`w-3 h-3 sm:w-3.5 sm:h-3.5 flex-shrink-0 ${config.color.split(' ')[0]}`} />
            </div>
            <div className="text-xs sm:text-sm text-surface-400 truncate">
              {step.from} → {step.to}
            </div>
          </div>

          {/* Expand indicator */}
          <ChevronDown className={`w-4 h-4 text-surface-400 transition-transform mt-1 sm:mt-2 flex-shrink-0 ${isActive ? 'rotate-180' : ''}`} />
        </div>

        {/* Expanded content */}
        <AnimatePresence>
          {isActive && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="overflow-hidden"
            >
              <div className="px-2 sm:px-3 pb-2 sm:pb-3 pt-1 ml-10 sm:ml-[52px] space-y-2 sm:space-y-3">
                <p className="text-xs sm:text-sm text-surface-300">{step.description}</p>

                {step.parameters && Object.keys(step.parameters).length > 0 && (
                  <div className="grid gap-1 sm:gap-1.5">
                    {Object.entries(step.parameters).map(([key, value]) => (
                      <div key={key} className="flex flex-col sm:flex-row sm:gap-3 text-xs sm:text-sm">
                        <code className="text-cyan-400 font-mono break-all">{key}</code>
                        <span className="text-surface-400 break-words">{value}</span>
                      </div>
                    ))}
                  </div>
                )}

                {step.security && step.security.length > 0 && (
                  <div className="p-2 sm:p-3 rounded-lg bg-amber-500/5 border border-amber-500/20">
                    <div className="flex items-center gap-1.5 text-xs font-medium text-amber-400 mb-1.5 sm:mb-2">
                      <AlertTriangle className="w-3 h-3 sm:w-3.5 sm:h-3.5" />
                      Security Note
                    </div>
                    <ul className="space-y-1">
                      {step.security.map((note, i) => (
                        <li key={i} className="text-xs sm:text-sm text-amber-200/80">• {note}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    </div>
  )
}

