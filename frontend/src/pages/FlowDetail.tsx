import { useEffect, useState, useMemo } from 'react'
import { useParams, Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  ArrowLeft, Eye, ChevronDown, ChevronRight,
  Lock, Key, AlertTriangle, Copy, Check,
  Code, ExternalLink, Loader2, ArrowRight,
  Fingerprint, Server, Globe, FileKey, Shield
} from 'lucide-react'
import { TokenInspector } from '../components/lookingglass/TokenInspector'
import { FlowDiagram } from '../components/lookingglass/FlowDiagram'
import { useProtocolFlows, FlowStep } from '../protocols'
import { getFlowWithFallback, flowIdMap } from '../protocols/fallback-data'

export function FlowDetail() {
  const { protocolId, flowId } = useParams()
  const [activeStep, setActiveStep] = useState<number>(-1)
  const [token, setToken] = useState<string>('')
  const [copied, setCopied] = useState(false)
  const [showCode, setShowCode] = useState(false)

  const { flows, loading } = useProtocolFlows(protocolId)
  const mappedFlowId: string = flowIdMap[flowId || ''] || flowId || ''

  const flow = useMemo(() => {
    const apiFlow = flows.find(f => f.id === mappedFlowId)
    if (apiFlow) {
      return {
        title: apiFlow.name,
        description: apiFlow.description,
        steps: apiFlow.steps,
      }
    }
    return getFlowWithFallback(flowId || '')
  }, [flows, mappedFlowId, flowId])

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

  const copyCode = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const getCodeExample = () => {
    if (mappedFlowId === 'authorization_code_pkce') {
      return `// Generate PKCE parameters
const codeVerifier = base64URLEncode(crypto.getRandomValues(new Uint8Array(32)));
const codeChallenge = base64URLEncode(
  await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier))
);

// Redirect to authorization
const authUrl = new URL('/oauth2/authorize', origin);
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');
window.location.href = authUrl;

// Exchange code for tokens (in callback)
const tokens = await fetch('/oauth2/token', {
  method: 'POST',
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: authorizationCode,
    code_verifier: codeVerifier,
  }),
}).then(r => r.json());`
    }
    
    if (mappedFlowId === 'client_credentials') {
      return `// Client Credentials (server-side only)
const tokens = await fetch('/oauth2/token', {
  method: 'POST',
  headers: {
    'Authorization': 'Basic ' + btoa(clientId + ':' + clientSecret),
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    grant_type: 'client_credentials',
    scope: 'api:read api:write',
  }),
}).then(r => r.json());`
    }

    if (mappedFlowId === 'token_introspection') {
      return `// Token Introspection (RFC 7662)
const result = await fetch('/oauth2/introspect', {
  method: 'POST',
  headers: {
    'Authorization': 'Basic ' + btoa(clientId + ':' + clientSecret),
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({ token: accessToken }),
}).then(r => r.json());

if (result.active) {
  console.log('Valid until:', new Date(result.exp * 1000));
}`
    }

    if (mappedFlowId === 'token_revocation') {
      return `// Token Revocation (RFC 7009)
await fetch('/oauth2/revoke', {
  method: 'POST',
  headers: {
    'Authorization': 'Basic ' + btoa(clientId + ':' + clientSecret),
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    token: refreshToken,
    token_type_hint: 'refresh_token',
  }),
});`
    }

    if (mappedFlowId === 'oidc_userinfo') {
      return `// Fetch user claims
const userInfo = await fetch('/oidc/userinfo', {
  headers: { 'Authorization': 'Bearer ' + accessToken },
}).then(r => r.json());

console.log('User:', userInfo.name, userInfo.email);`
    }

    if (mappedFlowId === 'oidc_discovery') {
      return `// Auto-configure from discovery document
const config = await fetch('/.well-known/openid-configuration')
  .then(r => r.json());

const jwks = await fetch(config.jwks_uri).then(r => r.json());`
    }

    // SAML flows
    if (mappedFlowId === 'saml_sp_initiated_sso') {
      return `// SP-Initiated SSO - Redirect to IdP
// This would typically be handled server-side

// 1. Create AuthnRequest XML
const authnRequest = \`
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  ID="_\${crypto.randomUUID()}"
  Version="2.0"
  IssueInstant="\${new Date().toISOString()}"
  AssertionConsumerServiceURL="https://sp.example.com/saml/acs">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    https://sp.example.com
  </saml:Issuer>
</samlp:AuthnRequest>\`;

// 2. Encode and redirect (HTTP-Redirect binding)
const encoded = btoa(pako.deflateRaw(authnRequest, { to: 'string' }));
const redirectUrl = \`\${idpSsoUrl}?SAMLRequest=\${encodeURIComponent(encoded)}\`;`
    }

    if (mappedFlowId === 'saml_single_logout') {
      return `// Single Logout - Create LogoutRequest
const logoutRequest = \`
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  ID="_\${crypto.randomUUID()}"
  Version="2.0"
  IssueInstant="\${new Date().toISOString()}"
  Destination="\${idpSloUrl}">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    https://sp.example.com
  </saml:Issuer>
  <saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
    user@example.com
  </saml:NameID>
  <samlp:SessionIndex>\${sessionIndex}</samlp:SessionIndex>
</samlp:LogoutRequest>\`;`
    }

    if (mappedFlowId === 'saml_metadata') {
      return `// Fetch and parse SAML metadata
const metadataUrl = 'https://idp.example.com/saml/metadata';
const response = await fetch(metadataUrl);
const xml = await response.text();

// Parse the XML to extract endpoints and certificates
const parser = new DOMParser();
const doc = parser.parseFromString(xml, 'application/xml');

// Extract SSO endpoint
const ssoBinding = doc.querySelector('SingleSignOnService[Binding*="HTTP-POST"]');
const ssoUrl = ssoBinding?.getAttribute('Location');

// Extract signing certificate
const cert = doc.querySelector('KeyDescriptor[use="signing"] X509Certificate');
const certificate = cert?.textContent;`
    }

    return `// Authorization Code Flow
const authUrl = new URL('/oauth2/authorize', origin);
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('state', crypto.randomUUID());
window.location.href = authUrl;`
  }

  // Get flow badges
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
    if (mappedFlowId.includes('oidc')) {
      badges.push({ label: 'ID Token', color: 'purple', icon: Fingerprint })
    }
    // SAML badges
    if (mappedFlowId.includes('saml')) {
      badges.push({ label: 'XML-Based', color: 'cyan', icon: FileKey })
    }
    if (mappedFlowId === 'saml_sp_initiated_sso' || mappedFlowId === 'saml_idp_initiated_sso') {
      badges.push({ label: 'SSO', color: 'green', icon: Shield })
    }
    if (mappedFlowId === 'saml_single_logout') {
      badges.push({ label: 'Federated Logout', color: 'yellow', icon: Globe })
    }
    return badges
  }

  const getProtocolName = (id: string | undefined) => {
    switch (id) {
      case 'oidc': return 'OpenID Connect'
      case 'saml': return 'SAML 2.0'
      default: return 'OAuth 2.0'
    }
  }

  if (!flow) {
    return (
      <div className="text-center py-20">
        <h1 className="text-xl font-semibold text-white mb-4">Flow Not Found</h1>
        <Link to={`/protocol/${protocolId}`} className="text-cyan-400 hover:underline">
          Back to {getProtocolName(protocolId)}
        </Link>
      </div>
    )
  }

  const badges = getBadges()

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Breadcrumb & Title */}
      <header>
        <div className="flex items-center gap-2 text-sm text-surface-500 mb-2">
          <Link to="/protocols" className="hover:text-white transition-colors">Protocols</Link>
          <ChevronRight className="w-4 h-4" />
          <Link to={`/protocol/${protocolId}`} className="hover:text-white transition-colors">
            {getProtocolName(protocolId)}
          </Link>
          <ChevronRight className="w-4 h-4" />
          <span className="text-surface-300">{flow.title}</span>
        </div>
        
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold text-white mb-2">{flow.title}</h1>
            <p className="text-surface-400">{flow.description}</p>
          </div>
          
          <Link
            to="/looking-glass"
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500/20 to-purple-500/20 border border-cyan-500/30 text-cyan-400 text-sm font-medium hover:from-cyan-500/30 hover:to-purple-500/30 transition-all flex-shrink-0"
          >
            <Eye className="w-4 h-4" />
            Try in Looking Glass
          </Link>
        </div>

        {/* Badges */}
        {badges.length > 0 && (
          <div className="flex gap-2 mt-4">
            {badges.map(badge => (
              <span 
                key={badge.label}
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border
                  ${badge.color === 'green' ? 'bg-green-500/10 text-green-400 border-green-500/20' : ''}
                  ${badge.color === 'yellow' ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20' : ''}
                  ${badge.color === 'blue' ? 'bg-blue-500/10 text-blue-400 border-blue-500/20' : ''}
                  ${badge.color === 'purple' ? 'bg-purple-500/10 text-purple-400 border-purple-500/20' : ''}
                  ${badge.color === 'cyan' ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20' : ''}
                `}
              >
                <badge.icon className="w-3 h-3" />
                {badge.label}
              </span>
            ))}
          </div>
        )}
      </header>

      {/* Sequence Diagram */}
      <section className="rounded-xl border border-white/10 bg-surface-900/30 overflow-hidden">
        <div className="px-5 py-4 border-b border-white/10">
          <h2 className="font-medium text-white">Sequence Diagram</h2>
          <p className="text-sm text-surface-500 mt-1">Click any step for details</p>
        </div>
        <div className="p-5">
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
          className="w-full px-5 py-4 flex items-center justify-between hover:bg-white/[0.02] transition-colors"
        >
          <h2 className="font-medium text-white flex items-center gap-2">
            <Code className="w-4 h-4 text-surface-400" />
            Implementation Example
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
                  className="absolute top-3 right-3 flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs text-surface-400 hover:text-white hover:bg-white/10 transition-colors"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copied ? 'Copied!' : 'Copy'}
                </button>
                <pre className="p-5 overflow-x-auto text-sm">
                  <code className="text-surface-300 font-mono leading-relaxed">{getCodeExample()}</code>
                </pre>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </section>

      {/* Step-by-Step Breakdown */}
      <section className="rounded-xl border border-white/10 bg-surface-900/30 overflow-hidden">
        <div className="px-5 py-4 border-b border-white/10">
          <h2 className="font-medium text-white">Step-by-Step Breakdown</h2>
        </div>
        <div className="p-5">
          <div className="space-y-3">
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
        <div className="px-5 py-4 border-b border-white/10">
          <h2 className="font-medium text-white flex items-center gap-2">
            <Key className="w-4 h-4 text-amber-400" />
            Token Inspector
          </h2>
        </div>
        <div className="p-5">
          <input
            type="text"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="Paste a JWT to decode..."
            className="w-full px-4 py-2.5 rounded-lg bg-surface-900 border border-white/10 text-sm font-mono text-white placeholder-surface-600 focus:outline-none focus:border-cyan-500/50 mb-4"
          />
          {token && <TokenInspector token={token} />}
        </div>
      </section>

      {/* Navigation */}
      <div className="flex items-center justify-between pt-2">
        <Link
          to={`/protocols`}
          className="flex items-center gap-2 text-sm text-surface-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          All Protocols
        </Link>
        <Link
          to="/looking-glass"
          className="flex items-center gap-2 text-sm text-surface-400 hover:text-white transition-colors"
        >
          Open Looking Glass
          <ExternalLink className="w-4 h-4" />
        </Link>
      </div>
    </div>
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
        <div className="absolute left-5 top-10 bottom-0 w-px bg-white/10" />
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
        <div className="p-3 flex items-start gap-3">
          {/* Step number */}
          <div className={`w-10 h-10 rounded-full flex items-center justify-center text-sm font-medium flex-shrink-0 border ${config.color}`}>
            {step.order}
          </div>
          
          {/* Content */}
          <div className="flex-1 min-w-0 pt-1">
            <div className="flex items-center gap-2 mb-0.5">
              <span className="font-medium text-white">{step.name}</span>
              <TypeIcon className={`w-3.5 h-3.5 ${config.color.split(' ')[0]}`} />
            </div>
            <div className="text-sm text-surface-500">
              {step.from} → {step.to}
            </div>
          </div>

          {/* Expand indicator */}
          <ChevronDown className={`w-4 h-4 text-surface-500 transition-transform mt-2 ${isActive ? 'rotate-180' : ''}`} />
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
              <div className="px-3 pb-3 pt-1 ml-[52px] space-y-3">
                <p className="text-sm text-surface-300">{step.description}</p>

                {step.parameters && Object.keys(step.parameters).length > 0 && (
                  <div className="grid gap-1.5">
                    {Object.entries(step.parameters).map(([key, value]) => (
                      <div key={key} className="flex gap-3 text-sm">
                        <code className="text-cyan-400 font-mono">{key}</code>
                        <span className="text-surface-400">{value}</span>
                      </div>
                    ))}
                  </div>
                )}

                {step.security && step.security.length > 0 && (
                  <div className="p-3 rounded-lg bg-amber-500/5 border border-amber-500/20">
                    <div className="flex items-center gap-1.5 text-xs font-medium text-amber-400 mb-2">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      Security Note
                    </div>
                    <ul className="space-y-1">
                      {step.security.map((note, i) => (
                        <li key={i} className="text-sm text-amber-200/80">• {note}</li>
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

