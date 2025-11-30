import { useEffect, useState, useMemo } from 'react'
import { useParams, Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  ArrowLeft, Eye, ChevronDown, Zap, Shield,
  Lock, Key, AlertTriangle, CheckCircle2, Copy, Check,
  Code, ExternalLink, Loader2
} from 'lucide-react'
import { FlowDiagram } from '../components/lookingglass/FlowDiagram'
import { TokenInspector } from '../components/lookingglass/TokenInspector'
import { useProtocolFlows, FlowStep } from '../protocols'
import { getFlowWithFallback, flowIdMap } from '../protocols/fallback-data'

export function FlowDetail() {
  const { protocolId, flowId } = useParams()
  const [activeStep, setActiveStep] = useState<number>(-1)
  const [token, setToken] = useState<string>('')
  const [copied, setCopied] = useState(false)
  const [showCode, setShowCode] = useState(false)

  // Fetch flows from API (modular plugin system)
  const { flows, loading } = useProtocolFlows(protocolId)

  // Map URL slug to flow ID
  const mappedFlowId: string = flowIdMap[flowId || ''] || flowId || ''

  // Try API first, then fallback to local data
  const flow = useMemo(() => {
    // Look for flow from API
    const apiFlow = flows.find(f => f.id === mappedFlowId)
    if (apiFlow) {
      return {
        title: apiFlow.name,
        description: apiFlow.description,
        steps: apiFlow.steps,
      }
    }
    // Fallback to local data
    return getFlowWithFallback(flowId || '')
  }, [flows, mappedFlowId, flowId])

  useEffect(() => {
    setActiveStep(-1)
  }, [flowId])

  // Show loading state while fetching from API
  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[50vh]">
        <Loader2 className="w-8 h-8 text-accent-orange animate-spin" />
      </div>
    )
  }

  const handleStartDemo = async () => {
    const codeVerifier = generateCodeVerifier()
    const codeChallenge = await generateCodeChallenge(codeVerifier)
    
    sessionStorage.setItem('pkce_verifier', codeVerifier)
    sessionStorage.setItem('oauth_flow_type', protocolId || 'oauth2')

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: 'public-app',
      redirect_uri: window.location.origin + '/callback',
      scope: protocolId === 'oidc' ? 'openid profile email' : 'profile email',
      state: crypto.randomUUID(),
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    })

    if (protocolId === 'oidc') {
      params.append('nonce', crypto.randomUUID())
    }

    const endpoint = protocolId === 'oidc' ? '/oidc/authorize' : '/oauth2/authorize'
    window.location.href = `${endpoint}?${params.toString()}`
  }

  const copyCode = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const getCodeExample = () => {
    if (mappedFlowId === 'authorization_code_pkce') {
      return `// 1. Generate PKCE parameters
const codeVerifier = base64URLEncode(crypto.getRandomValues(new Uint8Array(32)));
const codeChallenge = base64URLEncode(await crypto.subtle.digest('SHA-256', 
  new TextEncoder().encode(codeVerifier)));

// 2. Redirect to authorization endpoint
const authUrl = new URL('/oauth2/authorize', origin);
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('redirect_uri', 'https://app.com/callback');
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');
authUrl.searchParams.set('state', crypto.randomUUID());
window.location.href = authUrl;

// 3. Exchange code for tokens (in callback)
const tokens = await fetch('/oauth2/token', {
  method: 'POST',
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: authorizationCode,
    redirect_uri: 'https://app.com/callback',
    client_id: 'your-client-id',
    code_verifier: codeVerifier,
  }),
}).then(r => r.json());`
    }
    
    if (mappedFlowId === 'client_credentials') {
      return `// Client Credentials Flow (server-side only)
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
}).then(r => r.json());

// Use the access token
const data = await fetch('/api/resource', {
  headers: { 'Authorization': 'Bearer ' + tokens.access_token },
}).then(r => r.json());`
    }

    if (mappedFlowId === 'token_introspection') {
      return `// Token Introspection (RFC 7662)
// Resource server validates token with authorization server

const introspectionResult = await fetch('/oauth2/introspect', {
  method: 'POST',
  headers: {
    'Authorization': 'Basic ' + btoa(resourceServerId + ':' + resourceServerSecret),
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    token: accessToken,
    token_type_hint: 'access_token', // optional
  }),
}).then(r => r.json());

// Check if token is valid
if (introspectionResult.active) {
  console.log('Token is valid');
  console.log('Scopes:', introspectionResult.scope);
  console.log('Expires:', new Date(introspectionResult.exp * 1000));
  console.log('Client:', introspectionResult.client_id);
} else {
  console.log('Token is invalid or expired');
}`
    }

    if (mappedFlowId === 'token_revocation') {
      return `// Token Revocation (RFC 7009)
// Invalidate tokens on logout or security events

await fetch('/oauth2/revoke', {
  method: 'POST',
  headers: {
    'Authorization': 'Basic ' + btoa(clientId + ':' + clientSecret),
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    token: refreshToken, // or accessToken
    token_type_hint: 'refresh_token', // optional but recommended
  }),
});

// Note: Response is always 200 OK for security
// (prevents token existence disclosure)

// Clear local token storage
localStorage.removeItem('access_token');
localStorage.removeItem('refresh_token');`
    }

    if (mappedFlowId === 'oidc_userinfo') {
      return `// OIDC UserInfo Endpoint
// Retrieve user claims with access token

const userInfo = await fetch('/oidc/userinfo', {
  headers: {
    'Authorization': 'Bearer ' + accessToken,
  },
}).then(r => r.json());

console.log('User ID:', userInfo.sub);
console.log('Name:', userInfo.name);
console.log('Email:', userInfo.email);
console.log('Email Verified:', userInfo.email_verified);`
    }

    if (mappedFlowId === 'oidc_discovery') {
      return `// OpenID Connect Discovery
// Auto-configure client from provider metadata

const config = await fetch('/.well-known/openid-configuration')
  .then(r => r.json());

console.log('Issuer:', config.issuer);
console.log('Authorization Endpoint:', config.authorization_endpoint);
console.log('Token Endpoint:', config.token_endpoint);
console.log('UserInfo Endpoint:', config.userinfo_endpoint);

// Fetch signing keys
const jwks = await fetch(config.jwks_uri).then(r => r.json());
console.log('Signing Keys:', jwks.keys);`
    }

    if (mappedFlowId === 'oidc_hybrid') {
      return `// OIDC Hybrid Flow
// Get ID token immediately, exchange code for access token

const authUrl = new URL('/oidc/authorize', origin);
authUrl.searchParams.set('response_type', 'code id_token');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('redirect_uri', 'https://app.com/callback');
authUrl.searchParams.set('scope', 'openid profile email');
authUrl.searchParams.set('nonce', crypto.randomUUID());
authUrl.searchParams.set('state', crypto.randomUUID());
window.location.href = authUrl;

// In callback: id_token in fragment, code in query
// Validate ID token immediately for user identity
// Exchange code for access_token on backend`
    }

    return `// Authorization Code Flow
const authUrl = new URL('/oauth2/authorize', origin);
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('redirect_uri', 'https://app.com/callback');
authUrl.searchParams.set('state', crypto.randomUUID());
window.location.href = authUrl;

// Exchange code (server-side)
const tokens = await fetch('/oauth2/token', {
  method: 'POST',
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: authorizationCode,
    client_id: 'your-client-id',
    client_secret: 'your-secret', // Server-side only!
  }),
}).then(r => r.json());`
  }

  if (!flow) {
    return (
      <div className="text-center py-20">
        <h1 className="text-2xl font-bold text-white mb-4">Flow Not Found</h1>
        <Link to={`/protocol/${protocolId}`} className="text-accent-orange hover:underline">
          Back to {protocolId === 'oidc' ? 'OpenID Connect' : 'OAuth 2.0'}
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link
            to={`/protocol/${protocolId}`}
            className="p-2 rounded-lg bg-white/5 hover:bg-white/10 transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
          </Link>
          <div>
            <div className="flex items-center gap-2 text-sm text-surface-400 mb-1">
              <span>{protocolId === 'oidc' ? 'OpenID Connect' : 'OAuth 2.0'}</span>
              <span>→</span>
              <span className="text-accent-orange">Flow</span>
            </div>
            <h1 className="font-display text-2xl font-bold text-white">
              {flow.title}
            </h1>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setShowCode(!showCode)}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
              showCode 
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' 
                : 'bg-white/5 text-surface-400 hover:text-white border border-white/10'
            }`}
          >
            <Code className="w-4 h-4" />
            Code
          </button>
          <button
            onClick={handleStartDemo}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-accent-orange to-accent-purple text-white font-medium hover:opacity-90 transition-opacity"
          >
            <Zap className="w-4 h-4" />
            Try Live Demo
          </button>
        </div>
      </div>

      {/* Flow Description & Badges */}
      <div className="glass rounded-xl p-6">
        <p className="text-surface-300 text-lg mb-4">{flow.description}</p>
        <div className="flex flex-wrap gap-2">
          {mappedFlowId.includes('pkce') && (
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-green-500/10 text-green-400 text-xs font-medium border border-green-500/20">
              <Lock className="w-3.5 h-3.5" />
              PKCE Protected
            </span>
          )}
          {mappedFlowId === 'authorization_code' && (
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-yellow-500/10 text-yellow-400 text-xs font-medium border border-yellow-500/20">
              <Key className="w-3.5 h-3.5" />
              Client Secret Required
            </span>
          )}
          {mappedFlowId === 'client_credentials' && (
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-blue-500/10 text-blue-400 text-xs font-medium border border-blue-500/20">
              <Shield className="w-3.5 h-3.5" />
              Machine-to-Machine
            </span>
          )}
          {mappedFlowId.includes('oidc') && (
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-purple-500/10 text-purple-400 text-xs font-medium border border-purple-500/20">
              <CheckCircle2 className="w-3.5 h-3.5" />
              ID Token Included
            </span>
          )}
        </div>
      </div>

      {/* Code Example */}
      <AnimatePresence>
        {showCode && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden"
          >
            <div className="glass rounded-xl overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 bg-surface-800 border-b border-white/10">
                <span className="text-sm font-medium text-white">Implementation Example</span>
                <button
                  onClick={() => copyCode(getCodeExample())}
                  className="flex items-center gap-1.5 px-2 py-1 rounded text-xs text-surface-400 hover:text-white hover:bg-white/10 transition-colors"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              </div>
              <pre className="p-4 overflow-x-auto">
                <code className="text-sm text-surface-300 font-mono">{getCodeExample()}</code>
              </pre>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Sequence Diagram */}
      <div className="glass rounded-xl p-6">
        <h2 className="font-display text-lg font-semibold text-white mb-4">
          Sequence Diagram
        </h2>
        <p className="text-surface-400 text-sm mb-6">
          Click any step to see detailed information about what happens at that stage.
        </p>
        <FlowDiagram 
          steps={flow.steps}
          activeStep={activeStep}
          onStepClick={setActiveStep}
        />
      </div>

      {/* Step Details */}
      <div className="glass rounded-xl p-6">
        <h2 className="font-display text-lg font-semibold text-white mb-4">
          Step-by-Step Breakdown
        </h2>
        <div className="space-y-3">
          {flow.steps.map((step, index) => (
            <StepCard 
              key={step.order}
              step={step}
              index={index}
              isActive={activeStep === step.order}
              onClick={() => setActiveStep(activeStep === step.order ? -1 : step.order)}
            />
          ))}
        </div>
      </div>

      {/* Token Inspector */}
      <div className="glass rounded-xl p-6">
        <h3 className="font-display font-semibold text-white mb-4 flex items-center gap-2">
          <Key className="w-5 h-5 text-accent-cyan" />
          Token Inspector
        </h3>
        <p className="text-surface-400 text-sm mb-4">
          Paste a JWT token to decode and analyze its contents.
        </p>
        <textarea
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
          className="w-full h-24 px-4 py-3 rounded-lg bg-surface-900 border border-white/10 text-sm font-mono text-white placeholder-surface-500 focus:outline-none focus:border-accent-orange/50 resize-none mb-4"
        />
        {token && <TokenInspector token={token} />}
      </div>

      {/* Navigation */}
      <div className="flex items-center justify-center gap-4 pt-4">
        <Link
          to={`/protocol/${protocolId}`}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-white/5 border border-white/10 text-white font-medium hover:bg-white/10 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Flows
        </Link>
        <Link
          to="/looking-glass"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-white/5 border border-white/10 text-white font-medium hover:bg-white/10 transition-colors"
        >
          <Eye className="w-4 h-4" />
          Looking Glass
          <ExternalLink className="w-3.5 h-3.5 text-surface-400" />
        </Link>
      </div>
    </div>
  )
}

// Step Card Component
function StepCard({ step, index, isActive, onClick }: { 
  step: FlowStep & { security?: string[] }
  index: number
  isActive: boolean
  onClick: () => void 
}) {
  const typeColors: Record<string, string> = {
    request: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
    response: 'bg-green-500/10 text-green-400 border-green-500/20',
    redirect: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
    internal: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
  }

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.05 }}
      className={`rounded-xl border transition-all cursor-pointer ${
        isActive 
          ? 'bg-indigo-500/10 border-indigo-500/30' 
          : 'bg-surface-900/50 border-white/5 hover:border-white/10'
      }`}
      onClick={onClick}
    >
      <div className="p-4">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-full flex items-center justify-center font-bold text-sm ${
            isActive ? 'bg-indigo-500 text-white' : 'bg-surface-800 text-surface-400'
          }`}>
            {step.order}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-0.5">
              <h4 className="font-medium text-white truncate">{step.name}</h4>
              <span className={`px-2 py-0.5 rounded-full text-xs font-medium border ${typeColors[step.type] || typeColors.request}`}>
                {step.type}
              </span>
            </div>
            <p className="text-sm text-surface-400">
              {step.from} → {step.to}
            </p>
          </div>
          <ChevronDown className={`w-5 h-5 text-surface-400 transition-transform ${isActive ? 'rotate-180' : ''}`} />
        </div>
      </div>

      <AnimatePresence>
        {isActive && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4 pt-2 border-t border-white/5 space-y-4">
              <p className="text-surface-300">{step.description}</p>

              {step.parameters && Object.keys(step.parameters).length > 0 && (
                <div>
                  <h5 className="text-xs font-semibold text-surface-500 uppercase tracking-wider mb-2">Parameters</h5>
                  <div className="grid gap-2">
                    {Object.entries(step.parameters).map(([key, value]) => (
                      <div key={key} className="flex gap-3 p-2.5 rounded-lg bg-surface-900/80">
                        <code className="text-cyan-400 text-sm font-mono whitespace-nowrap">{key}</code>
                        <span className="text-surface-300 text-sm">{value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {step.security && step.security.length > 0 && (
                <div className="p-3 rounded-lg bg-yellow-500/5 border border-yellow-500/20">
                  <h5 className="text-xs font-semibold text-yellow-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    Security Considerations
                  </h5>
                  <ul className="space-y-1.5">
                    {step.security.map((note, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-yellow-200/90">
                        <CheckCircle2 className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />
                        {note}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

// PKCE Helper Functions
function generateCodeVerifier(): string {
  const array = new Uint8Array(32)
  crypto.getRandomValues(array)
  return base64URLEncode(array)
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return base64URLEncode(new Uint8Array(digest))
}

function base64URLEncode(buffer: Uint8Array): string {
  return btoa(String.fromCharCode(...buffer))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

