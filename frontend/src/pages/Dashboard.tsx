import { Link } from 'react-router-dom'
import { 
  Shield, Eye, Terminal, Fingerprint, 
  ExternalLink, ChevronRight, Key, 
  Code, FileSearch, Zap, FileKey
} from 'lucide-react'

export function Dashboard() {
  return (
    <div className="max-w-4xl mx-auto space-y-8 sm:space-y-10">
      {/* Header */}
      <header className="py-2 sm:py-4">
        <div className="flex items-center gap-2 text-amber-400 font-mono text-sm mb-3">
          <Terminal className="w-4 h-4" />
          <span>protocol-soup v1.0</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-semibold text-white mb-3 flex items-center gap-3">
          Protocol Soup
          <span className="text-2xl sm:text-3xl">🍜</span>
        </h1>
        <p className="text-surface-300 text-base sm:text-lg max-w-2xl">
          Learn authentication protocols by running them. Execute real OAuth 2.0, OpenID Connect, 
          and SAML 2.0 flows against a local identity provider and see exactly what happens at each step.
        </p>
      </header>

      {/* Value Props */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <ValueCard
          icon={Code}
          title="Real Protocol Execution"
          description="Not simulations — actual HTTP requests to a working identity provider"
        />
        <ValueCard
          icon={FileSearch}
          title="Full Traffic Inspection"
          description="See every request, response, header, and parameter exchanged"
        />
        <ValueCard
          icon={Zap}
          title="Live Token Decoding"
          description="Decode JWTs instantly as they're issued, examine claims and signatures"
        />
      </section>

      {/* Main Navigation */}
      <section>
        <h2 className="text-sm font-medium text-surface-400 uppercase tracking-wider mb-4">
          Get Started
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <NavCard
            to="/looking-glass"
            icon={Eye}
            color="cyan"
            title="Looking Glass"
            description="The main workspace. Select a protocol flow, execute it, and inspect every step of the exchange in real-time."
            cta="Open Looking Glass"
          />
          <NavCard
            to="/protocols"
            icon={Shield}
            color="purple"
            title="Protocol Reference"
            description="Documentation for each flow with sequence diagrams, parameter explanations, and security considerations."
            cta="Browse Protocols"
          />
        </div>
      </section>

      {/* Available Protocols */}
      <section>
        <h2 className="text-sm font-medium text-surface-400 uppercase tracking-wider mb-4">
          Supported Protocols
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          <ProtocolCard
            icon={Key}
            name="OAuth 2.0"
            description="Authorization framework for delegated access"
            color="blue"
            flows={['authorization_code', 'client_credentials', 'pkce', 'refresh_token']}
            to="/looking-glass"
          />
          <ProtocolCard
            icon={Fingerprint}
            name="OpenID Connect"
            description="Authentication layer built on OAuth 2.0"
            color="orange"
            flows={['oidc_code', 'hybrid', 'userinfo', 'discovery']}
            to="/looking-glass"
          />
          <ProtocolCard
            icon={FileKey}
            name="SAML 2.0"
            description="XML-based federated identity and SSO"
            color="cyan"
            flows={['sp_initiated_sso', 'idp_initiated_sso', 'single_logout']}
            to="/looking-glass"
          />
        </div>
      </section>

      {/* Coming Soon */}
      <section className="rounded-xl border border-dashed border-white/10 p-4 sm:p-6 text-center">
        <p className="text-surface-400 mb-2">More protocols on the roadmap</p>
        <div className="flex flex-wrap items-center justify-center gap-2 sm:gap-4 text-surface-500 text-sm">
          <span>WebAuthn</span>
          <span className="text-surface-700 hidden sm:inline">•</span>
          <span>FIDO2</span>
          <span className="text-surface-700 hidden sm:inline">•</span>
          <span>mTLS</span>
          <span className="text-surface-700 hidden sm:inline">•</span>
          <span>SPIFFE</span>
        </div>
      </section>

      {/* Quick References */}
      <section>
        <h2 className="text-sm font-medium text-surface-400 uppercase tracking-wider mb-3">
          Specifications
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2">
          <RFCLink number="6749" title="OAuth 2.0" />
          <RFCLink number="7636" title="PKCE" />
          <RFCLink number="6750" title="Bearer Token" />
          <RFCLink number="7519" title="JWT" />
        </div>
      </section>
    </div>
  )
}

function ValueCard({ 
  icon: Icon, 
  title, 
  description 
}: {
  icon: React.ElementType
  title: string
  description: string
}) {
  return (
    <div className="p-4 rounded-xl bg-surface-900/50 border border-white/5">
      <Icon className="w-5 h-5 text-amber-400 mb-3" />
      <h3 className="font-medium text-white mb-1">{title}</h3>
      <p className="text-sm text-surface-400">{description}</p>
    </div>
  )
}

function NavCard({ 
  to, 
  icon: Icon, 
  color, 
  title, 
  description, 
  cta 
}: {
  to: string
  icon: React.ElementType
  color: 'cyan' | 'purple'
  title: string
  description: string
  cta: string
}) {
  const colors = {
    cyan: {
      border: 'border-cyan-500/20 hover:border-cyan-500/40',
      bg: 'from-cyan-500/10',
      icon: 'bg-cyan-500/20',
      iconText: 'text-cyan-400',
      cta: 'text-cyan-400',
    },
    purple: {
      border: 'border-purple-500/20 hover:border-purple-500/40',
      bg: 'from-purple-500/10',
      icon: 'bg-purple-500/20',
      iconText: 'text-purple-400',
      cta: 'text-purple-400',
    },
  }
  const c = colors[color]

  return (
    <Link
      to={to}
      className={`group relative overflow-hidden rounded-xl border ${c.border} bg-gradient-to-br ${c.bg} to-transparent p-6 transition-all`}
    >
      <div className={`absolute top-0 right-0 w-32 h-32 ${c.bg.replace('from-', 'bg-')} rounded-full blur-2xl -translate-y-1/2 translate-x-1/2 opacity-50`} />
      <div className="relative">
        <div className={`w-12 h-12 rounded-xl ${c.icon} flex items-center justify-center mb-4`}>
          <Icon className={`w-6 h-6 ${c.iconText}`} />
        </div>
        <h3 className="text-xl font-semibold text-white mb-2">{title}</h3>
        <p className="text-surface-400 mb-4 leading-relaxed">{description}</p>
        <span className={`inline-flex items-center gap-1.5 ${c.cta} text-sm font-medium group-hover:gap-2.5 transition-all`}>
          {cta} <ChevronRight className="w-4 h-4" />
        </span>
      </div>
    </Link>
  )
}

function ProtocolCard({ 
  icon: Icon, 
  name, 
  description, 
  color,
  flows, 
  to 
}: {
  icon: React.ElementType
  name: string
  description: string
  color: 'blue' | 'orange' | 'cyan'
  flows: string[]
  to: string
}) {
  const colors = {
    blue: {
      border: 'border-blue-500/20 hover:border-blue-500/40',
      bg: 'bg-blue-500/10',
      text: 'text-blue-400',
      tag: 'bg-blue-500/10 text-blue-300',
    },
    orange: {
      border: 'border-orange-500/20 hover:border-orange-500/40',
      bg: 'bg-orange-500/10',
      text: 'text-orange-400',
      tag: 'bg-orange-500/10 text-orange-300',
    },
    cyan: {
      border: 'border-cyan-500/20 hover:border-cyan-500/40',
      bg: 'bg-cyan-500/10',
      text: 'text-cyan-400',
      tag: 'bg-cyan-500/10 text-cyan-300',
    },
  }
  const c = colors[color]

  return (
    <Link to={to} className={`block rounded-xl border ${c.border} p-5 transition-colors group`}>
      <div className="flex items-start gap-4">
        <div className={`w-10 h-10 rounded-lg ${c.bg} flex items-center justify-center flex-shrink-0`}>
          <Icon className={`w-5 h-5 ${c.text}`} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="font-semibold text-white">{name}</span>
            <ChevronRight className="w-4 h-4 text-surface-600 group-hover:text-surface-400 transition-colors" />
          </div>
          <p className="text-sm text-surface-500 mb-3">{description}</p>
          <div className="flex flex-wrap gap-1.5">
            {flows.map(flow => (
              <code key={flow} className={`px-2 py-0.5 rounded text-xs font-mono ${c.tag}`}>
                {flow}
              </code>
            ))}
          </div>
        </div>
      </div>
    </Link>
  )
}

function RFCLink({ number, title }: { number: string; title: string }) {
  return (
    <a
      href={`https://datatracker.ietf.org/doc/html/rfc${number}`}
      target="_blank"
      rel="noopener noreferrer"
      className="flex items-center gap-2 px-3 py-2 rounded-lg border border-white/5 hover:border-white/20 hover:bg-white/5 transition-all text-sm group"
    >
      <span className="text-surface-500 font-mono group-hover:text-amber-400 transition-colors">RFC {number}</span>
      <span className="text-surface-400 group-hover:text-white transition-colors">{title}</span>
      <ExternalLink className="w-3 h-3 text-surface-600 opacity-0 group-hover:opacity-100 transition-opacity ml-auto" />
    </a>
  )
}
