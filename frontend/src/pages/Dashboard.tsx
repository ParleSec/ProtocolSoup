import { Link } from 'react-router-dom'
import { 
  Shield, Eye, Terminal, Fingerprint, 
  ChevronRight, Key, 
  Code, FileSearch, Zap, FileKey, Users, Radio
} from 'lucide-react'
import { SEO } from '../components/common/SEO'
import { generateHomepageSchema } from '../utils/schema'

interface SpecLinkItem {
  label: string
  url: string
  tone?: 'rfc' | 'spec'
}

interface SpecGroupItem {
  label: string
  links: SpecLinkItem[]
}

const SPEC_GROUPS: SpecGroupItem[] = [
  {
    label: 'OAuth/OIDC',
    links: [
      { label: 'RFC 6749', url: 'https://datatracker.ietf.org/doc/html/rfc6749', tone: 'rfc' },
      { label: 'RFC 7636', url: 'https://datatracker.ietf.org/doc/html/rfc7636', tone: 'rfc' },
      { label: 'RFC 6750', url: 'https://datatracker.ietf.org/doc/html/rfc6750', tone: 'rfc' },
      { label: 'RFC 7519', url: 'https://datatracker.ietf.org/doc/html/rfc7519', tone: 'rfc' },
    ],
  },
  {
    label: 'SPIFFE',
    links: [
      { label: 'SPIFFE', url: 'https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/' },
      { label: 'X.509-SVID', url: 'https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/#spiffe-verifiable-identity-document-svid' },
      { label: 'JWT-SVID', url: 'https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/#jwt-svid' },
      { label: 'SPIRE', url: 'https://spiffe.io/docs/latest/spire-about/' },
    ],
  },
  {
    label: 'SCIM',
    links: [
      { label: 'RFC 7642', url: 'https://datatracker.ietf.org/doc/html/rfc7642', tone: 'rfc' },
      { label: 'RFC 7643', url: 'https://datatracker.ietf.org/doc/html/rfc7643', tone: 'rfc' },
      { label: 'RFC 7644', url: 'https://datatracker.ietf.org/doc/html/rfc7644', tone: 'rfc' },
    ],
  },
  {
    label: 'SSF',
    links: [
      { label: 'RFC 8417', url: 'https://datatracker.ietf.org/doc/html/rfc8417', tone: 'rfc' },
      { label: 'CAEP 1.0', url: 'https://openid.net/specs/openid-caep-1_0.html', tone: 'spec' },
      { label: 'RISC 1.0', url: 'https://openid.net/specs/openid-risc-profile-1_0.html', tone: 'spec' },
      { label: 'SSF 1.0', url: 'https://openid.net/specs/openid-sse-framework-1_0.html', tone: 'spec' },
    ],
  },
]

export function Dashboard() {
  const structuredData = generateHomepageSchema()

  return (
    <>
      <SEO
        title="Protocol Soup - Interactive Authentication Protocol Playground"
        description="Protocol Soup helps you learn authentication protocols by running them. Execute real OAuth 2.0, OpenID Connect, SAML 2.0, SPIFFE/SPIRE, SCIM 2.0, and SSF flows against working infrastructure."
        canonical="/"
        ogType="website"
        keywords={[
          'oauth2 playground',
          'oauth testing tool',
          'oidc testing',
          'authentication protocol sandbox',
          'jwt decoder',
          'token inspector',
          'oauth2 tutorial',
          'openid connect tutorial',
        ]}
        structuredData={structuredData}
      />
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
          Learn authentication and identity protocols by running them. Execute real OAuth 2.0, OpenID Connect, 
          SAML 2.0, SPIFFE/SPIRE, SCIM 2.0, and SSF flows against working infrastructure and see exactly what happens at each step.
        </p>
      </header>

      {/* Value Props */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <ValueCard
          icon={Code}
          title="Real Protocol Execution"
          description="Not simulations - actual HTTP requests to a working identity provider"
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
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <NavCard
            to="/looking-glass"
            icon={Eye}
            color="cyan"
            title="Looking Glass"
            description="Execute protocol flows and inspect every step of the exchange in real-time."
            cta="Open Looking Glass"
          />
          <NavCard
            to="/ssf-sandbox"
            icon={Radio}
            color="amber"
            title="SSF Sandbox"
            description="Interactive playground for Shared Signals Framework - trigger events and watch real-time security signals."
            cta="Open Sandbox"
          />
          <NavCard
            to="/protocols"
            icon={Shield}
            color="purple"
            title="Protocol Reference"
            description="Documentation with sequence diagrams, parameters, and security considerations."
            cta="Browse Protocols"
          />
        </div>
      </section>

      {/* Available Protocols */}
      <section>
        <h2 className="text-sm font-medium text-surface-400 uppercase tracking-wider mb-4">
          Supported Protocols
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <ProtocolCard
            icon={Key}
            name="OAuth 2.0"
            description="Authorization framework for delegated access"
            color="blue"
            flows={['authorization_code', 'client_credentials', 'pkce', 'refresh_token']}
            to="/protocol/oauth2"
          />
          <ProtocolCard
            icon={Fingerprint}
            name="OpenID Connect"
            description="Authentication layer built on OAuth 2.0"
            color="orange"
            flows={['oidc_code', 'hybrid', 'userinfo', 'discovery']}
            to="/protocol/oidc"
          />
          <ProtocolCard
            icon={FileKey}
            name="SAML 2.0"
            description="XML-based federated identity and SSO"
            color="cyan"
            flows={['sp_initiated_sso', 'idp_initiated_sso', 'single_logout']}
            to="/protocol/saml"
          />
          <ProtocolCard
            icon={Shield}
            name="SPIFFE/SPIRE"
            description="Zero-trust workload identity framework"
            color="green"
            flows={['x509_svid', 'jwt_svid', 'mtls', 'cert_rotation']}
            to="/protocol/spiffe"
          />
          <ProtocolCard
            icon={Users}
            name="SCIM 2.0"
            description="Cross-domain identity provisioning"
            color="purple"
            flows={['user_lifecycle', 'group_mgmt', 'filters', 'bulk_ops']}
            to="/protocol/scim"
          />
          <ProtocolCard
            icon={Radio}
            name="SSF (Shared Signals)"
            description="Real-time security event sharing framework"
            color="amber"
            flows={['caep_events', 'risc_events', 'set_tokens', 'zero_trust']}
            to="/protocol/ssf"
          />
        </div>
      </section>

      {/* Coming Soon */}
      <section className="rounded-xl border border-dashed border-white/10 p-4 sm:p-6 text-center">
        <p className="text-surface-400 mb-2">More protocols on the roadmap</p>
        <div className="flex flex-wrap items-center justify-center gap-2 sm:gap-4 text-surface-400 text-sm">
          <span>WebAuthn</span>
          <span className="text-surface-700 hidden sm:inline">•</span>
          <span>FIDO2</span>
        </div>
      </section>

      {/* Quick References */}
      <section>
        <h2 className="text-sm font-medium text-surface-400 uppercase tracking-wider mb-3">
          Specifications
        </h2>
        <div className="space-y-2.5">
          {SPEC_GROUPS.map((group) => (
            <SpecGroup key={group.label} label={group.label} links={group.links} />
          ))}
        </div>
      </section>
    </div>
    </>
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
  color: 'cyan' | 'purple' | 'amber'
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
    amber: {
      border: 'border-amber-500/20 hover:border-amber-500/40',
      bg: 'from-amber-500/10',
      icon: 'bg-amber-500/20',
      iconText: 'text-amber-400',
      cta: 'text-amber-400',
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
  color: 'blue' | 'orange' | 'cyan' | 'green' | 'purple' | 'amber'
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
    green: {
      border: 'border-green-500/20 hover:border-green-500/40',
      bg: 'bg-green-500/10',
      text: 'text-green-400',
      tag: 'bg-green-500/10 text-green-300',
    },
    purple: {
      border: 'border-purple-500/20 hover:border-purple-500/40',
      bg: 'bg-purple-500/10',
      text: 'text-purple-400',
      tag: 'bg-purple-500/10 text-purple-300',
    },
    amber: {
      border: 'border-amber-500/20 hover:border-amber-500/40',
      bg: 'bg-amber-500/10',
      text: 'text-amber-400',
      tag: 'bg-amber-500/10 text-amber-300',
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
          <p className="text-sm text-surface-400 mb-3">{description}</p>
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

function SpecGroup({ label, links }: SpecGroupItem) {
  return (
    <div className="flex flex-wrap items-start gap-x-3 gap-y-1.5">
      <span className="text-surface-500 text-[11px] sm:text-xs font-medium uppercase tracking-wide w-full sm:w-24 flex-shrink-0 pt-1">
        {label}
      </span>
      <div className="flex flex-wrap gap-1.5">
        {links.map((link) => (
          <a
            key={link.label}
            href={link.url}
            target="_blank"
            rel="noopener noreferrer"
            className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs font-mono transition-colors ${
              link.tone === 'rfc'
                ? 'text-amber-300/90 hover:text-amber-200 hover:bg-amber-500/10'
                : 'text-emerald-300/90 hover:text-emerald-200 hover:bg-emerald-500/10'
            }`}
          >
            {link.label}
          </a>
        ))}
      </div>
    </div>
  )
}
