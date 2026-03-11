import { Link } from 'react-router-dom'
import { 
  Shield, Eye, Terminal, Fingerprint, 
  ChevronRight, Key, KeyRound,
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
    label: 'SAML',
    links: [
      { label: 'RFC 7522', url: 'https://datatracker.ietf.org/doc/rfc7522/', tone: 'rfc' },
    ],
  },
  {
    label: 'OpenID4VC',
    links: [
      { label: 'OpenID4VCI 1.0', url: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html', tone: 'spec' },
      { label: 'OpenID4VP 1.0', url: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html', tone: 'spec' },
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
        title="OAuth 2.0 Playground & Identity Protocol Testing Tool | Protocol Soup"
        description="Execute real OAuth 2.0, OpenID Connect, OID4VCI, OID4VP, SAML, SPIFFE, SCIM and SSF flows against live infrastructure. Inspect every request, decode JWTs, and learn protocols hands-on."
        canonical="/"
        ogType="website"
        keywords={[
          'oauth2 playground',
          'oauth 2.0 testing tool',
          'oidc testing',
          'openid connect playground',
          'authentication protocol sandbox',
          'jwt decoder',
          'token inspector',
          'oauth2 tutorial',
          'openid connect tutorial',
          'saml testing tool',
          'saml 2.0 playground',
          'verifiable credentials',
          'oid4vci playground',
          'oid4vp testing',
          'openid4vci',
          'openid4vp',
          'spiffe spire tutorial',
          'scim 2.0 testing',
          'identity protocol testing',
          'oauth flow visualization',
          'pkce tutorial',
          'security protocol sandbox',
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
          <span className="text-2xl sm:text-3xl" aria-hidden="true">🍜</span>
        </h1>
        <p className="text-surface-300 text-base sm:text-lg max-w-2xl">
          Learn authentication and identity protocols by running them. Execute real protocol flows against working 
          infrastructure and see exactly what happens at each step.
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
            to="/protocol/oauth2"
          />
          <ProtocolCard
            icon={FileKey}
            name="SAML 2.0"
            description="XML-based federated identity and SSO"
            color="cyan"
            to="/protocol/saml"
          />
          <ProtocolCard
            icon={Fingerprint}
            name="OpenID Connect"
            description="Authentication layer built on OAuth 2.0"
            color="orange"
            to="/protocol/oidc"
          />
          <ProtocolCard
            icon={Radio}
            name="SSF"
            description="Real-time security event sharing framework"
            color="amber"
            to="/protocol/ssf"
          />
          <ProtocolCard
            icon={KeyRound}
            name="OID4VCI"
            description="Verifiable credential issuance over OpenID"
            color="green"
            to="/protocol/oid4vci"
          />
          <ProtocolCard
            icon={Shield}
            name="SPIFFE/SPIRE"
            description="Zero-trust workload identity framework"
            color="green"
            to="/protocol/spiffe"
          />
          <ProtocolCard
            icon={Eye}
            name="OID4VP"
            description="Verifiable presentation requests and verification"
            color="purple"
            to="/protocol/oid4vp"
          />
          <ProtocolCard
            icon={Users}
            name="SCIM 2.0"
            description="Cross-domain identity provisioning"
            color="purple"
            to="/protocol/scim"
          />
          <ComingSoonCard name="WebAuthn" description="Passwordless authentication" />
          <ComingSoonCard name="FIDO2" description="Strong authentication framework" />
        </div>
      </section>

      {/* Quick References */}
      <section>
        <h2 className="text-sm font-medium text-surface-400 uppercase tracking-wider mb-3">
          Specifications
        </h2>
        <div className="space-y-0.5 sm:space-y-2.5">
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
    <div className="p-4 rounded-xl bg-surface-900/50 border border-white/10">
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
      className={`group relative overflow-hidden rounded-xl border ${c.border} bg-gradient-to-br ${c.bg} to-transparent p-6 transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/30 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-950`}
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
  to,
}: {
  icon: React.ElementType
  name: string
  description: string
  color: 'blue' | 'orange' | 'cyan' | 'green' | 'purple' | 'amber'
  to: string
}) {
  const colors = {
    blue: {
      border: 'border-blue-500/20 hover:border-blue-500/40',
      accent: 'bg-blue-500/50',
      bg: 'bg-blue-500/10',
      text: 'text-blue-400',
    },
    orange: {
      border: 'border-orange-500/20 hover:border-orange-500/40',
      accent: 'bg-orange-500/50',
      bg: 'bg-orange-500/10',
      text: 'text-orange-400',
    },
    cyan: {
      border: 'border-cyan-500/20 hover:border-cyan-500/40',
      accent: 'bg-cyan-500/50',
      bg: 'bg-cyan-500/10',
      text: 'text-cyan-400',
    },
    green: {
      border: 'border-green-500/20 hover:border-green-500/40',
      accent: 'bg-green-500/50',
      bg: 'bg-green-500/10',
      text: 'text-green-400',
    },
    purple: {
      border: 'border-purple-500/20 hover:border-purple-500/40',
      accent: 'bg-purple-500/50',
      bg: 'bg-purple-500/10',
      text: 'text-purple-400',
    },
    amber: {
      border: 'border-amber-500/20 hover:border-amber-500/40',
      accent: 'bg-amber-500/50',
      bg: 'bg-amber-500/10',
      text: 'text-amber-400',
    },
  }
  const c = colors[color]

  return (
    <Link to={to} className={`block rounded-xl border ${c.border} bg-surface-900/30 overflow-hidden transition-colors group focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/30 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-950`}>
      <div className={`h-0.5 ${c.accent}`} />
      <div className="flex items-center gap-3 p-4">
        <div className={`w-9 h-9 rounded-lg ${c.bg} flex items-center justify-center flex-shrink-0`}>
          <Icon className={`w-[18px] h-[18px] ${c.text}`} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-white text-sm">{name}</span>
            <ChevronRight className="w-3.5 h-3.5 text-surface-600 group-hover:text-surface-400 transition-colors" />
          </div>
          <p className="text-xs text-surface-400 mt-0.5">{description}</p>
        </div>
      </div>
    </Link>
  )
}

function ComingSoonCard({ name, description }: { name: string; description: string }) {
  return (
    <div className="block rounded-xl border border-dashed border-white/10 bg-surface-900/20 overflow-hidden">
      <div className="h-0.5 bg-white/10" />
      <div className="flex items-center gap-3 p-4">
        <div className="w-9 h-9 rounded-lg bg-white/5 flex items-center justify-center flex-shrink-0">
          <span className="text-surface-600 text-xs font-bold">?</span>
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-surface-500 text-sm">{name}</span>
            <span className="px-1.5 py-0.5 rounded text-[10px] font-medium uppercase tracking-wide bg-white/5 text-surface-500">Soon</span>
          </div>
          <p className="text-xs text-surface-600 mt-0.5">{description}</p>
        </div>
      </div>
    </div>
  )
}

function SpecGroup({ label, links }: SpecGroupItem) {
  return (
    <div className="border-l-2 border-white/[0.06] hover:border-white/15 pl-3 pr-1 py-px sm:py-1 rounded-r-md transition-colors duration-200">
      <span className="text-surface-500 text-[11px] sm:text-xs font-medium uppercase tracking-wide block mb-0.5">
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
