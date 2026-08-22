import Link from 'next/link'
import { 
  Shield, Eye, Terminal, Wallet, ExternalLink,
  ChevronRight, Code, FileSearch, Zap
} from 'lucide-react'

import { HomepagePalette } from '@/components/palette/HomepagePalette'
import { SITE_CONFIG } from '@/config/seo'
import certification from '@/data/openid-certification.json'
import { PROTOCOL_ACCENT_CLASSES, PROTOCOL_CATALOG, COMING_SOON_PROTOCOLS, protocolHomepageBlurb } from '@/protocols/presentation/protocol-catalog'

interface SpecLinkItem {
  label: string
  url: string
  tone?: 'rfc' | 'spec'
}

interface SpecGroupItem {
  label: string
  links: SpecLinkItem[]
}

const showCertifiedMark =
  certification.status === 'active' && certification.profiles.length > 0

const SPEC_GROUPS: SpecGroupItem[] = [
  {
    label: 'OAuth/OIDC',
    links: [
      { label: 'RFC 6749', url: 'https://datatracker.ietf.org/doc/html/rfc6749', tone: 'rfc' },
      { label: 'RFC 7636', url: 'https://datatracker.ietf.org/doc/html/rfc7636', tone: 'rfc' },
      { label: 'RFC 8414', url: 'https://datatracker.ietf.org/doc/html/rfc8414', tone: 'rfc' },
      { label: 'RFC 9700', url: 'https://datatracker.ietf.org/doc/html/rfc9700', tone: 'rfc' },
      { label: 'OIDC Core', url: 'https://openid.net/specs/openid-connect-core-1_0.html', tone: 'spec' },
    ],
  },
  {
    label: 'SAML',
    links: [
      { label: 'SAML 2.0 Core', url: 'https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf', tone: 'spec' },
      { label: 'Bindings', url: 'https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf', tone: 'spec' },
      { label: 'Profiles', url: 'https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf', tone: 'spec' },
      { label: 'Metadata', url: 'https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf', tone: 'spec' },
    ],
  },
  {
    label: 'OpenID4VC',
    links: [
      { label: 'OpenID4VCI 1.0', url: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html', tone: 'spec' },
      { label: 'OpenID4VP 1.0', url: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html', tone: 'spec' },
      { label: 'HAIP 1.0', url: 'https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html', tone: 'spec' },
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
      { label: 'SSF 1.0', url: 'https://openid.net/specs/openid-sharedsignals-framework-1_0.html', tone: 'spec' },
    ],
  },
]

export function Dashboard() {
  return (
    <div className="max-w-4xl mx-auto space-y-8 sm:space-y-10">
      {/* Header */}
      <header className="py-2 sm:py-4">
        <div className="flex items-center gap-2 text-amber-400 font-mono text-sm mb-3">
          <Terminal className="w-4 h-4" />
          <span>live protocol execution</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-semibold text-white mb-3 flex items-center gap-3">
          ProtocolSoup
          <span className="text-2xl sm:text-3xl" aria-hidden="true">🍜</span>
        </h1>
        <p className="text-surface-300 text-base sm:text-lg max-w-2xl">
          Run real identity protocol flows against live infrastructure. Inspect every request, token, and validation decision.
        </p>
      </header>

      {/* Palette: prominent multi-axis content retrieval surface */}
      <section aria-label="Search protocols, flows, and concepts">
        <HomepagePalette />
      </section>

      {/* Value Props */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <ValueCard
          icon={Code}
          title="Real Protocol Execution"
          description="Live HTTP to working authorization servers, issuers, verifiers, and event transmitters."
        />
        <ValueCard
          icon={FileSearch}
          title="Full Traffic Inspection"
          description="See every request, response, header, and parameter exchanged"
        />
        <ValueCard
          icon={Zap}
          title="Live Artifact Decoding"
          description="Decode JWTs, SAML assertions, SETs, and issued credentials as they are produced"
        />
      </section>

      {/* Main Navigation */}
      <section>
        <h2 className="text-sm font-medium text-surface-400 uppercase tracking-wider mb-4">
          Start here
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <NavCard
            to="/looking-glass"
            icon={Eye}
            color="cyan"
            title="Looking Glass"
            description="Execute live protocol flows and inspect every hop, token, and validation decision."
            cta="Open Looking Glass"
          />
          <NavCard
            to="/protocols"
            icon={Shield}
            color="purple"
            title="Protocol Reference"
            description="Guides, sequence diagrams, parameters, and security considerations for every shipped protocol family."
            cta="Browse Protocols"
          />
          <NavCard
            to={SITE_CONFIG.walletUrl}
            icon={Wallet}
            color="amber"
            title="Wallet Harness"
            description="Issue and present mdoc and SD-JWT credentials with a real OID4VCI and OID4VP wallet, including HAIP attestation."
            cta="Open Wallet"
          />
        </div>
      </section>

      {/* Available Protocols */}
      <section>
        <h2 className="text-sm font-medium text-surface-400 uppercase tracking-wider mb-4">
          Supported Protocols
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {PROTOCOL_CATALOG.map((protocol) => (
            <ProtocolCard
              key={protocol.id}
              icon={protocol.icon}
              name={protocol.name}
              description={protocolHomepageBlurb(protocol.id, protocol.description)}
              color={protocol.color}
              to={`/protocol/${protocol.id}`}
            />
          ))}
          {COMING_SOON_PROTOCOLS.map((item) => (
            <ComingSoonCard key={item.name} name={item.name} description={item.description} />
          ))}
        </div>
      </section>

      {showCertifiedMark ? (
        <section>
          <Link
            href="/trust#conformance"
            className="flex items-center gap-4 rounded-xl border border-white/10 bg-surface-900/30 p-4 transition-colors hover:border-white/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/30 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-950"
          >
            <span className="shrink-0 rounded-md bg-white p-1.5">
              <img
                src="/openid-certified.png"
                alt=""
                className="h-10 w-auto"
              />
            </span>
            <span className="min-w-0 flex-1">
              <span className="block text-sm font-medium text-white">OpenID Certified™</span>
              <span className="mt-0.5 block text-xs text-surface-400 leading-relaxed">
                {certification.tagline}
              </span>
            </span>
            <ChevronRight className="w-4 h-4 shrink-0 text-surface-600" />
          </Link>
        </section>
      ) : null}

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
  )
}

export default Dashboard

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
  const c = colors[color] ?? colors.cyan
  const isExternal = /^https?:\/\//.test(to)
  const className = `group relative overflow-hidden rounded-xl border ${c.border} bg-gradient-to-br ${c.bg} to-transparent p-6 transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/30 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-950`
  const body = (
    <>
      <div className={`absolute top-0 right-0 w-32 h-32 ${c.bg.replace('from-', 'bg-')} rounded-full blur-2xl -translate-y-1/2 translate-x-1/2 opacity-50 hidden sm:block`} />
      <div className="relative">
        <div className={`w-12 h-12 rounded-xl ${c.icon} flex items-center justify-center mb-4`}>
          <Icon className={`w-6 h-6 ${c.iconText}`} />
        </div>
        <h3 className="text-xl font-semibold text-white mb-2">{title}</h3>
        <p className="text-surface-400 mb-4 leading-relaxed">{description}</p>
        <span className={`inline-flex items-center gap-1.5 ${c.cta} text-sm font-medium group-hover:gap-2.5 transition-all`}>
          {cta} {isExternal ? <ExternalLink className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </span>
      </div>
    </>
  )

  if (isExternal) {
    return (
      <a href={to} rel="noopener noreferrer" className={className}>
        {body}
      </a>
    )
  }

  return (
    <Link href={to} className={className}>
      {body}
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
  color: keyof typeof PROTOCOL_ACCENT_CLASSES
  to: string
}) {
  const c = PROTOCOL_ACCENT_CLASSES[color]

  return (
    <Link href={to} className={`block rounded-xl border ${c.border} ${c.borderHover} bg-surface-900/30 overflow-hidden transition-colors group focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/30 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-950`}>
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
