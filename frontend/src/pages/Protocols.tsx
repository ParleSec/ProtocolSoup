/**
 * Protocols Index Page
 * Lists all available protocols with links to their detail pages
 */

import { Link } from 'react-router-dom'
import { 
  Key, Fingerprint, FileKey, ChevronRight, 
  ExternalLink, BookOpen, Shield, Users
} from 'lucide-react'

const protocols = [
  {
    id: 'oauth2',
    name: 'OAuth 2.0',
    description: 'The industry-standard authorization framework for delegated access. Enables applications to obtain limited access to user accounts without exposing credentials.',
    icon: Key,
    color: 'blue',
    spec: 'RFC 6749',
    specUrl: 'https://datatracker.ietf.org/doc/html/rfc6749',
    flows: [
      { id: 'authorization-code', name: 'Authorization Code', rfc: '§4.1' },
      { id: 'authorization-code-pkce', name: 'Authorization Code + PKCE', rfc: 'RFC 7636' },
      { id: 'client-credentials', name: 'Client Credentials', rfc: '§4.4' },
      { id: 'refresh-token', name: 'Refresh Token', rfc: '§6' },
      { id: 'token-introspection', name: 'Token Introspection', rfc: 'RFC 7662' },
      { id: 'token-revocation', name: 'Token Revocation', rfc: 'RFC 7009' },
    ],
  },
  {
    id: 'oidc',
    name: 'OpenID Connect',
    description: 'An identity layer built on top of OAuth 2.0. Adds authentication to authorization, enabling clients to verify user identity and obtain basic profile information.',
    icon: Fingerprint,
    color: 'orange',
    spec: 'OpenID Connect Core 1.0',
    specUrl: 'https://openid.net/specs/openid-connect-core-1_0.html',
    flows: [
      { id: 'oidc-authorization-code', name: 'Authorization Code Flow', rfc: '§3.1' },
      { id: 'oidc-implicit', name: 'Implicit Flow (Legacy)', rfc: '§3.2' },
      { id: 'hybrid', name: 'Hybrid Flow', rfc: '§3.3' },
      { id: 'userinfo', name: 'UserInfo Endpoint', rfc: '§5.3' },
      { id: 'discovery', name: 'Discovery', rfc: 'Discovery 1.0' },
    ],
  },
  {
    id: 'saml',
    name: 'SAML 2.0',
    description: 'XML-based standard for exchanging authentication and authorization data between identity providers and service providers. Enables enterprise single sign-on.',
    icon: FileKey,
    color: 'cyan',
    spec: 'SAML 2.0 Core',
    specUrl: 'https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf',
    flows: [
      { id: 'sp-initiated-sso', name: 'SP-Initiated SSO', rfc: 'Profiles §4.1' },
      { id: 'idp-initiated-sso', name: 'IdP-Initiated SSO', rfc: 'Profiles §4.1.5' },
      { id: 'single-logout', name: 'Single Logout (SLO)', rfc: 'Profiles §4.4' },
      { id: 'metadata', name: 'Metadata Exchange', rfc: 'Metadata' },
    ],
  },
  {
    id: 'spiffe',
    name: 'SPIFFE/SPIRE',
    description: 'Secure Production Identity Framework for Everyone. Provides cryptographic workload identity for zero-trust architectures via X.509 and JWT SVIDs.',
    icon: Shield,
    color: 'green',
    spec: 'SPIFFE Specifications',
    specUrl: 'https://spiffe.io/docs/latest/spiffe-about/overview/',
    flows: [
      { id: 'x509-svid-issuance', name: 'X.509-SVID Acquisition', rfc: 'X.509-SVID' },
      { id: 'jwt-svid-issuance', name: 'JWT-SVID Acquisition', rfc: 'JWT-SVID' },
      { id: 'mtls-handshake', name: 'mTLS with X.509-SVIDs', rfc: 'RFC 8446' },
      { id: 'certificate-rotation', name: 'Certificate Rotation', rfc: 'Workload API' },
    ],
  },
  {
    id: 'scim',
    name: 'SCIM 2.0',
    description: 'System for Cross-domain Identity Management. Standards-based protocol for automating user provisioning and lifecycle management between identity providers and service providers.',
    icon: Users,
    color: 'purple',
    spec: 'RFC 7642, 7643, 7644',
    specUrl: 'https://datatracker.ietf.org/doc/html/rfc7644',
    flows: [
      { id: 'user-lifecycle', name: 'User Lifecycle', rfc: 'RFC 7644 §3.2-3.6' },
      { id: 'group-management', name: 'Group Management', rfc: 'RFC 7644 §3.2-3.6' },
      { id: 'filter-queries', name: 'Filter Queries', rfc: 'RFC 7644 §3.4.2' },
      { id: 'schema-discovery', name: 'Schema Discovery', rfc: 'RFC 7644 §4' },
      { id: 'bulk-operations', name: 'Bulk Operations', rfc: 'RFC 7644 §3.7' },
    ],
  },
]

const comingSoon = [
  { name: 'WebAuthn', description: 'Passwordless authentication' },
  { name: 'FIDO2', description: 'Strong authentication framework' },
]

export function Protocols() {
  return (
    <div className="max-w-4xl mx-auto space-y-6 sm:space-y-8">
      {/* Header */}
      <header className="py-2">
        <div className="flex items-center gap-3 mb-3">
          <div className="w-9 h-9 sm:w-10 sm:h-10 rounded-xl bg-purple-500/20 flex items-center justify-center flex-shrink-0">
            <BookOpen className="w-4 h-4 sm:w-5 sm:h-5 text-purple-400" />
          </div>
          <h1 className="text-xl sm:text-2xl font-semibold text-white">Protocol Reference</h1>
        </div>
        <p className="text-surface-400 ml-12 sm:ml-[52px] text-sm sm:text-base">
          Documentation, flow diagrams, and security considerations for each protocol.
        </p>
      </header>

      {/* Protocol List */}
      <section className="space-y-4">
        {protocols.map((protocol) => (
          <ProtocolCard key={protocol.id} protocol={protocol} />
        ))}
      </section>

      {/* Coming Soon */}
      <section>
        <h2 className="text-sm font-medium text-surface-400 uppercase tracking-wider mb-3">
          Coming Soon
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-2 md:grid-cols-4 gap-2 sm:gap-3">
          {comingSoon.map((item) => (
            <div 
              key={item.name}
              className="p-3 sm:p-4 rounded-xl border border-dashed border-white/10 text-center"
            >
              <div className="font-medium text-surface-400 text-sm sm:text-base">{item.name}</div>
              <div className="text-xs text-surface-600 mt-1">{item.description}</div>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}

function ProtocolCard({ protocol }: { protocol: typeof protocols[0] }) {
  const colors = {
    blue: {
      border: 'border-blue-500/20',
      bg: 'bg-blue-500/10',
      text: 'text-blue-400',
      tag: 'bg-blue-500/10 text-blue-300 border-blue-500/20',
    },
    orange: {
      border: 'border-orange-500/20',
      bg: 'bg-orange-500/10',
      text: 'text-orange-400',
      tag: 'bg-orange-500/10 text-orange-300 border-orange-500/20',
    },
    cyan: {
      border: 'border-cyan-500/20',
      bg: 'bg-cyan-500/10',
      text: 'text-cyan-400',
      tag: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/20',
    },
    green: {
      border: 'border-green-500/20',
      bg: 'bg-green-500/10',
      text: 'text-green-400',
      tag: 'bg-green-500/10 text-green-300 border-green-500/20',
    },
    purple: {
      border: 'border-purple-500/20',
      bg: 'bg-purple-500/10',
      text: 'text-purple-400',
      tag: 'bg-purple-500/10 text-purple-300 border-purple-500/20',
    },
  }
  const c = colors[protocol.color as keyof typeof colors]

  return (
    <div className={`rounded-xl border ${c.border} bg-surface-900/30 overflow-hidden`}>
      {/* Header */}
      <div className="p-4 sm:p-5 border-b border-white/5">
        <div className="flex items-start gap-3 sm:gap-4">
          <div className={`w-10 h-10 sm:w-12 sm:h-12 rounded-xl ${c.bg} flex items-center justify-center flex-shrink-0`}>
            <protocol.icon className={`w-5 h-5 sm:w-6 sm:h-6 ${c.text}`} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2 sm:gap-3 mb-1">
              <h2 className="text-lg sm:text-xl font-semibold text-white">{protocol.name}</h2>
              <a
                href={protocol.specUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 text-xs text-surface-400 hover:text-surface-300 active:text-surface-200 transition-colors"
              >
                <span className="hidden sm:inline">{protocol.spec}</span>
                <span className="sm:hidden">Spec</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
            <p className="text-surface-400 text-sm sm:text-base">{protocol.description}</p>
          </div>
        </div>
      </div>

      {/* Flows */}
      <div className="p-4 sm:p-5">
        <h3 className="text-sm font-medium text-surface-400 mb-3">Available Flows</h3>
        <div className="grid grid-cols-1 gap-2">
          {protocol.flows.map((flow) => (
            <Link
              key={flow.id}
              to={`/protocol/${protocol.id}/flow/${flow.id}`}
              className="flex items-center justify-between p-2.5 sm:p-3 rounded-lg border border-white/5 hover:border-white/10 hover:bg-white/[0.02] active:bg-white/[0.04] transition-all group"
            >
              <div className="flex flex-wrap items-center gap-2 sm:gap-3 min-w-0">
                <span className="text-white group-hover:text-white/90 text-sm sm:text-base">{flow.name}</span>
                <span className={`px-1.5 py-0.5 rounded text-[10px] sm:text-xs font-mono border flex-shrink-0 ${c.tag}`}>
                  {flow.rfc}
                </span>
              </div>
              <ChevronRight className="w-4 h-4 text-surface-600 group-hover:text-surface-400 transition-colors flex-shrink-0 ml-2" />
            </Link>
          ))}
        </div>
      </div>

      {/* Footer */}
      <div className="px-4 sm:px-5 py-3 border-t border-white/5 bg-surface-900/50">
        <Link
          to={`/protocol/${protocol.id}`}
          className={`inline-flex items-center gap-1.5 text-sm ${c.text} hover:underline active:opacity-80`}
        >
          View {protocol.name} overview
          <ChevronRight className="w-4 h-4" />
        </Link>
      </div>
    </div>
  )
}

