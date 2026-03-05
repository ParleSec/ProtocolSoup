/**
 * Protocols Index Page
 * Lists all available protocols with links to their detail pages
 */

import { Link } from 'react-router-dom'
import { 
  ChevronRight, ExternalLink, BookOpen
} from 'lucide-react'
import { SEO } from '../components/common/SEO'
import { generateBreadcrumbSchema, generateFAQSchema } from '../utils/schema'
import { SITE_CONFIG } from '../config/seo'
import {
  COMING_SOON_PROTOCOLS,
  PROTOCOL_CATALOG,
  type ProtocolCatalogItem,
} from '../protocols/presentation/protocol-catalog'

export function Protocols() {
  // Generate structured data for this page
  const breadcrumbSchema = generateBreadcrumbSchema([
    { name: 'Home', url: SITE_CONFIG.baseUrl },
    { name: 'Protocols', url: `${SITE_CONFIG.baseUrl}/protocols` },
  ])

  const faqSchema = generateFAQSchema([
    {
      question: 'What authentication protocols does Protocol Soup support?',
      answer: 'Protocol Soup supports OAuth 2.0, OpenID Connect (OIDC), SAML 2.0, SPIFFE/SPIRE, SCIM 2.0, and SSF (Shared Signals Framework). Each protocol includes multiple flows and detailed documentation.',
    },
    {
      question: 'What is the difference between OAuth 2.0 and OpenID Connect?',
      answer: 'OAuth 2.0 is an authorization framework that grants access to resources without sharing credentials. OpenID Connect is an authentication layer built on top of OAuth 2.0 that adds user identity verification through ID tokens.',
    },
    {
      question: 'What is SAML used for?',
      answer: 'SAML (Security Assertion Markup Language) is used for enterprise single sign-on (SSO), allowing users to authenticate once and access multiple applications without re-entering credentials.',
    },
    {
      question: 'What is the Shared Signals Framework (SSF)?',
      answer: 'SSF is an OpenID standard for real-time security event sharing between identity providers and applications. It includes CAEP (Continuous Access Evaluation Profile) for session management and RISC (Risk Incident Sharing and Coordination) for security incident response.',
    },
  ])

  return (
    <>
      <SEO
        title="Identity Protocol Reference Guide - OAuth 2.0, OIDC, SAML, SPIFFE, SCIM, SSF"
        description="Comprehensive reference for authentication and identity protocols. Documentation, sequence diagrams, and security considerations for OAuth 2.0, OpenID Connect, SAML 2.0, SPIFFE/SPIRE, SCIM 2.0, and Shared Signals Framework (SSF)."
        canonical="/protocols"
        ogType="website"
        keywords={[
          'identity protocol reference',
          'authentication protocols',
          'oauth2 documentation',
          'oidc specification',
          'saml documentation',
          'security protocols',
          'shared signals framework',
          'ssf caep risc',
          'security event tokens',
          'continuous access evaluation',
        ]}
        structuredData={[breadcrumbSchema, faqSchema]}
      />
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
        {PROTOCOL_CATALOG.map((protocol) => (
          <ProtocolCard key={protocol.id} protocol={protocol} />
        ))}
      </section>

      {/* Coming Soon */}
      <section>
        <h2 className="text-sm font-medium text-surface-400 uppercase tracking-wider mb-3">
          Coming Soon
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-2 md:grid-cols-4 gap-2 sm:gap-3">
          {COMING_SOON_PROTOCOLS.map((item) => (
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
    </>
  )
}

function ProtocolCard({ protocol }: { protocol: ProtocolCatalogItem }) {
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
    amber: {
      border: 'border-amber-500/20',
      bg: 'bg-amber-500/10',
      text: 'text-amber-400',
      tag: 'bg-amber-500/10 text-amber-300 border-amber-500/20',
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

