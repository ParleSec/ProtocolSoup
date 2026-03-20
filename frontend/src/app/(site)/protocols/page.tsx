import { Protocols } from '@/views/Protocols'
import { PAGE_SEO, SITE_CONFIG } from '@/config/seo'
import { createPageMetadata } from '@/lib/seo'
import { generateBreadcrumbSchema, generateFAQSchema } from '@/utils/schema'

const seo = PAGE_SEO['/protocols']

export const revalidate = 3600

export const metadata = createPageMetadata({
  title: seo.title,
  description: seo.description,
  keywords: seo.keywords,
  path: '/protocols',
  type: 'website',
})

export default function ProtocolsPage() {
  const schemas = [
    generateBreadcrumbSchema([
      { name: 'Home', url: SITE_CONFIG.baseUrl },
      { name: 'Protocols', url: `${SITE_CONFIG.baseUrl}/protocols` },
    ]),
    generateFAQSchema([
      {
        question: 'What authentication protocols does Protocol Soup support?',
        answer:
          'Protocol Soup supports OAuth 2.0, OpenID Connect (OIDC), OID4VCI, OID4VP, SAML 2.0, SPIFFE/SPIRE, SCIM 2.0, and SSF (Shared Signals Framework). Each protocol includes multiple flows and detailed documentation.',
      },
      {
        question: 'What is the difference between OAuth 2.0 and OpenID Connect?',
        answer:
          'OAuth 2.0 is an authorization framework that grants access to resources without sharing credentials. OpenID Connect is an authentication layer built on top of OAuth 2.0 that adds user identity verification through ID tokens.',
      },
      {
        question: 'What is SAML used for?',
        answer:
          'SAML (Security Assertion Markup Language) is used for enterprise single sign-on (SSO), allowing users to authenticate once and access multiple applications without re-entering credentials.',
      },
      {
        question: 'What is the Shared Signals Framework (SSF)?',
        answer:
          'SSF is an OpenID standard for real-time security event sharing between identity providers and applications. It includes CAEP (Continuous Access Evaluation Profile) for session management and RISC (Risk Incident Sharing and Coordination) for security incident response.',
      },
      {
        question: 'What are OID4VCI and OID4VP used for?',
        answer:
          'OID4VCI (OpenID for Verifiable Credential Issuance) is used to issue verifiable credentials to wallets. OID4VP (OpenID for Verifiable Presentations) is used by verifiers to request and validate credential presentations from wallets.',
      },
    ]),
  ]

  return (
    <>
      {schemas.map((schema, index) => (
        <script
          key={`protocols-schema-${index}`}
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }}
        />
      ))}
      <Protocols />
    </>
  )
}

