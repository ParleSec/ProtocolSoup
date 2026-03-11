/**
 * SEO Component for Protocol Soup
 * 
 * Provides dynamic meta tags, Open Graph, Twitter Cards,
 * canonical URLs, and JSON-LD structured data injection.
 */

import { Helmet } from 'react-helmet-async'
import { SITE_CONFIG, PageSEO } from '../../config/seo'

export interface SEOProps extends Partial<PageSEO> {
  /** Page title */
  title?: string
  /** Meta description */
  description?: string
  /** Canonical URL path (relative to base URL) */
  canonical?: string
  /** Open Graph type */
  ogType?: 'website' | 'article'
  /** Open Graph image URL */
  ogImage?: string
  /** Keywords for meta tag */
  keywords?: string[]
  /** JSON-LD structured data (can be object or array of objects) */
  structuredData?: object | object[]
  /** Prevent indexing */
  noIndex?: boolean
  /** Additional meta tags */
  meta?: Array<{ name?: string; property?: string; content: string }>
}

export function SEO({
  title,
  description,
  canonical,
  ogType = 'website',
  ogImage,
  keywords = [],
  structuredData,
  noIndex = false,
  meta = [],
}: SEOProps) {
  // Construct full title with site name while avoiding duplicate brand suffixes.
  const trimmedTitle = title?.trim()
  const titleHasSiteName = trimmedTitle
    ? trimmedTitle.toLowerCase().includes(SITE_CONFIG.name.toLowerCase())
    : false
  const fullTitle = trimmedTitle
    ? (titleHasSiteName ? trimmedTitle : `${trimmedTitle} | ${SITE_CONFIG.name}`)
    : `${SITE_CONFIG.name} - ${SITE_CONFIG.tagline}`

  // Use provided description or default
  const metaDescription = description || SITE_CONFIG.tagline

  // Construct canonical URL
  const canonicalUrl = canonical 
    ? `${SITE_CONFIG.baseUrl}${canonical.startsWith('/') ? canonical : `/${canonical}`}`
    : undefined

  // Use provided OG image or default
  const ogImageUrl = ogImage || SITE_CONFIG.defaultImage

  // Format structured data for injection
  const structuredDataJson = structuredData
    ? Array.isArray(structuredData)
      ? structuredData.map(data => JSON.stringify(data))
      : [JSON.stringify(structuredData)]
    : []

  return (
    <Helmet>
      {/* Primary Meta Tags */}
      <title>{fullTitle}</title>
      <meta name="title" content={fullTitle} />
      <meta name="description" content={metaDescription} />
      
      {/* Keywords */}
      {keywords.length > 0 && (
        <meta name="keywords" content={keywords.join(', ')} />
      )}
      
      {/* Canonical URL */}
      {canonicalUrl && <link rel="canonical" href={canonicalUrl} />}
      
      {/* Robots */}
      {noIndex ? (
        <meta name="robots" content="noindex, nofollow" />
      ) : (
        <meta name="robots" content="index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1" />
      )}
      
      {/* Open Graph / Facebook */}
      <meta property="og:type" content={ogType} />
      <meta property="og:site_name" content={SITE_CONFIG.name} />
      <meta property="og:title" content={fullTitle} />
      <meta property="og:description" content={metaDescription} />
      <meta property="og:image" content={ogImageUrl} />
      <meta property="og:image:alt" content={fullTitle} />
      <meta property="og:locale" content={SITE_CONFIG.locale} />
      {canonicalUrl && <meta property="og:url" content={canonicalUrl} />}
      
      {/* Twitter */}
      <meta name="twitter:card" content="summary_large_image" />
      <meta name="twitter:site" content={SITE_CONFIG.twitterHandle} />
      <meta name="twitter:creator" content={SITE_CONFIG.twitterHandle} />
      <meta name="twitter:title" content={fullTitle} />
      <meta name="twitter:description" content={metaDescription} />
      <meta name="twitter:image" content={ogImageUrl} />
      
      {/* Additional Meta Tags */}
      {meta.map((tag, index) => (
        <meta key={index} {...tag} />
      ))}
      
      {/* Structured Data / JSON-LD */}
      {structuredDataJson.map((json, index) => (
        <script key={index} type="application/ld+json">
          {json}
        </script>
      ))}
    </Helmet>
  )
}

/**
 * Preset SEO for common page types
 */
export function HomeSEO() {
  return (
    <SEO
      title="Protocol Soup | Run Real Authentication & Identity Protocol Flows"
      description="Execute real OAuth 2.0, OpenID Connect, OID4VCI, OID4VP, SAML, SPIFFE, SCIM and SSF flows against live infrastructure. Inspect every request, decode JWTs, and learn protocols hands-on."
      canonical="/"
      ogType="website"
      keywords={[
        'oauth2 playground',
        'oauth 2.0 testing tool',
        'oidc testing',
        'authentication protocol sandbox',
        'jwt decoder',
        'token inspector',
        'verifiable credentials',
        'oid4vci',
        'oid4vp',
        'saml testing tool',
        'identity protocol testing',
      ]}
    />
  )
}

export function ProtocolsSEO() {
  return (
    <SEO
      title="Identity Protocol Reference - OAuth 2.0, OIDC, OID4VCI, OID4VP, SAML, SPIFFE, SCIM, SSF"
      description="Comprehensive reference for authentication, identity, and verifiable credential protocols. Sequence diagrams, security considerations, and spec-accurate documentation for every flow."
      canonical="/protocols"
      ogType="website"
      keywords={[
        'identity protocol reference',
        'authentication protocols',
        'verifiable credential protocols',
        'oauth2 documentation',
        'oidc specification',
        'oid4vci documentation',
        'oid4vp specification',
        'saml documentation',
        'scim reference',
        'security protocols',
      ]}
    />
  )
}

export function LookingGlassSEO() {
  return (
    <SEO
      title="Looking Glass - Live Protocol Flow Execution & Traffic Inspector"
      description="Execute OAuth 2.0, OIDC, OID4VCI, OID4VP, SAML, SPIFFE, and SCIM flows in real-time. Inspect every HTTP request, response, header, and token as it happens."
      canonical="/looking-glass"
      ogType="website"
      keywords={[
        'protocol debugger',
        'oauth flow inspector',
        'http traffic inspector',
        'authentication debugger',
        'token debugger',
        'api testing tool',
        'verifiable credential debugger',
      ]}
    />
  )
}

export function SSFSandboxSEO() {
  return (
    <SEO
      title="SSF Sandbox - Shared Signals Framework Interactive Playground"
      description="Interactive playground for the Shared Signals Framework (SSF). Trigger CAEP and RISC security events, decode SET tokens, and understand real-time security signal sharing."
      canonical="/ssf-sandbox"
      ogType="website"
      keywords={[
        'shared signals framework',
        'ssf tutorial',
        'caep events',
        'risc events',
        'security event tokens',
        'zero trust signals',
      ]}
    />
  )
}

export function NotFoundSEO() {
  return (
    <SEO
      title="Page Not Found"
      description="The page you're looking for doesn't exist."
      noIndex={true}
    />
  )
}

