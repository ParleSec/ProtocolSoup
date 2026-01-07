/**
 * SEO Component for Protocol Soup
 * 
 * Provides dynamic meta tags, Open Graph, Twitter Cards,
 * canonical URLs, and JSON-LD structured data injection.
 */

import { Helmet } from 'react-helmet-async'
import { SITE_CONFIG, PageSEO } from '../../config/seo'

export interface SEOProps extends Partial<PageSEO> {
  /** Page title - will be appended with site name */
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
  // Construct full title with site name
  const fullTitle = title 
    ? `${title} | ${SITE_CONFIG.name}`
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
      title="Interactive OAuth 2.0, OIDC & SAML Testing Playground"
      description="Learn authentication protocols by running them. Execute real OAuth 2.0, OpenID Connect, SAML 2.0, SPIFFE/SPIRE, and SCIM flows against working infrastructure. Decode JWTs, inspect tokens, and understand security flows."
      canonical="/"
      ogType="website"
      keywords={[
        'oauth2 playground',
        'oauth testing tool',
        'oidc testing',
        'authentication protocol sandbox',
        'jwt decoder',
        'token inspector',
      ]}
    />
  )
}

export function ProtocolsSEO() {
  return (
    <SEO
      title="Identity Protocol Reference Guide - OAuth 2.0, OIDC, SAML, SPIFFE, SCIM"
      description="Comprehensive reference for authentication and identity protocols. Documentation, sequence diagrams, and security considerations for OAuth 2.0, OpenID Connect, SAML 2.0, SPIFFE/SPIRE, and SCIM 2.0."
      canonical="/protocols"
      ogType="website"
      keywords={[
        'identity protocol reference',
        'authentication protocols',
        'oauth2 documentation',
        'oidc specification',
        'saml documentation',
      ]}
    />
  )
}

export function LookingGlassSEO() {
  return (
    <SEO
      title="Looking Glass - Live Protocol Flow Execution & Traffic Inspector"
      description="Execute authentication protocol flows in real-time and inspect every HTTP request, response, header, and token. See OAuth 2.0, OIDC, and SAML flows as they happen."
      canonical="/looking-glass"
      ogType="website"
      keywords={[
        'protocol debugger',
        'oauth flow inspector',
        'http traffic inspector',
        'authentication debugger',
        'token debugger',
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

