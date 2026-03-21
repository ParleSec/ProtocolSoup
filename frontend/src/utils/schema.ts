/**
 * Schema.org JSON-LD Generators for Rich Snippets
 * 
 * Generates structured data for Google rich results, knowledge panels,
 * and enhanced search listings.
 */

import { SITE_CONFIG } from '../config/seo'

/**
 * Base organization schema (used across pages)
 */
export function generateOrganizationSchema() {
  return {
    '@context': 'https://schema.org',
    '@type': 'Organization',
    '@id': `${SITE_CONFIG.baseUrl}#organization`,
    name: SITE_CONFIG.name,
    url: SITE_CONFIG.baseUrl,
    logo: `${SITE_CONFIG.baseUrl}/icons/icon-512.svg`,
    sameAs: [
      `https://twitter.com/${SITE_CONFIG.twitterHandle.replace('@', '')}`,
      'https://github.com/ParleSec/ProtocolSoup',
    ],
  }
}

/**
 * WebApplication schema for the main tool
 */
export function generateWebApplicationSchema() {
  return {
    '@context': 'https://schema.org',
    '@type': 'WebApplication',
    name: SITE_CONFIG.name,
    description: 'Interactive playground for learning authentication and verifiable credential protocols by running real OAuth 2.0, OpenID Connect, OID4VCI, OID4VP, SAML, SPIFFE, and SCIM flows.',
    url: SITE_CONFIG.baseUrl,
    applicationCategory: 'DeveloperApplication',
    operatingSystem: 'Web Browser',
    offers: {
      '@type': 'Offer',
      price: '0',
      priceCurrency: 'USD',
    },
    featureList: [
      'Real protocol execution against working infrastructure',
      'Live HTTP traffic inspection',
      'JWT token decoding and validation',
      'OAuth 2.0 flow visualization',
      'OpenID Connect testing',
      'OID4VCI issuance flow testing',
      'OID4VP verification flow testing',
      'SAML 2.0 SSO debugging',
      'SPIFFE/SPIRE workload identity',
      'SCIM 2.0 provisioning testing',
    ],
    screenshot: `${SITE_CONFIG.baseUrl}/opengraph-image`,
    softwareVersion: '1.0.0',
    author: {
      '@type': 'Person',
      name: SITE_CONFIG.author,
    },
  }
}

/**
 * SoftwareApplication schema (alternative for app stores)
 */
export function generateSoftwareApplicationSchema() {
  return {
    '@context': 'https://schema.org',
    '@type': 'SoftwareApplication',
    name: SITE_CONFIG.name,
    description: 'Learn authentication and identity protocols by executing real flows. Interactive OAuth 2.0, OIDC, OID4VCI, OID4VP, SAML, SPIFFE, and SCIM testing tool.',
    url: SITE_CONFIG.baseUrl,
    applicationCategory: 'SecurityApplication',
    operatingSystem: 'Any',
    offers: {
      '@type': 'Offer',
      price: '0',
      priceCurrency: 'USD',
    },
  }
}

/**
 * WebSite schema for brand/entity clarity in search
 */
export function generateWebsiteSchema() {
  return {
    '@context': 'https://schema.org',
    '@type': 'WebSite',
    '@id': `${SITE_CONFIG.baseUrl}#website`,
    name: SITE_CONFIG.name,
    url: SITE_CONFIG.baseUrl,
    inLanguage: 'en-US',
    publisher: {
      '@id': `${SITE_CONFIG.baseUrl}#organization`,
    },
  }
}

/**
 * TechArticle schema for protocol documentation pages
 */
export interface TechArticleParams {
  title: string
  description: string
  url: string
  datePublished?: string
  dateModified?: string
  keywords?: string[]
}

export function generateTechArticleSchema(params: TechArticleParams) {
  return {
    '@context': 'https://schema.org',
    '@type': 'TechArticle',
    headline: params.title,
    description: params.description,
    url: params.url,
    datePublished: params.datePublished || '2024-01-01',
    dateModified: params.dateModified || new Date().toISOString().split('T')[0],
    author: {
      '@type': 'Person',
      name: SITE_CONFIG.author,
    },
    publisher: {
      '@type': 'Organization',
      name: SITE_CONFIG.name,
      logo: {
        '@type': 'ImageObject',
        url: `${SITE_CONFIG.baseUrl}/icons/icon-512.svg`,
      },
    },
    mainEntityOfPage: {
      '@type': 'WebPage',
      '@id': params.url,
    },
    keywords: params.keywords?.join(', '),
    inLanguage: 'en-US',
    isAccessibleForFree: true,
  }
}

/**
 * HowTo schema for flow step-by-step guides
 */
export interface HowToStep {
  name: string
  description: string
  url?: string
}

export interface HowToParams {
  name: string
  description: string
  url: string
  totalTime?: string // ISO 8601 duration, e.g., "PT10M" for 10 minutes
  steps: HowToStep[]
  tools?: string[]
}

export function generateHowToSchema(params: HowToParams) {
  return {
    '@context': 'https://schema.org',
    '@type': 'HowTo',
    name: params.name,
    description: params.description,
    url: params.url,
    totalTime: params.totalTime || 'PT15M',
    tool: params.tools?.map(tool => ({
      '@type': 'HowToTool',
      name: tool,
    })),
    step: params.steps.map((step, index) => ({
      '@type': 'HowToStep',
      position: index + 1,
      name: step.name,
      text: step.description,
      url: step.url || `${params.url}#step-${index + 1}`,
    })),
    author: {
      '@type': 'Person',
      name: SITE_CONFIG.author,
    },
  }
}

/**
 * BreadcrumbList schema for navigation hierarchy
 */
export interface BreadcrumbItem {
  name: string
  url: string
}

export function generateBreadcrumbSchema(items: BreadcrumbItem[]) {
  return {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: items.map((item, index) => ({
      '@type': 'ListItem',
      position: index + 1,
      name: item.name,
      item: item.url,
    })),
  }
}

/**
 * FAQPage schema for "People Also Ask" targeting
 */
export interface FAQItem {
  question: string
  answer: string
}

export function generateFAQSchema(faqs: FAQItem[]) {
  return {
    '@context': 'https://schema.org',
    '@type': 'FAQPage',
    mainEntity: faqs.map(faq => ({
      '@type': 'Question',
      name: faq.question,
      acceptedAnswer: {
        '@type': 'Answer',
        text: faq.answer,
      },
    })),
  }
}

/**
 * Combined schema for homepage
 */
export function generateHomepageSchema() {
  return [
    generateWebsiteSchema(),
    generateWebApplicationSchema(),
    generateOrganizationSchema(),
    generateFAQSchema([
      {
        question: 'What is Protocol Soup?',
        answer: 'Protocol Soup is a free, interactive testing tool for authentication and identity protocols. Execute real OAuth 2.0, OpenID Connect, OID4VCI, OID4VP, SAML 2.0, SPIFFE/SPIRE, SCIM 2.0, and SSF flows against live infrastructure, inspect every HTTP exchange, and decode tokens in real-time.',
      },
      {
        question: 'How do I test OAuth 2.0 flows?',
        answer: 'Protocol Soup lets you execute real OAuth 2.0 flows — Authorization Code, Authorization Code + PKCE, Client Credentials, Refresh Token, Token Introspection, and Token Revocation — against a working authorization server. You see every request, response, header, and token as it happens.',
      },
      {
        question: 'What is the difference between OAuth 2.0 and OpenID Connect?',
        answer: 'OAuth 2.0 is an authorization framework that grants delegated access to resources. OpenID Connect (OIDC) is an authentication layer built on OAuth 2.0 that adds an ID token containing verified user identity claims. OAuth answers "what can this app access?" while OIDC answers "who is this user?"',
      },
      {
        question: 'What are verifiable credentials and how do OID4VCI and OID4VP work?',
        answer: 'Verifiable credentials are tamper-evident digital credentials (like diplomas or licenses) that a holder can present to a verifier. OID4VCI (OpenID for Verifiable Credential Issuance) defines how an issuer delivers credentials to a wallet. OID4VP (OpenID for Verifiable Presentations) defines how a verifier requests and validates credential presentations from a wallet.',
      },
      {
        question: 'What is PKCE and why is it required for OAuth 2.0?',
        answer: 'PKCE (Proof Key for Code Exchange, RFC 7636) prevents authorization code interception attacks by binding the token request to the original authorization request via a code_verifier/code_challenge pair. It is required for public clients (SPAs, mobile apps) and recommended for all OAuth 2.0 clients.',
      },
      {
        question: 'How is SAML different from OAuth and OIDC?',
        answer: 'SAML 2.0 is an XML-based federation protocol primarily used for enterprise single sign-on (SSO) between identity providers and service providers. OAuth 2.0 and OIDC are JSON/REST-based protocols designed for API authorization and modern web/mobile authentication. SAML predates OAuth and is common in enterprise environments.',
      },
      {
        question: 'What is SPIFFE and how does it provide zero-trust workload identity?',
        answer: 'SPIFFE (Secure Production Identity Framework For Everyone) provides cryptographic identities to workloads in distributed systems. SPIRE is the reference implementation that issues X.509-SVIDs and JWT-SVIDs, enabling mTLS between services and automatic certificate rotation — the foundation for zero-trust service mesh architectures.',
      },
      {
        question: 'What is SCIM 2.0 and how does it automate user provisioning?',
        answer: 'SCIM 2.0 (System for Cross-domain Identity Management, RFC 7644) is a REST API standard for automating user and group provisioning across identity domains. It supports create, read, update, delete operations, filter queries, bulk operations, and schema discovery.',
      },
      {
        question: 'What is the Shared Signals Framework (SSF)?',
        answer: 'SSF enables real-time security event sharing between cooperating systems using Security Event Tokens (SETs). It includes CAEP (Continuous Access Evaluation Protocol) for session signals and RISC (Risk Incident Sharing and Coordination) for account compromise signals — essential for zero-trust continuous authorization.',
      },
    ]),
  ]
}

/**
 * Protocol page schema generator
 */
export function generateProtocolPageSchema(
  protocolName: string,
  description: string,
  url: string,
  flows: Array<{ name: string; description: string }>
) {
  const techArticle = generateTechArticleSchema({
    title: `${protocolName} Tutorial - Complete Guide`,
    description,
    url,
    keywords: [protocolName.toLowerCase(), 'authentication', 'identity', 'tutorial'],
  })

  const breadcrumbs = generateBreadcrumbSchema([
    { name: 'Home', url: SITE_CONFIG.baseUrl },
    { name: 'Protocols', url: `${SITE_CONFIG.baseUrl}/protocols` },
    { name: protocolName, url },
  ])

  // Generate FAQ from flows
  const faqs = flows.slice(0, 5).map(flow => ({
    question: `How does the ${flow.name} flow work in ${protocolName}?`,
    answer: flow.description,
  }))

  return [techArticle, breadcrumbs, ...(faqs.length > 0 ? [generateFAQSchema(faqs)] : [])]
}

/**
 * Flow detail page schema generator
 */
export function generateFlowPageSchema(
  protocolId: string,
  protocolName: string,
  flowName: string,
  description: string,
  url: string,
  steps: Array<{ name: string; description: string }>
) {
  const protocolSlug = protocolId || protocolName.toLowerCase().replace(/[^a-z0-9]/g, '')

  const howTo = generateHowToSchema({
    name: `How to implement ${flowName} in ${protocolName}`,
    description,
    url,
    totalTime: 'PT15M',
    steps: steps.map(step => ({
      name: step.name,
      description: step.description,
    })),
    tools: ['Web Browser', 'Protocol Soup', 'Code Editor'],
  })

  const techArticle = generateTechArticleSchema({
    title: `${flowName} - ${protocolName} Flow Guide`,
    description,
    url,
    keywords: [flowName.toLowerCase(), protocolName.toLowerCase(), 'tutorial', 'implementation'],
  })

  const breadcrumbs = generateBreadcrumbSchema([
    { name: 'Home', url: SITE_CONFIG.baseUrl },
    { name: 'Protocols', url: `${SITE_CONFIG.baseUrl}/protocols` },
    { name: protocolName, url: `${SITE_CONFIG.baseUrl}/protocol/${protocolSlug}` },
    { name: flowName, url },
  ])

  return [howTo, techArticle, breadcrumbs]
}

