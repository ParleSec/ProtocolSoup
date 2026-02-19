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
    name: SITE_CONFIG.name,
    url: SITE_CONFIG.baseUrl,
    logo: `${SITE_CONFIG.baseUrl}/icons/icon-512.png`,
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
    description: 'Interactive playground for learning authentication protocols by running real OAuth 2.0, OpenID Connect, SAML, SPIFFE, and SCIM flows.',
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
      'SAML 2.0 SSO debugging',
      'SPIFFE/SPIRE workload identity',
      'SCIM 2.0 provisioning testing',
    ],
    screenshot: `${SITE_CONFIG.baseUrl}/og-image.png`,
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
    description: 'Learn authentication and identity protocols by executing real flows. Interactive OAuth 2.0, OIDC, SAML, SPIFFE, and SCIM testing tool.',
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
    name: SITE_CONFIG.name,
    url: SITE_CONFIG.baseUrl,
    inLanguage: 'en-US',
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
        url: `${SITE_CONFIG.baseUrl}/icons/icon-512.png`,
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
        answer: 'Protocol Soup is an interactive playground for learning authentication and identity protocols. You can execute real OAuth 2.0, OpenID Connect, SAML, SPIFFE/SPIRE, and SCIM flows against working infrastructure and see exactly what happens at each step.',
      },
      {
        question: 'What is OAuth 2.0 and how does it work?',
        answer: 'OAuth 2.0 is an authorization framework that enables applications to obtain limited access to user accounts on HTTP services. It works by delegating user authentication to the service that hosts the user account and authorizing third-party applications to access the user account.',
      },
      {
        question: 'What is the difference between OAuth and OpenID Connect?',
        answer: 'OAuth 2.0 is an authorization protocol that grants access to resources, while OpenID Connect (OIDC) is an authentication layer built on top of OAuth 2.0. OIDC adds an ID token that contains information about the authenticated user.',
      },
      {
        question: 'What is PKCE and why is it important?',
        answer: 'PKCE (Proof Key for Code Exchange) is a security extension to OAuth 2.0 that prevents authorization code interception attacks. It is essential for public clients like mobile apps and single-page applications that cannot securely store client secrets.',
      },
      {
        question: 'What is SAML and how is it different from OAuth?',
        answer: 'SAML (Security Assertion Markup Language) is an XML-based protocol for exchanging authentication and authorization data between identity providers and service providers. Unlike OAuth, which is designed for API authorization, SAML is primarily used for enterprise single sign-on (SSO).',
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
  protocolName: string,
  flowName: string,
  description: string,
  url: string,
  steps: Array<{ name: string; description: string }>
) {
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
    { name: protocolName, url: `${SITE_CONFIG.baseUrl}/protocol/${protocolName.toLowerCase().replace(/[^a-z0-9]/g, '')}` },
    { name: flowName, url },
  ])

  return [howTo, techArticle, breadcrumbs]
}

