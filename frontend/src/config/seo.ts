/**
 * SEO Configuration for Protocol Soup
 * 
 * Centralized SEO metadata, keywords, and configuration for all pages.
 * Optimized for competitive identity/security protocol keywords.
 */

export const SITE_CONFIG = {
  name: 'Protocol Soup',
  tagline: 'An Interactive Protocol Sandbox',
  baseUrl: 'https://protocolsoup.com',
  defaultImage: 'https://protocolsoup.com/og-image.png',
  twitterHandle: '@protocolsoup',
  author: 'Mason Parle',
  locale: 'en_US',
}

export interface PageSEO {
  title: string
  description: string
  keywords: string[]
  ogType?: 'website' | 'article'
  canonical?: string
  noIndex?: boolean
}

/**
 * SEO metadata for each route
 * Keywords are optimized for competitive search rankings
 */
export const PAGE_SEO: Record<string, PageSEO> = {
  // Homepage - Primary landing page
  '/': {
    title: 'Protocol Soup - OAuth 2.0, OIDC & SAML Testing Playground',
    description: 'Learn authentication protocols by running them. Execute real OAuth 2.0, OpenID Connect, SAML 2.0, SPIFFE/SPIRE, and SCIM flows against working infrastructure. Decode JWTs, inspect tokens, and understand security flows.',
    keywords: [
      'oauth2 playground',
      'oauth testing tool',
      'oidc testing',
      'authentication protocol sandbox',
      'jwt decoder',
      'token inspector',
      'oauth2 tutorial',
      'openid connect tutorial',
    ],
    ogType: 'website',
  },

  // Protocols Hub
  '/protocols': {
    title: 'Identity Protocol Reference Guide - OAuth 2.0, OIDC, SAML, SPIFFE, SCIM',
    description: 'Comprehensive reference for authentication and identity protocols. Documentation, sequence diagrams, and security considerations for OAuth 2.0, OpenID Connect, SAML 2.0, SPIFFE/SPIRE, and SCIM 2.0.',
    keywords: [
      'identity protocol reference',
      'authentication protocols',
      'oauth2 documentation',
      'oidc specification',
      'saml documentation',
      'security protocols',
    ],
    ogType: 'website',
  },

  // Looking Glass Tool
  '/looking-glass': {
    title: 'Looking Glass - Live Protocol Flow Execution & Traffic Inspector',
    description: 'Execute authentication protocol flows in real-time and inspect every HTTP request, response, header, and token. See OAuth 2.0, OIDC, and SAML flows as they happen.',
    keywords: [
      'protocol debugger',
      'oauth flow inspector',
      'http traffic inspector',
      'authentication debugger',
      'token debugger',
      'api testing tool',
    ],
    ogType: 'website',
  },

  // SSF Sandbox
  '/ssf-sandbox': {
    title: 'SSF Sandbox - Shared Signals Framework Interactive Playground',
    description: 'Interactive playground for the Shared Signals Framework (SSF). Trigger CAEP and RISC security events, decode SET tokens, and understand real-time security signal sharing.',
    keywords: [
      'shared signals framework',
      'ssf tutorial',
      'caep events',
      'risc events',
      'security event tokens',
      'zero trust signals',
      'continuous access evaluation',
    ],
    ogType: 'website',
  },

  // OAuth 2.0 Protocol
  '/protocol/oauth2': {
    title: 'OAuth 2.0 Tutorial - Complete Authorization Framework Guide',
    description: 'Master OAuth 2.0 with interactive examples. Learn Authorization Code, Client Credentials, PKCE, Token Introspection, and Revocation flows with live demonstrations.',
    keywords: [
      'oauth 2.0 tutorial',
      'oauth authorization code flow',
      'oauth2 explained',
      'oauth client credentials',
      'oauth2 grant types',
      'rfc 6749',
    ],
    ogType: 'article',
  },

  // OpenID Connect Protocol
  '/protocol/oidc': {
    title: 'OpenID Connect Tutorial - Authentication Layer for OAuth 2.0',
    description: 'Learn OpenID Connect (OIDC) with hands-on examples. Understand ID tokens, UserInfo endpoint, Discovery, and how OIDC adds authentication to OAuth 2.0.',
    keywords: [
      'openid connect tutorial',
      'oidc authentication',
      'id token explained',
      'oidc vs oauth',
      'openid connect flow',
      'oidc discovery',
    ],
    ogType: 'article',
  },

  // SAML 2.0 Protocol
  '/protocol/saml': {
    title: 'SAML 2.0 Tutorial - Enterprise SSO & Federation Explained',
    description: 'Master SAML 2.0 for enterprise single sign-on. Learn SP-Initiated SSO, IdP-Initiated SSO, Single Logout, and metadata exchange with interactive examples.',
    keywords: [
      'saml 2.0 tutorial',
      'saml sso explained',
      'saml assertion',
      'sp initiated sso',
      'idp initiated sso',
      'saml metadata',
      'enterprise sso',
    ],
    ogType: 'article',
  },

  // SPIFFE/SPIRE Protocol
  '/protocol/spiffe': {
    title: 'SPIFFE/SPIRE Tutorial - Zero Trust Workload Identity',
    description: 'Learn SPIFFE and SPIRE for zero-trust workload identity. Understand X.509-SVIDs, JWT-SVIDs, mTLS authentication, and automatic certificate rotation.',
    keywords: [
      'spiffe tutorial',
      'spire workload identity',
      'zero trust identity',
      'x509 svid',
      'jwt svid',
      'workload attestation',
      'mtls authentication',
    ],
    ogType: 'article',
  },

  // SCIM 2.0 Protocol
  '/protocol/scim': {
    title: 'SCIM 2.0 Tutorial - Cross-Domain Identity Provisioning',
    description: 'Master SCIM 2.0 for automated user provisioning. Learn user lifecycle management, group operations, filter queries, schema discovery, and bulk operations.',
    keywords: [
      'scim 2.0 tutorial',
      'scim provisioning',
      'scim api tutorial',
      'user provisioning protocol',
      'identity provisioning',
      'rfc 7644',
    ],
    ogType: 'article',
  },
}

/**
 * Flow-specific SEO data generator
 * Creates optimized titles and descriptions for protocol flow pages
 */
export function getFlowSEO(protocolId: string, flowId: string, flowName: string): PageSEO {
  const protocolNames: Record<string, string> = {
    oauth2: 'OAuth 2.0',
    oidc: 'OpenID Connect',
    saml: 'SAML 2.0',
    spiffe: 'SPIFFE/SPIRE',
    scim: 'SCIM 2.0',
  }

  const protocolName = protocolNames[protocolId] || protocolId.toUpperCase()
  
  // Flow-specific keyword mappings
  const flowKeywords: Record<string, string[]> = {
    'authorization-code': ['oauth authorization code', 'oauth2 code flow', 'authorization code grant'],
    'authorization-code-pkce': ['oauth pkce', 'pkce flow', 'code verifier', 'code challenge', 'pkce implementation'],
    'client-credentials': ['client credentials flow', 'machine to machine auth', 'service account oauth'],
    'refresh-token': ['oauth refresh token', 'token refresh', 'refresh token grant'],
    'token-introspection': ['token introspection', 'rfc 7662', 'validate access token'],
    'token-revocation': ['token revocation', 'rfc 7009', 'revoke oauth token'],
    'oidc-authorization-code': ['oidc authorization code', 'openid code flow', 'id token flow'],
    'oidc-implicit': ['oidc implicit flow', 'implicit grant', 'spa authentication'],
    'hybrid': ['oidc hybrid flow', 'hybrid grant type'],
    'userinfo': ['userinfo endpoint', 'oidc claims', 'user profile endpoint'],
    'discovery': ['oidc discovery', 'well-known openid-configuration', 'provider metadata'],
    'sp-initiated-sso': ['sp initiated sso', 'service provider sso', 'saml redirect'],
    'idp-initiated-sso': ['idp initiated sso', 'identity provider sso', 'unsolicited response'],
    'single-logout': ['saml single logout', 'slo', 'federated logout'],
    'metadata': ['saml metadata', 'federation metadata', 'entity descriptor'],
    'x509-svid-issuance': ['x509 svid', 'spiffe certificate', 'workload certificate'],
    'jwt-svid-issuance': ['jwt svid', 'spiffe jwt', 'workload jwt token'],
    'mtls-handshake': ['mtls handshake', 'mutual tls', 'client certificate auth'],
    'certificate-rotation': ['certificate rotation', 'auto cert renewal', 'svid rotation'],
    'user-lifecycle': ['scim user lifecycle', 'user provisioning', 'create update delete user'],
    'group-management': ['scim groups', 'group provisioning', 'membership management'],
    'filter-queries': ['scim filter', 'scim query', 'rfc 7644 filter'],
    'schema-discovery': ['scim schema', 'resource types', 'service provider config'],
    'bulk-operations': ['scim bulk', 'batch provisioning', 'bulk user creation'],
  }

  const keywords = flowKeywords[flowId] || [`${protocolId} ${flowId}`, flowName.toLowerCase()]

  return {
    title: `${flowName} - ${protocolName} Flow Step-by-Step Guide`,
    description: `Learn the ${flowName} flow with interactive examples. Understand each step, see the HTTP requests, and decode tokens in real-time. Complete ${protocolName} implementation guide.`,
    keywords: [
      ...keywords,
      `${protocolId} tutorial`,
      `${flowName.toLowerCase()} example`,
      'authentication flow',
    ],
    ogType: 'article',
  }
}

/**
 * Protocol-specific SEO helper
 */
export function getProtocolSEO(protocolId: string): PageSEO {
  const key = `/protocol/${protocolId}`
  return PAGE_SEO[key] || {
    title: `${protocolId.toUpperCase()} Protocol - Protocol Soup`,
    description: `Learn ${protocolId.toUpperCase()} protocol with interactive examples and documentation.`,
    keywords: [protocolId, 'authentication', 'identity protocol'],
    ogType: 'article',
  }
}

