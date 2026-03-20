import type { MetadataRoute } from 'next'
import { SITE_ORIGIN } from '@/lib/seo'

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: '*',
        allow: ['/'],
        disallow: [
          '/api/',
          '/ws/',
          '/oauth2/',
          '/oidc/',
          '/oid4vci/',
          '/oid4vp/',
          '/saml/',
          '/spiffe/',
          '/scim/',
          '/ssf/',
          '/callback',
          '/looking-glass/*',
        ],
      },
      { userAgent: 'GPTBot', allow: '/' },
      { userAgent: 'ChatGPT-User', allow: '/' },
      { userAgent: 'ClaudeBot', allow: '/' },
      { userAgent: 'anthropic-ai', allow: '/' },
      { userAgent: 'Google-Extended', allow: '/' },
      { userAgent: 'CCBot', disallow: '/' },
      { userAgent: 'meta-externalagent', disallow: '/' },
      { userAgent: 'Amazonbot', disallow: '/' },
      { userAgent: 'Applebot-Extended', disallow: '/' },
      { userAgent: 'Bytespider', disallow: '/' },
      { userAgent: 'cohere-ai', disallow: '/' },
      { userAgent: 'PerplexityBot', disallow: '/' },
      { userAgent: 'YouBot', disallow: '/' },
      { userAgent: 'Diffbot', disallow: '/' },
    ],
    host: SITE_ORIGIN,
    sitemap: [`${SITE_ORIGIN}/sitemap-index.xml`, `${SITE_ORIGIN}/sitemap.xml`],
  }
}
