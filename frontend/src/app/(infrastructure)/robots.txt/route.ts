import { SITE_ORIGIN, WALLET_ORIGIN } from '@/lib/seo'

/**
 * robots.txt is generated here rather than through Next's metadata route so it
 * can carry Content-Signal directives (https://contentsignals.org/,
 * draft-romm-aipref-contentsignals). Next's MetadataRoute.Robots type has no
 * field for them.
 */

interface RobotsGroup {
  userAgents: string[]
  /** Omitted for groups that are fully disallowed, where it would say nothing. */
  contentSignal?: string
  allow?: string[]
  disallow?: string[]
}

/**
 * Crawling is welcome and the content may ground answers, but the site owner
 * does not grant permission to train or fine-tune models on it. A signal only
 * applies to the group it appears in, so every group that is allowed to crawl
 * repeats it.
 */
const CONTENT_SIGNAL = 'search=yes, ai-input=yes, ai-train=no'

/** Protocol runtimes and per-session Looking Glass state are not crawlable. */
const DISALLOWED_PATHS = [
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
]

const GROUPS: RobotsGroup[] = [
  {
    userAgents: ['*'],
    contentSignal: CONTENT_SIGNAL,
    allow: ['/'],
    disallow: DISALLOWED_PATHS,
  },
  {
    userAgents: ['GPTBot', 'ChatGPT-User', 'ClaudeBot', 'anthropic-ai', 'Google-Extended'],
    contentSignal: CONTENT_SIGNAL,
    allow: ['/'],
  },
  {
    userAgents: [
      'CCBot',
      'meta-externalagent',
      'Amazonbot',
      'Applebot-Extended',
      'Bytespider',
      'cohere-ai',
      'PerplexityBot',
      'YouBot',
      'Diffbot',
    ],
    disallow: ['/'],
  },
]

const PREAMBLE = [
  '# Content Signals — https://contentsignals.org/',
  '#',
  '# The Content-Signal directives below express how the operator of this site',
  '# permits its content to be used once it has been accessed. A signal set to',
  '# "yes" grants permission for that use; "no" withholds it. A use with no',
  '# signal is neither granted nor withheld here.',
  '#',
  '#   search   — building a search index and returning links and short excerpts.',
  '#   ai-input — supplying content to an AI model at inference time, such as',
  '#              retrieval-augmented generation or grounding a generated answer.',
  '#   ai-train — training or fine-tuning an AI model.',
  '#',
  '# These directives express the operator\'s preferences. They do not replace',
  '# the terms of the repository licence or any applicable law.',
]

function renderGroup(group: RobotsGroup): string[] {
  const lines = group.userAgents.map((userAgent) => `User-agent: ${userAgent}`)

  if (group.contentSignal) {
    lines.push(`Content-Signal: ${group.contentSignal}`)
  }
  for (const path of group.allow ?? []) {
    lines.push(`Allow: ${path}`)
  }
  for (const path of group.disallow ?? []) {
    lines.push(`Disallow: ${path}`)
  }

  return lines
}

export async function GET() {
  const body = [
    ...PREAMBLE,
    '',
    ...GROUPS.flatMap((group) => [...renderGroup(group), '']),
    `Host: ${SITE_ORIGIN}`,
    `Sitemap: ${SITE_ORIGIN}/sitemap-index.xml`,
    `Sitemap: ${SITE_ORIGIN}/sitemap.xml`,
    `Sitemap: ${WALLET_ORIGIN}/sitemap.xml`,
    '',
  ].join('\n')

  return new Response(body, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=3600, s-maxage=3600',
    },
  })
}
