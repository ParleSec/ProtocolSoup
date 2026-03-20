import { PROTOCOL_CATALOG_DATA } from '@/protocols/presentation/protocol-catalog-data'
import { DOCS_ORIGIN, SITE_ORIGIN, WALLET_ORIGIN } from '@/lib/seo'

export async function GET() {
  const protocolLines = PROTOCOL_CATALOG_DATA.map(
    (protocol) => `- ${protocol.name}: ${SITE_ORIGIN}/protocol/${protocol.id}`,
  )

  const body = [
    '# Protocol Soup',
    '',
    '> Interactive platform for learning authentication, identity, and verifiable credential protocols through real execution.',
    '',
    '## Canonical Properties',
    `- Main site: ${SITE_ORIGIN}`,
    `- Documentation: ${DOCS_ORIGIN}`,
    `- Wallet harness: ${WALLET_ORIGIN}`,
    '',
    '## Priority URLs',
    `- Homepage: ${SITE_ORIGIN}/`,
    `- Protocols hub: ${SITE_ORIGIN}/protocols`,
    `- Looking Glass: ${SITE_ORIGIN}/looking-glass`,
    `- SSF Sandbox: ${SITE_ORIGIN}/ssf-sandbox`,
    '',
    '## Protocol Guides',
    ...protocolLines,
    '',
    '## Sitemap Feeds',
    `- ${SITE_ORIGIN}/sitemap-index.xml`,
    `- ${SITE_ORIGIN}/sitemap.xml`,
    '',
    '## Machine-Readable Profiles',
    `- Full profile: ${SITE_ORIGIN}/llms-full.txt`,
    '',
  ].join('\n')

  return new Response(body, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=3600, s-maxage=3600',
    },
  })
}

