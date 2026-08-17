import { sortedProtocolCatalogData } from '@/protocols/presentation/protocol-catalog-data'
import { DOCS_ORIGIN, SITE_ORIGIN, WALLET_ORIGIN } from '@/lib/seo'

export async function GET() {
  const protocolSections = sortedProtocolCatalogData().flatMap((protocol) => {
    const protocolUrl = `${SITE_ORIGIN}/protocol/${protocol.id}`
    const lines = [
      `### ${protocol.name}`,
      `- [Guide](${protocolUrl})`,
      `- [Specification](${protocol.specUrl})`,
      `- Summary: ${protocol.description}`,
      '- Flows:',
      ...protocol.flows.map(
        (flow) =>
          `  - [${flow.name}](${SITE_ORIGIN}/protocol/${protocol.id}/flow/${flow.id}) (${flow.rfc})`,
      ),
      '',
    ]
    return lines
  })

  const body = [
    '# ProtocolSoup - Full LLM Profile',
    '',
    '> Deep-link catalog for protocol guides, flow references, and standards coverage.',
    '',
    '## Platforms',
    `- [Main](${SITE_ORIGIN})`,
    `- [Looking Glass](${SITE_ORIGIN}/looking-glass)`,
    `- [Protocols hub](${SITE_ORIGIN}/protocols)`,
    `- [Docs](${DOCS_ORIGIN})`,
    `- [Wallet harness](${WALLET_ORIGIN})`,
    `- [Wallet llms.txt](${WALLET_ORIGIN}/llms.txt)`,
    '',
    '## Protocol Catalog',
    ...protocolSections,
    '## Crawl Entry Points',
    `- [Sitemap index](${SITE_ORIGIN}/sitemap-index.xml)`,
    `- [App sitemap](${SITE_ORIGIN}/sitemap.xml)`,
    '',
  ].join('\n')

  return new Response(body, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=3600, s-maxage=3600',
    },
  })
}

