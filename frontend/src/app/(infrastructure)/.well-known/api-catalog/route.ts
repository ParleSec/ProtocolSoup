import { PROTOCOL_CATALOG_DATA } from '@/protocols/presentation/protocol-catalog-data'
import {
  AGENT_PATHS,
  API_OVERVIEW_URL,
  API_REFERENCE_URL,
  OPENAPI_CONTRACTS,
  PROTOCOL_CONTRACTS,
  protocolDocsUrl,
  siteUrl,
} from '@/lib/agent-discovery'

/**
 * RFC 9727 API catalog, serialised as an RFC 9264 linkset. The entries are
 * generated from the protocol catalog the site already renders, so a new
 * protocol appears here as soon as it ships rather than needing a second list
 * to be maintained by hand.
 */

interface LinkTarget {
  href: string
  type?: string
  title?: string
}

interface LinksetEntry {
  anchor: string
  'service-desc'?: LinkTarget[]
  'service-doc'?: LinkTarget[]
  describedby?: LinkTarget[]
  status?: LinkTarget[]
}

const statusTarget: LinkTarget[] = [
  { href: siteUrl(AGENT_PATHS.health), type: 'application/json', title: 'Runtime health' },
]

function platformEntry(): LinksetEntry {
  return {
    anchor: siteUrl('/api'),
    'service-desc': [
      {
        href: OPENAPI_CONTRACTS.gateway,
        type: 'application/yaml',
        title: 'ProtocolSoup Gateway API (OpenAPI 3.1)',
      },
    ],
    'service-doc': [
      { href: API_REFERENCE_URL, type: 'text/html', title: 'Interactive API reference' },
      { href: API_OVERVIEW_URL, type: 'text/html', title: 'API overview' },
    ],
    describedby: [
      { href: siteUrl(AGENT_PATHS.llmsFull), type: 'text/plain', title: 'Full site profile for agents' },
      { href: siteUrl(AGENT_PATHS.skillsIndex), type: 'application/json', title: 'Agent skills index' },
    ],
    status: statusTarget,
  }
}

function protocolEntry(protocol: { id: string; name: string; spec: string }): LinksetEntry {
  const contract = PROTOCOL_CONTRACTS[protocol.id]

  return {
    anchor: siteUrl(`/${protocol.id}`),
    'service-desc': contract
      ? [
          {
            href: OPENAPI_CONTRACTS[contract],
            type: 'application/yaml',
            title: `${protocol.name} endpoints (OpenAPI 3.1)`,
          },
        ]
      : undefined,
    'service-doc': [
      {
        href: protocolDocsUrl(protocol.id),
        type: 'text/html',
        title: `${protocol.name} (${protocol.spec}) documentation`,
      },
    ],
    describedby: [
      {
        href: siteUrl(`/protocol/${protocol.id}`),
        type: 'text/html',
        title: `${protocol.name} interactive flows`,
      },
    ],
    status: statusTarget,
  }
}

export async function GET() {
  const linkset: LinksetEntry[] = [
    platformEntry(),
    ...PROTOCOL_CATALOG_DATA.map(protocolEntry),
  ]

  return new Response(`${JSON.stringify({ linkset }, null, 2)}\n`, {
    headers: {
      'Content-Type': 'application/linkset+json; charset=utf-8',
      'Cache-Control': 'public, max-age=3600, s-maxage=3600',
      Link: `<${AGENT_PATHS.apiCatalog}>; rel="self"; type="application/linkset+json"`,
    },
  })
}
