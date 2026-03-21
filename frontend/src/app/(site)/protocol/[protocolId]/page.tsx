import type { Metadata } from 'next'
import { notFound } from 'next/navigation'
import { ProtocolDemo } from '@/views/ProtocolDemo'
import { getProtocolSEO, SITE_CONFIG } from '@/config/seo'
import { createPageMetadata } from '@/lib/seo'
import { generateProtocolPageSchema } from '@/utils/schema'
import { getProtocolPageData, isBackendNotFoundError } from '@/lib/protocols.server'
import {
  getAllowedBackendFlowIds,
  PROTOCOL_IDS,
} from '@/protocols/presentation/protocol-catalog-data'

interface ProtocolPageProps {
  params: Promise<{ protocolId: string }>
}

export const dynamic = 'force-dynamic'

export async function generateMetadata({ params }: ProtocolPageProps): Promise<Metadata> {
  const { protocolId } = await params
  const seo = getProtocolSEO(protocolId)
  return createPageMetadata({
    title: seo.title,
    description: seo.description,
    keywords: seo.keywords,
    path: `/protocol/${protocolId}`,
    type: 'article',
    imagePath: `/protocol/${protocolId}/opengraph-image`,
  })
}

export default async function ProtocolPage({ params }: ProtocolPageProps) {
  const { protocolId } = await params
  if (!PROTOCOL_IDS.includes(protocolId)) {
    notFound()
  }

  let protocolPageData: Awaited<ReturnType<typeof getProtocolPageData>>
  try {
    protocolPageData = await getProtocolPageData(protocolId)
  } catch (error) {
    if (isBackendNotFoundError(error)) {
      notFound()
    }
    throw error
  }
  const { protocol, flows } = protocolPageData
  const allowedBackendFlowIds = getAllowedBackendFlowIds(protocolId)
  const catalogFlows = flows.filter((flow) => allowedBackendFlowIds.has(flow.id))

  const schema = generateProtocolPageSchema(
    protocol.name,
    protocol.description,
    `${SITE_CONFIG.baseUrl}/protocol/${protocolId}`,
    catalogFlows.map((flow) => ({ name: flow.name, description: flow.description })),
  )

  return (
    <>
      {schema.map((entry, index) => (
        <script
          key={`protocol-schema-${index}`}
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(entry) }}
        />
      ))}
      <ProtocolDemo
        protocolId={protocolId}
        protocol={protocol}
        flows={catalogFlows}
      />
    </>
  )
}

