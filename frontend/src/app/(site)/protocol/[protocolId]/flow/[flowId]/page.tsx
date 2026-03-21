import type { Metadata } from 'next'
import { notFound } from 'next/navigation'
import { FlowDetail } from '@/views/FlowDetail'
import { getFlowSEO, SITE_CONFIG } from '@/config/seo'
import { createPageMetadata } from '@/lib/seo'
import { generateFlowPageSchema } from '@/utils/schema'
import { getFlowPageData, isBackendNotFoundError } from '@/lib/protocols.server'
import {
  getBackendFlowId,
  getCatalogFlow,
  getCatalogProtocol,
} from '@/protocols/presentation/protocol-catalog-data'

interface FlowPageProps {
  params: Promise<{ protocolId: string; flowId: string }>
}

export const dynamic = 'force-dynamic'

export async function generateMetadata({ params }: FlowPageProps): Promise<Metadata> {
  const { protocolId, flowId } = await params
  const catalogFlow = getCatalogFlow(protocolId, flowId)
  const flowName = catalogFlow?.name || flowId
  const seo = getFlowSEO(protocolId, flowId, flowName)
  return createPageMetadata({
    title: seo.title,
    description: seo.description,
    keywords: seo.keywords,
    path: `/protocol/${protocolId}/flow/${flowId}`,
    type: 'article',
    imagePath: `/protocol/${protocolId}/flow/${flowId}/opengraph-image`,
  })
}

export default async function FlowPage({ params }: FlowPageProps) {
  const { protocolId, flowId } = await params
  const catalogProtocol = getCatalogProtocol(protocolId)
  const catalogFlow = getCatalogFlow(protocolId, flowId)
  const backendFlowId = getBackendFlowId(protocolId, flowId)
  if (!catalogProtocol || !catalogFlow) {
    notFound()
  }
  if (!backendFlowId) {
    notFound()
  }

  let flowPageData: Awaited<ReturnType<typeof getFlowPageData>>
  try {
    flowPageData = await getFlowPageData(protocolId)
  } catch (error) {
    if (isBackendNotFoundError(error)) {
      notFound()
    }
    throw error
  }
  const { flows } = flowPageData
  const selectedFlow = flows.find((entry) => entry.id === backendFlowId)
  if (!selectedFlow) {
    notFound()
  }
  const protocolName = catalogProtocol.name
  const schema = generateFlowPageSchema(
    protocolId,
    protocolName,
    selectedFlow.name,
    selectedFlow.description,
    `${SITE_CONFIG.baseUrl}/protocol/${protocolId}/flow/${flowId}`,
    [],
  )

  return (
    <>
      {schema.map((entry, index) => (
        <script
          key={`flow-schema-${index}`}
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(entry) }}
        />
      ))}
      <FlowDetail
        protocolId={protocolId}
        flow={selectedFlow}
      />
    </>
  )
}

