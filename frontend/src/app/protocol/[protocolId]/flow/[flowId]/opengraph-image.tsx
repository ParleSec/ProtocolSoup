import { ImageResponse } from 'next/og'
import { SITE_CONFIG } from '@/config/seo'
import { OG_CONTENT_TYPE, OG_SIZE, OgCard, ogFonts } from '@/lib/og'
import {
  getCatalogFlow,
  getCatalogProtocol,
} from '@/protocols/presentation/protocol-catalog-data'

export const runtime = 'edge'
export const contentType = OG_CONTENT_TYPE
export const size = OG_SIZE

interface FlowImageProps {
  params: Promise<{ protocolId: string; flowId: string }>
}

export default async function FlowOpenGraphImage({ params }: FlowImageProps) {
  const { protocolId, flowId } = await params
  const protocol = getCatalogProtocol(protocolId)
  const flow = getCatalogFlow(protocolId, flowId)

  const protocolName = protocol?.name || protocolId.toUpperCase()
  const flowName = flow?.name || flowId.replace(/-/g, ' ')

  return new ImageResponse(
    (
      <OgCard
        kicker={protocolName}
        title={flowName}
        description="Step-by-step flow breakdown and live protocol execution."
        host={SITE_CONFIG.baseUrl.replace(/^https?:\/\//, '')}
        footer="Looking Glass"
      />
    ),
    { ...size, fonts: await ogFonts() },
  )
}
