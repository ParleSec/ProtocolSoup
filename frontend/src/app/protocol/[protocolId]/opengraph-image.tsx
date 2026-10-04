import { ImageResponse } from 'next/og'
import { SITE_CONFIG } from '@/config/seo'
import { OG_CONTENT_TYPE, OG_SIZE, OgCard, ogFonts } from '@/lib/og'
import { getCatalogProtocol } from '@/protocols/presentation/protocol-catalog-data'

export const runtime = 'edge'
export const contentType = OG_CONTENT_TYPE
export const size = OG_SIZE

interface ProtocolImageProps {
  params: Promise<{ protocolId: string }>
}

export default async function ProtocolOpenGraphImage({ params }: ProtocolImageProps) {
  const { protocolId } = await params
  const protocol = getCatalogProtocol(protocolId)
  const title = protocol?.name || protocolId.toUpperCase()
  const description =
    protocol?.description ||
    'Interactive protocol documentation and flow execution walkthrough.'

  return new ImageResponse(
    (
      <OgCard
        kicker="protocol"
        title={title}
        description={description}
        host={SITE_CONFIG.baseUrl.replace(/^https?:\/\//, '')}
        footer="Protocol reference + live Looking Glass runs"
      />
    ),
    { ...size, fonts: await ogFonts() },
  )
}
