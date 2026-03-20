import { ImageResponse } from 'next/og'
import {
  getCatalogFlow,
  getCatalogProtocol,
} from '@/protocols/presentation/protocol-catalog-data'

export const runtime = 'edge'
export const contentType = 'image/png'
export const size = {
  width: 1200,
  height: 630,
}

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
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          padding: '54px',
          background:
            'radial-gradient(circle at 90% 8%, rgba(168,85,247,0.3), transparent 40%), radial-gradient(circle at 8% 88%, rgba(14,165,233,0.28), transparent 35%), linear-gradient(135deg, #09090f 0%, #111827 100%)',
          color: '#f8fafc',
          fontFamily: 'system-ui, sans-serif',
        }}
      >
        <div style={{ fontSize: 28, color: '#93c5fd', fontWeight: 700 }}>
          {protocolName}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{ fontSize: 56, lineHeight: 1.06, fontWeight: 800, letterSpacing: '-0.02em' }}>
            {flowName}
          </div>
          <div style={{ fontSize: 26, color: '#d4d4d8' }}>
            Step-by-step flow breakdown and live protocol execution
          </div>
        </div>

        <div style={{ fontSize: 20, color: '#cbd5e1' }}>
          protocolsoup.com
        </div>
      </div>
    ),
    size,
  )
}

