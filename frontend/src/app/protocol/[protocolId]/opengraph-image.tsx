import { ImageResponse } from 'next/og'
import { getCatalogProtocol } from '@/protocols/presentation/protocol-catalog-data'

export const runtime = 'edge'
export const contentType = 'image/png'
export const size = {
  width: 1200,
  height: 630,
}

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
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          padding: '56px',
          background:
            'radial-gradient(circle at 88% 12%, rgba(99,102,241,0.34), transparent 40%), radial-gradient(circle at 8% 85%, rgba(6,182,212,0.25), transparent 38%), linear-gradient(135deg, #0a0a0f 0%, #111827 100%)',
          color: '#f4f4f5',
          fontFamily: 'system-ui, sans-serif',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 30, fontWeight: 700 }}>
          <span>Protocol Soup</span>
          <span style={{ fontSize: 26 }}>🍜</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ fontSize: 62, lineHeight: 1.02, fontWeight: 800, letterSpacing: '-0.03em' }}>
            {title}
          </div>
          <div style={{ fontSize: 28, lineHeight: 1.28, color: '#cbd5e1', maxWidth: 1060 }}>
            {description}
          </div>
        </div>

        <div style={{ fontSize: 21, color: '#93c5fd' }}>Protocol Guide + Interactive Flows</div>
      </div>
    ),
    size,
  )
}

