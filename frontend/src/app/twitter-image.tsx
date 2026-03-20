import { ImageResponse } from 'next/og'
import { SITE_CONFIG } from '@/config/seo'

export const runtime = 'edge'
export const contentType = 'image/png'
export const size = {
  width: 1200,
  height: 630,
}
export const alt = 'Protocol Soup - Identity Protocol Playground'

export default function TwitterImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          padding: '52px',
          background:
            'radial-gradient(circle at 85% 15%, rgba(249,115,22,0.28), transparent 38%), radial-gradient(circle at 12% 88%, rgba(6,182,212,0.25), transparent 36%), linear-gradient(135deg, #08080d 0%, #121225 100%)',
          color: '#f4f4f5',
          fontFamily: 'system-ui, sans-serif',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <span style={{ fontSize: 34, fontWeight: 700 }}>Protocol Soup</span>
          <span style={{ fontSize: 28 }}>🍜</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{ fontSize: 50, lineHeight: 1.08, fontWeight: 700, letterSpacing: '-0.02em' }}>
            Interactive Identity Protocol Testing
          </div>
          <div style={{ fontSize: 24, lineHeight: 1.3, color: '#d4d4d8' }}>
            OAuth 2.0, OIDC, OID4VCI, OID4VP, SAML, SPIFFE, SCIM, and SSF.
          </div>
        </div>

        <div style={{ fontSize: 19, color: '#cbd5e1' }}>
          {SITE_CONFIG.baseUrl.replace(/^https?:\/\//, '')}
        </div>
      </div>
    ),
    size,
  )
}

