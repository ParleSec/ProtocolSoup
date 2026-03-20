import { ImageResponse } from 'next/og'
import { SITE_CONFIG } from '@/config/seo'

export const runtime = 'edge'
export const contentType = 'image/png'
export const size = {
  width: 1200,
  height: 630,
}
export const alt = 'Protocol Soup - Interactive Identity Protocol Testing'

export default function OpenGraphImage() {
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
            'radial-gradient(circle at 90% 10%, rgba(168,85,247,0.35), transparent 45%), radial-gradient(circle at 10% 90%, rgba(6,182,212,0.3), transparent 40%), linear-gradient(135deg, #0a0a0f 0%, #101018 100%)',
          color: '#e4e4e7',
          fontFamily: 'system-ui, sans-serif',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 16,
            fontSize: 34,
            fontWeight: 700,
            letterSpacing: '-0.02em',
          }}
        >
          <span>Protocol Soup</span>
          <span style={{ fontSize: 30 }}>🍜</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          <div
            style={{
              fontSize: 56,
              lineHeight: 1.06,
              fontWeight: 700,
              maxWidth: 980,
              letterSpacing: '-0.02em',
            }}
          >
            Run Real OAuth, OIDC, OID4VCI, OID4VP, SAML, SPIFFE, SCIM, and SSF Flows
          </div>
          <div
            style={{
              fontSize: 24,
              lineHeight: 1.35,
              color: '#a1a1aa',
              maxWidth: 1040,
            }}
          >
            Execute live protocol exchanges, inspect wire traffic, and decode tokens step-by-step.
          </div>
        </div>

        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            fontSize: 20,
            color: '#cbd5e1',
          }}
        >
          <span>{SITE_CONFIG.baseUrl.replace(/^https?:\/\//, '')}</span>
          <span>Identity Protocol Playground</span>
        </div>
      </div>
    ),
    size,
  )
}

