import { ImageResponse } from 'next/og'
import { SITE_CONFIG } from '@/config/seo'
import { OG_CONTENT_TYPE, OG_SIZE, OgCard, ogFonts } from '@/lib/og'

export const runtime = 'edge'
export const contentType = OG_CONTENT_TYPE
export const size = OG_SIZE
export const alt = 'ProtocolSoup - Live Identity Protocol Execution'

export default async function OpenGraphImage() {
  return new ImageResponse(
    (
      <OgCard
        title="Run real OAuth, OIDC, OID4VCI, OID4VP, SAML, SPIFFE, SCIM, and SSF flows"
        description="Execute live protocol exchanges, inspect wire traffic, and decode tokens step-by-step."
        host={SITE_CONFIG.baseUrl.replace(/^https?:\/\//, '')}
        footer="Live identity protocol execution"
      />
    ),
    { ...size, fonts: await ogFonts() },
  )
}
