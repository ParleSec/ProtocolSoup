import { ImageResponse } from 'next/og'
import { SITE_CONFIG } from '@/config/seo'
import { OG_CONTENT_TYPE, OG_SIZE, OgCard, ogFonts } from '@/lib/og'

export const runtime = 'edge'
export const contentType = OG_CONTENT_TYPE
export const size = OG_SIZE
export const alt = 'ProtocolSoup - Live Identity Protocol Execution'

export default async function TwitterImage() {
  return new ImageResponse(
    (
      <OgCard
        title="Live identity protocol execution"
        description="OAuth 2.0, OIDC, OID4VCI, OID4VP, SAML, SPIFFE, SCIM, and SSF against real infrastructure."
        host={SITE_CONFIG.baseUrl.replace(/^https?:\/\//, '')}
        footer="Inspect requests · Decode tokens · Execute live flows"
      />
    ),
    { ...size, fonts: await ogFonts() },
  )
}
