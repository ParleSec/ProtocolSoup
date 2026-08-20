import { SITE_ORIGIN } from '@/lib/seo'
import { SECURITY_TXT_EXPIRES } from '@/lib/trust'

export async function GET() {
  const body = [
    'Contact: mailto:mason@protocolsoup.com',
    `Expires: ${SECURITY_TXT_EXPIRES}`,
    'Preferred-Languages: en',
    `Canonical: ${SITE_ORIGIN}/.well-known/security.txt`,
    'Policy: https://protocolsoup.com/trust#vulnerability-disclosure',
    '',
  ].join('\n')

  return new Response(body, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=86400, s-maxage=86400',
    },
  })
}
