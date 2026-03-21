import { CallbackClient } from '@/views/client/CallbackClient'
import { createPageMetadata } from '@/lib/seo'

export const metadata = createPageMetadata({
  title: 'OAuth Callback',
  description: 'OAuth and OpenID Connect callback handler.',
  path: '/callback',
  type: 'website',
  noIndex: true,
})

export default function CallbackPage() {
  return <CallbackClient />
}

