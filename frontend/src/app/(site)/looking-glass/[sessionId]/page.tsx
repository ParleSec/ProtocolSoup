import { LookingGlassClient } from '@/views/client/LookingGlassClient'
import { createPageMetadata } from '@/lib/seo'

export const metadata = createPageMetadata({
  title: 'Looking Glass Session',
  description: 'Live Looking Glass protocol session view.',
  path: '/looking-glass',
  type: 'website',
  noIndex: true,
})

export default function LookingGlassSessionPage() {
  return <LookingGlassClient />
}

