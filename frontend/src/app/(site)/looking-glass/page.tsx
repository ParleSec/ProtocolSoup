import { LookingGlassClient } from '@/views/client/LookingGlassClient'
import { PAGE_SEO } from '@/config/seo'
import { createPageMetadata } from '@/lib/seo'

const seo = PAGE_SEO['/looking-glass']

export const metadata = createPageMetadata({
  title: seo.title,
  description: seo.description,
  keywords: seo.keywords,
  path: '/looking-glass',
  type: 'website',
})

export default function LookingGlassPage() {
  return <LookingGlassClient />
}

