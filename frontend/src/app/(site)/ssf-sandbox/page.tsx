import { redirect } from 'next/navigation'
import { PAGE_SEO } from '@/config/seo'
import { createPageMetadata } from '@/lib/seo'

const seo = PAGE_SEO['/ssf-sandbox']

export const metadata = createPageMetadata({
  title: seo.title,
  description: seo.description,
  keywords: seo.keywords,
  path: '/ssf-sandbox',
  type: 'website',
})

export default function SSFLookingGlassRedirectPage() {
  redirect('/looking-glass?protocol=ssf')
}
