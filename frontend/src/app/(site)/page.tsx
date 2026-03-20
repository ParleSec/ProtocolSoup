import { Dashboard } from '@/views/Dashboard'
import { PAGE_SEO } from '@/config/seo'
import { createPageMetadata } from '@/lib/seo'
import { generateHomepageSchema } from '@/utils/schema'

const seo = PAGE_SEO['/']

export const revalidate = 3600

export const metadata = createPageMetadata({
  title: seo.title,
  description: seo.description,
  keywords: seo.keywords,
  path: '/',
  type: 'website',
})

export default function HomePage() {
  const schemas = generateHomepageSchema()
  return (
    <>
      {schemas.map((schema, index) => (
        <script
          key={`home-schema-${index}`}
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }}
        />
      ))}
      <Dashboard />
    </>
  )
}

