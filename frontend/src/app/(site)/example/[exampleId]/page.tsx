import type { Metadata } from 'next'
import { notFound, permanentRedirect } from 'next/navigation'
import { ExamplePage } from '@/views/ExamplePage'
import { createPageMetadata, absoluteUrl } from '@/lib/seo'
import { generateBreadcrumbSchema, generateTechArticleSchema } from '@/utils/schema'
import {
  examplePath,
  getConformanceExample,
  truncateDescription,
  type ConformanceExampleResponse,
} from '@/lib/conformance.server'
import { isBackendNotFoundError } from '@/lib/protocols.server'

interface ExamplePageProps {
  params: Promise<{ exampleId: string }>
}

export const dynamic = 'force-dynamic'

async function loadExample(exampleId: string): Promise<ConformanceExampleResponse> {
  try {
    return await getConformanceExample(exampleId)
  } catch (error) {
    if (isBackendNotFoundError(error)) {
      notFound()
    }
    throw error
  }
}

export async function generateMetadata({ params }: ExamplePageProps): Promise<Metadata> {
  const { exampleId } = await params
  const example = await loadExample(exampleId)
  return createPageMetadata({
    title: example.question,
    description: truncateDescription(example.summary),
    path: examplePath(example.id),
    type: 'article',
    noIndex: !example.indexable,
    keywords: [example.title, `${example.title} example`, 'real example', 'decoded'],
  })
}

export default async function ExampleRoute({ params }: ExamplePageProps) {
  const { exampleId } = await params
  const example = await loadExample(exampleId)
  const canonical = examplePath(example.id)
  if (`/example/${exampleId}` !== canonical) {
    permanentRedirect(canonical)
  }

  const url = absoluteUrl(canonical)
  const schema = [
    generateTechArticleSchema({
      title: example.question,
      description: truncateDescription(example.summary),
      url,
      dateModified: example.captured_at?.slice(0, 10),
      keywords: [example.title, `${example.title} example`],
    }),
    generateBreadcrumbSchema([
      { name: 'Protocols', url: absoluteUrl('/protocols') },
      { name: example.title, url },
    ]),
  ]

  return (
    <>
      {schema.map((entry, index) => (
        <script
          key={`example-schema-${index}`}
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(entry) }}
        />
      ))}
      <ExamplePage example={example} />
    </>
  )
}
