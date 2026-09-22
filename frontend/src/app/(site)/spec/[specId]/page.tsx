import type { Metadata } from 'next'
import { notFound, permanentRedirect } from 'next/navigation'
import { SpecIndexPage } from '@/views/SpecIndexPage'
import { createPageMetadata, absoluteUrl } from '@/lib/seo'
import { generateBreadcrumbSchema, generateTechArticleSchema } from '@/utils/schema'
import {
  getConformanceSpec,
  specPath,
  truncateDescription,
  type ConformanceSpecResponse,
} from '@/lib/conformance.server'
import { isBackendNotFoundError } from '@/lib/protocols.server'
import { getProtocolForSpec } from '@/protocols/presentation/protocol-catalog-data'

interface SpecPageProps {
  params: Promise<{ specId: string }>
}

export const dynamic = 'force-dynamic'

async function loadSpec(specId: string): Promise<ConformanceSpecResponse> {
  try {
    return await getConformanceSpec(specId)
  } catch (error) {
    if (isBackendNotFoundError(error)) {
      notFound()
    }
    throw error
  }
}

function specDescription(spec: ConformanceSpecResponse): string {
  return truncateDescription(
    `${spec.requirement_count} normative requirements from ${spec.title} (${spec.version}) as recorded in the ProtocolSoup registry, with ProtocolSoup's self-test verdict for the build serving this page.`,
  )
}

export async function generateMetadata({ params }: SpecPageProps): Promise<Metadata> {
  const { specId } = await params
  const spec = await loadSpec(specId)
  return createPageMetadata({
    title: `${spec.short_title} normative requirements`,
    description: specDescription(spec),
    path: specPath(spec.id),
    type: 'article',
    noIndex: !spec.indexable,
    keywords: [spec.short_title, spec.title, 'normative requirements', 'conformance'],
  })
}

export default async function SpecPage({ params }: SpecPageProps) {
  const { specId } = await params
  const spec = await loadSpec(specId)
  if (specId !== spec.id) {
    permanentRedirect(specPath(spec.id))
  }

  const url = absoluteUrl(specPath(spec.id))
  const schema = [
    generateTechArticleSchema({
      title: `${spec.short_title} normative requirements`,
      description: specDescription(spec),
      url,
      dateModified: spec.generated_at?.slice(0, 10),
      keywords: [spec.short_title, 'normative requirements'],
    }),
    generateBreadcrumbSchema([
      { name: 'Protocols', url: absoluteUrl('/protocols') },
      { name: spec.short_title, url },
    ]),
  ]

  return (
    <>
      {schema.map((entry, index) => (
        <script
          key={`spec-schema-${index}`}
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(entry) }}
        />
      ))}
      <SpecIndexPage spec={spec} relatedProtocol={getProtocolForSpec(spec.id)} />
    </>
  )
}
