import type { Metadata } from 'next'
import { notFound, permanentRedirect } from 'next/navigation'
import { RequirementPage } from '@/views/RequirementPage'
import { createPageMetadata, absoluteUrl } from '@/lib/seo'
import { generateBreadcrumbSchema, generateTechArticleSchema } from '@/utils/schema'
import {
  getConformanceRequirement,
  requirementPath,
  specPath,
  truncateDescription,
  type ConformanceRequirementResponse,
} from '@/lib/conformance.server'
import { isBackendNotFoundError } from '@/lib/protocols.server'
import { getProtocolForSpec } from '@/protocols/presentation/protocol-catalog-data'

interface RequirementPageProps {
  params: Promise<{ specId: string; requirementId: string }>
}

export const dynamic = 'force-dynamic'

async function loadRequirement(requirementId: string): Promise<ConformanceRequirementResponse> {
  try {
    return await getConformanceRequirement(requirementId)
  } catch (error) {
    if (isBackendNotFoundError(error)) {
      notFound()
    }
    throw error
  }
}

function pageTitle(requirement: ConformanceRequirementResponse): string {
  return `${requirement.title} · ${requirement.specification.short_title} §${requirement.section} (${requirement.level})`
}

export async function generateMetadata({ params }: RequirementPageProps): Promise<Metadata> {
  const { requirementId } = await params
  const requirement = await loadRequirement(requirementId)
  return createPageMetadata({
    title: pageTitle(requirement),
    description: truncateDescription(requirement.statement),
    path: requirementPath(requirement.specification.id, requirement.id),
    type: 'article',
    noIndex: !requirement.indexable,
    keywords: [
      requirement.id,
      requirement.specification.short_title,
      `section ${requirement.section}`,
      requirement.level,
      'normative requirement',
    ],
  })
}

export default async function RequirementRoute({ params }: RequirementPageProps) {
  const { specId, requirementId } = await params
  const requirement = await loadRequirement(requirementId)
  const canonical = requirementPath(requirement.specification.id, requirement.id)
  if (`/spec/${specId}/${requirementId}` !== canonical) {
    permanentRedirect(canonical)
  }

  const url = absoluteUrl(canonical)
  const spec = requirement.specification
  const schema = [
    generateTechArticleSchema({
      title: pageTitle(requirement),
      description: truncateDescription(requirement.statement),
      url,
      dateModified: requirement.generated_at?.slice(0, 10),
      keywords: [requirement.id, spec.short_title, requirement.level],
    }),
    generateBreadcrumbSchema([
      { name: 'Protocols', url: absoluteUrl('/protocols') },
      { name: spec.short_title, url: absoluteUrl(specPath(spec.id)) },
      { name: requirement.title, url },
    ]),
  ]

  return (
    <>
      {schema.map((entry, index) => (
        <script
          key={`requirement-schema-${index}`}
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(entry) }}
        />
      ))}
      <RequirementPage requirement={requirement} relatedProtocol={getProtocolForSpec(spec.id)} />
    </>
  )
}
