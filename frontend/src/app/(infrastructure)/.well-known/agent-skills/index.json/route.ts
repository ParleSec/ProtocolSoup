import { createHash } from 'node:crypto'
import { listSkills, renderSkill, skillUrl } from '@/lib/agent-skills'

/**
 * Agent Skills Discovery RFC v0.2.0 index.
 *
 * Digests are computed from the same rendering the artifact route serves, so a
 * consumer that verifies the digest against the downloaded SKILL.md will always
 * get a match.
 */

export const runtime = 'nodejs'

const SCHEMA_URL = 'https://schemas.agentskills.io/discovery/0.2.0/schema.json'

function sha256(content: string): string {
  return `sha256:${createHash('sha256').update(content, 'utf8').digest('hex')}`
}

export async function GET() {
  const skills = listSkills().map((skill) => ({
    name: skill.name,
    type: 'skill-md' as const,
    description: skill.description,
    url: skillUrl(skill),
    digest: sha256(renderSkill(skill)),
  }))

  const document = {
    $schema: SCHEMA_URL,
    skills,
  }

  return new Response(`${JSON.stringify(document, null, 2)}\n`, {
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'public, max-age=3600, s-maxage=3600',
    },
  })
}
