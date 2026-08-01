import { findSkill, listSkills, renderSkill } from '@/lib/agent-skills'

/** Serves the SKILL.md artifacts advertised by the agent skills index. */

export function generateStaticParams() {
  return listSkills().map((skill) => ({ skill: skill.name }))
}

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ skill: string }> },
) {
  const { skill: name } = await params
  const skill = findSkill(name)

  if (!skill) {
    return new Response('Skill not found\n', {
      status: 404,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    })
  }

  return new Response(renderSkill(skill), {
    headers: {
      'Content-Type': 'text/markdown; charset=utf-8',
      'Cache-Control': 'public, max-age=3600, s-maxage=3600',
    },
  })
}
