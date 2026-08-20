import { createPageMetadata } from '@/lib/seo'
import { TRUST_LAST_REVIEWED } from '@/lib/trust'

export const metadata = createPageMetadata({
  title: 'Trust',
  description: 'Placeholder Trust page. Content will be published after live-environment facts are collected.',
  path: '/trust',
})

const SECTIONS = [
  { id: 'scope', title: 'Scope' },
  { id: 'trust-boundary', title: 'Trust boundary' },
  { id: 'scanner-alerts', title: 'Scanner alerts' },
  { id: 'supply-chain', title: 'Supply chain' },
  { id: 'hosted-instance', title: 'Hosted instance' },
  { id: 'conformance', title: 'Conformance' },
  { id: 'vulnerability-disclosure', title: 'Vulnerability disclosure' },
  { id: 'governance', title: 'Governance' },
  { id: 'limitations', title: 'Limitations' },
] as const

export default function TrustPage() {
  return (
    <article className="max-w-3xl mx-auto py-8 sm:py-12">
      <h1 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight">Trust</h1>
      <p className="mt-3 text-sm text-surface-400">Last reviewed: {TRUST_LAST_REVIEWED}</p>
      <div className="mt-10 space-y-10">
        {SECTIONS.map((section) => (
          <section key={section.id} aria-labelledby={section.id}>
            <h2 id={section.id} className="text-xl font-semibold text-white scroll-mt-24">
              {section.title}
            </h2>
            <p className="mt-3 text-sm text-surface-400">
              Placeholder. This section will be filled after live-environment facts are collected.
            </p>
          </section>
        ))}
      </div>
    </article>
  )
}
