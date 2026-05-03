import { BookMarked, ExternalLink, ShieldCheck, FileText, Layers, Award } from 'lucide-react'
import type {
  ProtocolReference,
  ProtocolReferenceCategory,
} from '@/protocols/presentation/protocol-catalog-data'

interface ProtocolReferencesProps {
  title: string
  description: string
  references: ProtocolReference[]
}

const CATEGORY_ORDER: ProtocolReferenceCategory[] = ['core', 'security', 'companion', 'profile']

const CATEGORY_META: Record<
  ProtocolReferenceCategory,
  { title: string; description: string; icon: typeof FileText; accent: string }
> = {
  core: {
    title: 'Core specs',
    description: 'The specifications that define this protocol.',
    icon: FileText,
    accent: 'text-blue-300',
  },
  security: {
    title: 'Security & privacy',
    description: 'Dedicated security and privacy considerations.',
    icon: ShieldCheck,
    accent: 'text-emerald-300',
  },
  companion: {
    title: 'Companion specs',
    description: 'Extensions, hardenings, and supporting RFCs.',
    icon: Layers,
    accent: 'text-purple-300',
  },
  profile: {
    title: 'Deployment profiles',
    description: 'Profiles that constrain the protocol for specific assurance regimes.',
    icon: Award,
    accent: 'text-amber-300',
  },
}

export function ProtocolReferences({ title, description, references }: ProtocolReferencesProps) {
  if (references.length === 0) {
    return null
  }

  const grouped = CATEGORY_ORDER
    .map((category) => ({
      category,
      items: references.filter((r) => r.category === category),
    }))
    .filter((group) => group.items.length > 0)

  return (
    <section className="rounded-xl border border-white/10 bg-surface-900/40 overflow-hidden">
      <header className="px-4 sm:px-5 py-3 sm:py-4 border-b border-white/5 flex items-start gap-3">
        <div className="w-9 h-9 rounded-lg bg-purple-500/15 flex items-center justify-center flex-shrink-0">
          <BookMarked className="w-4 h-4 text-purple-300" />
        </div>
        <div className="min-w-0">
          <h2 className="text-base sm:text-lg font-semibold text-white">{title}</h2>
          <p className="text-xs sm:text-sm text-surface-400 mt-0.5">{description}</p>
        </div>
      </header>

      <div className="divide-y divide-white/5">
        {grouped.map(({ category, items }) => (
          <CategoryGroup key={category} category={category} items={items} />
        ))}
      </div>
    </section>
  )
}

function CategoryGroup({
  category,
  items,
}: {
  category: ProtocolReferenceCategory
  items: ProtocolReference[]
}) {
  const meta = CATEGORY_META[category]
  const Icon = meta.icon

  return (
    <div className="px-4 sm:px-5 py-3 sm:py-4">
      <div className="flex items-center gap-2 mb-2 sm:mb-3">
        <Icon className={`w-3.5 h-3.5 ${meta.accent}`} />
        <h3 className={`text-xs sm:text-sm font-medium uppercase tracking-wider ${meta.accent}`}>
          {meta.title}
        </h3>
        <span className="text-xs text-surface-500">· {meta.description}</span>
      </div>
      <ul className="space-y-1.5 sm:space-y-2">
        {items.map((ref) => (
          <li key={ref.href}>
            <a
              href={ref.href}
              target="_blank"
              rel="noopener noreferrer"
              className="group flex items-start gap-2 rounded-lg px-2 py-1.5 hover:bg-white/[0.03] active:bg-white/[0.05] transition-colors"
            >
              <ExternalLink className="w-3.5 h-3.5 mt-0.5 text-surface-500 group-hover:text-surface-300 transition-colors flex-shrink-0" />
              <div className="min-w-0">
                <span className="text-sm text-surface-200 group-hover:text-white transition-colors">
                  {ref.label}
                </span>
                {ref.note && (
                  <p className="text-xs text-surface-500 mt-0.5">{ref.note}</p>
                )}
              </div>
            </a>
          </li>
        ))}
      </ul>
    </div>
  )
}

export default ProtocolReferences
