import { PAGE_SEO } from '@/config/seo'
import { createPageMetadata } from '@/lib/seo'
import { TRUST_LAST_REVIEWED } from '@/lib/trust'
import {
  TRUST_SECTIONS,
  type TrustBlock,
  type TrustText,
} from '@/lib/trustContent'

const seo = PAGE_SEO['/trust']

export const metadata = createPageMetadata({
  title: seo.title,
  description: seo.description,
  keywords: seo.keywords,
  path: '/trust',
})

const linkClass =
  'text-amber-300 hover:text-amber-200 underline underline-offset-2 break-all'

function isLink(part: TrustText): part is { href: string; label: string } {
  return typeof part === 'object'
}

function TextParts({ parts }: { parts: TrustText[] }) {
  return (
    <>
      {parts.map((part, index) =>
        isLink(part) ? (
          <a
            key={`${part.href}-${index}`}
            href={part.href}
            className={linkClass}
            {...(part.href.startsWith('http')
              ? { target: '_blank', rel: 'noopener noreferrer' }
              : {})}
          >
            {part.label}
          </a>
        ) : (
          <span key={index}>{part}</span>
        ),
      )}
    </>
  )
}

function Block({ block }: { block: TrustBlock }) {
  switch (block.type) {
    case 'p':
      return (
        <p className="mt-3 text-sm text-surface-300 leading-relaxed">
          <TextParts parts={block.parts} />
        </p>
      )
    case 'ul':
      return (
        <ul className="mt-3 list-disc pl-5 space-y-1.5 text-sm text-surface-300 leading-relaxed">
          {block.items.map((item) => (
            <li key={item}>
              <code className="text-xs sm:text-[13px] text-surface-200">{item}</code>
            </li>
          ))}
        </ul>
      )
    case 'pre':
      return (
        <pre className="mt-3 overflow-x-auto rounded-lg border border-white/10 bg-black/40 p-3 text-xs text-surface-200 whitespace-pre-wrap break-all">
          <code>{block.code}</code>
        </pre>
      )
    case 'table':
      return (
        <div className="mt-3 overflow-x-auto">
          <table className="w-full text-left text-sm text-surface-300 border-collapse">
            <thead>
              <tr className="border-b border-white/10">
                {block.headers.map((header) => (
                  <th key={header} className="py-2 pr-4 font-medium text-white whitespace-nowrap">
                    {header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {block.rows.map((row) => (
                <tr key={row.join('|')} className="border-b border-white/5 align-top">
                  {row.map((cell, cellIndex) => (
                    <td key={`${cellIndex}-${cell.slice(0, 24)}`} className="py-2 pr-4">
                      {cell}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )
  }
}

export default function TrustPage() {
  return (
    <article className="max-w-3xl mx-auto py-8 sm:py-12">
      <h1 className="text-3xl sm:text-4xl font-semibold text-white tracking-tight">Trust</h1>
      <p className="mt-3 text-sm text-surface-400">Last reviewed: {TRUST_LAST_REVIEWED}</p>
      <nav aria-label="On this page" className="mt-8">
        <ul className="flex flex-wrap gap-x-4 gap-y-2 text-sm">
          {TRUST_SECTIONS.map((section) => (
            <li key={section.id}>
              <a href={`#${section.id}`} className="text-surface-400 hover:text-amber-300">
                {section.title}
              </a>
            </li>
          ))}
        </ul>
      </nav>
      <div className="mt-10 space-y-10">
        {TRUST_SECTIONS.map((section) => (
          <section key={section.id} aria-labelledby={section.id}>
            <h2 id={section.id} className="text-xl font-semibold text-white scroll-mt-24">
              {section.title}
            </h2>
            {section.blocks.map((block, index) => (
              <Block key={`${section.id}-${index}`} block={block} />
            ))}
          </section>
        ))}
      </div>
    </article>
  )
}
