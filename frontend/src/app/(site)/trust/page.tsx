import { PAGE_SEO } from '@/config/seo'
import { createPageMetadata } from '@/lib/seo'
import { TRUST_LAST_REVIEWED } from '@/lib/trust'
import {
  TRUST_SECTIONS,
  type TrustBlock,
  type TrustEmail,
  type TrustLink,
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

function isLink(part: TrustText): part is TrustLink {
  return typeof part === 'object' && 'href' in part
}

function isEmail(part: TrustText): part is TrustEmail {
  return typeof part === 'object' && 'address' in part
}

function DisclosureEmail({ address }: TrustEmail) {
  const safeAddress = address.replace(/[^a-zA-Z0-9@._+-]/g, '')
  const markup = `<!--email_off--><a href="mailto:${safeAddress}" class="${linkClass}">${safeAddress}</a><!--/email_off-->`

  return <span dangerouslySetInnerHTML={{ __html: markup }} />
}

function TextParts({ parts }: { parts: TrustText[] }) {
  return (
    <>
      {parts.map((part, index) =>
        isEmail(part) ? (
          <DisclosureEmail key={`${part.address}-${index}`} address={part.address} />
        ) : isLink(part) ? (
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
    case 'callout':
      return (
        <div className="mt-4 rounded-lg border border-amber-400/25 bg-amber-400/[0.06] px-4 py-3">
          <p className="text-sm font-medium text-amber-200">{block.title}</p>
          <p className="mt-1 text-sm text-surface-200 leading-relaxed">
            <TextParts parts={block.parts} />
          </p>
        </div>
      )
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
            <li key={item}>{item}</li>
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
        <div className="mt-3 overflow-x-auto rounded-lg border border-white/10">
          <table className="w-full min-w-[42rem] text-left text-sm text-surface-300 border-collapse">
            <thead>
              <tr className="border-b border-white/10 bg-white/[0.03]">
                {block.headers.map((header) => (
                  <th
                    key={header}
                    scope="col"
                    className="px-3 py-2.5 font-medium text-white whitespace-nowrap"
                  >
                    {header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {block.rows.map((row) => (
                <tr key={row.join('|')} className="border-b border-white/5 align-top">
                  {row.map((cell, cellIndex) =>
                    cellIndex === 0 ? (
                      <th
                        key={`${cellIndex}-${cell.slice(0, 24)}`}
                        scope="row"
                        className="px-3 py-2.5 font-medium text-surface-100"
                      >
                        {cell}
                      </th>
                    ) : (
                      <td key={`${cellIndex}-${cell.slice(0, 24)}`} className="px-3 py-2.5">
                        {cell}
                      </td>
                    ),
                  )}
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
    <article className="max-w-5xl mx-auto py-8 sm:py-12">
      <header className="max-w-3xl">
        <p className="text-xs font-medium uppercase tracking-[0.18em] text-amber-300">
          Check it yourself
        </p>
        <h1 className="mt-2 text-3xl sm:text-4xl font-semibold text-white tracking-tight">
          Trust &amp; verification
        </h1>
        <p className="mt-4 text-base text-surface-300 leading-relaxed">
          Decide what ProtocolSoup exposes you to, close a security alert, or verify the
          software before it enters your environment.
        </p>
        <p className="mt-3 text-sm text-surface-400">Last reviewed: {TRUST_LAST_REVIEWED}</p>
      </header>

      <div className="mt-8 grid gap-3 sm:grid-cols-2">
        <a
          href="#scanner-alerts"
          className="group rounded-xl border border-white/10 bg-white/[0.025] p-4 transition-colors hover:border-amber-400/30 hover:bg-amber-400/[0.04]"
        >
          <span className="text-xs font-medium uppercase tracking-wider text-amber-300">
            Security analyst
          </span>
          <span className="mt-1 block text-base font-medium text-white group-hover:text-amber-100">
            Close the alert in 60 seconds
          </span>
          <span className="mt-1 block text-sm text-surface-400">
            Indicators, expected behaviour, egress, and blocking guidance.
          </span>
        </a>
        <a
          href="#scope"
          className="group rounded-xl border border-white/10 bg-white/[0.025] p-4 transition-colors hover:border-amber-400/30 hover:bg-amber-400/[0.04]"
        >
          <span className="text-xs font-medium uppercase tracking-wider text-amber-300">
            Environment evaluator
          </span>
          <span className="mt-1 block text-base font-medium text-white group-hover:text-amber-100">
            Evaluate the boundary
          </span>
          <span className="mt-1 block text-sm text-surface-400">
            Data, operators, failure modes, verification, and self-hosting.
          </span>
        </a>
      </div>

      <nav aria-label="On this page" className="mt-8 border-y border-white/10 py-4">
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
      <div className="mt-10 space-y-12">
        {TRUST_SECTIONS.map((section) => (
          <section key={section.id} aria-labelledby={section.id}>
            <h2 id={section.id} className="text-xl font-semibold text-white scroll-mt-24">
              {section.title}
            </h2>
            {section.summary ? (
              <p className="mt-1 text-sm text-surface-500">{section.summary}</p>
            ) : null}
            {section.blocks.map((block, index) => (
              <Block key={`${section.id}-${index}`} block={block} />
            ))}
          </section>
        ))}
      </div>
    </article>
  )
}
