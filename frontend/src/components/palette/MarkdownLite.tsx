'use client'

import { Fragment } from 'react'

/**
 * MarkdownLite renders the small subset of markdown used in ProtocolSoup
 * artefact bodies — paragraphs, inline `code`, **bold**, *italic*, links,
 * and bullet/numbered lists. It deliberately does NOT support raw HTML
 * (with one exception: `<mark>` spans coming from the backend snippet
 * builder are recognised and rendered as highlighted spans).
 *
 * The point is to keep the dependency surface zero — the project prompt
 * forbids new UI library dependencies — while still rendering the corpus
 * faithfully. If the corpus ever grows to need tables, code blocks, or
 * nested lists, swap this for a real markdown library.
 */
interface MarkdownLiteProps {
  source: string
  /** When true, the source is the query-aware snippet that may contain
   *  literal `<mark>...</mark>` spans from the backend. */
  allowMark?: boolean
  className?: string
}

export function MarkdownLite({ source, allowMark, className }: MarkdownLiteProps) {
  if (!source) return null
  const blocks = splitBlocks(source)
  return (
    <div className={className ?? 'space-y-2 text-[13px] leading-relaxed text-surface-200'}>
      {blocks.map((block, i) => renderBlock(block, i, !!allowMark))}
    </div>
  )
}

type Block =
  | { kind: 'paragraph'; text: string }
  | { kind: 'heading'; level: number; text: string }
  | { kind: 'ul'; items: string[] }
  | { kind: 'ol'; items: string[] }

function splitBlocks(source: string): Block[] {
  const lines = source.replace(/\r\n/g, '\n').split('\n')
  const blocks: Block[] = []
  let buffer: string[] = []

  const flushParagraph = () => {
    const text = buffer.join(' ').trim()
    if (text) blocks.push({ kind: 'paragraph', text })
    buffer = []
  }

  let i = 0
  while (i < lines.length) {
    const line = lines[i]

    if (line.trim() === '') {
      flushParagraph()
      i++
      continue
    }

    const heading = /^(#{1,6})\s+(.*)$/.exec(line)
    if (heading) {
      flushParagraph()
      blocks.push({ kind: 'heading', level: heading[1].length, text: heading[2].trim() })
      i++
      continue
    }

    if (/^\s*[-*+]\s+/.test(line)) {
      flushParagraph()
      const items: string[] = []
      while (i < lines.length && /^\s*[-*+]\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*[-*+]\s+/, ''))
        i++
      }
      blocks.push({ kind: 'ul', items })
      continue
    }

    if (/^\s*\d+\.\s+/.test(line)) {
      flushParagraph()
      const items: string[] = []
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*\d+\.\s+/, ''))
        i++
      }
      blocks.push({ kind: 'ol', items })
      continue
    }

    buffer.push(line)
    i++
  }
  flushParagraph()
  return blocks
}

function renderBlock(block: Block, key: number, allowMark: boolean) {
  switch (block.kind) {
    case 'paragraph':
      return (
        <p key={key} className="text-surface-200">
          {renderInline(block.text, allowMark)}
        </p>
      )
    case 'heading': {
      const sizes = ['text-base', 'text-base', 'text-sm', 'text-sm', 'text-xs', 'text-xs']
      const size = sizes[Math.min(block.level - 1, sizes.length - 1)]
      return (
        <p key={key} className={`font-semibold text-white ${size} mt-1`}>
          {renderInline(block.text, allowMark)}
        </p>
      )
    }
    case 'ul':
      return (
        <ul key={key} className="list-disc pl-5 space-y-0.5 text-surface-200">
          {block.items.map((item, j) => (
            <li key={j}>{renderInline(item, allowMark)}</li>
          ))}
        </ul>
      )
    case 'ol':
      return (
        <ol key={key} className="list-decimal pl-5 space-y-0.5 text-surface-200">
          {block.items.map((item, j) => (
            <li key={j}>{renderInline(item, allowMark)}</li>
          ))}
        </ol>
      )
  }
}

/**
 * Inline tokeniser. Walks the string once, splitting on the smallest set of
 * inline markers we support: `<mark>`, backticks, `**`, `*`, and link
 * syntax `[text](url)`. Each segment is rendered with the right tag. No
 * raw HTML is ever passed through except the `<mark>` open/close tags
 * recognised here.
 */
function renderInline(text: string, allowMark: boolean): React.ReactNode {
  const nodes: React.ReactNode[] = []
  let i = 0
  let key = 0
  let plain = ''

  const flushPlain = () => {
    if (plain) {
      nodes.push(plain)
      plain = ''
    }
  }

  while (i < text.length) {
    if (allowMark && text.startsWith('<mark>', i)) {
      const end = text.indexOf('</mark>', i + 6)
      if (end >= 0) {
        flushPlain()
        nodes.push(
          <mark
            key={`m-${key++}`}
            className="bg-amber-400/20 text-amber-100 rounded px-0.5 py-px"
          >
            {text.slice(i + 6, end)}
          </mark>,
        )
        i = end + 7
        continue
      }
    }

    const ch = text[i]

    if (ch === '`') {
      const end = text.indexOf('`', i + 1)
      if (end > i) {
        flushPlain()
        nodes.push(
          <code
            key={`c-${key++}`}
            className="rounded bg-surface-800/80 border border-white/5 px-1 py-px font-mono text-[12px] text-surface-100"
          >
            {text.slice(i + 1, end)}
          </code>,
        )
        i = end + 1
        continue
      }
    }

    if (text.startsWith('**', i)) {
      const end = text.indexOf('**', i + 2)
      if (end > i + 1) {
        flushPlain()
        nodes.push(
          <strong key={`b-${key++}`} className="font-semibold text-white">
            {text.slice(i + 2, end)}
          </strong>,
        )
        i = end + 2
        continue
      }
    }

    if (ch === '*' && text[i + 1] !== ' ') {
      const end = text.indexOf('*', i + 1)
      if (end > i) {
        flushPlain()
        nodes.push(
          <em key={`i-${key++}`} className="italic">
            {text.slice(i + 1, end)}
          </em>,
        )
        i = end + 1
        continue
      }
    }

    if (ch === '[') {
      const close = text.indexOf(']', i + 1)
      if (close > i && text[close + 1] === '(') {
        const urlEnd = text.indexOf(')', close + 2)
        if (urlEnd > close + 1) {
          flushPlain()
          const linkText = text.slice(i + 1, close)
          const url = text.slice(close + 2, urlEnd)
          nodes.push(
            <a
              key={`a-${key++}`}
              href={url}
              target={url.startsWith('http') ? '_blank' : undefined}
              rel={url.startsWith('http') ? 'noopener noreferrer' : undefined}
              className="text-amber-300 underline-offset-2 hover:underline"
            >
              {linkText}
            </a>,
          )
          i = urlEnd + 1
          continue
        }
      }
    }

    plain += ch
    i++
  }

  flushPlain()
  return (
    <Fragment>
      {nodes.map((n, idx) => (
        <Fragment key={idx}>{n}</Fragment>
      ))}
    </Fragment>
  )
}
