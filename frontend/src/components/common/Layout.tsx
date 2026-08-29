import { ReactNode } from 'react'
import Link from 'next/link'
import { BookOpen, Eye, FileText, Shield, Wallet } from 'lucide-react'
import { LayoutHeader } from './LayoutHeader.client'
import { SITE_CONFIG } from '@/config/seo'

function Github({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden="true">
      <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
    </svg>
  )
}

interface LayoutProps {
  children: ReactNode
}

export function Layout({ children }: LayoutProps) {
  return (
    <div className="min-h-screen bg-surface-950 overflow-x-hidden">
      <div className="fixed inset-0 opacity-30 pointer-events-none">
        <svg className="absolute inset-0 w-full h-full">
          <defs>
            <pattern id="grid" width="60" height="60" patternUnits="userSpaceOnUse">
              <path d="M 60 0 L 0 0 0 60" fill="none" stroke="rgba(255,255,255,0.02)" strokeWidth="1"/>
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#grid)" />
        </svg>
      </div>

      <LayoutHeader />

      <main className="relative pt-16 sm:pt-20 pb-8 sm:pb-12 min-h-screen">
        <div className="max-w-5xl mx-auto px-4 sm:px-6">
          {children}
        </div>
      </main>

      <footer className="relative border-t border-white/5 py-8 sm:py-10">
        <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-amber-500/50 to-transparent" />
        <div className="max-w-5xl mx-auto px-4 sm:px-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-6">
          <div className="flex flex-col items-center sm:items-start gap-2">
            <Link href="/" className="inline-flex items-center gap-2 group">
              <span className="text-lg" aria-hidden="true">🍜</span>
              <span className="text-sm font-semibold text-white group-hover:text-amber-100 transition-colors">ProtocolSoup</span>
            </Link>
            <p className="font-mono text-[11px] tracking-wide text-amber-400/80">
              real hops · real tokens · no mocks
            </p>
            <p className="text-xs text-surface-600">
              Built by{' '}
              <a
                href="https://www.linkedin.com/in/mason-parle/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-surface-400 hover:text-amber-400 transition-colors"
              >
                Mason Parle
              </a>
            </p>
          </div>
          <nav className="flex flex-wrap items-center justify-center sm:justify-end gap-2 text-xs text-surface-400" aria-label="Footer">
            <Link
              href="/looking-glass"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-white/10 bg-white/[0.03] hover:border-amber-500/40 hover:text-amber-300 transition-colors"
            >
              <Eye className="w-3.5 h-3.5" />
              Looking Glass
            </Link>
            <Link
              href="/trust"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-white/10 bg-white/[0.03] hover:border-amber-500/40 hover:text-amber-300 transition-colors"
            >
              <Shield className="w-3.5 h-3.5" />
              Trust
            </Link>
            <Link
              href="/protocols"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-white/10 bg-white/[0.03] hover:border-amber-500/40 hover:text-amber-300 transition-colors"
            >
              <BookOpen className="w-3.5 h-3.5" />
              Protocol Reference
            </Link>
            <a
              href={SITE_CONFIG.walletUrl}
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-white/10 bg-white/[0.03] hover:border-amber-500/40 hover:text-amber-300 transition-colors"
            >
              <Wallet className="w-3.5 h-3.5" />
              Wallet
            </a>
            <a
              href="https://docs.protocolsoup.com"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-white/10 bg-white/[0.03] hover:border-amber-500/40 hover:text-amber-300 transition-colors"
            >
              <FileText className="w-3.5 h-3.5" />
              Docs
            </a>
            <a
              href="https://github.com/ParleSec/ProtocolSoup"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-white/10 bg-white/[0.03] hover:border-amber-500/40 hover:text-amber-300 transition-colors"
            >
              <Github className="w-3.5 h-3.5" />
              GitHub
            </a>
          </nav>
        </div>
      </footer>
    </div>
  )
}

