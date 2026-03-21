import { ReactNode } from 'react'
import { FileText } from 'lucide-react'
import { LayoutHeader } from './LayoutHeader.client'

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

      <footer className="relative border-t border-white/5 py-4 sm:py-6">
        <div className="max-w-5xl mx-auto px-4 sm:px-6">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 sm:gap-2">
            <div className="flex flex-col sm:flex-row items-center gap-2 text-xs text-surface-600">
              <p>Protocol Soup - explore authentication protocols</p>
              <span className="hidden sm:inline text-surface-700">·</span>
              <p className="font-mono">OAuth 2.0 · OIDC · SAML · SPIFFE · SSF</p>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span className="text-surface-600">Built by</span>
              <a
                href="https://www.linkedin.com/in/mason-parle/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-surface-400 hover:text-amber-400 transition-colors font-medium"
              >
                Mason Parle
              </a>
              <span className="text-surface-700">·</span>
              <a
                href="https://docs.protocolsoup.com"
                target="_blank"
                rel="noopener noreferrer"
                className="text-surface-400 hover:text-amber-400 transition-colors inline-flex items-center gap-1"
              >
                <FileText className="w-3 h-3" />
                <span>Docs</span>
              </a>
              <span className="text-surface-700">·</span>
              <a
                href="https://github.com/ParleSec/ProtocolSoup"
                target="_blank"
                rel="noopener noreferrer"
                className="text-surface-400 hover:text-amber-400 transition-colors inline-flex items-center gap-1"
              >
                <Github className="w-3 h-3" />
                <span>GitHub</span>
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}

