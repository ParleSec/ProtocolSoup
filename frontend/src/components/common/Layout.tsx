import { ReactNode } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Eye, Home, Github, ExternalLink, BookOpen } from 'lucide-react'

interface LayoutProps {
  children: ReactNode
}

export function Layout({ children }: LayoutProps) {
  const location = useLocation()

  const navItems = [
    { path: '/', icon: Home, label: 'Home' },
    { path: '/looking-glass', icon: Eye, label: 'Looking Glass' },
    { path: '/protocols', icon: BookOpen, label: 'Protocols' },
  ]

  return (
    <div className="min-h-screen bg-surface-950">
      {/* Subtle grid background */}
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

      {/* Header */}
      <header className="fixed top-0 left-0 right-0 z-50 bg-surface-950/80 backdrop-blur-sm border-b border-white/5">
        <div className="max-w-5xl mx-auto px-6 py-3">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-2.5 group">
              <span className="text-xl">🍜</span>
              <span className="font-semibold text-white group-hover:text-amber-100 transition-colors">Protocol Soup</span>
            </Link>

            <nav className="flex items-center gap-1">
              {navItems.map((item) => {
                const isActive = location.pathname === item.path || 
                  (item.path !== '/' && location.pathname.startsWith(item.path))
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    className={`flex items-center gap-2 px-3 py-1.5 rounded-md transition-colors text-sm ${
                      isActive
                        ? 'bg-white/10 text-white'
                        : 'text-surface-400 hover:text-white hover:bg-white/5'
                    }`}
                  >
                    <item.icon className="w-4 h-4" />
                    <span>{item.label}</span>
                  </Link>
                )
              })}
              <div className="w-px h-4 bg-white/10 mx-2" />
              <a
                href="https://github.com"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-surface-500 hover:text-white hover:bg-white/5 transition-colors text-sm"
              >
                <Github className="w-4 h-4" />
                <span>Source</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </nav>
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="relative pt-20 pb-12 min-h-screen">
        <div className="max-w-5xl mx-auto px-6">
          {children}
        </div>
      </main>

      {/* Footer */}
      <footer className="relative border-t border-white/5 py-6">
        <div className="max-w-5xl mx-auto px-6">
          <div className="flex items-center justify-between text-xs text-surface-600">
            <p>Protocol Soup — explore authentication protocols</p>
            <p className="font-mono">OAuth 2.0 · OIDC · more soon</p>
          </div>
        </div>
      </footer>
    </div>
  )
}
