import { ReactNode, useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Eye, Home, ExternalLink, BookOpen, Menu, X, Radio, FileText } from 'lucide-react'
import { AnimatePresence, motion } from 'framer-motion'

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
  const location = useLocation()
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)

  const navItems = [
    { path: '/', icon: Home, label: 'Home' },
    { path: '/looking-glass', icon: Eye, label: 'Looking Glass' },
    { path: '/ssf-sandbox', icon: Radio, label: 'SSF Sandbox' },
    { path: '/protocols', icon: BookOpen, label: 'Protocols' },
  ]

  // Close mobile menu on route change
  useEffect(() => {
    setIsMobileMenuOpen(false)
  }, [location.pathname])

  // Prevent body scroll when mobile menu is open
  useEffect(() => {
    if (isMobileMenuOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = ''
    }
    return () => {
      document.body.style.overflow = ''
    }
  }, [isMobileMenuOpen])

  return (
    <div className="min-h-screen bg-surface-950 overflow-x-hidden">
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
        <div className="max-w-5xl mx-auto px-3 sm:px-6 py-2.5 sm:py-3">
          <div className="flex items-center justify-between gap-2">
            <Link to="/" className="flex items-center gap-2 sm:gap-2.5 group min-w-0">
              <span className="text-lg sm:text-xl flex-shrink-0">🍜</span>
              <span className="font-semibold text-white group-hover:text-amber-100 transition-colors text-sm sm:text-base truncate">Protocol Soup</span>
            </Link>

            {/* Desktop Navigation */}
            <nav className="hidden lg:flex items-center gap-1">
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
                href="https://docs.protocolsoup.com"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-surface-400 hover:text-white hover:bg-white/5 transition-colors text-sm"
              >
                <FileText className="w-4 h-4" />
                <span>Docs</span>
                <ExternalLink className="w-3 h-3" />
              </a>
              <a
                href="https://github.com/ParleSec/ProtocolSoup"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-surface-400 hover:text-white hover:bg-white/5 transition-colors text-sm"
              >
                <Github className="w-4 h-4" />
                <span>Source</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </nav>

            {/* Mobile Menu Button */}
            <button
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              className="lg:hidden p-2 -mr-2 rounded-lg text-surface-400 hover:text-white hover:bg-white/5 transition-colors"
              aria-label={isMobileMenuOpen ? 'Close menu' : 'Open menu'}
            >
              {isMobileMenuOpen ? (
                <X className="w-6 h-6" />
              ) : (
                <Menu className="w-6 h-6" />
              )}
            </button>
          </div>
        </div>
      </header>

      {/* Mobile Menu Drawer */}
      <AnimatePresence>
        {isMobileMenuOpen && (
          <>
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden"
              onClick={() => setIsMobileMenuOpen(false)}
            />
            
            {/* Drawer */}
            <motion.nav
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 25, stiffness: 300 }}
              className="fixed top-0 right-0 bottom-0 z-50 w-[280px] max-w-[85vw] bg-surface-900 border-l border-white/10 lg:hidden"
            >
              <div className="flex flex-col h-full">
                {/* Drawer Header */}
                <div className="flex items-center justify-between p-4 border-b border-white/5">
                  <span className="font-semibold text-white">Menu</span>
                  <button
                    onClick={() => setIsMobileMenuOpen(false)}
                    className="p-2 -mr-2 rounded-lg text-surface-400 hover:text-white hover:bg-white/5 transition-colors"
                    aria-label="Close menu"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>

                {/* Navigation Links */}
                <div className="flex-1 overflow-y-auto p-4 space-y-1">
                  {navItems.map((item) => {
                    const isActive = location.pathname === item.path || 
                      (item.path !== '/' && location.pathname.startsWith(item.path))
                    return (
                      <Link
                        key={item.path}
                        to={item.path}
                        className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-colors ${
                          isActive
                            ? 'bg-white/10 text-white'
                            : 'text-surface-400 hover:text-white hover:bg-white/5'
                        }`}
                      >
                        <item.icon className="w-5 h-5" />
                        <span className="font-medium">{item.label}</span>
                      </Link>
                    )
                  })}
                </div>

                {/* Drawer Footer */}
                <div className="p-4 border-t border-white/5 space-y-2">
                  <a
                    href="https://docs.protocolsoup.com"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center justify-center gap-2 w-full px-4 py-3 rounded-xl bg-surface-800 text-surface-400 hover:text-white transition-colors"
                  >
                    <FileText className="w-5 h-5" />
                    <span className="font-medium">Documentation</span>
                    <ExternalLink className="w-4 h-4" />
                  </a>
                  <a
                    href="https://github.com/ParleSec/ProtocolSoup"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center justify-center gap-2 w-full px-4 py-3 rounded-xl bg-surface-800 text-surface-400 hover:text-white transition-colors"
                  >
                    <Github className="w-5 h-5" />
                    <span className="font-medium">View Source</span>
                    <ExternalLink className="w-4 h-4" />
                  </a>
                </div>
              </div>
            </motion.nav>
          </>
        )}
      </AnimatePresence>

      {/* Main content */}
      <main className="relative pt-16 sm:pt-20 pb-8 sm:pb-12 min-h-screen">
        <div className="max-w-5xl mx-auto px-4 sm:px-6">
          {children}
        </div>
      </main>

      {/* Footer */}
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
