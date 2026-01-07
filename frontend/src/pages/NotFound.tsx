import { Link } from 'react-router-dom'
import { Home, Eye, Radio, BookOpen, AlertCircle } from 'lucide-react'
import { motion } from 'framer-motion'
import { NotFoundSEO } from '../components/common/SEO'

export function NotFound() {
  const quickLinks = [
    { path: '/', icon: Home, label: 'Home', description: 'Return to dashboard' },
    { path: '/looking-glass', icon: Eye, label: 'Looking Glass', description: 'Inspect protocol flows' },
    { path: '/ssf-sandbox', icon: Radio, label: 'SSF Sandbox', description: 'Test SSF events' },
    { path: '/protocols', icon: BookOpen, label: 'Protocols', description: 'Explore protocols' },
  ]

  return (
    <>
      <NotFoundSEO />
      <div className="min-h-[70vh] flex items-center justify-center">
      <div className="max-w-2xl mx-auto text-center space-y-8">
        {/* Animated 404 */}
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5, ease: 'easeOut' }}
          className="relative"
        >
          <div className="text-[120px] sm:text-[180px] font-bold leading-none">
            <span className="inline-block gradient-text">404</span>
          </div>
          
          {/* Floating decorative elements */}
          <motion.div
            animate={{ 
              y: [-10, 10, -10],
              rotate: [0, 5, -5, 0]
            }}
            transition={{ 
              duration: 4, 
              repeat: Infinity,
              ease: 'easeInOut'
            }}
            className="absolute -top-8 -left-8 text-6xl opacity-20"
          >
            🍜
          </motion.div>
          
          <motion.div
            animate={{ 
              y: [10, -10, 10],
              rotate: [0, -5, 5, 0]
            }}
            transition={{ 
              duration: 3.5, 
              repeat: Infinity,
              ease: 'easeInOut',
              delay: 0.5
            }}
            className="absolute -top-4 -right-8 text-5xl opacity-20"
          >
            🔍
          </motion.div>
        </motion.div>

        {/* Error message */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="space-y-3"
        >
          <div className="flex items-center justify-center gap-2 text-amber-400">
            <AlertCircle className="w-5 h-5" />
            <h1 className="text-xl sm:text-2xl font-semibold">Page Not Found</h1>
          </div>
          
          <p className="text-surface-400 text-sm sm:text-base max-w-md mx-auto">
            Looks like this protocol endpoint doesn't exist. The page you're looking for might have been moved or doesn't exist.
          </p>
        </motion.div>

        {/* Quick links */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.4 }}
          className="space-y-4"
        >
          <p className="text-surface-500 text-sm font-medium">Try one of these instead:</p>
          
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {quickLinks.map((link, index) => (
              <motion.div
                key={link.path}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: 0.5 + index * 0.1 }}
              >
                <Link
                  to={link.path}
                  className="group block p-4 rounded-xl bg-surface-900/50 border border-white/5 hover:border-amber-500/30 hover:bg-surface-900 transition-all duration-300"
                >
                  <div className="flex items-start gap-3">
                    <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-surface-800 group-hover:bg-amber-500/10 flex items-center justify-center transition-colors">
                      <link.icon className="w-5 h-5 text-surface-400 group-hover:text-amber-400 transition-colors" />
                    </div>
                    <div className="flex-1 min-w-0 text-left">
                      <div className="font-medium text-white group-hover:text-amber-100 transition-colors text-sm sm:text-base">
                        {link.label}
                      </div>
                      <div className="text-xs text-surface-500 group-hover:text-surface-400 transition-colors mt-0.5">
                        {link.description}
                      </div>
                    </div>
                  </div>
                </Link>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Back to home button */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5, delay: 0.8 }}
        >
          <Link
            to="/"
            className="inline-flex items-center gap-2 px-6 py-3 rounded-lg bg-amber-500 hover:bg-amber-600 text-white font-medium transition-colors"
          >
            <Home className="w-4 h-4" />
            <span>Go to Homepage</span>
          </Link>
        </motion.div>
      </div>
    </div>
    </>
  )
}

