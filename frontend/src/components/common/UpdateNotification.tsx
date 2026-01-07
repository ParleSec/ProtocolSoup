import { useServiceWorker } from '../../hooks/useServiceWorker';
import { motion, AnimatePresence } from 'framer-motion';

export function UpdateNotification() {
  const { showReload, reloadPage } = useServiceWorker();

  return (
    <AnimatePresence>
      {showReload && (
        <motion.div
          initial={{ y: 100, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          exit={{ y: 100, opacity: 0 }}
          className="fixed bottom-4 right-4 z-50 max-w-md"
        >
          <div className="bg-gradient-to-r from-amber-500 to-orange-500 text-white rounded-lg shadow-lg p-4 flex items-center gap-3">
            <div className="flex-1">
              <h3 className="font-semibold text-sm mb-1">New Version Available</h3>
              <p className="text-xs opacity-90">
                A new version of Protocol Soup is available. Reload to get the latest features and fixes.
              </p>
            </div>
            <button
              onClick={reloadPage}
              className="px-4 py-2 bg-white text-amber-600 rounded font-medium text-sm hover:bg-amber-50 transition-colors flex-shrink-0"
            >
              Reload
            </button>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

