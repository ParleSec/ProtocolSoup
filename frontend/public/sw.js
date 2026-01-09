// Protocol Soup Service Worker
// Optimized for Cloudflare + Fly.io deployment
// Best practices: network-first HTML, cache-first for hashed assets

// Cache version - bump this on major deployments
const CACHE_VERSION = 'v2';
const CACHE = `protocol-soup-${CACHE_VERSION}`;

// Install: skip waiting to activate immediately
self.addEventListener('install', () => self.skipWaiting());

// Activate: clean ALL old caches and claim clients
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((k) => k !== CACHE).map((k) => {
          console.log('[SW] Deleting old cache:', k);
          return caches.delete(k);
        })
      ))
      .then(() => {
        console.log('[SW] Activated, claiming clients');
        return self.clients.claim();
      })
  );
});

// Fetch handler
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip: non-GET, cross-origin, websockets
  if (request.method !== 'GET') return;
  if (url.origin !== location.origin) return;
  if (url.protocol === 'ws:' || url.protocol === 'wss:') return;

  // Skip: API and protocol endpoints (real-time data)
  if (/^\/(api|ws|oauth2|oidc|saml|spiffe|scim|ssf)/.test(url.pathname)) return;

  // HTML navigation: ALWAYS network-first (prevents stale HTML/JS mismatch)
  if (request.mode === 'navigate' || request.destination === 'document') {
    event.respondWith(
      fetch(request)
        .then((response) => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE).then((c) => c.put(request, clone));
          }
          return response;
        })
        .catch(() => {
          // Only serve cache as absolute last resort (offline)
          return caches.match(request).then((r) => r || offlinePage());
        })
    );
    return;
  }

  // JavaScript files: network-first to ensure fresh code
  if (url.pathname.endsWith('.js') || url.pathname.endsWith('.mjs')) {
    event.respondWith(
      fetch(request)
        .then((response) => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE).then((c) => c.put(request, clone));
          }
          return response;
        })
        .catch(() => caches.match(request))
    );
    return;
  }

  // Hashed assets (/assets/*): cache-first (safe - hash changes on update)
  if (url.pathname.startsWith('/assets/')) {
    event.respondWith(
      caches.match(request).then((cached) => {
        if (cached) return cached;
        return fetch(request).then((response) => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE).then((c) => c.put(request, clone));
          }
          return response;
        });
      })
    );
    return;
  }

  // Other static files (icons, manifest, etc.): stale-while-revalidate
  event.respondWith(
    caches.match(request).then((cached) => {
      const fetched = fetch(request).then((response) => {
        if (response.ok) {
          const clone = response.clone();
          caches.open(CACHE).then((c) => c.put(request, clone));
        }
        return response;
      });
      return cached || fetched;
    })
  );
});

// Simple offline page
function offlinePage() {
  return new Response(
    `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Offline - Protocol Soup</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: system-ui, -apple-system, sans-serif;
      background: #020617; 
      color: #f1f5f9; 
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .container { text-align: center; padding: 2rem; max-width: 400px; }
    h1 { color: #f97316; margin-bottom: 1rem; font-size: 1.5rem; }
    p { margin-bottom: 1.5rem; opacity: 0.8; font-size: 0.9rem; }
    button {
      background: #f97316;
      color: white;
      border: none;
      padding: 0.75rem 1.5rem;
      border-radius: 0.5rem;
      font-size: 1rem;
      cursor: pointer;
      margin: 0.5rem;
    }
    button:hover { background: #ea580c; }
    .secondary {
      background: transparent;
      border: 1px solid rgba(255,255,255,0.2);
    }
    .secondary:hover { background: rgba(255,255,255,0.1); }
  </style>
</head>
<body>
  <div class="container">
    <div style="font-size: 3rem; margin-bottom: 1rem;">🍜</div>
    <h1>You're Offline</h1>
    <p>Check your connection and try again.</p>
    <button onclick="location.reload()">Retry</button>
    <button class="secondary" onclick="clearCache()">Clear Cache</button>
  </div>
  <script>
    async function clearCache() {
      if ('caches' in window) {
        const names = await caches.keys();
        await Promise.all(names.map(n => caches.delete(n)));
      }
      if ('serviceWorker' in navigator) {
        const regs = await navigator.serviceWorker.getRegistrations();
        await Promise.all(regs.map(r => r.unregister()));
      }
      location.reload();
    }
  </script>
</body>
</html>`,
    { headers: { 'Content-Type': 'text/html' } }
  );
}

// Handle messages from the app
self.addEventListener('message', (event) => {
  if (event.data === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  if (event.data === 'CLEAR_CACHE') {
    caches.keys().then((names) => {
      names.forEach((name) => caches.delete(name));
    });
  }
});
