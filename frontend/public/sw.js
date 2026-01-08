// Protocol Soup Service Worker
// Optimized for Cloudflare + Fly.io deployment
// Best practices: network-first HTML, cache-first for hashed assets

const CACHE = 'protocol-soup-v1';

// Install: skip waiting to activate immediately
self.addEventListener('install', () => self.skipWaiting());

// Activate: clean old caches and claim clients
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))
      ))
      .then(() => self.clients.claim())
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

  // HTML navigation: network-first (prevents stale HTML with wrong asset hashes)
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then((response) => {
          // Cache for offline
          const clone = response.clone();
          caches.open(CACHE).then((c) => c.put(request, clone));
          return response;
        })
        .catch(() => caches.match(request).then((r) => r || offlinePage()))
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

  // Other static files: stale-while-revalidate
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
    .container { text-align: center; padding: 2rem; }
    h1 { color: #f97316; margin-bottom: 1rem; font-size: 2rem; }
    p { margin-bottom: 1.5rem; opacity: 0.8; }
    button {
      background: #f97316;
      color: white;
      border: none;
      padding: 0.75rem 1.5rem;
      border-radius: 0.5rem;
      font-size: 1rem;
      cursor: pointer;
    }
    button:hover { background: #ea580c; }
  </style>
</head>
<body>
  <div class="container">
    <h1>You're Offline</h1>
    <p>Check your connection and try again.</p>
    <button onclick="location.reload()">Retry</button>
  </div>
</body>
</html>`,
    { headers: { 'Content-Type': 'text/html' } }
  );
}

// Handle messages
self.addEventListener('message', (event) => {
  if (event.data === 'SKIP_WAITING') self.skipWaiting();
});
