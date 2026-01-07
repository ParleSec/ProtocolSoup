// Protocol Soup Service Worker
// Increment version when making breaking changes
const VERSION = 'v2';
const CACHE_NAME = `protocol-soup-${VERSION}`;
const RUNTIME_CACHE = `protocol-soup-runtime-${VERSION}`;

// Assets to cache on install (static assets only, NOT HTML)
const PRECACHE_ASSETS = [
  '/favicon.svg',
  '/manifest.json'
];

// Install event - cache core assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('[SW] Precaching static assets');
        return cache.addAll(PRECACHE_ASSETS);
      })
      .then(() => {
        console.log('[SW] Skip waiting - activating new service worker');
        return self.skipWaiting();
      })
      .catch((error) => {
        console.error('[SW] Precache failed:', error);
      })
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames
            .filter((name) => name !== CACHE_NAME && name !== RUNTIME_CACHE)
            .map((name) => {
              console.log('[SW] Deleting old cache:', name);
              return caches.delete(name);
            })
        );
      })
      .then(() => {
        console.log('[SW] Claiming clients');
        return self.clients.claim();
      })
      .catch((error) => {
        console.error('[SW] Activation failed:', error);
      })
  );
});

// Helper to determine if request is for navigation (with null safety)
function isNavigationRequest(request) {
  if (request.mode === 'navigate') {
    return true;
  }
  const accept = request.headers.get('accept');
  return request.method === 'GET' && accept && accept.includes('text/html');
}

// Helper to safely cache a response
async function cacheResponse(cacheName, request, response) {
  try {
    const cache = await caches.open(cacheName);
    await cache.put(request, response);
  } catch (error) {
    console.warn('[SW] Failed to cache response:', error);
  }
}

// Fetch event - smart caching strategies
self.addEventListener('fetch', (event) => {
  const { request } = event;
  
  // Parse URL safely
  let url;
  try {
    url = new URL(request.url);
  } catch {
    return; // Invalid URL, let browser handle it
  }

  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }

  // Skip WebSocket connections
  if (url.protocol === 'ws:' || url.protocol === 'wss:') {
    return;
  }

  // Skip cross-origin requests (third-party scripts, analytics, CDNs, etc.)
  // Let the browser handle these directly to avoid CORS issues and unnecessary caching
  if (url.origin !== self.location.origin) {
    return;
  }

  // Network-only for API calls (no caching, real-time data)
  if (url.pathname.startsWith('/api') || 
      url.pathname.startsWith('/oauth2') || 
      url.pathname.startsWith('/oidc') ||
      url.pathname.startsWith('/saml') ||
      url.pathname.startsWith('/scim') ||
      url.pathname.startsWith('/ssf') ||
      url.pathname.startsWith('/spiffe') ||
      url.pathname.startsWith('/ws')) {
    event.respondWith(
      fetch(request).catch(() => {
        return new Response(
          JSON.stringify({ error: 'Offline - API unavailable' }),
          { 
            status: 503,
            headers: { 'Content-Type': 'application/json' }
          }
        );
      })
    );
    return;
  }

  // Network-first for HTML navigation requests (fixes blank page issue)
  if (isNavigationRequest(request)) {
    event.respondWith(
      fetch(request)
        .then((response) => {
          // Cache the HTML for offline access (don't await, fire and forget)
          if (response.ok) {
            cacheResponse(RUNTIME_CACHE, request, response.clone());
          }
          return response;
        })
        .catch(async () => {
          // Fallback to cache if offline
          const cachedResponse = await caches.match(request);
          if (cachedResponse) {
            return cachedResponse;
          }
          // Return a basic offline page
          return new Response(
            '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Offline</title><style>body{font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#020617;color:#f1f5f9}div{text-align:center}h1{color:#f97316}</style></head><body><div><h1>You\'re Offline</h1><p>Please check your internet connection and try again.</p><button onclick="location.reload()" style="margin-top:1rem;padding:0.5rem 1rem;background:#f97316;color:white;border:none;border-radius:4px;cursor:pointer">Retry</button></div></body></html>',
            { headers: { 'Content-Type': 'text/html' } }
          );
        })
    );
    return;
  }

  // Cache-first for static assets (CSS, JS, images, fonts)
  event.respondWith(
    caches.match(request)
      .then(async (cachedResponse) => {
        if (cachedResponse) {
          return cachedResponse;
        }

        // Not in cache - fetch from network
        try {
          const response = await fetch(request);
          // Cache successful responses for static assets (don't await)
          if (response.ok) {
            cacheResponse(RUNTIME_CACHE, request, response.clone());
          }
          return response;
        } catch (error) {
          // Network failed and not in cache - return error
          console.warn('[SW] Fetch failed for:', request.url, error);
          return new Response('Network error', { status: 408 });
        }
      })
  );
});

// Listen for messages from the main thread
self.addEventListener('message', (event) => {
  if (!event.data) return;
  
  switch (event.data.type) {
    case 'SKIP_WAITING':
      self.skipWaiting();
      break;
    case 'CLEAR_CACHE':
      // Allow main thread to request cache clear
      caches.keys().then((names) => {
        Promise.all(names.map((name) => caches.delete(name)));
      });
      break;
  }
});
