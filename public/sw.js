const CACHE_NAME = 'hospital-attendance-v4';

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => caches.delete(key))
      );
    })
  );
  self.clients.claim();
});

// Network first for static assets, bypass API calls to prevent cache interference
self.addEventListener('fetch', (event) => {
  if (event.request.url.includes('/api/')) {
    return;
  }
  event.respondWith(
    fetch(event.request).catch(async () => {
      const cached = await caches.match(event.request);
      return cached || new Response('Offline', { status: 503, statusText: 'Service Unavailable' });
    })
  );
});
