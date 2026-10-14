const CACHE_NAME = 'private-gallery-v2';

const FILES_TO_CACHE = [
  './',
  './index.html',
  './style.css',
  './app.js',
  './manifest.json',
  './icon-192.png',
  './icon-512.png'
];

// Install: cache the app files
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      const results = await Promise.allSettled(
        FILES_TO_CACHE.map((file) => cache.add(file))
      );

      const failed = results
        .map((result, index) => ({ result, file: FILES_TO_CACHE[index] }))
        .filter((item) => item.result.status === 'rejected');

      if (failed.length > 0) {
        console.warn(
          'Some app files could not be cached:',
          failed.map((item) => item.file)
        );
      }
    })
  );

  self.skipWaiting();
});

// Activate: remove old app caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();

      await Promise.all(
        keys
          .filter(
            (key) =>
              key.startsWith('private-gallery-') &&
              key !== CACHE_NAME
          )
          .map((key) => caches.delete(key))
      );

      await self.clients.claim();
    })()
  );
});

// Fetch: prefer fresh network files, fall back to cache offline
self.addEventListener('fetch', (event) => {
  const request = event.request;
  const url = new URL(request.url);

  // Only handle requests belonging to this app
  if (url.origin !== self.location.origin) {
    return;
  }

  // Do not intercept non-GET requests
  if (request.method !== 'GET') {
    return;
  }

  // HTML navigation: network first, cached page as offline fallback
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then((response) => {
          if (response.ok) {
            const copy = response.clone();

            caches.open(CACHE_NAME).then((cache) => {
              cache.put('./index.html', copy);
            });
          }

          return response;
        })
        .catch(async () => {
          return (
            (await caches.match(request)) ||
            (await caches.match('./index.html')) ||
            Response.error()
          );
        })
    );

    return;
  }

  // App assets: network first, then cache
  event.respondWith(
    fetch(request)
      .then((response) => {
        if (response.ok) {
          const copy = response.clone();

          caches.open(CACHE_NAME).then((cache) => {
            cache.put(request, copy);
          });
        }

        return response;
      })
      .catch(async () => {
        return (await caches.match(request)) || Response.error();
      })
  );
});
