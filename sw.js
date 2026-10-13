const CACHE_NAME = 'private-gallery-v1';

// आपके रिपॉजिटरी की सभी जरूरी फाइलें
const FILES_TO_CACHE = [
  './',
  './index.html',
  './style.css',
  './app.js',
  './manifest.json',
  './icon-192.png',
  './icon-512.png'
];

// 1. Install Event: फाइलों को फोन की मेमोरी में सेव करना
self.addEventListener('install', (evt) => {
  evt.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(FILES_TO_CACHE);
    })
  );
  self.skipWaiting();
});

// 2. Activate Event: पुरानी कैशे (Cache) को हटाकर नई अपडेट करना
self.addEventListener('activate', (evt) => {
  evt.waitUntil(
    caches.keys().then((keyList) => {
      return Promise.all(keyList.map((key) => {
        if (key !== CACHE_NAME) {
          return caches.delete(key);
        }
      }));
    })
  );
  self.clients.claim();
});

// 3. Fetch Event: बिना इंटरनेट (Offline) के सेव की गई फाइलें दिखाना
self.addEventListener('fetch', (evt) => {
  evt.respondWith(
    caches.match(evt.request).then((response) => {
      // अगर फाइल फोन में सेव है, तो उसे दिखाओ, वरना इंटरनेट से लाओ
      return response || fetch(evt.request);
    }).catch(() => {
      // अगर इंटरनेट भी नहीं है और फाइल भी नहीं है, तो कुछ न करें
      return null;
    })
  );
});
