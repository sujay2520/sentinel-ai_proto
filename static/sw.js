const CACHE_NAME = "sentinel-v1";
const STATIC_ASSETS = [
  "/",
  "/static/index.html",
  "/static/manifest.json",
  "/static/icon-512.png"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  // Network first strategy with fallback to cached shell
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});