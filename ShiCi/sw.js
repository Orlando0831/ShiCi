/* 拾词 service worker — caches the app shell so the installed PWA opens offline.
   (Service workers require a secure origin: HTTPS or localhost. Over plain LAN http
   they simply won't register, and the app still works online — this only ADDS offline launch.) */
const CACHE = "shici-shell-v1";
const SHELL = ["/", "/vocab-app.html", "/manifest.webmanifest",
               "/apple-touch-icon.png", "/icon-192.png", "/icon-512.png"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;                       // mutations -> straight to network
  const url = new URL(req.url);
  if (url.origin === location.origin && url.pathname.startsWith("/api/")) return;  // API -> network only

  if (req.mode === "navigate") {
    // network-first so updates arrive online; fall back to the cached shell when offline
    e.respondWith(
      fetch(req).then((r) => { const cc = r.clone(); caches.open(CACHE).then((c) => c.put("/", cc)); return r; })
        .catch(() => caches.match("/").then((r) => r || caches.match("/vocab-app.html")))
    );
    return;
  }

  // other GETs (icons, fonts, …): cache-first, then network (and cache the result)
  e.respondWith(
    caches.match(req).then((cached) =>
      cached || fetch(req).then((r) => {
        if (r && (r.ok || r.type === "opaque")) { const cc = r.clone(); caches.open(CACHE).then((c) => c.put(req, cc)); }
        return r;
      }).catch(() => cached)
    )
  );
});
