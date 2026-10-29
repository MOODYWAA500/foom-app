// FOAM driver app service worker: caches the app shell only. API calls are NEVER cached.
const V = 'driver-v1';
const SHELL = ['/driver.html', '/manifest-driver.webmanifest', '/icons/driver-192.png', '/icons/driver-512.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(V).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== V).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== location.origin || u.pathname.startsWith('/api/')) return;
  if (e.request.mode === 'navigate') {   // network first, fall back to the cached shell when offline
    e.respondWith(fetch(e.request).then(r => { if (r.ok) { const c = r.clone(); caches.open(V).then(x => x.put('/driver.html', c)); } return r; })
      .catch(() => caches.match('/driver.html')));
    return;
  }
  e.respondWith(caches.match(e.request).then(m => m || fetch(e.request)));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window' }).then(l => { for (const c of l) if ('focus' in c) return c.focus(); return self.clients.openWindow('/driver.html'); }));
});
