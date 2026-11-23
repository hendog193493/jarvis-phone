/* JARVIS phone service worker: offline shell + decrypting Web Push notifications. */
importScripts('vendor/nacl-fast.min.js', 'lib.js');

var CACHE = 'jarvis-shell-v6';
var SHELL = ['./', 'index.html', 'style.css', 'guard.js', 'app.js', 'lib.js', 'vendor/nacl-fast.min.js', 'manifest.webmanifest', 'icon.svg', 'icon-192.png', 'icon-512.png',
  'fonts/orbitron-latin-700-normal.woff2', 'fonts/rajdhani-latin-500-normal.woff2', 'fonts/rajdhani-latin-600-normal.woff2', 'fonts/share-tech-mono-latin-400-normal.woff2'];

self.addEventListener('install', function (e) {
  e.waitUntil(caches.open(CACHE).then(function (c) { return c.addAll(SHELL); }).then(function () { return self.skipWaiting(); }));
});
self.addEventListener('activate', function (e) {
  e.waitUntil(caches.keys().then(function (ks) { return Promise.all(ks.filter(function (k) { return k !== CACHE; }).map(function (k) { return caches.delete(k); })); }).then(function () { return self.clients.claim(); }));
});
// Same-origin GETs: network first (fresh app after deploys), cache fallback (offline). The relay is never cached.
self.addEventListener('fetch', function (e) {
  var u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== self.location.origin) return;
  e.respondWith(fetch(e.request).then(function (r) {
    if (r.ok) { var copy = r.clone(); caches.open(CACHE).then(function (c) { c.put(e.request, copy); }); }
    return r;
  }).catch(function () { return caches.match(e.request, { ignoreSearch: true }).then(function (r) { return r || caches.match('index.html'); }); }));
});

// Pushes are sealed with the push-only key (stored for the SW; the main pairing key stays PIN-encrypted), and carry
// only a short preview: approvals say just "approval needed" and are decided in the unlocked app with Face ID.
self.addEventListener('push', function (e) {
  e.waitUntil(JV.kvGet('pushkey').then(function (pk) {
    var env = pk && e.data ? JV.open(JV.fromB64(pk), e.data.text()) : null;
    var kind = env && env.kind || 'note';
    var opts = { body: env ? String(env.text || 'New message from JARVIS') : 'New message from JARVIS', tag: 'jarvis-' + kind, renotify: true, icon: 'icon-192.png', badge: 'icon-192.png', data: { kind: kind } };
    if (kind === 'approval') opts.requireInteraction = true;
    return self.clients.matchAll({ type: 'window' }).then(function (cs) {
      cs.forEach(function (c) { c.postMessage({ type: 'push', kind: kind }); });
      return self.registration.showNotification('JARVIS', opts);
    });
  }));
});

self.addEventListener('notificationclick', function (e) {
  var d = e.notification.data || {};
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (cs) {
    var tab = d.kind === 'approval' ? 'approvals' : d.kind === 'alert' ? 'alerts' : 'chat';
    for (var i = 0; i < cs.length; i++) { cs[i].postMessage({ type: 'open', tab: tab }); if ('focus' in cs[i]) return cs[i].focus(); }
    return self.clients.openWindow('./?tab=' + tab);
  }));
});
