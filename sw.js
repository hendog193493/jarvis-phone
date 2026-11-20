/* JARVIS phone service worker: offline shell + decrypting Web Push notifications. */
importScripts('vendor/nacl-fast.min.js', 'lib.js');

var CACHE = 'jarvis-shell-v1';
var SHELL = ['./', 'index.html', 'style.css', 'app.js', 'lib.js', 'vendor/nacl-fast.min.js', 'manifest.webmanifest', 'icon.svg', 'icon-192.png', 'icon-512.png',
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

self.addEventListener('push', function (e) {
  e.waitUntil(JV.pairing().then(function (p) {
    var env = p && e.data ? JV.open(p.keyBytes, e.data.text()) : null;
    if (!env) return self.registration.showNotification('JARVIS', { body: 'New message', tag: 'jarvis' });
    var opts = { body: String(env.text || 'New message'), tag: env.kind === 'approval' ? 'ap-' + env.requestId : 'jarvis-' + env.kind, renotify: true, icon: 'icon-192.png', badge: 'icon-192.png', data: { kind: env.kind, requestId: env.requestId || null } };
    if (env.kind === 'approval') { opts.requireInteraction = true; opts.actions = [{ action: 'approve', title: 'Approve' }, { action: 'deny', title: 'Deny' }]; }
    return self.clients.matchAll({ type: 'window' }).then(function (cs) {
      cs.forEach(function (c) { c.postMessage({ type: 'push', kind: env.kind }); });
      return self.registration.showNotification(env.kind === 'approval' ? 'JARVIS · approval needed' : 'JARVIS', opts);
    });
  }));
});

self.addEventListener('notificationclick', function (e) {
  var d = e.notification.data || {};
  e.notification.close();
  if ((e.action === 'approve' || e.action === 'deny') && d.requestId) {
    var allow = e.action === 'approve';
    e.waitUntil(JV.pairing().then(function (p) { return p && JV.send(p, { type: 'approve', requestId: d.requestId, allow: allow }); })
      .then(function () { return self.registration.showNotification('JARVIS', { body: allow ? 'Approved.' : 'Denied.', tag: 'ap-' + d.requestId }); })
      .catch(function () { return self.registration.showNotification('JARVIS', { body: 'Could not reach the relay. Open the app to retry.', tag: 'ap-' + d.requestId }); }));
    return;
  }
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (cs) {
    var tab = d.kind === 'approval' ? 'approvals' : d.kind === 'alert' ? 'alerts' : 'chat';
    for (var i = 0; i < cs.length; i++) { cs[i].postMessage({ type: 'open', tab: tab }); if ('focus' in cs[i]) return cs[i].focus(); }
    return self.clients.openWindow('./?tab=' + tab);
  }));
});
