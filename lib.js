// Shared by the page and the service worker (classic script: <script src> or importScripts).
// Envelope = base64(nonce || secretbox(JSON {v:1,id,ts,type,...})), identical to app/electron/remote/crypto.ts.
(function (g) {
  'use strict';
  var NTFY = 'https://ntfy.sh';
  var nacl = g.nacl;
  var enc = new TextEncoder(), dec = new TextDecoder();

  function toB64(u) { var s = ''; for (var i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(s); }
  function fromB64(s) { var b = atob(s); var u = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
  function fromB64url(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return fromB64(s); }
  function hex(u) { return Array.prototype.map.call(u, function (x) { return ('0' + x.toString(16)).slice(-2); }).join(''); }

  function seal(key, obj) {
    var env = Object.assign({ v: 1, id: hex(nacl.randomBytes(12)), ts: Date.now() }, obj);
    var nonce = nacl.randomBytes(24);
    var box = nacl.secretbox(enc.encode(JSON.stringify(env)), nonce, key);
    var out = new Uint8Array(24 + box.length); out.set(nonce); out.set(box, 24);
    return toB64(out);
  }
  function open(key, data) {
    try {
      var raw = fromB64(String(data).trim());
      if (raw.length < 40) return null;
      var p = nacl.secretbox.open(raw.subarray(24), raw.subarray(0, 24), key);
      if (!p) return null;
      var env = JSON.parse(dec.decode(p));
      return env && env.v === 1 && typeof env.id === 'string' && typeof env.ts === 'number' && typeof env.type === 'string' ? env : null;
    } catch (e) { return null; }
  }

  // Tiny IndexedDB key/value store (works in pages and service workers).
  var dbp = null;
  function db() {
    if (!dbp) dbp = new Promise(function (res, rej) {
      var r = indexedDB.open('jarvis-phone', 1);
      r.onupgradeneeded = function () { r.result.createObjectStore('kv'); };
      r.onsuccess = function () { res(r.result); };
      r.onerror = function () { rej(r.error); };
    });
    return dbp;
  }
  function kvGet(k) { return db().then(function (d) { return new Promise(function (res, rej) { var r = d.transaction('kv').objectStore('kv').get(k); r.onsuccess = function () { res(r.result); }; r.onerror = function () { rej(r.error); }; }); }); }
  function kvSet(k, v) { return db().then(function (d) { return new Promise(function (res, rej) { var t = d.transaction('kv', 'readwrite'); t.objectStore('kv').put(v, k); t.oncomplete = function () { res(); }; t.onerror = function () { rej(t.error); }; }); }); }
  function kvDel(k) { return db().then(function (d) { return new Promise(function (res) { var t = d.transaction('kv', 'readwrite'); t.objectStore('kv').delete(k); t.oncomplete = function () { res(); }; t.onerror = function () { res(); }; }); }); }

  /** Pairing = {key (b64), up, down, dev}. Returns {key: Uint8Array, ...} or null. */
  function pairing() { return kvGet('pair').then(function (p) { return p && p.key ? Object.assign({}, p, { keyBytes: fromB64(p.key) }) : null; }); }

  function send(p, obj) {
    var body = seal(p.keyBytes, Object.assign({ dev: p.dev }, obj));
    return fetch(NTFY + '/' + p.up, { method: 'POST', body: body }).then(function (r) { if (!r.ok) throw new Error('relay ' + r.status); });
  }

  g.JV = { NTFY: NTFY, seal: seal, open: open, toB64: toB64, fromB64: fromB64, fromB64url: fromB64url, hex: hex, kvGet: kvGet, kvSet: kvSet, kvDel: kvDel, pairing: pairing, send: send };
})(typeof self !== 'undefined' ? self : this);
