// Shared by the page and the service worker (classic script: <script src> or importScripts).
// Envelope = base64(nonce || secretbox(uint16 len || JSON {v:1,id,ts,type,...} || zero padding)), identical to
// app/electron/remote/crypto.ts. Padding buckets hide message sizes from the relay.
// Vault = the pairing secrets, AES-GCM encrypted under a PBKDF2-SHA256 key derived from Henry's PIN (never stored).
(function (g) {
  'use strict';
  var NTFY = 'https://ntfy.sh';
  var PAD = [512, 1024, 2048, 3000];
  var ITER = 310000, MAX_FAILS = 5;
  var nacl = g.nacl;
  var enc = new TextEncoder(), dec = new TextDecoder();

  function toB64(u) { var s = ''; for (var i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(s); }
  function fromB64(s) { var b = atob(s); var u = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
  function fromB64url(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return fromB64(s); }
  function toB64url(u) { return toB64(u).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function hex(u) { return Array.prototype.map.call(u, function (x) { return ('0' + x.toString(16)).slice(-2); }).join(''); }
  function rand(n) { return crypto.getRandomValues(new Uint8Array(n)); }

  function pad(j) {
    var need = j.length + 2, size = 0;
    for (var i = 0; i < PAD.length; i++) if (PAD[i] >= need) { size = PAD[i]; break; }
    if (!size) size = Math.ceil(need / 512) * 512;
    var o = new Uint8Array(size); o[0] = j.length >> 8; o[1] = j.length & 255; o.set(j, 2);
    return o;
  }
  function unpad(p) {
    if (p.length && p[0] === 0x7b) return p; // legacy unpadded JSON
    if (p.length < 2) return null;
    var n = (p[0] << 8) | p[1];
    return n + 2 <= p.length ? p.subarray(2, 2 + n) : null;
  }

  function seal(key, obj) {
    var env = Object.assign({ v: 1, id: hex(nacl.randomBytes(12)), ts: Date.now() }, obj);
    var nonce = nacl.randomBytes(24);
    var box = nacl.secretbox(pad(enc.encode(JSON.stringify(env))), nonce, key);
    var out = new Uint8Array(24 + box.length); out.set(nonce); out.set(box, 24);
    return toB64(out);
  }
  function open(key, data) {
    try {
      var raw = fromB64(String(data).trim());
      if (raw.length < 40) return null;
      var p = nacl.secretbox.open(raw.subarray(24), raw.subarray(0, 24), key);
      var j = p && unpad(p);
      if (!j) return null;
      var env = JSON.parse(dec.decode(j));
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

  // ---------- PIN vault (page only: needs WebCrypto subtle, which also exists in workers but the SW never unlocks) ----------
  function deriveKey(pin, salt, iter) {
    return crypto.subtle.importKey('raw', enc.encode(String(pin)), 'PBKDF2', false, ['deriveKey']).then(function (k) {
      return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salt, iterations: iter, hash: 'SHA-256' }, k, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    });
  }
  function aesSeal(key, obj, label) {
    var iv = rand(12);
    return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: enc.encode(label) }, key, enc.encode(JSON.stringify(obj)))
      .then(function (ct) { return { iv: toB64(iv), ct: toB64(new Uint8Array(ct)) }; });
  }
  function aesOpen(key, rec, label) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(rec.iv), additionalData: enc.encode(label) }, key, fromB64(rec.ct))
      .then(function (p) { return JSON.parse(dec.decode(p)); });
  }
  /** New vault for `secrets` ({key, up, down, dev, cred}). Resolves to the in-memory AES key. */
  function createVault(pin, secrets) {
    var salt = rand(16);
    return deriveKey(pin, salt, ITER).then(function (key) {
      return aesSeal(key, secrets, 'jarvis-vault').then(function (rec) {
        return kvSet('vault', { v: 1, salt: toB64(salt), iter: ITER, fails: 0, iv: rec.iv, ct: rec.ct }).then(function () { return key; });
      });
    });
  }
  function saveVault(key, secrets) {
    return kvGet('vault').then(function (v) {
      if (!v) throw new Error('no vault');
      return aesSeal(key, secrets, 'jarvis-vault').then(function (rec) { return kvSet('vault', Object.assign({}, v, rec)); });
    });
  }
  /** Resolves {key, secrets}; rejects {wrong, left, wiped}. The failure counter is bumped before trying, so killing the app mid-try still counts. */
  function unlockVault(pin) {
    return kvGet('vault').then(function (v) {
      if (!v) throw { wiped: true, left: 0 };
      var fails = (v.fails || 0) + 1;
      return kvSet('vault', Object.assign({}, v, { fails: fails })).then(function () {
        return deriveKey(pin, fromB64(v.salt), v.iter || ITER).then(function (key) {
          return aesOpen(key, v, 'jarvis-vault').then(function (secrets) {
            return kvSet('vault', Object.assign({}, v, { fails: 0 })).then(function () { return { key: key, secrets: secrets }; });
          });
        }).catch(function () {
          if (fails >= MAX_FAILS) return wipe().then(function () { throw { wrong: true, left: 0, wiped: true }; });
          throw { wrong: true, left: MAX_FAILS - fails };
        });
      });
    });
  }
  function wipe() { return Promise.all(['vault', 'state', 'pushkey', 'pair'].map(kvDel)); }
  function hasVault() { return kvGet('vault').then(function (v) { return !!(v && v.ct); }); }

  /** p = {keyBytes, up, dev}. */
  function send(p, obj) {
    var body = seal(p.keyBytes, Object.assign({ dev: p.dev }, obj));
    return fetch(NTFY + '/' + p.up, { method: 'POST', body: body, referrerPolicy: 'no-referrer' }).then(function (r) { if (!r.ok) throw new Error('relay ' + r.status); });
  }

  g.JV = {
    NTFY: NTFY, seal: seal, open: open, pad: pad, unpad: unpad, toB64: toB64, fromB64: fromB64, fromB64url: fromB64url, toB64url: toB64url, hex: hex, rand: rand,
    kvGet: kvGet, kvSet: kvSet, kvDel: kvDel, send: send,
    createVault: createVault, saveVault: saveVault, unlockVault: unlockVault, aesSeal: aesSeal, aesOpen: aesOpen, wipe: wipe, hasVault: hasVault, MAX_FAILS: MAX_FAILS,
  };
})(typeof self !== 'undefined' ? self : this);
