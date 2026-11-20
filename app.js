// JARVIS phone companion. Talks to the PC only through ntfy.sh, end-to-end encrypted (see lib.js).
// Security: pairing secrets live only in a PIN-encrypted vault (IndexedDB) and in memory while unlocked; approvals are
// signed with a platform WebAuthn credential (Face ID / fingerprint); the service worker only holds a push-only key.
const JV = globalThis.JV;
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const LOCK_AFTER_MS = 5 * 60_000;

const S = {
  pair: null,            // unlocked secrets: {key, up, down, dev, cred, keyBytes}
  chat: [],              // {id, role:'me'|'jv', text, ts, origin?, partial?, failed?, kind?}
  approvals: [],         // {requestId, tool, summary, fields, ts, nonce, state:null|'sent'|'ok'|'no'|'expired'|'pc'}
  alerts: [],            // {id, kind, text, ts}
  lastId: '',            // ntfy message id to resume from
  lastPc: 0, pcStatus: 'idle', vapidKey: '', seenAlerts: 0, sec: null,
  tab: 'chat',
};
let vaultKey = null;     // AES-GCM CryptoKey (non-extractable), only while unlocked
const seen = new Set();
let es = null, esRetry = 1000, pingTimer = null, saveTimer = null, uiBound = false;
let lastActive = Date.now(), hiddenAt = 0;

const hasWebAuthn = () => isSecureContext && 'PublicKeyCredential' in window && !!navigator.credentials;

// ---------------- start ----------------
/** Parse a pairing fragment ("k=..&u=..&d=..", optionally inside a full URL). Returns null if invalid. */
function parsePairing(text) {
  const i = String(text || '').indexOf('#');
  const h = new URLSearchParams((i >= 0 ? String(text).slice(i + 1) : String(text)).trim());
  if (!(h.get('k') && h.get('u') && h.get('d'))) return null;
  try {
    if (JV.fromB64url(h.get('k')).length === 32 && /^[\w-]{8,64}$/.test(h.get('u')) && /^[\w-]{8,64}$/.test(h.get('d')))
      return { key: JV.toB64(JV.fromB64url(h.get('k'))), up: h.get('u'), down: h.get('d') };
  } catch { /* invalid */ }
  return null;
}

async function init() {
  let link = null;
  if (/[#&]k=/.test(location.hash)) {
    link = parsePairing(location.hash);
    history.replaceState(null, '', location.pathname + location.search); // the key never stays in the URL bar/history
  }
  // iPhone home-screen apps don't share storage with Safari, so pairing can also be pasted inside the app.
  $('pair-btn')?.addEventListener('click', async () => {
    const field = $('pair-link');
    const l = parsePairing(field.value);
    field.value = ''; // don't leave the key on screen
    if (!l) { $('unpaired-why').textContent = "That isn't a valid JARVIS pairing link. Copy it from the QR code on the PC again."; return; }
    await JV.kvDel('pair');
    setPinFlow(l);
  });
  const qtab = new URLSearchParams(location.search).get('tab');
  if (qtab) S.tab = qtab;
  if ('serviceWorker' in navigator && isSecureContext) navigator.serviceWorker.register('sw.js').catch(() => {});
  navigator.serviceWorker?.addEventListener?.('message', (e) => { if (!S.pair) return; if (e.data?.type === 'open') showTab(e.data.tab); if (e.data?.type === 'push') connect(); });
  bindPad();
  bindLockTriggers();
  if (link) { await JV.kvDel('pair'); setPinFlow(link); return; } // a pairing link always starts a fresh, PIN-protected pairing
  await JV.kvDel('pair'); // legacy plaintext pairing from before the PIN vault: never kept
  if (await JV.hasVault()) showLock();
  else showUnpaired('');
}

function onlyView(id) {
  document.querySelectorAll('.view').forEach((v) => v.classList.toggle('on', v.id === id));
}

function showUnpaired(why) {
  document.body.classList.add('locked', 'no-bar');
  onlyView('unpaired');
  $('unpaired-why').textContent = why;
  setPc('off', 'NOT PAIRED');
}

// ---------------- PIN pad ----------------
const pad = { digits: '', mode: 'unlock', first: '', link: null, busy: false };

function bindPad() {
  $('keypad').addEventListener('click', (e) => {
    const b = e.target.closest('button'); if (!b || pad.busy) return;
    const k = b.dataset.k;
    if (k === 'del') pad.digits = pad.digits.slice(0, -1);
    else if (k === 'ok') return void pinSubmit();
    else if (pad.digits.length < 8) pad.digits += k;
    $('pin-msg').textContent = '';
    renderDots();
  });
}
function renderDots() {
  const d = $('pin-dots'); d.replaceChildren();
  const n = Math.max(4, pad.digits.length);
  for (let i = 0; i < n; i++) d.append(el('span', i < pad.digits.length ? 'on' : ''));
}
function pinScreen(title, sub) {
  document.body.classList.add('locked', 'no-bar');
  onlyView('lock');
  $('pin-title').textContent = title; $('pin-sub').textContent = sub;
  pad.digits = ''; renderDots();
}
function pinError(msg) {
  $('pin-msg').textContent = msg;
  const d = $('pin-dots'); d.classList.remove('shake'); void d.offsetWidth; d.classList.add('shake');
  pad.digits = ''; renderDots();
}
function setPinFlow(link) {
  pad.mode = 'set'; pad.link = link; pad.first = '';
  pinScreen('SET A PIN', '4 to 8 digits. It locks JARVIS on this phone.');
  setPc('off', 'PAIRING');
}
function showLock() {
  pad.mode = 'unlock';
  pinScreen('LOCKED', 'Enter your PIN');
  setPc('off', 'LOCKED');
}

async function pinSubmit() {
  const pin = pad.digits;
  if (pin.length < 4) return pinError('AT LEAST 4 DIGITS');
  if (pad.mode === 'set') {
    pad.first = pin; pad.mode = 'confirm';
    pinScreen('CONFIRM PIN', 'Enter the same PIN again');
    return;
  }
  pad.busy = true;
  try {
    if (pad.mode === 'confirm') {
      if (pin !== pad.first) { pad.mode = 'set'; pinScreen('SET A PIN', '4 to 8 digits. It locks JARVIS on this phone.'); return pinError("PINS DIDN'T MATCH"); }
      $('pin-msg').textContent = 'SECURING…';
      await JV.wipe();
      const secrets = { ...pad.link, dev: JV.hex(nacl.randomBytes(8)), cred: null, pairedAt: Date.now() };
      vaultKey = await JV.createVault(pin, secrets);
      pad.link = null; pad.first = '';
      await JV.kvSet('pushkey', JV.toB64(nacl.randomBytes(32)));
      await startSession(secrets, true);
      showEnroll();
      return;
    }
    $('pin-msg').textContent = 'CHECKING…';
    const r = await JV.unlockVault(pin).catch((e) => e);
    if (r && r.key) { vaultKey = r.key; await startSession(r.secrets, false); return; }
    if (r && r.wiped) { vaultKey = null; showUnpaired('Too many wrong PINs: this phone was unpaired. Scan the QR code on the PC again.'); return; }
    pinError(`WRONG PIN · ${r?.left ?? 0} ${r?.left === 1 ? 'TRY' : 'TRIES'} LEFT`);
  } finally { pad.busy = false; }
}

// ---------------- session (unlocked) ----------------
async function startSession(secrets, fresh) {
  S.pair = { ...secrets, keyBytes: JV.fromB64(secrets.key) };
  Object.assign(S, { chat: [], approvals: [], alerts: [], lastId: '', lastPc: 0, pcStatus: 'idle', vapidKey: '', seenAlerts: 0, sec: null });
  seen.clear();
  if (!fresh) {
    const rec = await JV.kvGet('state');
    if (rec && rec.ct) try { Object.assign(S, await JV.aesOpen(vaultKey, rec, 'jarvis-state')); } catch { /* unreadable: start clean */ }
  }
  lastActive = Date.now();
  document.body.classList.remove('locked');
  $('lock-btn').hidden = false;
  bindUi();
  renderAll();
  showTab(S.tab);
  await connect();
}

function lock(why) {
  if (!S.pair) return;
  flushSave();
  if (es) { es.close(); es = null; }
  clearInterval(pingTimer);
  S.pair = null; vaultKey = null;
  Object.assign(S, { chat: [], approvals: [], alerts: [] });
  seen.clear();
  ['log', 'ap-list', 'al-list'].forEach((id) => $(id).replaceChildren());
  showLock();
  if (why) $('pin-msg').textContent = why;
}

function bindLockTriggers() {
  const touch = () => { lastActive = Date.now(); };
  ['pointerdown', 'keydown', 'touchstart'].forEach((t) => document.addEventListener(t, touch, { passive: true, capture: true }));
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') { hiddenAt = Date.now(); flushSave(); }
    else if (S.pair && hiddenAt && Date.now() - hiddenAt > LOCK_AFTER_MS) lock('LOCKED AFTER 5 MIN AWAY');
    else touch();
  });
  setInterval(() => { if (S.pair && Date.now() - lastActive > LOCK_AFTER_MS) lock('LOCKED AFTER 5 MIN IDLE'); }, 10_000);
  $('lock-btn').addEventListener('click', () => lock(''));
}

// ---------------- biometric enrolment ----------------
function showEnroll() {
  document.body.classList.add('locked', 'no-bar');
  onlyView('enroll');
  $('enroll-why').textContent = '';
  const btn = $('enroll-btn');
  btn.disabled = false;
  if (!hasWebAuthn()) {
    btn.disabled = true;
    $('enroll-text').textContent = isSecureContext ? 'This browser has no Face ID / fingerprint support, so this phone can only deny approvals.' : 'Face ID / fingerprint needs the hosted HTTPS app. On this Wi-Fi test link approvals can only be denied.';
  } else {
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?.().then((ok) => {
      if (!ok) { btn.disabled = true; $('enroll-text').textContent = 'No Face ID / fingerprint is set up on this phone, so it can only deny approvals. Set one up in the phone settings, then use SET UP on an approval card.'; }
    }).catch(() => {});
  }
  btn.onclick = async () => {
    btn.disabled = true;
    try { await enrollBiometric(); finishEnroll(); }
    catch (e) { btn.disabled = false; $('enroll-why').textContent = `Not enabled: ${e?.name === 'NotAllowedError' ? 'cancelled' : e?.message || e}`; }
  };
  $('enroll-skip').onclick = () => { sendEnroll(null).catch(() => toast('Could not reach the relay.')); finishEnroll(); };
}
function finishEnroll() { document.body.classList.remove('locked'); showTab('chat'); }

async function enrollBiometric() {
  const cred = await navigator.credentials.create({ publicKey: {
    rp: { id: location.hostname, name: 'JARVIS' },
    user: { id: JV.rand(16), name: 'henry', displayName: 'JARVIS phone' },
    challenge: JV.rand(32),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
    authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
    attestation: 'none', timeout: 60_000,
  } });
  const pk = cred?.response?.getPublicKey?.();
  const alg = cred?.response?.getPublicKeyAlgorithm?.();
  if (!pk || (alg !== -7 && alg !== -257)) throw new Error('this browser cannot export the key');
  const c = { id: JV.toB64url(new Uint8Array(cred.rawId)), publicKey: JV.toB64(new Uint8Array(pk)), alg };
  S.pair.cred = c;
  await saveSecrets();
  await sendEnroll(c);
}

async function sendEnroll(cred) {
  const pushKey = await JV.kvGet('pushkey');
  await send({ type: 'enroll', pushKey, cred });
}

async function saveSecrets() {
  if (!S.pair || !vaultKey) return;
  const { keyBytes, ...secrets } = S.pair;
  await JV.saveVault(vaultKey, secrets);
}

async function approvalAssertion(a) {
  const challenge = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`jarvis-approve|v1|${a.requestId}|allow|${a.nonce}`)));
  const r = await navigator.credentials.get({ publicKey: {
    challenge, rpId: location.hostname, userVerification: 'required', timeout: 60_000,
    allowCredentials: [{ type: 'public-key', id: JV.fromB64url(S.pair.cred.id), transports: ['internal'] }],
  } });
  return {
    id: JV.toB64url(new Uint8Array(r.rawId)),
    authenticatorData: JV.toB64(new Uint8Array(r.response.authenticatorData)),
    clientDataJSON: JV.toB64(new Uint8Array(r.response.clientDataJSON)),
    signature: JV.toB64(new Uint8Array(r.response.signature)),
  };
}

/** null = this phone may approve; otherwise the reason it can only deny. */
function approveBlock() {
  if (S.sec?.untrusted) return 'Approvals from phones are paused: the PC saw the hosted app change. Confirm it on the PC.';
  if (S.sec && !S.sec.bio) return null;
  if (!isSecureContext) return 'Approvals need the hosted HTTPS app (Face ID / fingerprint). This Wi-Fi link can only deny.';
  if (S.sec?.origin && location.origin !== S.sec.origin) return `Approvals only work from ${S.sec.origin}. This copy can only deny.`;
  if (!S.pair?.cred || (S.sec && !S.sec.bioDevs?.includes(S.pair.dev))) return 'Face ID / fingerprint is not set up for this phone, so it can only deny.';
  return null;
}

// ---------------- relay ----------------
async function connect() {
  if (!S.pair) return;
  const pair = S.pair;
  // 1) catch up on what we missed (ntfy keeps ~12 h)
  try {
    const r = await fetch(`${JV.NTFY}/${pair.down}/json?poll=1&since=${encodeURIComponent(S.lastId || '12h')}`, { referrerPolicy: 'no-referrer' });
    if (r.ok) for (const line of (await r.text()).split('\n')) { if (S.pair !== pair) return; if (line.trim()) try { onRelay(JSON.parse(line), true); } catch { /* */ } }
  } catch { /* offline: the cached shell still shows history */ }
  if (S.pair !== pair) return;
  renderAll();
  // 2) live stream
  openStream();
  hello();
}

function openStream() {
  if (es) es.close();
  if (!S.pair) return;
  es = new EventSource(`${JV.NTFY}/${S.pair.down}/sse?since=${encodeURIComponent(S.lastId || 'all')}`);
  es.onopen = () => { esRetry = 1000; };
  es.onmessage = (e) => { try { onRelay(JSON.parse(e.data), false); } catch { /* */ } };
  es.onerror = () => { es?.close(); es = null; setTimeout(() => { if (!es && S.pair && document.visibilityState === 'visible') openStream(); }, esRetry); esRetry = Math.min(esRetry * 2, 30000); };
}

function hello() {
  send({ type: 'hello' }).catch(() => {});
  clearInterval(pingTimer);
  pingTimer = setInterval(() => { if (S.pair && document.visibilityState === 'visible') send({ type: 'ping' }).catch(() => {}); updatePc(); }, 300000); // every 5 min: relay quota is ~250 msgs/day per IP
}

function send(obj) { if (!S.pair) return Promise.reject(new Error('locked')); return JV.send(S.pair, obj); }

function onRelay(m, batch) {
  if (!S.pair || m.event !== 'message' || !m.message) return;
  S.lastId = m.id;
  const env = JV.open(S.pair.keyBytes, m.message);
  if (!env || seen.has(env.id)) return;
  seen.add(env.id);
  handle(env, batch);
  if (!batch && S.pair) renderAll();
  save();
}

function handle(env, batch) {
  if (env.pcTime || ['hb', 'state', 'reply', 'approval', 'approval_done', 'user'].includes(env.type)) { S.lastPc = Math.max(S.lastPc, env.ts); }
  if (env.status) S.pcStatus = env.status;
  if (env.sec) S.sec = env.sec;
  switch (env.type) {
    case 'state':
      if (env.vapidKey) S.vapidKey = env.vapidKey;
      { const live = new Map((env.pending || []).map((p) => [p.requestId, p]));
        for (const a of S.approvals) { if (!a.state && !live.has(a.requestId)) a.state = 'expired'; if (live.has(a.requestId)) a.nonce = live.get(a.requestId).nonce; }
        for (const p of env.pending || []) if (!S.approvals.some((a) => a.requestId === p.requestId)) S.approvals.unshift({ ...p, state: null }); }
      break;
    case 'user':
      S.chat.push({ id: env.id, role: 'me', origin: 'pc', text: env.text, ts: env.ts });
      break;
    case 'reply': {
      const ex = S.chat.find((c) => c.turnId === env.turnId);
      if (ex) { ex.text = env.text; ex.partial = !env.final; ex.ts = env.ts; }
      else S.chat.push({ id: env.id, role: 'jv', turnId: env.turnId, text: env.text, partial: !env.final, ts: env.ts });
      break;
    }
    case 'note':
      if (!env.quiet) S.chat.push({ id: env.id, role: 'jv', kind: 'note', text: env.text, ts: env.ts });
      else toast(env.text);
      break;
    case 'approval':
      if (!S.approvals.some((a) => a.requestId === env.requestId)) {
        S.approvals.unshift({ requestId: env.requestId, tool: env.tool, summary: env.summary, fields: env.fields || [], ts: env.ts, nonce: env.nonce, state: Date.now() - env.ts > 15 * 60000 ? 'expired' : null });
        if (!batch && S.tab !== 'approvals') showTab('approvals');
      }
      break;
    case 'approval_done': {
      const a = S.approvals.find((x) => x.requestId === env.requestId);
      if (a) a.state = env.via === 'phone' ? (env.allow ? 'ok' : 'no') : env.via === 'expired' ? 'expired' : (a.state === 'ok' || a.state === 'no' ? a.state : 'pc');
      break;
    }
    case 'approval_rejected': {
      const a = S.approvals.find((x) => x.requestId === env.requestId);
      if (a && a.state === 'sent') a.state = null;
      if (!batch) toast(env.why || 'The PC refused that approval.');
      break;
    }
    case 'enrolled':
      if (env.dev === S.pair.dev && !batch) toast(env.ok ? 'Face ID / fingerprint is on for approvals.' : env.skipped ? 'This phone can only deny approvals.' : `Not enrolled: ${env.why || 'rejected by the PC'}`);
      break;
    case 'alert':
      if (!S.alerts.some((x) => x.id === env.alert.id)) S.alerts.unshift(env.alert);
      break;
    case 'rekey':
      rekey(env);
      return;
    case 'unpaired':
      unpair('This phone was unpaired on the PC (key rotated). Scan the new code to pair again.');
      return;
  }
  S.chat = S.chat.slice(-200); S.alerts = S.alerts.slice(0, 50); S.approvals = S.approvals.slice(0, 30);
}

/** Automatic rotation from the PC: switch key + topics (persisted in the vault), fresh push-only key, reconnect. */
async function rekey(env) {
  try {
    if (JV.fromB64url(env.k).length !== 32 || !/^[\w-]{8,64}$/.test(env.u) || !/^[\w-]{8,64}$/.test(env.d)) return;
  } catch { return; }
  S.pair.key = JV.toB64(JV.fromB64url(env.k)); S.pair.up = env.u; S.pair.down = env.d; S.pair.keyBytes = JV.fromB64url(env.k);
  S.lastId = '';
  if (es) { es.close(); es = null; }
  await saveSecrets();
  const pushKey = JV.toB64(nacl.randomBytes(32));
  await JV.kvSet('pushkey', pushKey);
  await send({ type: 'pushkey', pushKey }).catch(() => {});
  save();
  connect();
}

async function unpair(why) {
  S.pair = null; vaultKey = null;
  if (es) { es.close(); es = null; }
  clearInterval(pingTimer);
  await JV.wipe();
  showUnpaired(why);
}

function save() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(flushSave, 300);
}
function flushSave() {
  clearTimeout(saveTimer);
  if (!S.pair || !vaultKey) return;
  const { chat, approvals, alerts, lastId, lastPc, pcStatus, vapidKey, seenAlerts, sec } = S;
  JV.aesSeal(vaultKey, { chat, approvals, alerts, lastId, lastPc, pcStatus, vapidKey, seenAlerts, sec }, 'jarvis-state').then((rec) => JV.kvSet('state', rec)).catch(() => {});
}

// ---------------- UI ----------------
function bindUi() {
  if (uiBound) return;
  uiBound = true;
  document.querySelectorAll('.tabs button').forEach((b) => b.addEventListener('click', () => showTab(b.dataset.tab)));
  const input = $('input');
  const grow = () => { input.style.height = 'auto'; input.style.height = `${Math.min(input.scrollHeight, 120)}px`; };
  input.addEventListener('input', grow);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey && !matchMedia('(pointer: coarse)').matches) { e.preventDefault(); $('bar').requestSubmit(); } });
  $('bar').addEventListener('submit', (e) => {
    e.preventDefault();
    const text = input.value.trim();
    if (!text || !S.pair) return;
    input.value = ''; grow();
    const msg = { id: `local-${Date.now()}`, role: 'me', text, ts: Date.now(), sending: true };
    S.chat.push(msg);
    showTab('chat');
    deliver(msg);
  });
  $('push-btn').addEventListener('click', enablePush);
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible' && S.pair) { if (!es) openStream(); hello(); updatePc(); } });
  setInterval(updatePc, 15000);
}

function deliver(msg) {
  msg.failed = false; msg.sending = true; renderChat();
  send({ type: 'text', text: msg.text }).then(() => { msg.sending = false; renderChat(); save(); })
    .catch(() => { msg.sending = false; msg.failed = true; renderChat(); save(); });
}

function showTab(tab) {
  if (!S.pair) return;
  S.tab = ['chat', 'approvals', 'alerts'].includes(tab) ? tab : 'chat';
  document.body.classList.remove('locked');
  document.querySelectorAll('.tabs button').forEach((b) => b.classList.toggle('on', b.dataset.tab === S.tab));
  onlyView(S.tab);
  document.body.classList.toggle('no-bar', S.tab !== 'chat');
  if (S.tab === 'alerts') { S.seenAlerts = S.alerts.length ? S.alerts[0].ts : 0; save(); }
  renderBadges();
  if (S.tab === 'chat') scrollChat();
}

function renderAll() { if (!S.pair) return; renderChat(); renderApprovals(); renderAlerts(); renderBadges(); updatePc(); }

const hhmm = (ts) => new Date(ts).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
const dayOf = (ts) => new Date(ts).toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' });

function renderChat() {
  const log = $('log');
  log.replaceChildren();
  if (!S.chat.length) {
    const e = el('div', 'empty');
    e.append(el('h2', null, 'ONLINE'), el('p', null, 'Type below to talk to JARVIS on your PC. Replies, approvals and alerts show up here.'));
    log.append(e);
  }
  let lastDay = '';
  for (const c of S.chat) {
    const d = dayOf(c.ts);
    if (d !== lastDay) { log.append(el('div', 'day', d.toUpperCase())); lastDay = d; }
    const b = el('div', `msg ${c.role}${c.origin === 'pc' ? ' pc' : ''}${c.partial ? ' partial' : ''}${c.failed ? ' failed' : ''}${c.kind ? ` ${c.kind}` : ''}`, c.text);
    const meta = c.role === 'me'
      ? (c.failed ? 'NOT SENT · TAP TO RETRY' : c.sending ? 'SENDING…' : c.origin === 'pc' ? `ON PC · ${hhmm(c.ts)}` : hhmm(c.ts))
      : `${c.kind === 'note' ? 'NOTE · ' : ''}${c.partial ? 'TYPING' : hhmm(c.ts)}`;
    b.append(el('span', 'meta', meta));
    if (c.failed) b.addEventListener('click', () => deliver(c));
    log.append(b);
  }
  scrollChat();
}
function scrollChat() { const v = $('chat'); requestAnimationFrame(() => { v.scrollTop = v.scrollHeight; }); }

function renderApprovals() {
  const list = $('ap-list');
  list.replaceChildren();
  if (!S.approvals.length) { const e = el('div', 'empty'); e.append(el('h2', null, 'ALL CLEAR'), el('p', null, 'Nothing is waiting for your approval.')); list.append(e); return; }
  const block = approveBlock();
  for (const a of S.approvals) {
    const card = el('div', `card ap${a.state ? ' done' : ''}`);
    card.append(el('h3', null, `APPROVAL · ${String(a.tool || '').toUpperCase()}`));
    if (a.summary && a.summary !== a.tool) card.append(el('div', 'sum', a.summary));
    for (const [k, v] of a.fields || []) { const r = el('div', 'row'); r.append(el('span', 'k', k), el('span', 'v', v)); card.append(r); }
    if (!a.state) {
      const btns = el('div', 'btns');
      const ok = el('button', 'btn-ok', S.sec?.bio === false ? 'APPROVE' : 'APPROVE · ID'), no = el('button', 'btn-no', 'DENY');
      ok.disabled = true;
      if (!block) setTimeout(() => { ok.disabled = false; }, 800); // same arming delay as the HUD
      const decide = async (allow) => {
        ok.disabled = no.disabled = true;
        let assertion;
        if (allow && S.sec?.bio !== false) {
          try { assertion = await approvalAssertion(a); }
          catch (e) { ok.disabled = no.disabled = false; toast(e?.name === 'NotAllowedError' ? 'Face ID / fingerprint cancelled.' : `Biometric check failed: ${e?.message || e}`); return; }
        }
        a.state = 'sent'; save();
        send({ type: 'approve', requestId: a.requestId, allow, ...(assertion ? { assertion } : {}) }).then(() => { setTimeout(() => { if (a.state === 'sent') { a.state = null; renderApprovals(); toast('No answer from the PC yet.'); } }, 20000); })
          .catch(() => { a.state = null; renderApprovals(); toast('Could not reach the relay.'); });
        renderApprovals(); renderBadges();
      };
      ok.addEventListener('click', () => decide(true));
      no.addEventListener('click', () => decide(false));
      btns.append(no, ok);
      card.append(btns);
      if (block) {
        const note = el('div', 'ap-note', block);
        if (hasWebAuthn() && !S.sec?.untrusted && (!S.pair.cred || !S.sec?.bioDevs?.includes(S.pair.dev)) && (!S.sec?.origin || location.origin === S.sec.origin)) {
          const setup = el('button', 'chip', 'SET UP FACE ID / FINGERPRINT');
          setup.addEventListener('click', () => { setup.disabled = true; enrollBiometric().catch((e) => { setup.disabled = false; toast(`Not enabled: ${e?.name === 'NotAllowedError' ? 'cancelled' : e?.message || e}`); }); });
          note.append(setup);
        }
        card.append(note);
      }
    } else {
      const label = { sent: 'SENDING…', ok: 'APPROVED FROM PHONE', no: 'DENIED FROM PHONE', expired: 'EXPIRED', pc: 'HANDLED ON THE PC' }[a.state] || a.state;
      card.append(el('div', `state ${a.state === 'ok' ? 'ok' : a.state === 'no' ? 'no' : ''}`, `${label} · ${hhmm(a.ts)}`));
    }
    list.append(card);
  }
}

function renderAlerts() {
  const list = $('al-list');
  list.replaceChildren();
  const box = $('push-box');
  const canPush = 'serviceWorker' in navigator && 'PushManager' in window && isSecureContext;
  if (!canPush) {
    box.hidden = false; $('push-btn').hidden = true;
    $('push-text').textContent = isSecureContext ? 'This browser has no push support. On iPhone: Share → Add to Home Screen, then open JARVIS from the home screen.' : 'Notifications need the HTTPS app link (Wi-Fi test link: chat only).';
  } else if (Notification.permission !== 'granted' || !S.pushOn) {
    box.hidden = false; $('push-btn').hidden = false;
    $('push-text').textContent = S.vapidKey ? 'Get a notification for replies, approvals and alerts when the app is closed. Notifications show only a short preview.' : 'Waiting for the PC before notifications can be enabled…';
    $('push-btn').disabled = !S.vapidKey;
    navigator.serviceWorker.ready.then((r) => r.pushManager.getSubscription()).then((s) => { if (s && Notification.permission === 'granted') { S.pushOn = true; box.hidden = true; } }).catch(() => {});
  } else box.hidden = true;
  if (!S.alerts.length) { const e = el('div', 'empty'); e.append(el('h2', null, 'QUIET'), el('p', null, 'No alerts from the background monitor.')); list.append(e); return; }
  for (const a of S.alerts) {
    const card = el('div', 'card al');
    card.append(el('div', 'kind', String(a.kind || 'info').toUpperCase()), el('div', 't', a.text), el('div', 'when', `${dayOf(a.ts)} · ${hhmm(a.ts)}`.toUpperCase()));
    list.append(card);
  }
}

function renderBadges() {
  const open = S.approvals.filter((a) => !a.state).length;
  $('ap-badge').hidden = !open; $('ap-badge').textContent = open;
  const fresh = S.alerts.filter((a) => a.ts > (S.seenAlerts || 0)).length;
  $('al-badge').hidden = !fresh || S.tab === 'alerts'; $('al-badge').textContent = fresh;
}

function setPc(cls, text) { const p = $('pc'); p.className = `pc ${cls}`; $('pc-text').textContent = text; }
function updatePc() {
  if (!S.pair) return;
  const age = Date.now() - (S.lastPc || 0);
  if (S.lastPc && age < 660000) { // PC heartbeats every 5 min
    const st = S.pcStatus;
    setPc(st === 'approval' ? 'busy' : st === 'thinking' ? 'busy' : '', st === 'thinking' ? 'PC THINKING' : st === 'approval' ? 'PC WAITING' : 'PC ONLINE');
  } else setPc('off', S.lastPc ? `PC OFFLINE · ${ago(S.lastPc)}` : 'PC OFFLINE');
}
function ago(ts) { const s = Math.round((Date.now() - ts) / 1000); return s < 3600 ? `${Math.max(1, Math.round(s / 60))}M` : s < 86400 ? `${Math.round(s / 3600)}H` : `${Math.round(s / 86400)}D`; }

let toastTimer = null;
function toast(text) {
  let t = document.querySelector('.toast');
  if (!t) { t = el('div', 'toast'); document.body.append(t); }
  t.textContent = text; t.classList.add('on');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('on'), 3500);
}

async function enablePush() {
  try {
    const perm = await Notification.requestPermission();
    if (perm !== 'granted') { toast('Notifications are blocked for this site.'); return; }
    const reg = await navigator.serviceWorker.ready;
    const sub = (await reg.pushManager.getSubscription()) || (await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: JV.fromB64url(S.vapidKey) }));
    await send({ type: 'pushkey', pushKey: await JV.kvGet('pushkey') });
    await send({ type: 'sub', sub: sub.toJSON() });
    S.pushOn = true; renderAlerts();
    toast('Notifications on.');
  } catch (e) { toast(`Could not enable notifications: ${e.message || e}`); }
}

// A new pairing link opened while the app is running: re-run pairing from a clean page.
window.addEventListener('hashchange', () => { if (/[#&]k=/.test(location.hash)) location.reload(); });
init();
