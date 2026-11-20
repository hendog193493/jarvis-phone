// JARVIS phone companion. Talks to the PC only through ntfy.sh, end-to-end encrypted (see lib.js).
const JV = globalThis.JV;
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };

const S = {
  pair: null,            // {key, up, down, dev, keyBytes}
  chat: [],              // {id, role:'me'|'jv', text, ts, origin?, partial?, failed?, kind?}
  approvals: [],         // {requestId, tool, summary, fields, ts, state:null|'sent'|'ok'|'no'|'expired'|'pc'}
  alerts: [],            // {id, kind, text, ts}
  lastId: '',            // ntfy message id to resume from
  lastPc: 0, pcStatus: 'idle', vapidKey: '', seenAlerts: 0,
  tab: 'chat',
};
const seen = new Set();
let es = null, esRetry = 1000, pingTimer = null, saveTimer = null;

// ---------------- pairing ----------------
async function init() {
  const h = new URLSearchParams(location.hash.slice(1));
  if (h.get('k') && h.get('u') && h.get('d')) {
    const k = h.get('k');
    let ok = false;
    try { ok = JV.fromB64url(k).length === 32 && /^[\w-]{8,64}$/.test(h.get('u')) && /^[\w-]{8,64}$/.test(h.get('d')); } catch { ok = false; }
    history.replaceState(null, '', location.pathname + location.search); // the key never stays in the URL bar/history
    if (ok) {
      const old = await JV.kvGet('pair');
      const key = JV.toB64(JV.fromB64url(k));
      if (!old || old.key !== key || old.up !== h.get('u')) {
        await JV.kvSet('pair', { key, up: h.get('u'), down: h.get('d'), dev: old?.dev || JV.hex(nacl.randomBytes(8)), pairedAt: Date.now() });
        await JV.kvSet('state', null);
      }
    }
  }
  S.pair = await JV.pairing();
  const saved = S.pair && (await JV.kvGet('state'));
  if (saved) Object.assign(S, saved, { tab: S.tab });
  const qtab = new URLSearchParams(location.search).get('tab');
  if (qtab) S.tab = qtab;
  if ('serviceWorker' in navigator && isSecureContext) navigator.serviceWorker.register('sw.js').catch(() => {});
  navigator.serviceWorker?.addEventListener?.('message', (e) => { if (e.data?.type === 'open') showTab(e.data.tab); if (e.data?.type === 'push') connect(); });
  if (!S.pair) { showUnpaired(''); return; }
  bindUi();
  renderAll();
  showTab(S.tab);
  await connect();
}

function showUnpaired(why) {
  document.body.classList.add('no-bar');
  document.querySelectorAll('.tabs').forEach((t) => (t.hidden = true));
  document.querySelectorAll('.view').forEach((v) => v.classList.remove('on'));
  $('unpaired').classList.add('on');
  $('unpaired-why').textContent = why;
  setPc('off', 'NOT PAIRED');
}

// ---------------- relay ----------------
async function connect() {
  if (!S.pair) return;
  // 1) catch up on what we missed (ntfy keeps ~12 h)
  try {
    const r = await fetch(`${JV.NTFY}/${S.pair.down}/json?poll=1&since=${encodeURIComponent(S.lastId || '12h')}`);
    if (r.ok) for (const line of (await r.text()).split('\n')) { if (line.trim()) try { onRelay(JSON.parse(line), true); } catch { /* */ } }
  } catch { /* offline: the cached shell still shows history */ }
  renderAll();
  // 2) live stream
  openStream();
  hello();
}

function openStream() {
  if (es) es.close();
  es = new EventSource(`${JV.NTFY}/${S.pair.down}/sse?since=${encodeURIComponent(S.lastId || 'all')}`);
  es.onopen = () => { esRetry = 1000; };
  es.onmessage = (e) => { try { onRelay(JSON.parse(e.data), false); } catch { /* */ } };
  es.onerror = () => { es.close(); es = null; setTimeout(() => { if (!es && document.visibilityState === 'visible') openStream(); }, esRetry); esRetry = Math.min(esRetry * 2, 30000); };
}

function hello() {
  send({ type: 'hello' }).catch(() => {});
  clearInterval(pingTimer);
  pingTimer = setInterval(() => { if (document.visibilityState === 'visible') send({ type: 'ping' }).catch(() => {}); updatePc(); }, 60000);
}

function send(obj) { return JV.send(S.pair, obj); }

function onRelay(m, batch) {
  if (m.event !== 'message' || !m.message) return;
  S.lastId = m.id;
  const env = JV.open(S.pair.keyBytes, m.message);
  if (!env || seen.has(env.id)) return;
  seen.add(env.id);
  handle(env, batch);
  if (!batch) renderAll();
  save();
}

function handle(env, batch) {
  if (env.pcTime || ['hb', 'state', 'reply', 'approval', 'approval_done', 'user'].includes(env.type)) { S.lastPc = Math.max(S.lastPc, env.ts); }
  if (env.status) S.pcStatus = env.status;
  switch (env.type) {
    case 'state':
      if (env.vapidKey) S.vapidKey = env.vapidKey;
      { const live = new Set((env.pending || []).map((p) => p.requestId));
        for (const a of S.approvals) if (!a.state && !live.has(a.requestId)) a.state = 'expired';
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
        S.approvals.unshift({ requestId: env.requestId, tool: env.tool, summary: env.summary, fields: env.fields || [], ts: env.ts, state: Date.now() - env.ts > 15 * 60000 ? 'expired' : null });
        if (!batch && S.tab !== 'approvals') showTab('approvals');
      }
      break;
    case 'approval_done': {
      const a = S.approvals.find((x) => x.requestId === env.requestId);
      if (a) a.state = env.via === 'phone' ? (env.allow ? 'ok' : 'no') : env.via === 'expired' ? 'expired' : (a.state === 'ok' || a.state === 'no' ? a.state : 'pc');
      break;
    }
    case 'alert':
      if (!S.alerts.some((x) => x.id === env.alert.id)) S.alerts.unshift(env.alert);
      break;
    case 'unpaired':
      JV.kvDel('pair'); JV.kvDel('state'); S.pair = null;
      if (es) es.close();
      showUnpaired('This phone was unpaired on the PC (key rotated). Scan the new code to pair again.');
      return;
  }
  S.chat = S.chat.slice(-200); S.alerts = S.alerts.slice(0, 50); S.approvals = S.approvals.slice(0, 30);
}

function save() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    if (!S.pair) return;
    const { chat, approvals, alerts, lastId, lastPc, pcStatus, vapidKey, seenAlerts } = S;
    JV.kvSet('state', { chat, approvals, alerts, lastId, lastPc, pcStatus, vapidKey, seenAlerts }).catch(() => {});
  }, 300);
}

// ---------------- UI ----------------
function bindUi() {
  document.querySelectorAll('.tabs button').forEach((b) => b.addEventListener('click', () => showTab(b.dataset.tab)));
  const input = $('input');
  const grow = () => { input.style.height = 'auto'; input.style.height = `${Math.min(input.scrollHeight, 120)}px`; };
  input.addEventListener('input', grow);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey && !matchMedia('(pointer: coarse)').matches) { e.preventDefault(); $('bar').requestSubmit(); } });
  $('bar').addEventListener('submit', (e) => {
    e.preventDefault();
    const text = input.value.trim();
    if (!text) return;
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
  document.querySelectorAll('.tabs button').forEach((b) => b.classList.toggle('on', b.dataset.tab === S.tab));
  document.querySelectorAll('.view').forEach((v) => v.classList.toggle('on', v.id === S.tab));
  document.body.classList.toggle('no-bar', S.tab !== 'chat');
  if (S.tab === 'alerts') { S.seenAlerts = S.alerts.length ? S.alerts[0].ts : 0; save(); }
  renderBadges();
  if (S.tab === 'chat') scrollChat();
}

function renderAll() { renderChat(); renderApprovals(); renderAlerts(); renderBadges(); updatePc(); }

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
  for (const a of S.approvals) {
    const card = el('div', `card ap${a.state ? ' done' : ''}`);
    card.append(el('h3', null, `APPROVAL · ${String(a.tool || '').toUpperCase()}`));
    if (a.summary && a.summary !== a.tool) card.append(el('div', 'sum', a.summary));
    for (const [k, v] of a.fields || []) { const r = el('div', 'row'); r.append(el('span', 'k', k), el('span', 'v', v)); card.append(r); }
    if (!a.state) {
      const btns = el('div', 'btns');
      const ok = el('button', 'btn-ok', 'APPROVE'), no = el('button', 'btn-no', 'DENY');
      ok.disabled = true; setTimeout(() => { ok.disabled = false; }, 800); // same arming delay as the HUD
      const decide = (allow) => {
        ok.disabled = no.disabled = true;
        a.state = 'sent'; save();
        send({ type: 'approve', requestId: a.requestId, allow }).then(() => { setTimeout(() => { if (a.state === 'sent') { a.state = null; renderApprovals(); toast('No answer from the PC yet.'); } }, 20000); })
          .catch(() => { a.state = null; renderApprovals(); toast('Could not reach the relay.'); });
        renderApprovals(); renderBadges();
      };
      ok.addEventListener('click', () => decide(true));
      no.addEventListener('click', () => decide(false));
      btns.append(no, ok);
      card.append(btns);
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
    $('push-text').textContent = S.vapidKey ? 'Get a notification for replies, approvals and alerts when the app is closed.' : 'Waiting for the PC before notifications can be enabled…';
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
  if (S.lastPc && age < 150000) {
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
    await send({ type: 'sub', sub: sub.toJSON() });
    S.pushOn = true; renderAlerts();
    toast('Notifications on.');
  } catch (e) { toast(`Could not enable notifications: ${e.message || e}`); }
}

// A new pairing link opened while the app is running: re-run pairing from a clean page.
window.addEventListener('hashchange', () => { if (/[#&]k=/.test(location.hash)) location.reload(); });
init();
