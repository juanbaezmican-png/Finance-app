// Servidor de sincronización de "Mis Finanzas" (Cloudflare Worker)
// - Conecta tus bancos mediante Enable Banking (PSD2, uso personal)
// - Descarga movimientos y saldos varias veces al día (cron)
// - Guarda una copia de los datos de la app para usarla en varios dispositivos
// - Sirve un resumen de pockets para el widget del iPhone
//
// Variables (wrangler.toml / panel de Cloudflare):
//   EB_APP_ID       ID de la aplicación de Enable Banking (no es secreto)
//   REDIRECT_URL    URL a la que vuelve el banco (la raíz de este Worker)
// Secretos (se ponen en el panel de Cloudflare, nunca en el código):
//   EB_PRIVATE_KEY  contenido del archivo .pem de Enable Banking
//   APP_PASSWORD    contraseña que eliges tú para que solo tu app pueda leer los datos
// KV:
//   DB              almacenamiento de sesiones, movimientos y estado

const VERSION = '2026-11-26.2';
const SCHEMA = 2; // 2: movimientos identificados por cuenta estable (IBAN), sin duplicados entre conexiones
const EB_API = 'https://api.enablebanking.com';
const CONSENT_DAYS = 180;
const FIRST_SYNC_DAYS = 90;

/* ----------------------------- utilidades ----------------------------- */
const enc = new TextEncoder();
const b64url = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64urlStr = s => b64url(enc.encode(s));
const json = (data, status = 200, extra = {}) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', ...cors(), ...extra } });
const cors = () => ({ 'access-control-allow-origin': '*', 'access-control-allow-headers': 'authorization, content-type', 'access-control-allow-methods': 'GET, POST, PUT, OPTIONS' });
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const isoDate = d => d.toISOString().slice(0, 10);
const randomId = () => b64url(crypto.getRandomValues(new Uint8Array(18)));

function timingSafeEqual(a, b) {
  const x = enc.encode(String(a)), y = enc.encode(String(b));
  if (x.length !== y.length) return false;
  let r = 0; for (let i = 0; i < x.length; i++) r |= x[i] ^ y[i];
  return r === 0;
}
const normPass = s => String(s ?? '').normalize('NFC').trim();
function givenPassword(req, url) {
  const h = req.headers.get('authorization') || '';
  return normPass(h.startsWith('Bearer ') ? h.slice(7) : (url.searchParams.get('t') || ''));
}
function authorized(req, env, url) {
  if (!env.APP_PASSWORD) return false;
  return timingSafeEqual(givenPassword(req, url), normPass(env.APP_PASSWORD));
}

/* ------------------------------- JWT RS256 ------------------------------ */
function pemToDer(pem) {
  const body = pem.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----|\s+/g, '');
  return Uint8Array.from(atob(body), c => c.charCodeAt(0));
}
// Convierte una clave PKCS#1 ("BEGIN RSA PRIVATE KEY") a PKCS#8, que es lo que acepta WebCrypto
function pkcs1ToPkcs8(der) {
  const len = n => n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >> 8, n & 255];
  const algo = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
  const octet = [0x04, ...len(der.length), ...der];
  const inner = [0x02, 0x01, 0x00, ...algo, ...octet];
  return new Uint8Array([0x30, ...len(inner.length), ...inner]);
}
let keyCache = null;
async function signingKey(env) {
  if (keyCache) return keyCache;
  if (!env.EB_PRIVATE_KEY) throw new Error('Falta el secreto EB_PRIVATE_KEY en Cloudflare');
  let der = pemToDer(env.EB_PRIVATE_KEY);
  if (/BEGIN RSA PRIVATE KEY/.test(env.EB_PRIVATE_KEY)) der = pkcs1ToPkcs8(der);
  keyCache = await crypto.subtle.importKey('pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  return keyCache;
}
let jwtCache = { token: null, exp: 0 };
async function ebJwt(env) {
  const now = Math.floor(Date.now() / 1000);
  if (jwtCache.token && jwtCache.exp - 60 > now) return jwtCache.token;
  const header = { typ: 'JWT', alg: 'RS256', kid: env.EB_APP_ID };
  const payload = { iss: 'enablebanking.com', aud: 'api.enablebanking.com', iat: now, exp: now + 3600 };
  const data = `${b64urlStr(JSON.stringify(header))}.${b64urlStr(JSON.stringify(payload))}`;
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', await signingKey(env), enc.encode(data));
  jwtCache = { token: `${data}.${b64url(sig)}`, exp: now + 3600 };
  return jwtCache.token;
}
async function eb(env, path, { method = 'GET', body } = {}) {
  const res = await fetch(EB_API + path, {
    method,
    headers: { authorization: `Bearer ${await ebJwt(env)}`, 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = { raw: text }; }
  if (!res.ok) {
    const err = new Error(`Enable Banking ${res.status}: ${data.message || data.error || text.slice(0, 200)}`);
    err.status = res.status; err.data = data; throw err;
  }
  return data;
}

/* ------------------------------ almacenamiento ------------------------------ */
const getJSON = async (env, key, def) => (await env.DB.get(key, 'json')) ?? def;
const putJSON = (env, key, val) => env.DB.put(key, JSON.stringify(val));
// sessions: { [session_id]: { aspsp, country, valid_until, accounts:[{uid,name,iban,currency}], created, error } }

/* ------------------------------ normalización ------------------------------ */
// Identificador estable de una cuenta: el IBAN (o banco + nombre). El uid de Enable Banking cambia cada vez que reconectas el banco.
function accountKey(acc, aspsp) {
  const iban = (acc.iban || '').replace(/\s/g, '').toUpperCase();
  return iban ? `IBAN:${iban}` : `ACC:${String(aspsp || '').toLowerCase().replace(/^banco\s+/, '').trim()}|${String(acc.name || '').toLowerCase().trim()}`;
}
function normalizeTx(t, account, ownIbans) {
  const amt = Math.abs(parseFloat(t.transaction_amount?.amount ?? t.amount ?? 0)) || 0;
  const credit = (t.credit_debit_indicator || '').toUpperCase() === 'CRDT';
  const counter = credit ? (t.debtor || {}) : (t.creditor || {});
  const counterAcc = credit ? t.debtor_account : t.creditor_account;
  const counterIban = (counterAcc?.iban || '').replace(/\s/g, '').toUpperCase();
  const remit = Array.isArray(t.remittance_information) ? t.remittance_information.join(' ') : (t.remittance_information || '');
  const desc = [counter.name, remit, t.bank_transaction_code?.description, t.note].filter(Boolean).join(' · ').replace(/\s+/g, ' ').trim();
  // Fecha de la compra (transaction_date) si el banco la da; si no, la de contabilización
  const date = t.transaction_date || t.booking_date || t.value_date || '';
  const key = accountKey(account, account.aspsp);
  const idBase = t.transaction_id || t.entry_reference || `${t.booking_date || t.value_date || t.transaction_date || ''}|${amt}|${credit ? 'C' : 'D'}|${desc}`;
  return {
    id: `${key}:${idBase}`,
    account_key: key,
    account_uid: account.uid,
    account_name: account.name,
    aspsp: account.aspsp,
    date,
    amount: Math.round(amt * 100) / 100,
    currency: t.transaction_amount?.currency || account.currency || 'EUR',
    type: credit ? 'ingreso' : 'gasto',
    counterparty: counter.name || '',
    description: desc || remit || '(sin descripción)',
    mcc: t.merchant_category_code || '',
    status: t.status || 'BOOK',
    internal: !!(counterIban && ownIbans.has(counterIban)),
  };
}

/* ---------------------------------- sync ---------------------------------- */
async function syncAll(env, { force = false } = {}) {
  const sessions = await getJSON(env, 'sessions', {});
  const store = await getJSON(env, 'transactions', {});        // { id: tx }
  const balances = await getJSON(env, 'balances', {});         // { uid: {amount,currency,date} }
  let meta = await getJSON(env, 'meta', {});
  // Cambio de formato: se vacía y se vuelve a descargar todo (así desaparecen los duplicados antiguos)
  if (meta.schema !== SCHEMA) { for (const k of Object.keys(store)) delete store[k]; meta = { schema: SCHEMA }; }
  const ownIbans = new Set(Object.values(sessions).flatMap(s => s.accounts.map(a => (a.iban || '').replace(/\s/g, '').toUpperCase())).filter(Boolean));
  const log = [];
  let added = 0;
  const done = new Set();
  const ordered = Object.entries(sessions).sort((a, b) => String(b[1].created || '').localeCompare(String(a[1].created || '')));
  for (const [sid, s] of ordered) {
    if (s.valid_until && new Date(s.valid_until) < new Date()) { s.error = 'Permiso caducado: vuelve a conectar este banco'; continue; }
    for (const acc of s.accounts) {
      const key = accountKey(acc, s.aspsp);
      if (done.has(key)) continue; // la misma cuenta conectada dos veces: solo se lee una
      done.add(key);
      try {
        const last = meta[`last_${acc.uid}`];
        const from = new Date(last ? new Date(last).getTime() - 5 * 864e5 : Date.now() - FIRST_SYNC_DAYS * 864e5);
        let ck = null, pages = 0;
        do {
          const q = new URLSearchParams({ date_from: isoDate(from) });
          if (ck) q.set('continuation_key', ck);
          const r = await eb(env, `/accounts/${encodeURIComponent(acc.uid)}/transactions?${q}`);
          for (const t of r.transactions || []) {
            const n = normalizeTx(t, { ...acc, aspsp: s.aspsp }, ownIbans);
            if (!store[n.id]) added++;
            store[n.id] = { ...(store[n.id] || {}), ...n, first_seen: store[n.id]?.first_seen || new Date().toISOString() };
          }
          ck = r.continuation_key || null;
        } while (ck && ++pages < 10);
        try {
          const b = await eb(env, `/accounts/${encodeURIComponent(acc.uid)}/balances`);
          const pick = (b.balances || []).find(x => /ITAV|CLAV|XPCD|ITBD/.test(x.balance_type || '')) || (b.balances || [])[0];
          if (pick) balances[acc.uid] = { amount: parseFloat(pick.balance_amount?.amount), currency: pick.balance_amount?.currency, type: pick.balance_type, date: new Date().toISOString() };
        } catch (e) { log.push(`${acc.name}: saldo no disponible (${e.status || e.message})`); }
        meta[`last_${acc.uid}`] = new Date().toISOString();
        s.error = null;
      } catch (e) {
        log.push(`${s.aspsp} · ${acc.name}: ${e.message}`);
        if (e.status === 401 || e.status === 403) s.error = 'El banco ha rechazado el acceso: vuelve a conectarlo';
        else s.error = e.message;
      }
    }
  }
  // Recalcula transferencias internas con la lista completa de IBAN propios
  meta.last_sync = new Date().toISOString();
  meta.last_log = log;
  await Promise.all([putJSON(env, 'sessions', sessions), putJSON(env, 'transactions', store), putJSON(env, 'balances', balances), putJSON(env, 'meta', meta)]);
  return { added, log };
}

/* --------------------------------- páginas --------------------------------- */
const page = (title, body) => new Response(`<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
<style>:root{--ink:#1d1d1f;--muted:#707070;--blue:#0071e3;--line:#e6e6e8}*{box-sizing:border-box}body{margin:0;background:#f5f5f7;color:var(--ink);font:15px/1.45 -apple-system,BlinkMacSystemFont,"Helvetica Neue",Inter,Arial,sans-serif;letter-spacing:-.016em}
main{max-width:560px;margin:0 auto;padding:32px 16px 60px}h1{font-size:32px;font-weight:600;letter-spacing:-.02em;margin:0 0 8px}p{color:var(--muted)}.card{background:#fff;border-radius:28px;padding:22px;margin-top:16px}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 0;border-bottom:1px solid var(--line)}.row:last-child{border:0}.row img{width:32px;height:32px;object-fit:contain;border-radius:8px}
.btn{display:inline-block;background:var(--blue);color:#fff;border:0;border-radius:9999px;padding:9px 18px;font-size:14px;text-decoration:none;white-space:nowrap}.btn.o{background:none;color:var(--ink);box-shadow:inset 0 0 0 1px #86868b}
input{width:100%;border:1px solid #86868b;border-radius:980px;padding:11px 18px;font:inherit;margin:10px 0}.ok{color:#248a3d}.err{color:#d70015}small{color:var(--muted)}</style></head><body><main>${body}</main></body></html>`,
  { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });



async function connectPage(env, t, q) {
  const sessions = await getJSON(env, 'sessions', {});
  let list = [];
  try { list = (await eb(env, '/aspsps?country=ES')).aspsps || []; } catch (e) { return page('Error', `<h1>Error</h1><p class="err">${esc(e.message)}</p>`); }
  const filtered = q ? list.filter(a => a.name.toLowerCase().includes(q.toLowerCase())) : [...list].sort((x, y) => x.name.localeCompare(y.name, 'es'));
  const connected = Object.values(sessions);
  return page('Conectar bancos', `<h1>Tus bancos</h1><p>Conecta cada banco una vez. El permiso dura unos ${CONSENT_DAYS} días; después tendrás que renovarlo aquí.</p>
  <div class="card"><b>Conectados</b>${connected.length ? connected.map(s => `<div class="row"><div>${esc(s.aspsp)}<br><small>${s.accounts.length} cuenta(s) · hasta ${esc((s.valid_until || '').slice(0, 10))}</small>${s.error ? `<br><small class="err">${esc(s.error)}</small>` : ''}</div><span class="${s.error ? 'err' : 'ok'}">${s.error ? 'Revisar' : 'Activo'}</span></div>`).join('') : '<p>Todavía no hay ninguno.</p>'}</div>
  <div class="card"><b>${q ? 'Resultados' : 'Bancos en España'}</b>
  ${filtered.map(a => `<div class="row"><div style="display:flex;gap:12px;align-items:center">${a.logo ? `<img src="${esc(a.logo)}" alt="">` : ''}<div>${esc(a.name)}<br><small>${esc((a.psu_types || []).join(', '))}</small></div></div><a class="btn" href="/connect/start?t=${encodeURIComponent(t)}&name=${encodeURIComponent(a.name)}&country=${encodeURIComponent(a.country)}">Conectar</a></div>`).join('') || '<p>No he encontrado ese banco.</p>'}
  <form method="get" action="/connect"><input type="hidden" name="t" value="${esc(t)}"><input name="q" placeholder="Buscar otro banco (p. ej. Trade Republic)" value="${esc(q || '')}"><button class="btn o">Buscar</button></form></div>
  <div class="card"><a class="btn o" href="/sync?t=${encodeURIComponent(t)}">Sincronizar ahora</a></div>`);
}

async function startAuth(env, t, name, country) {
  const list = (await eb(env, `/aspsps?country=${encodeURIComponent(country)}`)).aspsps || [];
  const a = list.find(x => x.name === name);
  const maxSec = a?.maximum_consent_validity || CONSENT_DAYS * 86400;
  const validUntil = new Date(Date.now() + Math.min(maxSec, CONSENT_DAYS * 86400) * 1000 - 60000).toISOString();
  const state = randomId();
  await env.DB.put(`state_${state}`, JSON.stringify({ name, country }), { expirationTtl: 1800 });
  const psu = (a?.psu_types || []).includes('personal') || !a?.psu_types ? 'personal' : a.psu_types[0];
  const r = await eb(env, '/auth', { method: 'POST', body: { access: { valid_until: validUntil }, aspsp: { name, country }, state, redirect_url: env.REDIRECT_URL, psu_type: psu } });
  return Response.redirect(r.url, 302);
}

async function callback(env, url) {
  const err = url.searchParams.get('error');
  if (err) return page('No conectado', `<h1>No se ha conectado</h1><p class="err">${esc(url.searchParams.get('error_description') || err)}</p>`);
  const state = url.searchParams.get('state');
  let saved = state && await getJSON(env, `state_${state}`, null);
  if (saved) await env.DB.delete(`state_${state}`);
  // Si la conexión se inició desde el panel de Enable Banking ("Activate by linking accounts")
  // no hay estado guardado: el código solo es válido para esta aplicación, así que lo aceptamos.
  const code = url.searchParams.get('code');
  if (!code) return page('Enlace no válido', '<h1>Enlace no válido</h1><p>Vuelve a la página de conexión e inténtalo de nuevo.</p>');
  const s = await eb(env, '/sessions', { method: 'POST', body: { code } });
  if (!saved) saved = { name: s.aspsp?.name || 'Banco', country: s.aspsp?.country || 'ES' };
  // Las cuentas pueden llegar como objetos o solo como identificadores (+ accounts_data): se combinan ambas fuentes
  let detail = null;
  try { detail = await eb(env, `/sessions/${encodeURIComponent(s.session_id)}`); } catch (e) { console.warn('GET session', e.message); }
  const byUid = new Map();
  const add = a => {
    if (!a) return;
    if (typeof a === 'string') { if (!byUid.has(a)) byUid.set(a, { uid: a }); return; }
    const uid = a.uid || a.account_uid; if (!uid) return;
    byUid.set(uid, { ...(byUid.get(uid) || {}), ...a, uid });
  };
  [...(s.accounts || []), ...(detail?.accounts || []), ...(detail?.accounts_data || [])].forEach(add);
  const accounts = [...byUid.values()].map(a => ({
    uid: a.uid, name: a.name || a.product || a.details || saved.name, iban: a.account_id?.iban || a.iban || '', currency: a.currency || 'EUR',
  }));
  if (!accounts.length) { const ss = await getJSON(env, 'sessions', {}); for (const [k, v] of Object.entries(ss)) if (v.aspsp === saved.name && !v.accounts.length) delete ss[k]; await putJSON(env, 'sessions', ss); return page('Sin cuentas', `<h1 class="err">${esc(saved.name)}: 0 cuentas</h1><p>El banco ha dado permiso, pero Enable Banking no devuelve ninguna cuenta. En el modo gratuito solo se pueden leer las cuentas enlazadas antes desde el panel de Enable Banking (API applications → tu aplicación → enlazar cuentas). Enlaza allí ${esc(saved.name)} y después vuelve a conectarlo desde esta página.</p>`); }
  const sessions = await getJSON(env, 'sessions', {});
  // Sustituye una sesión anterior del mismo banco (renovación)
  const newKeys = new Set(accounts.map(a => accountKey(a, saved.name)));
  for (const [k, v] of Object.entries(sessions)) if (v.aspsp === saved.name || (v.accounts || []).some(a => newKeys.has(accountKey(a, v.aspsp)))) delete sessions[k];
  sessions[s.session_id] = { aspsp: saved.name, country: saved.country, valid_until: s.access?.valid_until || '', accounts, created: new Date().toISOString(), error: null };
  await putJSON(env, 'sessions', sessions);
  let res; try { res = await syncAll(env); } catch (e) { res = { added: 0, log: [e.message] }; }
  return page('Banco conectado', `<h1 class="ok">${esc(saved.name)} conectado</h1><p>${accounts.length} cuenta(s): ${accounts.map(a => esc(a.name)).join(', ')}.<br>${res.added} movimientos descargados.</p>${res.log.length ? `<p class="err">${res.log.map(esc).join('<br>')}</p>` : ''}<p>Ya puedes cerrar esta página y volver a la app.</p>`);
}

/* ---------------------------------- API ---------------------------------- */
const madridDate = (d = new Date()) => new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Madrid' }).format(d);
const eurTxt = n => { const [i, d] = Math.abs(n).toFixed(2).split('.'); return (n < 0 ? '-' : '') + i.replace(/\B(?=(\d{3})+(?!\d))/g, '.') + ',' + d + ' €'; };
// Traspasos entre tus propias cuentas y pockets: salen dos veces (salida y entrada) con el mismo importe
function internalIds(txs) {
  const out = new Set(txs.filter(t => t.internal).map(t => t.id));
  const by = {};
  for (const t of txs) (by[t.amount.toFixed(2)] = by[t.amount.toFixed(2)] || []).push(t);
  for (const list of Object.values(by)) for (const a of list) {
    if (out.has(a.id)) continue;
    const b = list.find(x => x.id !== a.id && !out.has(x.id) && (x.account_key || x.account_uid) !== (a.account_key || a.account_uid) && x.type !== a.type && Math.abs(new Date(x.date) - new Date(a.date)) <= 5 * 864e5);
    if (b) { out.add(a.id); out.add(b.id); }
  }
  for (const t of txs) if (/trade ?republic/i.test(`${t.counterparty} ${t.description}`) && !/trade ?republic/i.test(t.aspsp || '')) out.add(t.id);
  return out;
}
// Resumen del día para la notificación de la noche
async function apiToday(env, url) {
  let meta = await getJSON(env, 'meta', {});
  if (url.searchParams.get('refresh') === '1' && (!meta.last_sync || Date.now() - new Date(meta.last_sync) > 2 * 3600e3)) {
    try { await syncAll(env); meta = await getJSON(env, 'meta', {}); } catch (e) { console.warn('refresh', e.message); }
  }
  const [store, balances, widget] = await Promise.all([getJSON(env, 'transactions', {}), getJSON(env, 'balances', {}), getJSON(env, 'widget', null)]);
  const date = url.searchParams.get('date') || madridDate();
  const all = Object.values(store);
  const internal = internalIds(all);
  const today = all.filter(t => t.date === date && t.type === 'gasto' && !internal.has(t.id)).sort((a, b) => b.amount - a.amount);
  const total = Math.round(today.reduce((s, t) => s + t.amount, 0) * 100) / 100;
  const pockets = (widget?.pockets || []).filter(p => p.uid && balances[p.uid] && Number.isFinite(balances[p.uid].amount)).map(p => ({ n: p.n, b: balances[p.uid].amount }));
  const left = pockets.reduce((s, p) => s + p.b, 0);
  const top = today.slice(0, 3).map(t => `${(t.counterparty || t.description).slice(0, 24)} ${eurTxt(t.amount)}`);
  const body = today.length
    ? `Hoy has gastado ${eurTxt(total)} en ${today.length} ${today.length === 1 ? 'compra' : 'compras'}: ${top.join(', ')}${today.length > 3 ? '…' : '.'}`
    : 'Hoy no has gastado nada. ¡Bien hecho!';
  const extra = pockets.length ? ` Te quedan ${eurTxt(left)} en tus pockets${pockets.filter(p => p.b < 10).length ? ` (casi vacío: ${pockets.filter(p => p.b < 10).map(p => p.n).join(', ')})` : ''}.` : '';
  return json({ date, total, count: today.length, title: today.length ? `Hoy: ${eurTxt(total)}` : 'Hoy: 0 €', body: body + extra, last_sync: meta.last_sync || null, items: today.map(t => ({ name: t.counterparty || t.description, amount: t.amount, account: t.account_name })) });
}

async function apiData(env, url) {
  const since = url.searchParams.get('since') || '';
  if ((await getJSON(env, 'meta', {})).schema !== SCHEMA) { try { await syncAll(env); } catch (e) { console.warn('rebuild', e.message); } }
  const [sessions, store, balances, meta] = await Promise.all([getJSON(env, 'sessions', {}), getJSON(env, 'transactions', {}), getJSON(env, 'balances', {}), getJSON(env, 'meta', {})]);
  const seenKeys = new Set();
  const accounts = Object.entries(sessions).sort((a, b) => String(b[1].created || '').localeCompare(String(a[1].created || '')))
    .flatMap(([sid, s]) => s.accounts.map(a => ({ ...a, key: accountKey(a, s.aspsp), aspsp: s.aspsp, valid_until: s.valid_until, error: s.error, balance: balances[a.uid] || null })))
    .filter(a => !seenKeys.has(a.key) && seenKeys.add(a.key));
  const transactions = Object.values(store).filter(t => !since || t.date >= since).sort((a, b) => b.date.localeCompare(a.date));
  return json({ accounts, transactions, last_sync: meta.last_sync || null, log: meta.last_log || [] });
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors() });
    try {
      // Vuelta desde el banco (la URL de redirección es la raíz)
      if (url.pathname === '/' && (url.searchParams.has('code') || url.searchParams.has('error'))) return await callback(env, url);
      if (url.pathname === '/') return page('Mis Finanzas', `<h1>Mis Finanzas</h1><p>Servidor de sincronización funcionando.</p><p><small>Versión ${VERSION}</small></p>${env.EB_PRIVATE_KEY ? '' : '<p class="err">Falta el secreto EB_PRIVATE_KEY.</p>'}${env.APP_PASSWORD ? '' : '<p class="err">Falta el secreto APP_PASSWORD.</p>'}
        <form method="get" action="/connect" class="card"><b>Conectar bancos</b><input type="password" name="t" placeholder="Tu contraseña (APP_PASSWORD)"><button class="btn">Entrar</button></form>`);
      if (!authorized(req, env, url)) return url.pathname.startsWith('/api/') ? json({ error: 'unauthorized' }, 401) : (() => {
        const got = givenPassword(req, url).length, want = normPass(env.APP_PASSWORD).length;
        const hint = !env.APP_PASSWORD ? 'El servidor no tiene ninguna contraseña guardada (falta APP_PASSWORD).'
          : got !== want ? `Has escrito ${got} caracteres y la contraseña guardada tiene ${want}.`
          : `Tiene el mismo número de caracteres (${got}), así que probablemente cambia alguna letra o mayúscula.`;
        return page('Contraseña incorrecta', `<h1>Contraseña incorrecta</h1><p>${esc(hint)}</p><p><a href="/">Volver</a></p>`);
      })();
      const t = givenPassword(req, url);
      if (url.pathname === '/connect') return await connectPage(env, t, url.searchParams.get('q'));
      if (url.pathname === '/connect/start') return await startAuth(env, t, url.searchParams.get('name'), url.searchParams.get('country') || 'ES');
      if (url.pathname === '/sync') { const r = await syncAll(env, { force: true }); return page('Sincronizado', `<h1>Sincronizado</h1><p>${r.added} movimientos nuevos.</p>${r.log.length ? `<p class="err">${r.log.map(esc).join('<br>')}</p>` : ''}<p><a href="/connect?t=${encodeURIComponent(t)}">Volver</a></p>`); }
      if (url.pathname === '/api/data') return await apiData(env, url);
      if (url.pathname === '/api/today') return await apiToday(env, url);
      if (url.pathname === '/api/sync' && req.method === 'POST') return json(await syncAll(env, { force: true }));
      // Copia de los datos de la app (para usarla en varios dispositivos)
      if (url.pathname === '/api/state' && req.method === 'GET') return json((await getJSON(env, 'app_state', null)) || { state: null, updated: null });
      if (url.pathname === '/api/state' && req.method === 'PUT') {
        const body = await req.json();
        if (!body || typeof body.state !== 'object') return json({ error: 'bad state' }, 400);
        const rec = { state: body.state, updated: body.updated || new Date().toISOString(), device: body.device || '' };
        await putJSON(env, 'app_state', rec);
        if (body.widget) await putJSON(env, 'widget', { ...body.widget, updated: rec.updated });
        return json({ ok: true, updated: rec.updated });
      }
      if (url.pathname === '/api/widget') {
        // Configuración de pockets que envía la app + saldos reales que el cron descarga de Revolut
        const [w, bal, meta] = await Promise.all([getJSON(env, 'widget', null), getJSON(env, 'balances', {}), getJSON(env, 'meta', {})]);
        const out = w || { pockets: [] };
        out.pockets = (out.pockets || []).map(p => (p.uid && bal[p.uid] && Number.isFinite(bal[p.uid].amount)) ? { ...p, b: bal[p.uid].amount } : p);
        out.last_sync = meta.last_sync || null;
        return json(out);
      }
      return json({ error: 'not found' }, 404);
    } catch (e) {
      console.error(e);
      if (url.pathname.startsWith('/api/')) return json({ error: e.message }, 500);
      return page('Error', `<h1>Algo ha fallado</h1><p class="err">${esc(e.message)}</p>`);
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(syncAll(env).catch(e => console.error('sync', e)));
  },
};
