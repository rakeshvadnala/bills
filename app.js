'use strict';
/*
 * Bills — encrypted monthly payments tracker.
 * All data is encrypted in the browser (PBKDF2-SHA256 -> AES-256-GCM) before it
 * is written to a GitHub repository. Only ciphertext ever leaves this device.
 */

// ---------------------------------------------------------------- constants
const AAD_VAULT = 'bills-vault-v1';
const AAD_TOKEN = 'bills-token-v1';
const DEFAULT_ITER = 600000;
const LS_CONFIG = 'bills.config.v1';
const LS_CACHE = 'bills.cache.v1';
const MIN_PW = 10;

const TYPES = { card: 'Credit card', utility: 'Utility', rent: 'Rent', loan: 'Loan / EMI', transfer: 'Transfer', personal: 'Personal', other: 'Other' };
const STATUS = { pending: 'Pending', done: 'Done', skipped: 'Skipped', na: 'Not due' };
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

// ---------------------------------------------------------------- utils
const te = new TextEncoder();
const td = new TextDecoder();
function b64(buf) { const b = new Uint8Array(buf); let s = ''; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); }
function unb64(s) { const bin = atob(s); const b = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i); return b; }
function uid() { return b64(crypto.getRandomValues(new Uint8Array(9))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''); }
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function money(n) { return 'AED ' + (Number(n) || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }); }
function short(n) { n = Number(n) || 0; return n >= 1000 ? (n / 1000).toFixed(n >= 10000 ? 0 : 1) + 'k' : String(Math.round(n)); }
function pad(n) { return String(n).padStart(2, '0'); }
function todayISO() { const t = new Date(); return `${t.getFullYear()}-${pad(t.getMonth() + 1)}-${pad(t.getDate())}`; }
function fmtDate(iso) { if (!iso) return ''; const [y, m, d] = iso.split('-'); return `${+d} ${MONTHS[+m - 1]} ${y}`; }
function fmtMonth(ym) { if (!ym) return ''; const [y, m] = ym.split('-'); return `${MONTHS[+m - 1]} ${y}`; }
function round2(n) { return Math.round((Number(n) || 0) * 100) / 100; }
function timeNow() { return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }

// ---------------------------------------------------------------- crypto
async function deriveKey(password, saltBytes, iter) {
  const base = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: iter, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encryptJSON(key, obj, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode(aad) }, key, te.encode(JSON.stringify(obj)));
  return { iv: b64(iv), ct: b64(ct) };
}
async function decryptJSON(key, box, aad) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(box.iv), additionalData: te.encode(aad) }, key, unb64(box.ct));
  return JSON.parse(td.decode(pt));
}
async function sealWith(key, salt, iter, data) {
  const box = await encryptJSON(key, data, AAD_VAULT);
  return JSON.stringify({ format: 'bills-vault', v: 1, kdf: { name: 'PBKDF2-SHA256', iter, salt }, cipher: 'AES-256-GCM', iv: box.iv, ct: box.ct }, null, 1);
}
function readVaultHeader(text) {
  const f = JSON.parse(text);
  if (f.format !== 'bills-vault' || !f.kdf || !f.iv || !f.ct) throw new Error('This file is not a Bills vault');
  return f;
}
async function openVault(key, text) { return decryptJSON(key, readVaultHeader(text), AAD_VAULT); }

// ---------------------------------------------------------------- GitHub
function contentsUrl(cfg) {
  const p = cfg.path.split('/').filter(Boolean).map(encodeURIComponent).join('/');
  return `https://api.github.com/repos/${encodeURIComponent(cfg.owner)}/${encodeURIComponent(cfg.repo)}/contents/${p}`;
}
function ghHeaders(token, json) {
  const h = { Accept: 'application/vnd.github+json', Authorization: `Bearer ${token}`, 'X-GitHub-Api-Version': '2022-11-28' };
  if (json) h['Content-Type'] = 'application/json';
  return h;
}
async function ghErr(r) {
  let m = '';
  try { m = (await r.json()).message || ''; } catch (e) { /* ignore */ }
  if (r.status === 401) return 'GitHub token is invalid or expired';
  if (r.status === 403) return 'Token lacks permission (needs Contents: Read and write on this repo)' + (m ? ` — ${m}` : '');
  if (r.status === 404) return 'Repository not found, or the token has no access to it';
  return `GitHub error ${r.status}${m ? ': ' + m : ''}`;
}
async function ghRepo(cfg, token) {
  const r = await fetch(`https://api.github.com/repos/${encodeURIComponent(cfg.owner)}/${encodeURIComponent(cfg.repo)}`, { headers: ghHeaders(token), cache: 'no-store' });
  if (!r.ok) throw new Error(await ghErr(r));
  return r.json();
}
async function ghGet(cfg, token) {
  const r = await fetch(`${contentsUrl(cfg)}?ref=${encodeURIComponent(cfg.branch)}&t=${Date.now()}`, { headers: ghHeaders(token), cache: 'no-store' });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(await ghErr(r));
  const j = await r.json();
  return { sha: j.sha, text: td.decode(unb64(j.content.replace(/\s/g, ''))) };
}
async function ghPut(cfg, token, text, sha) {
  const body = { message: 'Update bills vault', content: b64(te.encode(text)), branch: cfg.branch };
  if (sha) body.sha = sha;
  const r = await fetch(contentsUrl(cfg), { method: 'PUT', headers: ghHeaders(token, true), body: JSON.stringify(body) });
  if (r.status === 409 || r.status === 422) {
    let m = ''; try { m = (await r.json()).message || ''; } catch (e) { /* ignore */ }
    if (r.status === 409 || /sha/i.test(m)) { const e = new Error('conflict'); e.conflict = true; throw e; }
    throw new Error(`GitHub error ${r.status}: ${m}`);
  }
  if (!r.ok) throw new Error(await ghErr(r));
  return (await r.json()).content.sha;
}

// ---------------------------------------------------------------- sheet import
const MONTH_IDX = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
function parseDate(s) {
  const m = /^\s*(\d{1,2})[-\s/]([A-Za-z]{3})[A-Za-z]*[-\s/](\d{4})\s*$/.exec(s || '');
  if (!m) return null;
  const mo = MONTH_IDX[m[2].toLowerCase()];
  if (mo == null) return null;
  return `${m[3]}-${pad(mo + 1)}-${pad(m[1])}`;
}
function parseAmount(s) {
  if (s == null) return null;
  const t = String(s).replace(/AED/i, '').replace(/,/g, '').trim();
  if (t === '' || t === '-') return null;
  const n = Number(t);
  return Number.isFinite(n) ? n : null;
}
function guessForMonth(iso) {
  let [y, m, d] = iso.split('-').map(Number);
  if (d >= 25) { m++; if (m > 12) { m = 1; y++; } } // paid late in the month -> covers next month
  return `${y}-${pad(m)}`;
}
function guessType(name) {
  const n = name.toLowerCase();
  if (/\bcc\b|card|noon|enbd/.test(n)) return 'card';
  if (/rent/.test(n)) return 'rent';
  if (/emi|loan/.test(n)) return 'loan';
  if (/inr|conversion|transfer|remit/.test(n)) return 'transfer';
  if (/\bdu|dewa|lootah|wifi|mobile|bill|gas|water|electric/.test(n)) return 'utility';
  return 'other';
}
/** Parses rows copied from the Google Sheet (tab separated: Date, Name, Amount, Note, Status). */
function parseSheet(text) {
  const cycles = [];
  const byDate = new Map();
  let cur = null;
  for (const raw of String(text).split(/\r?\n/)) {
    const cols = raw.split('\t');
    if (cols.every(c => !c.trim())) continue;
    const d = parseDate(cols[0]);
    if (d) {
      // Same date again (date repeated on every row) -> same cycle
      cur = byDate.get(d);
      if (!cur) { cur = { date: d, forMonth: guessForMonth(d), rows: [] }; cycles.push(cur); byDate.set(d, cur); }
    }
    const name = (cols[1] || '').trim();
    if (!cur || !name) continue; // totals lines have no name
    const amount = parseAmount(cols[2]);
    let note = (cols[3] || '').trim();
    const st = (cols[4] || '').trim();
    if (/^\s*AED\s*[\d,]+(\.\d+)?\s*$/i.test(note)) note = 'Also listed: ' + note;
    if (note === '-') note = '';
    let status;
    if (/^done$/i.test(st)) status = 'done';
    else if (st === '-') status = 'skipped';
    else if (!amount) status = 'na';
    else status = 'pending';
    cur.rows.push({ name, amount: amount || 0, note, status, paidVia: /used\s+.*cc/i.test(note) ? 'card' : 'bank' });
  }
  return cycles;
}
/** Merges parsed cycles into data. renames: {originalName: targetName}. Returns summary. */
function applyImport(data, parsed, renames) {
  const byName = new Map(data.payees.map(p => [p.name.toLowerCase(), p]));
  const existingDates = new Set(data.cycles.map(c => c.date));
  let added = 0, skipped = 0, newPayees = 0;
  const seen = new Map(); // payeeId -> list of {date, amount}
  for (const pc of parsed) {
    if (existingDates.has(pc.date)) { skipped++; continue; }
    const cycle = { id: uid(), date: pc.date, forMonth: pc.forMonth, items: [] };
    for (const r of pc.rows) {
      const target = ((renames && renames[r.name]) || r.name).trim();
      if (!target) continue;
      let p = byName.get(target.toLowerCase());
      if (!p) {
        p = { id: uid(), name: target, type: guessType(target), defaultAmount: null, active: true, order: data.payees.length };
        data.payees.push(p); byName.set(target.toLowerCase(), p); newPayees++;
      }
      const existing = cycle.items.find(i => i.payeeId === p.id);
      if (existing) { // two sheet names merged into one payee in the same cycle
        existing.amount = round2(existing.amount + r.amount);
        if (r.note) existing.note = [existing.note, r.note].filter(Boolean).join('; ');
        continue;
      }
      cycle.items.push({ id: uid(), payeeId: p.id, amount: round2(r.amount), status: r.status, paidVia: r.paidVia, note: r.note });
      if (!seen.has(p.id)) seen.set(p.id, []);
      seen.get(p.id).push({ date: pc.date, amount: r.amount });
    }
    data.cycles.push(cycle); existingDates.add(pc.date); added++;
  }
  // Infer active flag and fixed amounts from history
  const dates = [...new Set(data.cycles.map(c => c.date))].sort();
  const recent = new Set(dates.slice(-2));
  for (const p of data.payees) {
    const hist = data.cycles.filter(c => c.items.some(i => i.payeeId === p.id));
    if (!hist.length) continue;
    p.active = hist.some(c => recent.has(c.date));
    if (p.defaultAmount == null) {
      const amts = data.cycles.slice().sort((a, b) => a.date.localeCompare(b.date))
        .flatMap(c => c.items.filter(i => i.payeeId === p.id && i.amount > 0).map(i => i.amount));
      const last = amts.slice(-2);
      if (last.length === 2 && last[0] === last[1]) p.defaultAmount = last[0];
    }
  }
  return { added, skipped, newPayees };
}

/** Merges cycles that share the same payment date into one. Returns how many cycles were removed. */
function mergeSameDateCycles(data) {
  const keep = new Map(); let removed = 0;
  for (const c of data.cycles.slice().sort((a, b) => a.date.localeCompare(b.date))) {
    const k = keep.get(c.date);
    if (!k) { keep.set(c.date, c); continue; }
    for (const it of c.items) if (!k.items.some(i => i.payeeId === it.payeeId)) k.items.push(it);
    removed++;
  }
  if (removed) {
    const ids = new Set([...keep.values()].map(c => c.id));
    data.cycles = data.cycles.filter(c => ids.has(c.id));
  }
  return removed;
}
function duplicateDateCount(data) { return data.cycles.length - new Set(data.cycles.map(c => c.date)).size; }

// ---------------------------------------------------------------- data helpers
function emptyData() { return { version: 1, payees: [], cycles: [], updatedAt: new Date().toISOString() }; }
function cycleTotals(c) {
  const t = { total: 0, paid: 0, pending: 0, pendingN: 0, bank: 0, card: 0, doneN: 0, count: 0 };
  for (const it of c.items) {
    if (it.status === 'na' || it.status === 'skipped') continue;
    const a = Number(it.amount) || 0;
    t.total += a; t.count++;
    if (it.status === 'done') { t.paid += a; t.doneN++; if (!it.paidVia || it.paidVia === 'bank') t.bank += a; else t.card += a; }
    else { t.pending += a; t.pendingN++; }
  }
  return t;
}

// ---------------------------------------------------------------- state
const S = {
  cfg: null, key: null, token: null, sha: null, data: null,
  view: 'cycle', cycleId: null, panel: null, chartPayee: '',
  dirty: false, saving: false, saveAgain: false, saveTimer: null, retryTimer: null,
  conflict: false, lockTimer: null, importPreview: null, repoPrivate: null,
  syncState: 'ok', syncText: '',
};
function loadCfg() { try { return JSON.parse(localStorage.getItem(LS_CONFIG)); } catch (e) { return null; } }
function saveCfg() { localStorage.setItem(LS_CONFIG, JSON.stringify(S.cfg)); }
function cacheGet() { try { return JSON.parse(localStorage.getItem(LS_CACHE)); } catch (e) { return null; } }
function cacheSet(sha, text, unsynced) { try { localStorage.setItem(LS_CACHE, JSON.stringify({ sha, text, unsynced: !!unsynced, at: new Date().toISOString() })); } catch (e) { /* quota */ } }

const payee = id => S.data.payees.find(p => p.id === id);
const sortedPayees = () => S.data.payees.slice().sort((a, b) => a.order - b.order);
const sortedCycles = () => S.data.cycles.slice().sort((a, b) => b.date.localeCompare(a.date));
const cycleById = id => S.data.cycles.find(c => c.id === id);
function currentCycle() { return cycleById(S.cycleId) || sortedCycles()[0] || null; }

// ---------------------------------------------------------------- sync
function setSync(state, text) {
  S.syncState = state; S.syncText = text;
  const el = document.getElementById('sync');
  if (el) { el.className = 'sync ' + state; el.textContent = text; }
}
function markDirty() {
  S.data.updatedAt = new Date().toISOString();
  S.dirty = true;
  setSync('pending', 'Unsaved changes');
  clearTimeout(S.saveTimer);
  S.saveTimer = setTimeout(save, 1200);
}
async function save() {
  if (!S.key || S.conflict) return;
  if (S.saving) { S.saveAgain = true; return; }
  if (!S.dirty) return;
  clearTimeout(S.saveTimer); clearTimeout(S.retryTimer);
  S.saving = true; S.dirty = false;
  setSync('saving', 'Saving…');
  let text;
  try {
    text = await sealWith(S.key, S.cfg.salt, S.cfg.iter, S.data);
    cacheSet(S.sha, text, true);
    S.sha = await ghPut(S.cfg, S.token, text, S.sha);
    cacheSet(S.sha, text, false);
    setSync('ok', 'Saved ' + timeNow());
  } catch (e) {
    S.dirty = true;
    if (e.conflict) { S.conflict = true; setSync('error', 'Conflict'); render(); }
    else { setSync('error', 'Not saved — ' + e.message + '. Retrying…'); S.retryTimer = setTimeout(save, 20000); }
  } finally {
    S.saving = false;
    if (S.saveAgain) { S.saveAgain = false; save(); }
  }
}
async function pullRemote() {
  const remote = await ghGet(S.cfg, S.token);
  if (!remote) throw new Error('No vault file found on GitHub');
  const head = readVaultHeader(remote.text);
  if (head.kdf.salt !== S.cfg.salt) throw new Error('The GitHub vault uses a different master password. Lock, then unlock with the new password.');
  S.data = await openVault(S.key, remote.text);
  S.sha = remote.sha; S.dirty = false; S.conflict = false;
  cacheSet(remote.sha, remote.text, false);
  setSync('ok', 'Loaded ' + timeNow());
}

// ---------------------------------------------------------------- auth flows
async function doSetup(f) {
  const cfg = { owner: f.owner.trim(), repo: f.repo.trim(), branch: f.branch.trim() || 'main', path: f.path.trim() || 'vault.json', autoLockMin: 10 };
  const token = f.token.trim();
  const pw = f.pw;
  const repo = await ghRepo(cfg, token);
  const remote = await ghGet(cfg, token);
  let key, data, sha, text;
  if (remote) {
    const head = readVaultHeader(remote.text);
    cfg.salt = head.kdf.salt; cfg.iter = head.kdf.iter;
    key = await deriveKey(pw, unb64(cfg.salt), cfg.iter);
    try { data = await openVault(key, remote.text); } catch (e) { throw new Error('Wrong master password for the existing vault'); }
    sha = remote.sha; text = remote.text;
  } else {
    if (pw.length < MIN_PW) throw new Error(`No vault found, so a new one will be created. Use a master password of at least ${MIN_PW} characters.`);
    if (pw !== f.pw2) throw new Error('No vault found, so a new one will be created. The two passwords do not match.');
    cfg.salt = b64(crypto.getRandomValues(new Uint8Array(16))); cfg.iter = DEFAULT_ITER;
    key = await deriveKey(pw, unb64(cfg.salt), cfg.iter);
    data = emptyData();
    text = await sealWith(key, cfg.salt, cfg.iter, data);
    sha = await ghPut(cfg, token, text, null);
  }
  cfg.tokenEnc = await encryptJSON(key, { token }, AAD_TOKEN);
  cfg.repoPrivate = !!repo.private;
  S.cfg = cfg; saveCfg(); cacheSet(sha, text, false);
  Object.assign(S, { key, token, data, sha, dirty: false, conflict: false, repoPrivate: cfg.repoPrivate });
  setSync('ok', remote ? 'Loaded ' + timeNow() : 'New vault created');
}
async function doUnlock(pw) {
  const cfg = S.cfg;
  let key = await deriveKey(pw, unb64(cfg.salt), cfg.iter);
  let token;
  try { token = (await decryptJSON(key, cfg.tokenEnc, AAD_TOKEN)).token; }
  catch (e) { throw new Error('Wrong master password. (If you changed it on another device, use “Forget this device” and reconnect.)'); }
  let remote = null, offline = false;
  try { remote = await ghGet(cfg, token); } catch (e) { offline = e; }
  const cache = cacheGet();
  let data, sha, dirty = false, conflict = false, msg;
  if (remote) {
    const head = readVaultHeader(remote.text);
    if (head.kdf.salt !== cfg.salt) {
      key = await deriveKey(pw, unb64(head.kdf.salt), head.kdf.iter);
      try { await openVault(key, remote.text); } catch (e) { throw new Error('The vault on GitHub uses a different master password. Use “Forget this device” and reconnect with the new password.'); }
      cfg.salt = head.kdf.salt; cfg.iter = head.kdf.iter;
      cfg.tokenEnc = await encryptJSON(key, { token }, AAD_TOKEN); saveCfg();
    }
    if (cache && cache.unsynced) {
      data = await openVault(key, cache.text); sha = remote.sha; dirty = true;
      if (cache.sha !== remote.sha) conflict = true;
      msg = conflict ? 'Conflict' : 'Uploading offline changes…';
    } else {
      data = await openVault(key, remote.text); sha = remote.sha;
      cacheSet(sha, remote.text, false); msg = 'Loaded ' + timeNow();
    }
  } else if (cache) {
    data = await openVault(key, cache.text); sha = cache.sha;
    if (offline) msg = 'Offline — cached copy'; else { dirty = true; sha = null; msg = 'Vault missing on GitHub — re-uploading'; }
  } else if (!offline) {
    data = emptyData(); dirty = true; sha = null; msg = 'Creating vault';
  } else {
    throw new Error('Cannot reach GitHub (' + offline.message + ') and there is no cached copy on this device.');
  }
  Object.assign(S, { key, token, data, sha, dirty, conflict, repoPrivate: cfg.repoPrivate });
  setSync(conflict || offline ? 'error' : dirty ? 'pending' : 'ok', msg);
  if (dirty && !conflict && !offline) setTimeout(save, 300);
}
async function lock() {
  if (S.dirty && !S.conflict) { try { await save(); } catch (e) { /* keep cache */ } }
  clearTimeout(S.saveTimer); clearTimeout(S.retryTimer); clearTimeout(S.lockTimer);
  Object.assign(S, { key: null, token: null, data: null, sha: null, panel: null, importPreview: null, conflict: false, dirty: false });
  render();
}
function resetLockTimer() {
  if (!S.key) return;
  clearTimeout(S.lockTimer);
  const min = Number(S.cfg.autoLockMin) || 0;
  if (min > 0) S.lockTimer = setTimeout(lock, min * 60000);
}

// ---------------------------------------------------------------- views
function viewSetup() {
  return `<div class="auth"><div class="card">
  <div class="brandmark">B</div>
  <h1>Bills</h1>
  <p class="muted">Monthly payments, encrypted in your browser and stored in your own GitHub repository.</p>
  <form data-form="setup" autocomplete="off">
    <div class="grid2">
      <label>GitHub owner<input name="owner" required placeholder="username"></label>
      <label>Data repository<input name="repo" required value="bills-data"></label>
      <label>Branch<input name="branch" required value="main"></label>
      <label>File path<input name="path" required value="vault.json"></label>
    </div>
    <label>Fine-grained access token<input name="token" type="password" required placeholder="github_pat_…" autocomplete="off"></label>
    <label>Master password<input name="pw" type="password" required autocomplete="new-password"></label>
    <label>Confirm master password <span class="muted">(only for a new vault)</span><input name="pw2" type="password" autocomplete="new-password"></label>
    <p class="msg" hidden></p>
    <button class="primary wide">Connect</button>
    <p class="fine">The master password never leaves this device and cannot be recovered. Lose it and the data is gone for good.</p>
  </form></div></div>`;
}
function viewUnlock() {
  const c = S.cfg;
  return `<div class="auth"><div class="card">
  <div class="brandmark">B</div>
  <h1>Bills</h1>
  <p class="muted">${esc(c.owner)}/${esc(c.repo)} · ${esc(c.path)}</p>
  <form data-form="unlock">
    <label>Master password<input name="pw" type="password" required autocomplete="current-password" autofocus></label>
    <p class="msg" hidden></p>
    <button class="primary wide">Unlock</button>
  </form>
  <button class="link" data-act="forget">Forget this device</button>
  </div></div>`;
}
function viewShell() {
  const tabs = [['cycle', 'This cycle'], ['history', 'History'], ['payees', 'Payees'], ['settings', 'Settings']];
  return `<header class="top">
    <div class="brand"><span class="brandmark sm">B</span>Bills</div>
    <nav>${tabs.map(([v, l]) => `<button class="tab ${S.view === v ? 'on' : ''}" data-act="tab" data-v="${v}">${l}</button>`).join('')}</nav>
    <div class="right"><span id="sync" class="sync ${S.syncState}">${esc(S.syncText)}</span><button class="ghost" data-act="lock">Lock</button></div>
  </header>
  ${S.conflict ? `<div class="banner warn"><span>The vault on GitHub changed on another device since this copy was loaded.</span>
    <span><button data-act="resolveRemote">Load GitHub version</button> <button class="danger" data-act="resolveMine">Overwrite with this copy</button></span></div>` : ''}
  ${duplicateDateCount(S.data) ? `<div class="banner warn"><span>${duplicateDateCount(S.data)} extra cycle(s) share a payment date with another cycle.</span><span><button data-act="mergeDup">Merge cycles with the same date</button></span></div>` : ''}
  ${S.repoPrivate === false ? `<div class="banner">Your data repo is public. The vault is still encrypted, but making the repo private is recommended.</div>` : ''}
  <main>${({ cycle: viewCycle, history: viewHistory, payees: viewPayees, settings: viewSettings })[S.view]()}</main>`;
}
function summaryHtml(c) {
  const t = cycleTotals(c);
  return `<div class="stat"><div class="k">Total this cycle</div><div class="v">${money(t.total)}</div><div class="s">${t.count} items</div></div>
  <div class="stat ok"><div class="k">Paid</div><div class="v">${money(t.paid)}</div><div class="s">${t.doneN} of ${t.count} done</div></div>
  <div class="stat ${t.pendingN ? 'warn' : ''}"><div class="k">Still to pay</div><div class="v">${money(t.pending)}</div><div class="s">${t.pendingN} pending</div></div>
  <div class="stat"><div class="k">Paid from bank</div><div class="v">${money(t.bank)}</div><div class="s">${money(t.card)} put on cards</div></div>`;
}
function viaOptions(sel) {
  const opts = [['bank', 'Bank'], ['card', 'Card (any)']].concat(sortedPayees().filter(p => p.type === 'card').map(p => [p.id, p.name]));
  return opts.map(([v, l]) => `<option value="${esc(v)}" ${v === sel ? 'selected' : ''}>${esc(l)}</option>`).join('');
}
function itemRow(c, it) {
  const p = payee(it.payeeId);
  return `<div class="item st-${it.status}" data-cycle="${c.id}" data-item="${it.id}">
    <input class="chk" type="checkbox" data-f="done" ${it.status === 'done' ? 'checked' : ''} aria-label="Mark done">
    <div class="name">${esc(p ? p.name : 'Unknown')}<span class="tag">${esc(p ? TYPES[p.type] : '')}</span></div>
    <input class="amt" type="number" step="0.01" min="0" inputmode="decimal" data-f="amount" value="${it.amount ? Number(it.amount).toFixed(2) : ''}" placeholder="0.00" aria-label="Amount">
    <select class="st" data-f="status" aria-label="Status">${Object.entries(STATUS).map(([v, l]) => `<option value="${v}" ${v === it.status ? 'selected' : ''}>${l}</option>`).join('')}</select>
    <select class="via" data-f="paidVia" aria-label="Paid with">${viaOptions(it.paidVia || 'bank')}</select>
    <input class="note" data-f="note" value="${esc(it.note)}" placeholder="Note" aria-label="Note">
    <button class="icon del" data-act="delItem" title="Remove from this cycle" aria-label="Remove">×</button>
  </div>`;
}
function newCyclePanel() {
  const d = todayISO();
  return `<form class="panel" data-form="newCycle">
    <h3>Start a new cycle</h3>
    <p class="muted">Creates a row for every active payee, with fixed amounts filled in.</p>
    <div class="row">
      <label>Payment date<input type="date" name="date" value="${d}" required></label>
      <label>Covers month<input type="month" name="forMonth" value="${guessForMonth(d)}" required></label>
    </div>
    <div class="row"><button class="primary">Create cycle</button><button type="button" class="ghost" data-act="closePanel">Cancel</button></div>
  </form>`;
}
function viewCycle() {
  const c = currentCycle();
  const startBtn = `<button class="primary" data-act="panel" data-p="newCycle">+ Start new cycle</button>`;
  if (!c) {
    return `${S.panel === 'newCycle' ? newCyclePanel() : ''}
    <div class="empty"><h2>No cycles yet</h2><p>Start your first payday cycle, or import your Google Sheet history from Settings.</p>
    <div class="row center">${startBtn}<button class="ghost" data-act="tab" data-v="settings">Import from sheet</button></div></div>`;
  }
  const cycles = sortedCycles();
  const used = new Set(c.items.map(i => i.payeeId));
  const options = sortedPayees().filter(p => !used.has(p.id)).map(p => `<option value="${esc(p.name)}">`).join('');
  return `${S.panel === 'newCycle' ? newCyclePanel() : ''}
  <div class="cyclehead">
    <div>
      <select id="cycleSelect" aria-label="Choose cycle">${cycles.map(x => `<option value="${x.id}" ${x.id === c.id ? 'selected' : ''}>${fmtDate(x.date)} — ${fmtMonth(x.forMonth)}</option>`).join('')}</select>
      <div class="meta">
        <label>Paid on <input type="date" data-cf="date" value="${c.date}"></label>
        <label>Covers <input type="month" data-cf="forMonth" value="${c.forMonth}"></label>
      </div>
    </div>
    <div class="row">${startBtn}<button class="ghost danger" data-act="delCycle">Delete cycle</button></div>
  </div>
  <section id="summary" class="stats">${summaryHtml(c)}</section>
  <section class="list">
    <div class="item head"><span></span><span>Payee</span><span>Amount</span><span class="st">Status</span><span class="via">Paid with</span><span class="note">Note</span><span></span></div>
    ${c.items.map(it => itemRow(c, it)).join('') || '<p class="muted pad">No items in this cycle.</p>'}
  </section>
  <form class="addrow" data-form="addItem">
    <input name="name" list="payeeList" placeholder="Add a payee to this cycle (existing or new one-off)…" required>
    <datalist id="payeeList">${options}</datalist>
    <input name="amount" type="number" step="0.01" min="0" placeholder="Amount">
    <button class="ghost">Add</button>
  </form>`;
}
function chartSvg(points) {
  if (!points.length) return '<p class="muted">Nothing to chart yet.</p>';
  const W = 760, H = 240, L = 8, R = 8, T = 22, B = 34;
  const max = Math.max(1, ...points.map(p => p.value));
  const slot = (W - L - R) / points.length;
  const bw = Math.min(46, slot * 0.66);
  const bars = points.map((p, i) => {
    const h = (p.value / max) * (H - T - B);
    const x = L + i * slot + (slot - bw) / 2;
    const y = H - B - h;
    return `<g><title>${esc(p.title)}: ${money(p.value)}</title>
      <rect class="bar" x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${bw.toFixed(1)}" height="${Math.max(0, h).toFixed(1)}" rx="3"></rect>
      <text class="val" x="${(x + bw / 2).toFixed(1)}" y="${(y - 6).toFixed(1)}" text-anchor="middle">${short(p.value)}</text>
      <text class="lbl" x="${(x + bw / 2).toFixed(1)}" y="${H - B + 18}" text-anchor="middle">${esc(p.label)}</text></g>`;
  }).join('');
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Totals per cycle"><line class="axis" x1="${L}" x2="${W - R}" y1="${H - B}" y2="${H - B}"></line>${bars}</svg>`;
}
function viewHistory() {
  const cycles = sortedCycles();
  const asc = cycles.slice(0, 12).reverse();
  const pid = S.chartPayee;
  const points = asc.map(c => {
    const value = pid
      ? c.items.filter(i => i.payeeId === pid && i.status !== 'na' && i.status !== 'skipped').reduce((s, i) => s + (Number(i.amount) || 0), 0)
      : cycleTotals(c).total;
    return { label: fmtMonth(c.forMonth).replace(' 20', " '"), title: fmtDate(c.date), value };
  });
  const all = cycles.reduce((s, c) => s + cycleTotals(c).total, 0);
  const avg = cycles.length ? all / cycles.length : 0;
  return `<section class="card">
    <div class="cardhead"><h2>${pid ? esc(payee(pid)?.name || '') : 'Total per cycle'}</h2>
      <select id="chartPayee" aria-label="Chart for"><option value="">All payees</option>${sortedPayees().map(p => `<option value="${p.id}" ${p.id === pid ? 'selected' : ''}>${esc(p.name)}</option>`).join('')}</select></div>
    ${chartSvg(points)}
    <p class="muted">Last ${points.length} cycles. Average cycle: ${money(avg)}.</p>
  </section>
  <section class="card">
    <h2>All cycles</h2>
    <table class="tbl"><thead><tr><th>Paid on</th><th>Covers</th><th class="r">Total</th><th class="r">Paid</th><th class="r">Pending</th><th></th></tr></thead>
    <tbody>${cycles.map(c => { const t = cycleTotals(c); return `<tr><td>${fmtDate(c.date)}</td><td>${fmtMonth(c.forMonth)}</td><td class="r">${money(t.total)}</td><td class="r">${money(t.paid)}</td><td class="r ${t.pendingN ? 'warnt' : ''}">${t.pendingN ? `${t.pendingN} · ${money(t.pending)}` : '—'}</td><td><button class="ghost sm" data-act="openCycle" data-id="${c.id}">Open</button></td></tr>`; }).join('') || '<tr><td colspan="6" class="muted">No cycles yet.</td></tr>'}</tbody></table>
  </section>`;
}
function viewPayees() {
  const ps = sortedPayees();
  return `<section class="card">
    <div class="cardhead"><h2>Payees</h2><span class="muted">Active payees are added automatically to each new cycle.</span></div>
    <div class="prow head"><span>Name</span><span>Type</span><span>Fixed amount</span><span>Active</span><span></span></div>
    ${ps.map((p, i) => `<div class="prow" data-pid="${p.id}">
      <input data-pf="name" value="${esc(p.name)}" aria-label="Name">
      <select data-pf="type" aria-label="Type">${Object.entries(TYPES).map(([v, l]) => `<option value="${v}" ${v === p.type ? 'selected' : ''}>${l}</option>`).join('')}</select>
      <input data-pf="defaultAmount" type="number" step="0.01" min="0" value="${p.defaultAmount ?? ''}" placeholder="varies" aria-label="Fixed amount">
      <label class="switch"><input type="checkbox" data-pf="active" ${p.active ? 'checked' : ''}><span>${p.active ? 'Active' : 'Off'}</span></label>
      <span class="btns"><button class="icon" data-act="pUp" ${i === 0 ? 'disabled' : ''} aria-label="Move up">↑</button><button class="icon" data-act="pDown" ${i === ps.length - 1 ? 'disabled' : ''} aria-label="Move down">↓</button><button class="icon del" data-act="pDel" aria-label="Delete">×</button></span>
    </div>`).join('') || '<p class="muted">No payees yet.</p>'}
    <form class="addrow" data-form="addPayee">
      <input name="name" placeholder="New payee name" required>
      <select name="type">${Object.entries(TYPES).map(([v, l]) => `<option value="${v}">${l}</option>`).join('')}</select>
      <input name="amount" type="number" step="0.01" min="0" placeholder="Fixed amount (optional)">
      <button class="ghost">Add payee</button>
    </form>
  </section>`;
}
function importPreviewHtml() {
  const pv = S.importPreview;
  const names = [...new Set(pv.flatMap(c => c.rows.map(r => r.name)))];
  const rows = pv.reduce((s, c) => s + c.rows.length, 0);
  const exist = new Set(S.data.cycles.map(c => c.date));
  const dup = pv.filter(c => exist.has(c.date)).length;
  return `<div class="preview">
    <p><strong>${pv.length} cycles</strong>, ${rows} rows found${dup ? `, ${dup} already imported (will be skipped)` : ''}: ${pv.map(c => fmtDate(c.date)).join(', ')}.</p>
    <p class="muted">Rename to merge payees, e.g. change “FAB CC” to “FAB Share CC”. Leave a name empty to drop those rows.</p>
    <div class="renames">${names.map(n => `<label><span>${esc(n)}</span><input data-rename="${esc(n)}" value="${esc(n)}"></label>`).join('')}</div>
    <div class="row"><button class="primary" data-act="importRun">Import</button><button class="ghost" data-act="importCancel">Cancel</button></div>
  </div>`;
}
function viewSettings() {
  const c = S.cfg;
  return `<section class="card">
    <h2>Import from Google Sheet</h2>
    <p class="muted">In the sheet, select columns A to E (date, payee, amount, note, status) for all rows, copy, and paste below.</p>
    ${S.importPreview ? importPreviewHtml() : `<textarea id="importText" rows="7" placeholder="2-Jan-2026&#9;ADCB CC&#9;AED 2,581.09&#9;&#9;DONE"></textarea>
    <div class="row"><button class="ghost" data-act="importPreview">Preview import</button></div>`}
  </section>
  <section class="card">
    <h2>Storage</h2>
    <dl class="kv"><dt>Repository</dt><dd>${esc(c.owner)}/${esc(c.repo)} (${c.repoPrivate ? 'private' : 'public'})</dd><dt>Branch / file</dt><dd>${esc(c.branch)} / ${esc(c.path)}</dd>
    <dt>Encryption</dt><dd>AES-256-GCM, key from PBKDF2-SHA256 × ${Number(c.iter).toLocaleString()}</dd></dl>
    <div class="row"><button class="ghost" data-act="pull">Reload from GitHub</button><button class="ghost" data-act="downloadVault">Download encrypted backup</button><button class="ghost" data-act="exportCsv">Export CSV (unencrypted)</button></div>
  </section>
  <section class="card">
    <h2>Security</h2>
    <label class="inline">Auto-lock after <select id="autoLock">${[0, 5, 10, 15, 30, 60].map(m => `<option value="${m}" ${Number(c.autoLockMin) === m ? 'selected' : ''}>${m ? m + ' minutes' : 'Never'}</option>`).join('')}</select> of inactivity</label>
    <form data-form="changePw" class="pwform" autocomplete="off">
      <h3>Change master password</h3>
      <div class="row">
        <label>Current<input name="cur" type="password" required autocomplete="current-password"></label>
        <label>New<input name="pw" type="password" required autocomplete="new-password"></label>
        <label>Confirm new<input name="pw2" type="password" required autocomplete="new-password"></label>
      </div>
      <p class="msg" hidden></p>
      <button class="ghost">Change password</button>
      <p class="fine">Other devices will need “Forget this device” and reconnect with the new password.</p>
    </form>
    <div class="row"><button class="ghost danger" data-act="forget">Forget this device</button></div>
  </section>`;
}
function render() {
  const app = document.getElementById('app');
  if (!S.key) { app.innerHTML = S.cfg ? viewUnlock() : viewSetup(); const f = app.querySelector('input[type=password]'); if (f && S.cfg) f.focus(); return; }
  app.innerHTML = viewShell();
}

// ---------------------------------------------------------------- forms
function formMsg(form, text, ok) { const m = form.querySelector('.msg'); if (!m) return; m.hidden = !text; m.textContent = text || ''; m.className = 'msg ' + (ok ? 'good' : 'bad'); }
async function withBusy(form, label, fn) {
  const btn = form.querySelector('button:not([type=button])');
  const old = btn.textContent; btn.disabled = true; btn.textContent = label;
  formMsg(form, '');
  try { await fn(); } catch (e) { formMsg(form, e.message || String(e)); btn.disabled = false; btn.textContent = old; }
}
async function onSubmit(e) {
  const form = e.target.closest('form[data-form]');
  if (!form) return;
  e.preventDefault();
  const f = Object.fromEntries(new FormData(form).entries());
  switch (form.dataset.form) {
    case 'setup': await withBusy(form, 'Connecting…', async () => { await doSetup(f); S.view = 'cycle'; render(); resetLockTimer(); }); break;
    case 'unlock': await withBusy(form, 'Unlocking…', async () => { await doUnlock(f.pw); S.view = 'cycle'; render(); resetLockTimer(); }); break;
    case 'newCycle': {
      if (S.data.cycles.some(c => c.date === f.date) && !confirm('A cycle with this date already exists. Create another one?')) return;
      const c = { id: uid(), date: f.date, forMonth: f.forMonth, items: sortedPayees().filter(p => p.active).map(p => ({ id: uid(), payeeId: p.id, amount: p.defaultAmount || 0, status: 'pending', paidVia: 'bank', note: '' })) };
      S.data.cycles.push(c); S.cycleId = c.id; S.panel = null; markDirty(); render(); break;
    }
    case 'addItem': {
      const c = currentCycle(); const name = f.name.trim(); if (!c || !name) return;
      let p = S.data.payees.find(x => x.name.toLowerCase() === name.toLowerCase());
      if (!p) { p = { id: uid(), name, type: guessType(name), defaultAmount: null, active: false, order: S.data.payees.length }; S.data.payees.push(p); }
      if (c.items.some(i => i.payeeId === p.id)) { alert(`${p.name} is already in this cycle.`); return; }
      c.items.push({ id: uid(), payeeId: p.id, amount: round2(f.amount), status: 'pending', paidVia: 'bank', note: '' });
      markDirty(); render(); break;
    }
    case 'addPayee': {
      const name = f.name.trim(); if (!name) return;
      if (S.data.payees.some(x => x.name.toLowerCase() === name.toLowerCase())) { alert('A payee with that name already exists.'); return; }
      S.data.payees.push({ id: uid(), name, type: f.type, defaultAmount: f.amount ? round2(f.amount) : null, active: true, order: S.data.payees.length });
      markDirty(); render(); break;
    }
    case 'changePw': await withBusy(form, 'Re-encrypting…', async () => {
      const chk = await deriveKey(f.cur, unb64(S.cfg.salt), S.cfg.iter);
      try { await decryptJSON(chk, S.cfg.tokenEnc, AAD_TOKEN); } catch (err) { throw new Error('Current password is wrong'); }
      if (f.pw.length < MIN_PW) throw new Error(`Use at least ${MIN_PW} characters`);
      if (f.pw !== f.pw2) throw new Error('New passwords do not match');
      if (S.dirty) await save();
      if (S.conflict) throw new Error('Resolve the sync conflict first');
      const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
      const key = await deriveKey(f.pw, unb64(salt), DEFAULT_ITER);
      const text = await sealWith(key, salt, DEFAULT_ITER, S.data);
      const sha = await ghPut(S.cfg, S.token, text, S.sha);
      S.key = key; S.sha = sha;
      S.cfg.salt = salt; S.cfg.iter = DEFAULT_ITER; S.cfg.tokenEnc = await encryptJSON(key, { token: S.token }, AAD_TOKEN);
      saveCfg(); cacheSet(sha, text, false);
      form.reset(); formMsg(form, 'Master password changed and vault re-encrypted.', true);
      const btn = form.querySelector('button'); btn.disabled = false; btn.textContent = 'Change password';
      setSync('ok', 'Saved ' + timeNow());
    }); break;
  }
}

// ---------------------------------------------------------------- clicks
function download(name, text, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name; document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}
function csvCell(v) { const s = String(v ?? ''); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; }
async function onClick(e) {
  const b = e.target.closest('[data-act]');
  if (!b) return;
  const act = b.dataset.act;
  const prow = b.closest('[data-pid]');
  switch (act) {
    case 'tab': S.view = b.dataset.v; S.panel = null; render(); window.scrollTo(0, 0); break;
    case 'lock': await lock(); break;
    case 'forget':
      if (!confirm('Remove the saved connection and cached copy from this browser? Data on GitHub is not touched.')) return;
      if (S.key && S.dirty) await save();
      localStorage.removeItem(LS_CONFIG); localStorage.removeItem(LS_CACHE); S.cfg = null; await lock(); break;
    case 'panel': S.panel = b.dataset.p; render(); break;
    case 'closePanel': S.panel = null; render(); break;
    case 'openCycle': S.cycleId = b.dataset.id; S.view = 'cycle'; render(); window.scrollTo(0, 0); break;
    case 'delCycle': {
      const c = currentCycle(); if (!c || !confirm(`Delete the cycle paid on ${fmtDate(c.date)}? This cannot be undone.`)) return;
      S.data.cycles = S.data.cycles.filter(x => x.id !== c.id); S.cycleId = null; markDirty(); render(); break;
    }
    case 'delItem': {
      const row = b.closest('.item'); const c = cycleById(row.dataset.cycle);
      c.items = c.items.filter(i => i.id !== row.dataset.item); markDirty(); render(); break;
    }
    case 'pUp': case 'pDown': {
      const ps = sortedPayees(); const i = ps.findIndex(p => p.id === prow.dataset.pid); const j = act === 'pUp' ? i - 1 : i + 1;
      if (j < 0 || j >= ps.length) return;
      [ps[i], ps[j]] = [ps[j], ps[i]]; ps.forEach((p, k) => { p.order = k; }); markDirty(); render(); break;
    }
    case 'pDel': {
      const p = payee(prow.dataset.pid);
      const usedIn = S.data.cycles.filter(c => c.items.some(i => i.payeeId === p.id)).length;
      if (usedIn) { if (!confirm(`${p.name} appears in ${usedIn} cycle(s). Deleting removes those rows too. Turn it off instead to keep history.\n\nDelete anyway?`)) return; S.data.cycles.forEach(c => { c.items = c.items.filter(i => i.payeeId !== p.id); }); }
      else if (!confirm(`Delete ${p.name}?`)) return;
      S.data.payees = S.data.payees.filter(x => x.id !== p.id); markDirty(); render(); break;
    }
    case 'importPreview': {
      const text = document.getElementById('importText').value;
      const parsed = parseSheet(text);
      if (!parsed.length) { alert('No cycles found. Make sure the first column has dates like 2-Jan-2026 and columns are tab separated (copy straight from the sheet).'); return; }
      S.importPreview = parsed; render(); break;
    }
    case 'mergeDup': {
      const n = mergeSameDateCycles(S.data); S.cycleId = null;
      if (n) markDirty(); render(); alert(`Merged ${n} duplicate cycle(s).`); break;
    }
    case 'importCancel': S.importPreview = null; render(); break;
    case 'importRun': {
      const renames = {};
      document.querySelectorAll('[data-rename]').forEach(i => { renames[i.dataset.rename] = i.value.trim(); });
      const r = applyImport(S.data, S.importPreview, renames);
      S.importPreview = null; S.cycleId = null; markDirty(); S.view = 'history'; render();
      alert(`Imported ${r.added} cycles${r.skipped ? `, skipped ${r.skipped} already present` : ''}. ${r.newPayees} new payees. Review the Payees tab for types, fixed amounts and active flags.`);
      break;
    }
    case 'pull':
      if (S.dirty && !confirm('You have unsaved changes. Discard them and reload from GitHub?')) return;
      try { await pullRemote(); render(); } catch (err) { alert(err.message); } break;
    case 'resolveRemote':
      if (!confirm('Discard the changes on this device and load the GitHub version?')) return;
      try { await pullRemote(); render(); } catch (err) { alert(err.message); } break;
    case 'resolveMine':
      if (!confirm('Replace the GitHub version with this device’s copy? Changes made on the other device will be lost.')) return;
      try { const remote = await ghGet(S.cfg, S.token); S.sha = remote ? remote.sha : null; S.conflict = false; S.dirty = true; render(); await save(); } catch (err) { alert(err.message); } break;
    case 'downloadVault': {
      const text = await sealWith(S.key, S.cfg.salt, S.cfg.iter, S.data);
      download(`bills-vault-${todayISO()}.json`, text, 'application/json'); break;
    }
    case 'exportCsv': {
      if (!confirm('The CSV file is NOT encrypted. Anyone who gets the file can read it. Continue?')) return;
      const lines = [['Paid on', 'Covers month', 'Payee', 'Type', 'Amount (AED)', 'Status', 'Paid with', 'Note'].join(',')];
      for (const c of sortedCycles().reverse()) for (const it of c.items) {
        const p = payee(it.payeeId) || {}; const via = it.paidVia === 'bank' || !it.paidVia ? 'Bank' : it.paidVia === 'card' ? 'Card' : (payee(it.paidVia)?.name || 'Card');
        lines.push([c.date, c.forMonth, p.name, TYPES[p.type], it.amount, STATUS[it.status], via, it.note].map(csvCell).join(','));
      }
      download(`bills-${todayISO()}.csv`, lines.join('\n'), 'text/csv'); break;
    }
  }
}

// ---------------------------------------------------------------- inline edits
function onChange(e) {
  const el = e.target;
  if (!S.key) return;
  if (el.name === 'date' && el.form && el.form.dataset.form === 'newCycle') { if (el.value) el.form.elements.forMonth.value = guessForMonth(el.value); return; }
  if (el.id === 'cycleSelect') { S.cycleId = el.value; render(); return; }
  if (el.id === 'chartPayee') { S.chartPayee = el.value; render(); return; }
  if (el.id === 'autoLock') { S.cfg.autoLockMin = Number(el.value); saveCfg(); resetLockTimer(); return; }
  if (el.dataset.cf) {
    const c = currentCycle(); if (!c || !el.value) return;
    c[el.dataset.cf] = el.value; markDirty(); render(); return;
  }
  if (el.dataset.f) {
    const row = el.closest('.item'); const c = cycleById(row.dataset.cycle); const it = c.items.find(i => i.id === row.dataset.item);
    const f = el.dataset.f;
    if (f === 'done') it.status = el.checked ? 'done' : 'pending';
    else if (f === 'amount') { it.amount = round2(el.value); el.value = it.amount ? it.amount.toFixed(2) : ''; if (it.amount > 0 && it.status === 'na') it.status = 'pending'; }
    else if (f === 'status') it.status = el.value;
    else if (f === 'paidVia') it.paidVia = el.value;
    else if (f === 'note') it.note = el.value.trim();
    row.className = 'item st-' + it.status;
    row.querySelector('[data-f=done]').checked = it.status === 'done';
    row.querySelector('[data-f=status]').value = it.status;
    document.getElementById('summary').innerHTML = summaryHtml(c);
    markDirty(); return;
  }
  if (el.dataset.pf) {
    const p = payee(el.closest('[data-pid]').dataset.pid); const f = el.dataset.pf;
    if (f === 'name') { const v = el.value.trim(); if (!v) { el.value = p.name; return; } p.name = v; }
    else if (f === 'type') p.type = el.value;
    else if (f === 'defaultAmount') p.defaultAmount = el.value === '' ? null : round2(el.value);
    else if (f === 'active') { p.active = el.checked; el.nextElementSibling.textContent = p.active ? 'Active' : 'Off'; }
    markDirty();
  }
}

// ---------------------------------------------------------------- boot
function init() {
  if (!window.crypto || !crypto.subtle) {
    document.getElementById('app').innerHTML = '<div class="auth"><div class="card"><h1>Bills</h1><p>This page must be opened over HTTPS in a modern browser.</p></div></div>';
    return;
  }
  S.cfg = loadCfg();
  document.addEventListener('submit', onSubmit);
  document.addEventListener('click', onClick);
  document.addEventListener('change', onChange);
  ['pointerdown', 'keydown'].forEach(ev => document.addEventListener(ev, resetLockTimer, { passive: true }));
  document.addEventListener('visibilitychange', () => { if (document.hidden && S.dirty) save(); });
  window.addEventListener('beforeunload', e => { if (S.dirty || S.saving) { save(); e.preventDefault(); e.returnValue = ''; } });
  render();
}
if (typeof document !== 'undefined') init();
if (typeof module !== 'undefined') module.exports = { deriveKey, encryptJSON, decryptJSON, sealWith, openVault, parseSheet, applyImport, mergeSameDateCycles, emptyData, cycleTotals, guessForMonth, AAD_TOKEN };
