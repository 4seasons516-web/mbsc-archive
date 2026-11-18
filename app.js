import { gunzipSync, Zip, ZipPassThrough } from './vendor/fflate.mjs';

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64e = (u) => btoa(String.fromCharCode(...u));

let KEY = null;          // CryptoKey for content
let IDX = null;          // decrypted index
let NORM = null;         // [{n: string, m: Uint32Array}] per doc per page (lazy)
const state = { type: 'All', q: '', terms: [], sort: 'newest', results: null, flat: [], openId: null, page: 1, hitIdx: -1, expanded: new Set(), selected: new Set(), viewIds: [], busy: false,
  view: 'grid', yFrom: null, yTo: null, fuzzy: true, df: null, reading: false, readSize: 19, fit: initialFit(), zoomed: false };
let VOCAB = null, REAL = null; const fuzzyCache = new Map();

/* ---------------- crypto ---------------- */
async function aesDecrypt(key, buf) {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.subarray(0, 12) }, key, u.subarray(12)));
}
async function fetchBin(url) {
  const r = await fetch(url, { credentials: 'same-origin' });
  if (!r.ok) throw new Error(`HTTP ${r.status} for ${url}`);
  return new Uint8Array(await r.arrayBuffer());
}
async function deriveKey(pw, lock) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  const kek = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64d(lock.salt), iterations: lock.iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  return aesDecrypt(kek, b64d(lock.key)); // raw data key; throws on wrong password
}
const importRaw = (raw) => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);

/* ---------------- unlock ---------------- */
let LOCK = null;
function initialFit() {
  try { const v = localStorage.getItem('mbsc.fit'); if (v === 'page' || v === 'width') return v; } catch {}
  return window.matchMedia('(max-width: 560px)').matches ? 'width' : 'page';
}
async function boot() {
  try { LOCK = await (await fetch('data/lock.json', { cache: 'no-cache' })).json(); }
  catch { msg('The archive could not be loaded. Please refresh the page.'); return; }
  $('#lock').hidden = false;
  $('#pw').focus();
}
function msg(t, info) { const el = $('#lock-msg'); el.textContent = t; el.classList.toggle('info', !!info); }

$('#lock-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = $('#pw').value;
  if (!pw) return;
  const btn = $('#unlock-btn');
  btn.disabled = true; msg('Unlocking…', true);
  let raw;
  try { raw = await deriveKey(pw, LOCK); }
  catch { btn.disabled = false; msg('That password didn’t work. Please try again.'); $('#pw').select(); return; }
  try {
    await openWith(raw);
    $('#pw').value = ''; msg('');
  } catch (err) { console.error(err); msg('The archive could not be opened. Please refresh and try again.'); }
  btn.disabled = false;
});

async function openWith(raw) {
  KEY = await importRaw(raw);
  const blob = await aesDecrypt(KEY, await fetchBin(`data/index.bin?b=${LOCK.build}`));
  IDX = JSON.parse(new TextDecoder().decode(gunzipSync(blob)));
  IDX.byId = new Map(IDX.docs.map((d, i) => [d.id, Object.assign(d, { i })]));
  REAL = new Set(IDX.real || []);
  $('#lock').hidden = true;
  $('#app').hidden = false;
  document.title = `${IDX.club} · Archive`;
  initApp();
  if (!applyHash()) (window.requestIdleCallback || setTimeout)(() => buildNorm());
}

$('#lock-btn').addEventListener('click', () => {
  location.reload();
});

/* ---------------- search engine ---------------- */
function normalize(s) {
  // lowercase, strip accents, non letters/digits -> single space; keep map to original offsets
  const n = []; const m = [];
  let space = true;
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    let c;
    if (code < 128) {
      if ((code >= 48 && code <= 57) || (code >= 97 && code <= 122)) c = s[i];
      else if (code >= 65 && code <= 90) c = String.fromCharCode(code + 32);
      else if (code === 39) continue; // apostrophes: "member's" -> "members"
      else c = null;
    } else {
      if (code === 0x2019 || code === 0x2018) continue;
      const d = s[i].normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
      c = d.length === 1 && /[\p{L}\p{N}]/u.test(d) ? d : null;
    }
    if (c === null) { if (!space) { n.push(' '); m.push(i); space = true; } }
    else { n.push(c); m.push(i); space = false; }
  }
  m.push(s.length);
  return { n: n.join(''), m: Uint32Array.from(m) };
}
function buildNorm() {
  if (NORM) return NORM;
  NORM = IDX.text.map((pages) => pages.map((t) => normalize(t)));
  return NORM;
}
/* close spellings: words in the archive one or two letters away from a search
   word, that are not real English words (so they are likely OCR misreads) */
function buildVocab() {
  if (VOCAB) return VOCAB;
  VOCAB = new Map();
  for (const pages of buildNorm()) for (const pg of pages) for (const w of pg.n.split(' ')) if (w.length >= 4) VOCAB.set(w, (VOCAB.get(w) || 0) + 1);
  return VOCAB;
}
function editDist(a, b, k) {
  // optimal string alignment distance with early exit above k
  const la = a.length, lb = b.length;
  if (Math.abs(la - lb) > k) return k + 1;
  let prev2 = null, prev = Array.from({ length: lb + 1 }, (_, j) => j);
  for (let i = 1; i <= la; i++) {
    const cur = [i]; let rowMin = i;
    for (let j = 1; j <= lb; j++) {
      const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
      let v = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      if (prev2 && i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, prev2[j - 2] + 1);
      cur[j] = v; if (v < rowMin) rowMin = v;
    }
    if (rowMin > k) return k + 1;
    prev2 = prev; prev = cur;
  }
  return prev[lb];
}
function fuzzyAlts(n) {
  if (n.length < 5 || n.includes(' ') || /^\d+$/.test(n)) return [];
  if (fuzzyCache.has(n)) return fuzzyCache.get(n);
  const k = n.length >= 9 ? 2 : 1;
  const out = [];
  for (const [w, f] of buildVocab()) {
    if (w.startsWith(n) || REAL.has(w) || /\d/.test(w)) continue;
    const dl = w.length - n.length;
    if (dl < -k || dl > k + 3) continue;
    if (w[0] !== n[0] && w[1] !== n[1]) continue; // keep the start of the word anchored
    let ok = editDist(n, w, k) <= k;
    if (!ok && dl > 0 && dl <= 3) { const head = w.slice(0, n.length); ok = !REAL.has(head) && editDist(n, head, k) <= k; }
    if (ok) out.push([w, f]);
  }
  const res = out.sort((a, b) => b[1] - a[1]).slice(0, 30).map((x) => x[0]);
  fuzzyCache.set(n, res);
  return res;
}
function parseQuery(q) {
  const terms = [];
  const re = /"([^"]+)"|“([^”]+)”|(\S+)/g;
  let mm;
  while ((mm = re.exec(q))) {
    const raw = mm[1] || mm[2] || mm[3];
    const n = normalize(raw).n.trim();
    if (n) {
      const phrase = !!(mm[1] || mm[2]) || n.includes(' ');
      terms.push({ raw, n, phrase, alts: state.fuzzy && !phrase ? fuzzyAlts(n) : [] });
    }
  }
  // dedupe
  const seen = new Set();
  return terms.filter((t) => (seen.has(t.n) ? false : seen.add(t.n)));
}
function findAll(hay, needle, out, whole, fz) {
  const L = needle.length;
  let i = hay.indexOf(needle);
  while (i !== -1) {
    if ((i === 0 || hay.charCodeAt(i - 1) === 32) && (!whole || i + L === hay.length || hay.charCodeAt(i + L) === 32)) out.push([i, L, fz]);
    i = hay.indexOf(needle, i + 1);
  }
  return out;
}
function termPos(hay, t) {
  const out = findAll(hay, t.n, [], false, 0);
  for (const a of t.alts) findAll(hay, a, out, true, 1);
  return out;
}
function pageHits(pages, terms) {
  const hits = [];
  pages.forEach((pg, pi) => {
    const pos = [];
    for (const t of terms) {
      const p = termPos(pg.n, t);
      if (!p.length) return;
      pos.push(p.sort((a, b) => a[0] - b[0]));
    }
    let exact = 0, fz = 0;
    pos.forEach((p) => p.forEach((x) => (x[2] ? fz++ : exact++)));
    hits.push({ page: pi + 1, count: exact + fz, score: exact + fz * 0.5, pos, close: pos.some((p) => p.every((x) => x[2])) });
  });
  return hits;
}
const inYears = (d) => (state.yFrom == null || (d.year != null && d.year >= state.yFrom)) && (state.yTo == null || (d.year != null && d.year <= state.yTo));
const passes = (d) => (state.type === 'All' || d.type === state.type) && inYears(d);
function runSearch(terms) {
  const norm = buildNorm();
  const docs = [];
  IDX.docs.forEach((d, di) => {
    if (!passes(d)) return;
    const hits = pageHits(norm[di], terms);
    if (hits.length) docs.push({ doc: d, hits, score: hits.reduce((a, h) => a + h.score, 0) });
  });
  return docs;
}
function snippet(di, page, pos, terms) {
  const { n, m } = NORM[di][page - 1];
  const orig = IDX.text[di][page - 1];
  // anchor on the rarest term's first hit
  let best = 0;
  pos.forEach((p, i) => { if (p.length < pos[best].length) best = i; });
  const [a, al] = pos[best][0];
  let s = Math.max(0, m[a] - 80), e = Math.min(orig.length, m[a + al] + 110);
  if (s > 0) { const sp = orig.indexOf(' ', s); if (sp !== -1 && sp < m[a]) s = sp + 1; }
  if (e < orig.length) { const sp = orig.lastIndexOf(' ', e); if (sp > m[a]) e = sp; }
  const ranges = [];
  terms.forEach((t, ti) => pos[ti].forEach(([p, l, fz]) => {
    const rs = m[p], re = m[p + l - 1] + 1;
    if (rs >= s && re <= e) ranges.push([rs, re, fz]);
  }));
  ranges.sort((x, y) => x[0] - y[0]);
  let html = s > 0 ? '…' : '', cur = s;
  for (const [rs, re, fz] of ranges) {
    if (rs < cur) continue;
    html += esc(orig.slice(cur, rs)) + (fz ? '<mark class="fz" title="Close spelling (likely a scanning error)">' : '<mark>') + esc(orig.slice(rs, re)) + '</mark>';
    cur = re;
  }
  html += esc(orig.slice(cur, e)) + (e < orig.length ? '…' : '');
  return html;
}

/* ---------------- app UI ---------------- */
let inited = false;
function initApp() {
  if (inited) return; inited = true;
  renderTabs(); renderSort(); renderYears(); render();
  $('#search-form').addEventListener('submit', (e) => { e.preventDefault(); doSearch($('#q').value); $('#q').blur(); });
  $('#q').addEventListener('input', () => { $('#clear-q').hidden = !$('#q').value; });
  $('#clear-q').addEventListener('click', () => { $('#q').value = ''; $('#clear-q').hidden = true; doSearch(''); $('#q').focus(); });
  $('#home-btn').addEventListener('click', () => { $('#q').value = ''; $('#clear-q').hidden = true; state.type = 'All'; state.yFrom = state.yTo = null; renderYears(); if (state.openId) closeDoc(); doSearch(''); renderTabs(); });
  $('#sort').addEventListener('change', (e) => { state.sort = e.target.value; refresh(); });
  $('#y-from').addEventListener('change', (e) => setYears(e.target.value, state.yTo));
  $('#y-to').addEventListener('change', (e) => setYears(state.yFrom, e.target.value));
  document.querySelectorAll('[data-view]').forEach((b) => b.addEventListener('click', () => {
    state.view = b.dataset.view;
    document.querySelectorAll('[data-view]').forEach((x) => x.setAttribute('aria-pressed', x === b));
    if (state.q) { $('#q').value = ''; $('#clear-q').hidden = true; doSearch(''); } else render();
    $('#list').scrollTop = 0;
  }));
  document.addEventListener('keydown', (e) => {
    const typing = /INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName);
    if (e.key === '/' && !typing) { e.preventDefault(); $('#q').focus(); }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f' && state.openId) { e.preventDefault(); openFind(); }
    if (e.key === 'Escape' && state.openId && !typing && !document.querySelector('dialog[open]')) closeDoc();
    if (state.openId && currentPdf && !typing && !e.ctrlKey && !e.metaKey && !e.altKey && !document.querySelector('dialog[open]')) {
      const c = $('#v-container'), noSideScroll = c.scrollWidth <= c.clientWidth + 2;
      const back = e.key === 'ArrowLeft' ? noSideScroll : e.key === 'PageUp' && state.fit === 'page';
      const fwd = e.key === 'ArrowRight' ? noSideScroll : e.key === 'PageDown' && state.fit === 'page';
      if (back) { e.preventDefault(); prevPage(); } else if (fwd) { e.preventDefault(); nextPage(); }
    }
  });
  window.addEventListener('hashchange', applyHash);
  window.addEventListener('popstate', () => {
    const id = new URLSearchParams(location.hash.slice(1)).get('doc');
    if (state.openId && !id) { closeViewer(); }
  });
  initPhone();
  initViewer();
}
function refresh() { if (state.q) doSearch(state.q, true); else render(); }
function setYears(a, b) {
  a = a === '' || a == null ? null : +a; b = b === '' || b == null ? null : +b;
  if (a != null && b != null && a > b) [a, b] = [b, a];
  state.yFrom = a; state.yTo = b;
  renderYears(); refresh();
}
function renderYears() {
  const ys = [...new Set(IDX.docs.map((d) => d.year).filter((y) => y != null))].sort((a, b) => a - b);
  const opt = (sel, any) => `<option value="">${any}</option>` + ys.map((y) => `<option value="${y}" ${y === sel ? 'selected' : ''}>${y}</option>`).join('');
  $('#y-from').innerHTML = opt(state.yFrom, 'Earliest');
  $('#y-to').innerHTML = opt(state.yTo, 'Latest');
  $('.yr').classList.toggle('on', state.yFrom != null || state.yTo != null);
  updateFilterBtn();
}
const yearText = () => state.yFrom == null && state.yTo == null ? '' : state.yFrom === state.yTo ? String(state.yFrom) : `${state.yFrom ?? 'earliest'}–${state.yTo ?? 'latest'}`;
function renderTabs() {
  const counts = { All: IDX.docs.length };
  IDX.docs.forEach((d) => { counts[d.type] = (counts[d.type] || 0) + 1; });
  const types = ['All', ...IDX.types];
  $('#type-tabs').innerHTML = types.map((t) => `<button class="tab" role="tab" data-t="${esc(t)}" aria-selected="${t === state.type}">${t === 'All' ? 'All documents' : esc(t)}<span class="n">${counts[t] || 0}</span></button>`).join('');
  $('#type-tabs').querySelectorAll('.tab').forEach((b) => b.addEventListener('click', () => {
    state.type = b.dataset.t; renderTabs(); refresh();
    $(`#type-tabs .tab[data-t="${CSS.escape(b.dataset.t)}"]`)?.scrollIntoView({ inline: 'nearest', block: 'nearest' });
  }));
}
function renderSort() {
  const opts = state.q ? [['relevance', 'Most matches'], ['newest', 'Newest first'], ['oldest', 'Oldest first']] : [['newest', 'Newest first'], ['oldest', 'Oldest first']];
  if (!opts.find((o) => o[0] === state.sort)) state.sort = opts[0][0];
  $('#sort').innerHTML = opts.map(([v, l]) => `<option value="${v}" ${v === state.sort ? 'selected' : ''}>${l}</option>`).join('');
  updateFilterBtn();
}
function sortDocs(arr, key = (x) => x) {
  const s = state.sort;
  return arr.sort((a, b) => {
    if (s === 'relevance') return b.score - a.score || key(b).sort.localeCompare(key(a).sort);
    const c = key(a).sort.localeCompare(key(b).sort) || key(a).title.localeCompare(key(b).title);
    return s === 'oldest' ? c : -c;
  });
}
function doSearch(q, keepOpen, noOpen) {
  const prevQ = state.q;
  state.q = q.trim();
  state.terms = parseQuery(state.q);
  if (prevQ === '' && state.q) state.sort = 'relevance';
  state.expanded.clear();
  renderSort();
  if (!state.terms.length) { state.q = ''; state.results = null; state.flat = []; state.hitIdx = -1; renderSort(); render(); updateHitbar(); setHash(); return; }
  state.results = sortDocs(runSearch(state.terms), (x) => x.doc);
  state.flat = [];
  state.results.forEach((r) => r.hits.forEach((h) => state.flat.push({ id: r.doc.id, page: h.page })));
  state.hitIdx = -1;
  render();
  if (noOpen) { /* caller opens a specific page */ }
  else if (state.flat.length && (!keepOpen || state.openId)) {
    // On wide screens open the first match immediately; on phones keep the list visible
    if (window.matchMedia('(min-width: 981px)').matches) gotoHit(0);
    else if (state.openId) closeViewer();
  } else if (!state.flat.length && state.openId) closeViewer();
  updateHitbar(); setHash();
}

/* thumbnails */
const thumbCache = new Map();
const io = new IntersectionObserver((entries) => {
  entries.forEach((en) => {
    if (!en.isIntersecting) return;
    io.unobserve(en.target);
    loadThumb(en.target);
  });
}, { rootMargin: '400px' });
async function loadThumb(img) {
  const id = img.dataset.id;
  try {
    let url = thumbCache.get(id);
    if (!url) {
      const bytes = await aesDecrypt(KEY, await fetchBin(`data/t/${id}.bin?v=${IDX.byId.get(id)?.v || ''}`));
      url = URL.createObjectURL(new Blob([bytes], { type: 'image/jpeg' }));
      thumbCache.set(id, url);
    }
    img.src = url; img.onload = () => img.classList.add('ok');
  } catch (e) { console.warn('thumb', id, e); }
}
const checkHTML = (d) => `<label class="pick" title="Select for download"><input type="checkbox" data-pick="${d.id}" ${state.selected.has(d.id) ? 'checked' : ''} aria-label="Select ${esc(d.type)} ${esc(d.label)}"></label>`;
function selbarHTML(extra = '') {
  return `<div class="selbar" role="toolbar" aria-label="Download selection">
    <label class="selall"><input type="checkbox" id="sel-all"> <span>Select all <span class="selall-n">(${state.viewIds.length})</span></span></label>
    <button id="dl-sel" class="btn-primary sm-btn" ${state.busy ? 'disabled' : ''}>${state.busy ? 'Preparing…' : 'Download selected'}</button>
    <span id="sel-count" class="sel-count"></span>
    <button id="sel-clear" class="linkish" hidden>Clear selection</button>${extra}
  </div>`;
}
function syncSelection() {
  const all = $('#sel-all'); if (!all) return;
  const inView = state.viewIds.filter((id) => state.selected.has(id)).length;
  all.checked = inView > 0 && inView === state.viewIds.length;
  all.indeterminate = inView > 0 && inView < state.viewIds.length;
  const n = state.selected.size;
  const mb = [...state.selected].reduce((a, id) => a + IDX.byId.get(id).size, 0) / 1e6;
  $('#sel-count').textContent = n ? `${n} selected · ${mb >= 1 ? Math.round(mb) : mb.toFixed(1)} MB` : 'None selected';
  $('#sel-clear').hidden = !n;
  if (!state.busy) $('#dl-sel').disabled = !n;
  document.querySelectorAll('[data-pick]').forEach((cb) => { cb.checked = state.selected.has(cb.dataset.pick); cb.closest('.pickable')?.classList.toggle('picked', cb.checked); });
}
const thumbHTML = (d) => `<span class="thumb"><img alt="" data-id="${d.id}" decoding="async"></span>`;

const DAY = 86400000;
const isNew = (d) => IDX.launch && d.added > IDX.launch && (Date.parse(IDX.built) - Date.parse(d.added)) / DAY <= 90;
const newBadge = (d) => (isNew(d) ? '<span class="new">New</span>' : '');
const fmtDate = (iso) => new Date(iso + 'T12:00:00').toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

function render() {
  const el = $('#list');
  const split = !!state.openId;
  $('#main').classList.toggle('split', split);
  if (state.q) el.innerHTML = renderResults(split);
  else el.innerHTML = renderBrowse(split);
  el.querySelectorAll('img[data-id]').forEach((img) => (thumbCache.has(img.dataset.id) ? loadThumb(img) : io.observe(img)));
  el.querySelectorAll('[data-open]').forEach((b) => b.addEventListener('click', () => {
    const id = b.dataset.open, page = +b.dataset.page || 1;
    if (state.q && b.dataset.hit) gotoHit(+b.dataset.hit);
    else openDoc(id, page);
  }));
  el.querySelectorAll('[data-pick]').forEach((cb) => cb.addEventListener('change', () => {
    if (cb.checked) state.selected.add(cb.dataset.pick); else state.selected.delete(cb.dataset.pick);
    syncSelection();
  }));
  $('#sel-all')?.addEventListener('change', (e) => {
    state.viewIds.forEach((id) => (e.target.checked ? state.selected.add(id) : state.selected.delete(id)));
    syncSelection();
  });
  $('#sel-clear')?.addEventListener('click', () => { state.selected.clear(); syncSelection(); });
  $('#dl-sel')?.addEventListener('click', downloadSelected);
  syncSelection();
  el.querySelectorAll('[data-more]').forEach((b) => b.addEventListener('click', () => { state.expanded.add(b.dataset.more); render(); }));
  el.querySelectorAll('[data-jump]').forEach((b) => b.addEventListener('click', () => document.getElementById(b.dataset.jump)?.scrollIntoView({ block: 'start', behavior: 'smooth' })));
  $('#fz')?.addEventListener('change', (e) => { state.fuzzy = e.target.checked; doSearch(state.q, true); });
  el.querySelectorAll('[data-clear-years]').forEach((b) => b.addEventListener('click', () => setYears(null, null)));
  el.querySelectorAll('[data-all-types]').forEach((b) => b.addEventListener('click', () => { state.type = 'All'; renderTabs(); refresh(); }));
  markActive();
}
function itemHTML(split, showType) {
  return split
    ? (d) => `<div class="pickable row-wrap">${checkHTML(d)}<button class="row" data-open="${d.id}" data-doc="${d.id}">${thumbHTML(d)}<span><span class="row-t">${esc(d.label)}${newBadge(d)}</span><br><span class="row-m">${esc(d.type)} · ${d.pages} page${d.pages === 1 ? "" : "s"}</span></span></button></div>`
    : (d) => `<div class="pickable card-wrap">${checkHTML(d)}<button class="card" data-open="${d.id}" data-doc="${d.id}">${thumbHTML(d)}<span class="card-t">${esc(d.label)}${newBadge(d)}</span><span class="card-m">${showType ? esc(d.type) + ' · ' : ''}${d.pages} page${d.pages === 1 ? "" : "s"}</span></button></div>`;
}
function yearNote() {
  const y = yearText();
  return y ? ` · <span class="ychip">${y} <button class="linkish" data-clear-years>Show all years</button></span>` : '';
}
function renderBrowse(split) {
  let docs = IDX.docs.filter(passes);
  docs = sortDocs(docs.slice());
  const pages = docs.reduce((a, d) => a + d.pages, 0);
  const title = state.view === 'timeline' ? (state.type === 'All' ? 'Timeline' : `${state.type} timeline`) : (state.type === 'All' ? 'All documents' : state.type);
  const timeline = state.view === 'timeline';
  let groups;
  if (timeline) {
    const m = new Map();
    docs.forEach((d) => { const k = d.year ?? 'Undated'; if (!m.has(k)) m.set(k, []); m.get(k).push(d); });
    groups = [...m].map(([h, items]) => ({ h: String(h), id: `y-${h}`, items }));
  } else if (state.type === 'All') {
    groups = IDX.types.map((t) => ({ h: t, items: docs.filter((d) => d.type === t) })).filter((g) => g.items.length);
  } else {
    const m = new Map();
    docs.forEach((d) => { const k = d.year ? String(Math.floor(d.year / 10) * 10) + 's' : 'Undated'; if (!m.has(k)) m.set(k, []); m.get(k).push(d); });
    groups = [...m].map(([h, items]) => ({ h, items }));
  }
  const item = itemHTML(split, timeline);
  state.viewIds = docs.map((d) => d.id);
  // decade jump bar for the timeline
  let jump = '';
  if (timeline && docs.length) {
    const dec = new Map();
    groups.forEach((g) => { const y = parseInt(g.h); const k = isNaN(y) ? 'Undated' : `${Math.floor(y / 10) * 10}s`; if (!dec.has(k)) dec.set(k, g.id); });
    jump = `<nav class="decades" aria-label="Jump to decade"><span class="lbl">Jump to</span>${[...dec].map(([k, id]) => `<button class="chip" data-jump="${id}">${k}</button>`).join('')}</nav>`;
  }
  // recently added
  let recent = '';
  const fresh = docs.filter(isNew).sort((a, b) => b.added.localeCompare(a.added) || b.sort.localeCompare(a.sort));
  if (!timeline && fresh.length) {
    recent = `<section class="group recent"><h2 class="group-h">Recently added<span class="c">${fresh.length}</span></h2><div class="${split ? 'rows' : 'grid'}">${fresh.slice(0, split ? 6 : 12).map(itemHTML(split, true)).join('')}</div></section>`;
  }
  const updated = IDX.built ? ` · Updated ${fmtDate(IDX.built)}` : '';
  if (!docs.length) {
    return `<div class="wrap"><div class="page-head"><h1 class="page-title">${esc(title)}</h1></div><div class="empty"><h2>No documents from ${esc(yearText())}</h2><p>${state.type === 'All' ? '' : `There are no ${esc(state.type)} documents in these years. `}<button class="linkish" data-clear-years>Show all years</button>${state.type === 'All' ? '' : ' or <button class="linkish" data-all-types>look in all documents</button>'}.</p></div></div>`;
  }
  return `<div class="wrap">
    <div class="page-head"><h1 class="page-title">${esc(title)}</h1><span class="page-meta">${docs.length} documents · ${pages.toLocaleString()} pages${yearNote()}${yearText() ? '' : updated}</span></div>
    ${selbarHTML(jump)}
    ${recent}
    ${groups.map((g) => `<section class="group"${g.id ? ` id="${g.id}"` : ''}><h2 class="group-h">${esc(g.h)}<span class="c">${g.items.length}</span></h2><div class="${split ? 'rows' : 'grid'}">${g.items.map(item).join('')}</div></section>`).join('')}
  </div>`;
}
function fuzzyNote() {
  const alts = [...new Set(state.terms.flatMap((t) => t.alts))];
  const can = state.terms.some((t) => !t.phrase && t.n.length >= 5);
  if (!can) return '';
  return `<div class="ropts"><label class="chk"><input type="checkbox" id="fz" ${state.fuzzy ? 'checked' : ''}> Include close spellings</label>
    <span class="ropts-note">${state.fuzzy ? (alts.length ? `Also matching likely scanning errors: ${alts.slice(0, 8).map((a) => `<span class="alt">${esc(a)}</span>`).join(' ')}${alts.length > 8 ? ` and ${alts.length - 8} more` : ''}` : 'No likely scanning errors of these words were found.') : 'Turn on to also catch words the scanner misread.'}</span></div>`;
}
function renderResults(split) {
  const R = state.results;
  const where = (state.type === 'All' ? 'all documents' : esc(state.type)) + (yearText() ? `, ${yearText()}` : '');
  state.viewIds = R.map((r) => r.doc.id);
  if (!R.length) {
    return `<div class="results">${fuzzyNote()}<div class="empty"><h2>No pages mention “${esc(state.q)}”</h2><p>Searched ${where}. Try fewer words or a shorter spelling (“fish” also finds “fishing”)${state.type === 'All' ? '' : ', or <button class="linkish" data-all-types>search all documents</button>'}${yearText() ? ', or <button class="linkish" data-clear-years>search all years</button>' : ''}.</p><p class="tip">Older scans may contain OCR misreads, so try a related word if a name doesn’t turn up.</p></div></div>`;
  }
  const totalPages = state.flat.length;
  let k = 0;
  const parts = R.map((r) => {
    const di = r.doc.i;
    const lim = state.expanded.has(r.doc.id) ? Infinity : (split ? 3 : 4);
    const rows = r.hits.map((h, j) => {
      const idx = k++;
      if (j >= lim) return '';
      return `<button class="hit" data-open="${r.doc.id}" data-page="${h.page}" data-hit="${idx}"><span class="hit-p">Page ${h.page}${h.close ? '<span class="closetag">close spelling</span>' : ''}</span><span class="hit-s">${snippet(di, h.page, h.pos, state.terms)}</span></button>`;
    }).join('');
    const hidden = r.hits.length - Math.min(lim, r.hits.length);
    return `<article class="rdoc"><header class="rdoc-h pickable">${checkHTML(r.doc)}<span class="rdoc-t"><span class="ty">${esc(r.doc.type)}</span>${esc(r.doc.label)}</span><span class="rdoc-c">${r.hits.length} page${r.hits.length > 1 ? 's' : ''}</span></header>${rows}${hidden > 0 ? `<button class="more" data-more="${r.doc.id}">Show ${hidden} more page${hidden > 1 ? 's' : ''} in this document</button>` : ''}</article>`;
  }).join('');
  return `<div class="results"><div class="page-head" style="margin-bottom:0"><h1 class="page-title">Results for “${esc(state.q)}”</h1><span class="page-meta">${totalPages} page${totalPages > 1 ? 's' : ''} in ${R.length} document${R.length > 1 ? 's' : ''} · ${where}</span></div>${fuzzyNote()}${selbarHTML()}${parts}</div>`;
}
function markActive() {
  document.querySelectorAll('.list .active').forEach((x) => x.classList.remove('active'));
  if (!state.openId) return;
  if (state.q && state.hitIdx >= 0) {
    const el = document.querySelector(`.list [data-hit="${state.hitIdx}"]`);
    if (el) { el.classList.add('active'); el.scrollIntoView({ block: 'nearest' }); }
  } else {
    const el = document.querySelector(`.list [data-doc="${state.openId}"]`);
    if (el) { el.classList.add('active'); el.scrollIntoView({ block: 'nearest' }); }
  }
}

/* ---------------- viewer ---------------- */
let holdPage = false;
let pdfjs, viewer, eventBus, linkService, findController, currentPdf = null, loadToken = 0;
const pdfCache = new Map(); // id -> Uint8Array (decrypted)
async function initViewer() {
  pdfjs = await import('./vendor/pdfjs/pdf.min.mjs');
  globalThis.pdfjsLib = pdfjs;
  pdfjs.GlobalWorkerOptions.workerSrc = new URL('./vendor/pdfjs/pdf.worker.min.mjs', import.meta.url).href;
  const V = await import('./vendor/pdfjs/pdf_viewer.mjs');
  eventBus = new V.EventBus();
  linkService = new V.PDFLinkService({ eventBus });
  // the find controller jumps to the nearest match; when the page being shown has
  // no match (e.g. a shared link to a specific page) we keep the reader where they are
  const findLink = new Proxy(linkService, {
    get(t, k) { const v = t[k]; return typeof v === 'function' ? v.bind(t) : v; },
    set(t, k, v) { if (k === 'page' && holdPage) return true; t[k] = v; return true; },
  });
  findController = new V.PDFFindController({ eventBus, linkService: findLink });
  eventBus.on('updatefindcontrolstate', () => { if (holdPage) queueMicrotask(() => { findController._scrollMatches = false; }); });
  viewer = new V.PDFViewer({ container: $('#v-container'), viewer: $('#v-pdf'), eventBus, linkService, findController, removePageBorders: true });
  linkService.setViewer(viewer);
  eventBus.on('pagechanging', (e) => { state.page = e.pageNumber; $('#v-page').value = e.pageNumber; updateArrows(); if (state.fit === 'page') requestAnimationFrame(applyFit); if (state.q) updateHitbar(); setHash(); if (state.reading) renderReading(); updateFindLabel(); });
  $('#v-close').addEventListener('click', closeDoc);
  $('#v-prev').addEventListener('click', prevPage);
  $('#v-next').addEventListener('click', nextPage);
  $('#v-page').addEventListener('change', (e) => { const n = Math.max(1, Math.min(viewer.pagesCount, parseInt(e.target.value) || 1)); viewer.currentPageNumber = n; e.target.value = n; });
  $('#v-zin').addEventListener('click', () => { state.zoomed = true; viewer.increaseScale(); });
  $('#v-zout').addEventListener('click', () => { state.zoomed = true; viewer.decreaseScale(); });
  document.querySelectorAll('[data-fit]').forEach((b) => b.addEventListener('click', () => setFit(b.dataset.fit)));
  $('#v-left').addEventListener('click', prevPage);
  $('#v-right').addEventListener('click', nextPage);
  initPageWheel();
  setFit(state.fit, false);
  $('#v-dl').addEventListener('click', download);
  $('#v-find').addEventListener('click', () => ($('#dfind').hidden ? openFind() : closeFind()));
  $('#df-form').addEventListener('submit', (e) => { e.preventDefault(); findInDoc($('#df-q').value); });
  $('#df-q').addEventListener('keydown', (e) => { if (e.key === 'Escape') { e.preventDefault(); closeFind(); } });
  $('#df-prev').addEventListener('click', () => stepFind(-1));
  $('#df-next').addEventListener('click', () => stepFind(1));
  $('#df-close').addEventListener('click', closeFind);
  $('#v-read-btn').addEventListener('click', () => setReading(!state.reading));
  $('#rd-smaller').addEventListener('click', () => setReadSize(-2));
  $('#rd-bigger').addEventListener('click', () => setReadSize(2));
  $('#rd-copy').addEventListener('click', copyReading);
  $('#rd-scan').addEventListener('click', () => setReading(false));
  $('#lk-url').addEventListener('focus', (e) => e.target.select());
  $('#v-link').addEventListener('click', showLink);
  $('#lk-copy').addEventListener('click', () => copyText($('#lk-url').value, $('#lk-copy')));
  $('#v-pages').addEventListener('click', showPagesDialog);
  $('#pg-this').addEventListener('click', () => { $('#pg-from').value = $('#pg-to').value = state.page; });
  $('#pg-all').addEventListener('click', () => { $('#pg-from').value = 1; $('#pg-to').value = currentPdf?.numPages || 1; });
  $('#pg-print').addEventListener('click', () => pagesAction('print'));
  $('#pg-save').addEventListener('click', () => pagesAction('save'));
  document.querySelectorAll('dialog [data-close]').forEach((b) => b.addEventListener('click', () => b.closest('dialog').close()));
  window.addEventListener('afterprint', () => { $('#print-root').innerHTML = ''; });
  $('#h-prev').addEventListener('click', () => stepHit(-1));
  $('#h-next').addEventListener('click', () => stepHit(1));
  window.addEventListener('resize', () => { if (viewer && state.openId && currentPdf) { applyFit(); kick(); } });
  new ResizeObserver(() => { if (viewer && state.openId && currentPdf) { applyFit(); kick(); } }).observe($('#v-container'));
  viewerReady.resolve();
}
const viewerReady = (() => { let r; const p = new Promise((res) => (r = res)); p.resolve = r; return p; })();

async function getPdfBytes(id) {
  if (pdfCache.has(id)) return pdfCache.get(id);
  const bytes = await aesDecrypt(KEY, await fetchBin(`data/d/${id}.bin?v=${IDX.byId.get(id)?.v || ''}`));
  pdfCache.set(id, bytes);
  if (pdfCache.size > 6) pdfCache.delete(pdfCache.keys().next().value);
  return bytes;
}
function stepHit(dir) {
  const cur = state.flat[state.hitIdx];
  if (!state.openId || (cur && cur.id === state.openId && cur.page === state.page)) return gotoHit(state.hitIdx + dir);
  // not on a match (opened from a link or the list, or the reader turned pages): continue from this page
  const F = state.flat, here = (h) => h.id === state.openId;
  let i = dir > 0 ? F.findIndex((h) => here(h) && h.page > state.page) : F.findLastIndex((h) => here(h) && h.page < state.page);
  if (i < 0) { const first = F.findIndex(here); const last = F.findLastIndex(here); i = first < 0 ? 0 : dir > 0 ? Math.min(F.length - 1, last + 1) : Math.max(0, first - 1); }
  gotoHit(i);
}
function gotoHit(i, fromHistory = false) {
  if (!state.flat.length) return;
  i = Math.max(0, Math.min(state.flat.length - 1, i));
  state.hitIdx = i;
  const h = state.flat[i];
  // make sure the hit row is rendered (expand collapsed document)
  const wasOpen = !!state.openId;
  if (!document.querySelector(`.list [data-hit="${i}"]`)) { state.expanded.add(h.id); state.openId = h.id; render(); }
  openDoc(h.id, h.page, true, fromHistory, wasOpen);
}
async function openDoc(id, page = 1, fromHit = false, fromHistory = false, wasOpen) {
  await viewerReady;
  const d = IDX.byId.get(id);
  if (!fromHit) state.hitIdx = -1;
  const wasSplit = !!state.openId;
  if (!(wasOpen ?? wasSplit) && !fromHistory) { try { history.pushState({ viewer: 1 }, '', location.pathname + location.search + location.hash); state.pushed = true; } catch {} }
  const sameDoc = state.openId === id && currentPdf;
  state.openId = id; state.page = page;
  $('#viewer').hidden = false;
  if (!wasSplit) render(); else markActive();
  $('#v-type').textContent = d.type.toUpperCase();
  $('#v-name').textContent = d.label + (d.label !== d.title ? '' : '');
  $('#v-name').title = d.file;
  $('#v-count').textContent = `/ ${d.pages}`;
  updateHitbar();
  if (!sameDoc && state.df) { const q = state.df.q; state.df = null; if (!$('#dfind').hidden) setTimeout(() => findInDoc(q, true), 0); }
  setHash();
  if (sameDoc) { viewer.currentPageNumber = page; kick(); highlight(); if (state.reading) renderReading(); return; }
  const token = ++loadToken;
  $('#v-loading').hidden = false;
  try {
    const bytes = await getPdfBytes(id);
    if (token !== loadToken) return;
    const oldPdf = currentPdf; currentPdf = null;
    const pdf = await pdfjs.getDocument({ data: bytes.slice(), cMapUrl: 'vendor/pdfjs/cmaps/', cMapPacked: true, standardFontDataUrl: 'vendor/pdfjs/standard_fonts/', wasmUrl: 'vendor/pdfjs/wasm/', iccUrl: 'vendor/pdfjs/iccs/', isEvalSupported: false, verbosity: 0 }).promise;
    if (token !== loadToken) { currentPdf = oldPdf; pdf.destroy(); return; }
    currentPdf = pdf;
    const ready = new Promise((res) => eventBus.on('pagesinit', res, { once: true }));
    viewer.setDocument(pdf);
    linkService.setDocument(pdf, null);
    if (oldPdf) setTimeout(() => oldPdf.destroy(), 0);
    await ready;
    viewer.scrollMode = state.fit === 'page' ? SCROLL_PAGE : SCROLL_VERTICAL;
    state.zoomed = false;
    if (state.fit === 'width') viewer.currentScaleValue = 'page-width';
    viewer.currentPageNumber = state.page;
    applyFit();
    updateArrows();
    $('#v-page').value = state.page;
    kick();
    highlight();
    if (state.reading) renderReading();
  } catch (e) {
    console.error(e);
    $('#v-name').textContent = 'This document could not be opened.';
  } finally { if (token === loadToken) $('#v-loading').hidden = true; }
}
// make sure pdf.js draws the visible pages (it otherwise waits for a scroll event)
/* ---- page fit & page turning ---- */
const SCROLL_VERTICAL = 0, SCROLL_PAGE = 3;
function setFit(mode, save = true) {
  state.fit = mode; state.zoomed = false;
  if (save) try { localStorage.setItem('mbsc.fit', mode); } catch {}
  document.querySelectorAll('[data-fit]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.fit === mode)));
  $('#v-container').classList.toggle('fit-page', mode === 'page');
  if (!viewer || !currentPdf) return;
  const n = viewer.currentPageNumber;
  const want = mode === 'page' ? SCROLL_PAGE : SCROLL_VERTICAL;
  if (viewer.scrollMode !== want) viewer.scrollMode = want;
  if (mode === 'width') viewer.currentScaleValue = 'page-width';
  viewer.currentPageNumber = n;
  applyFit(); kick();
}
// scale so the whole current page fits inside the window, leaving room for the side arrows
function applyFit() {
  if (!viewer || !currentPdf || state.zoomed) return;
  if (state.fit !== 'page') { viewer.currentScaleValue = 'page-width'; return; }
  const pv = viewer.getPageView(viewer.currentPageNumber - 1); if (!pv || !pv.viewport) return;
  const c = $('#v-container'); if (!c.clientWidth || !c.clientHeight) return;
  const w1 = pv.viewport.width / pv.scale, h1 = pv.viewport.height / pv.scale;
  const side = window.innerWidth > 560 ? 76 : 6;
  const s = Math.min((c.clientWidth - side * 2) / w1, (c.clientHeight - 20) / h1);
  if (s > 0.05 && Math.abs(s - viewer.currentScale) > 0.002) viewer.currentScale = s;
}
function prevPage() { if (viewer && viewer.currentPageNumber > 1) viewer.currentPageNumber--; }
function nextPage() { if (viewer && viewer.currentPageNumber < viewer.pagesCount) viewer.currentPageNumber++; }
function updateArrows() {
  if (!viewer) return;
  const n = viewer.currentPageNumber, total = viewer.pagesCount || 1;
  $('#v-left').disabled = n <= 1; $('#v-right').disabled = n >= total;
  $('#v-left').title = n <= 1 ? 'First page' : `Previous page (${n - 1} of ${total})`;
  $('#v-right').title = n >= total ? 'Last page' : `Next page (${n + 1} of ${total})`;
}
// in whole-page view the mouse wheel turns pages (unless zoomed in far enough to scroll)
function initPageWheel() {
  const c = $('#v-container'); let acc = 0, last = 0;
  c.addEventListener('wheel', (e) => {
    if (state.fit !== 'page' || e.ctrlKey || !currentPdf) return;
    if (c.scrollHeight > c.clientHeight + 2) return;
    e.preventDefault();
    const now = Date.now();
    if (now - last < 380) return;
    acc += e.deltaY;
    if (Math.abs(acc) < 40) return;
    acc > 0 ? nextPage() : prevPage(); acc = 0; last = now;
  }, { passive: false });
}
function kick() {
  const go = () => { try { viewer.update(); viewer.forceRendering?.(); } catch {} };
  requestAnimationFrame(() => { go(); setTimeout(go, 150); });
}
function activeTerms() {
  if (state.df && state.df.terms.length) return state.df.terms;
  return state.q ? state.terms : [];
}
function highlight() {
  const terms = activeTerms();
  if (!terms.length) { eventBus.dispatch('findbarclose', { source: null }); return; }
  const d = IDX.byId.get(state.openId);
  holdPage = !(d && pageHits([buildNorm()[d.i][state.page - 1]], terms).length);
  // reset, then search from the current page so the page's first match is selected
  eventBus.dispatch('find', { source: null, type: '', query: '', caseSensitive: false, entireWord: false, highlightAll: false, findPrevious: false, matchDiacritics: false });
  eventBus.dispatch('find', { source: null, type: '', query: [...terms.map((t) => t.raw.replace(/[“”"]/g, '')), ...terms.flatMap((t) => t.alts)], caseSensitive: false, entireWord: false, highlightAll: true, findPrevious: false, matchDiacritics: false });
}
function updateHitbar() {
  const on = !!(state.q && state.flat.length && state.openId);
  $('#hitbar').hidden = !on;
  if (!on) return;
  const i = state.hitIdx;
  if (i < 0) {
    const n = state.flat.filter((h) => h.id === state.openId).length;
    $('#h-label').textContent = n ? `${n} matching page${n > 1 ? 's' : ''} in this document · ${state.flat.length} in all` : `${state.flat.length} matching pages in all results`;
  } else if (state.flat[i].id === state.openId && state.flat[i].page !== state.page) {
    const n = state.flat.filter((h) => h.id === state.openId).length;
    $('#h-label').textContent = `Viewing page ${state.page} · ${n} matching page${n > 1 ? 's' : ''} in this document — Next/Previous continue from here`;
    $('#h-prev').disabled = $('#h-next').disabled = false; return;
  } else {
    const h = state.flat[i]; const d = IDX.byId.get(h.id);
    $('#h-label').textContent = `Match ${i + 1} of ${state.flat.length} · ${d.type}, ${d.label}, page ${h.page}`;
  }
  $('#h-prev').disabled = i === 0;
  $('#h-next').disabled = i >= state.flat.length - 1;
}
function closeDoc() {
  // use the browser history when we added an entry, so Back and the close button agree
  if (state.pushed) { state.pushed = false; history.back(); }
  else closeViewer();
}
function closeViewer() {
  loadToken++;
  state.pushed = false;
  state.openId = null; state.hitIdx = -1;
  $('#viewer').hidden = true;
  state.df = null; $('#dfind').hidden = true; setReading(false, true);
  setHash();
  if (currentPdf) { viewer.setDocument(null); linkService.setDocument(null); currentPdf.destroy(); currentPdf = null; }
  render();
}
async function download() {
  if (!state.openId) return;
  const d = IDX.byId.get(state.openId);
  const bytes = await getPdfBytes(d.id);
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/pdf' }));
  const a = Object.assign(document.createElement('a'), { href: url, download: d.file });
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}

function saveBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement('a'), { href: url, download: name });
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}
function setBusy(on, label) {
  state.busy = on;
  const b = $('#dl-sel'); if (!b) return;
  b.disabled = on || !state.selected.size;
  b.textContent = on ? label : 'Download selected';
}
async function downloadSelected() {
  if (state.busy || !state.selected.size) return;
  // keep archive order: by type, then date
  const docs = IDX.docs.filter((d) => state.selected.has(d.id));
  try {
    if (docs.length === 1) {
      setBusy(true, 'Preparing…');
      const bytes = await getPdfBytes(docs[0].id);
      saveBlob(new Blob([bytes], { type: 'application/pdf' }), docs[0].file);
      return;
    }
    const chunks = [];
    let err = null;
    const zip = new Zip((e, chunk) => { if (e) err = e; else chunks.push(chunk); });
    const used = new Set();
    for (let i = 0; i < docs.length; i++) {
      const d = docs[i];
      setBusy(true, `Preparing ${i + 1} of ${docs.length}…`);
      const bytes = await aesDecrypt(KEY, await fetchBin(`data/d/${d.id}.bin?v=${d.v || ''}`));
      let name = `${d.type}/${d.file}`;
      for (let k = 2; used.has(name); k++) name = `${d.type}/${d.file.replace(/\.pdf$/i, '')} (${k}).pdf`;
      used.add(name);
      const f = new ZipPassThrough(name); // PDFs are already compressed
      zip.add(f); f.push(bytes, true);
      if (err) throw err;
    }
    zip.end();
    if (err) throw err;
    const types = [...new Set(docs.map((d) => d.type))];
    const label = types.length === 1 ? types[0] : 'Club Archive';
    saveBlob(new Blob(chunks, { type: 'application/zip' }), `MBSC ${label} - ${docs.length} documents.zip`);
  } catch (e) {
    console.error(e);
    alertBar('The download could not be prepared. Please try again, or select fewer documents.');
  } finally { setBusy(false); syncSelection(); }
}
function alertBar(t) {
  const el = $('#sel-count'); if (el) { el.textContent = t; el.classList.add('err'); setTimeout(() => el.classList.remove('err'), 6000); }
}

/* ---------------- page links (#doc=…&p=…) ---------------- */
let hashTimer = 0;
function hashFor(page) {
  const p = new URLSearchParams();
  if (state.openId) { p.set('doc', state.openId); p.set('p', page ?? state.page); }
  if (state.q) p.set('q', state.q);
  const h = p.toString();
  return h ? '#' + h : '';
}
function setHash() {
  clearTimeout(hashTimer);
  hashTimer = setTimeout(() => {
    const h = hashFor();
    if (h !== location.hash) try { history.replaceState(null, '', location.pathname + location.search + h); } catch {}
  }, 120);
}
function applyHash() {
  if (!IDX || !location.hash) return false;
  const p = new URLSearchParams(location.hash.slice(1));
  const q = p.get('q') || '', id = p.get('doc'), page = Math.max(1, parseInt(p.get('p')) || 1);
  if (id && !IDX.byId.has(id)) return false;
  if (q && q !== state.q) { $('#q').value = q; $('#clear-q').hidden = false; doSearch(q, false, !!id); }
  if (id) {
    const d = IDX.byId.get(id);
    const n = Math.min(page, d.pages);
    const hi = state.flat.findIndex((h) => h.id === id && h.page === n);
    if (hi >= 0) gotoHit(hi, true); else openDoc(id, n, false, true);
  }
  return !!(q || id);
}
function pageLink() {
  return location.href.split('#')[0] + hashFor(state.page);
}
function showLink() {
  if (!state.openId) return;
  const d = IDX.byId.get(state.openId);
  $('#lk-what').textContent = `${d.type}, ${d.label}, page ${state.page}`;
  $('#lk-url').value = pageLink();
  $('#lk-copy').textContent = 'Copy link';
  $('#link-dlg').showModal();
  $('#lk-url').select();
  copyText($('#lk-url').value, $('#lk-copy'), true);
}
async function copyText(t, btn, quiet) {
  let ok = false;
  try { await navigator.clipboard.writeText(t); ok = true; } catch {}
  if (!ok) {
    const ta = Object.assign(document.createElement('textarea'), { value: t });
    ta.style.cssText = 'position:fixed;opacity:0';
    (document.querySelector('dialog[open]') || document.body).appendChild(ta); ta.select();
    try { ok = document.execCommand('copy'); } catch {}
    ta.remove();
  }
  if (btn) {
    const was = btn.dataset.label || (btn.dataset.label = btn.textContent);
    if (ok) { btn.textContent = 'Copied'; setTimeout(() => (btn.textContent = was), 1800); }
    else if (!quiet) btn.textContent = 'Select and copy the text';
  }
  return ok;
}
function toast(t) {
  const el = $('#toast'); el.textContent = t; el.hidden = false;
  clearTimeout(toast.t); toast.t = setTimeout(() => (el.hidden = true), 2600);
}

/* ---------------- find in this document ---------------- */
function openFind() {
  $('#dfind').hidden = false; $('#v-find').setAttribute('aria-pressed', 'true');
  $('#df-q').focus(); $('#df-q').select();
}
function closeFind() {
  $('#dfind').hidden = true; $('#v-find').setAttribute('aria-pressed', 'false');
  state.df = null; $('#df-label').textContent = '';
  if (viewer) highlight();
  if (state.reading) renderReading();
}
function findInDoc(q, quiet) {
  q = q.trim();
  if (!q || !state.openId) { state.df = null; $('#df-label').textContent = ''; highlight(); return; }
  const terms = parseQuery(q);
  const di = IDX.byId.get(state.openId).i;
  const hits = pageHits(buildNorm()[di], terms);
  state.df = { q, terms, pages: hits.map((h) => h.page) };
  $('#df-q').value = q;
  if (!hits.length) { updateFindLabel(); highlight(); return; }
  const next = state.df.pages.find((p) => p >= state.page) ?? state.df.pages[0];
  if (next === state.page) { highlight(); updateFindLabel(); if (state.reading) renderReading(); }
  else viewer.currentPageNumber = next;
  highlight();
}
function stepFind(dir) {
  if (!state.df || !state.df.pages.length) { findInDoc($('#df-q').value); return; }
  const P = state.df.pages;
  const t = dir > 0 ? (P.find((p) => p > state.page) ?? P[0]) : ([...P].reverse().find((p) => p < state.page) ?? P[P.length - 1]);
  viewer.currentPageNumber = t;
  kick(); highlight();
}
function updateFindLabel() {
  const el = $('#df-label'); if (!el || !state.df) return;
  const P = state.df.pages;
  if (!P.length) { el.textContent = 'Not found in this document'; el.classList.add('none'); }
  else {
    el.classList.remove('none');
    const i = P.indexOf(state.page);
    el.textContent = i >= 0 ? `Page ${state.page} · ${i + 1} of ${P.length} matching page${P.length > 1 ? 's' : ''}` : `${P.length} matching page${P.length > 1 ? 's' : ''}`;
  }
  $('#df-prev').disabled = $('#df-next').disabled = P.length === 0;
}

/* ---------------- reading mode ---------------- */
let readToken = 0;
function setReading(on, silent) {
  state.reading = on;
  $('#v-read').hidden = !on;
  $('#v-read-btn').setAttribute('aria-pressed', String(on));
  if (on) renderReading();
  else if (!silent && viewer) kick();
}
function setReadSize(d) {
  state.readSize = Math.max(14, Math.min(34, state.readSize + d));
  $('#rd-body').style.fontSize = state.readSize + 'px';
}
function reflow(lines) {
  const lens = lines.filter(Boolean).map((l) => l.length).sort((a, b) => a - b);
  const med = lens[Math.floor(lens.length / 2)] || 60;
  const paras = []; let cur = '';
  const flush = () => { if (cur.trim()) paras.push(cur.trim()); cur = ''; };
  for (const raw of lines) {
    const l = raw.trim();
    if (!l) { flush(); continue; }
    if (/[A-Za-z]-$/.test(cur) && /^[a-z]/.test(l)) cur = cur.slice(0, -1) + l;
    else cur = cur ? cur + ' ' + l : l;
    if (l.length < med * 0.6 && /[.!?:"”)]$/.test(l)) flush();
  }
  flush();
  return paras;
}
function highlightHTML(text, terms) {
  const words = [...new Set(terms.flatMap((t) => [t.n, ...t.alts]))].filter(Boolean).sort((a, b) => b.length - a.length);
  if (!words.length) return esc(text);
  const pat = words.map((w) => w.split(' ').map((x) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join("[^\\p{L}\\p{N}]+")).join('|');
  const re = new RegExp(`(?<![\\p{L}\\p{N}])(${pat})`, 'giu');
  let out = '', last = 0, m;
  while ((m = re.exec(text))) { out += esc(text.slice(last, m.index)) + '<mark>' + esc(m[0]) + '</mark>'; last = m.index + m[0].length; if (!m[0].length) re.lastIndex++; }
  return out + esc(text.slice(last));
}
async function renderReading() {
  if (!state.openId) return;
  const token = ++readToken, page = state.page, d = IDX.byId.get(state.openId);
  $('#rd-label').textContent = `Page ${page} of ${d.pages} · text`;
  const body = $('#rd-body');
  body.style.fontSize = state.readSize + 'px';
  let paras = [];
  try {
    if (currentPdf) {
      const pg = await currentPdf.getPage(page);
      const tc = await pg.getTextContent();
      const lines = []; let line = '';
      for (const it of tc.items) { line += it.str ?? ''; if (it.hasEOL) { lines.push(line); line = ''; } }
      if (line) lines.push(line);
      paras = reflow(lines);
    }
  } catch (e) { console.warn(e); }
  if (token !== readToken) return;
  if (!paras.join('').trim()) { const t = IDX.text[d.i][page - 1]; if (t) paras = [t]; }
  const terms = activeTerms();
  body.innerHTML = paras.length ? paras.map((p) => `<p>${highlightHTML(p, terms)}</p>`).join('') : '<p class="read-empty">No text was found on this page. It may be a photo or a drawing.</p>';
  body.dataset.plain = paras.join('\n\n');
  $('#v-read').scrollTop = 0;
  body.querySelector('mark')?.scrollIntoView({ block: 'center' });
}
function copyReading() { copyText($('#rd-body').dataset.plain || '', $('#rd-copy')); }

/* ---------------- print or save a page range ---------------- */
function showPagesDialog() {
  if (!state.openId || !currentPdf) return;
  const d = IDX.byId.get(state.openId), n = currentPdf.numPages;
  $('#pg-what').textContent = `${d.type}, ${d.label} · ${n} pages`;
  for (const id of ['#pg-from', '#pg-to']) { $(id).max = n; $(id).value = state.page; }
  $('#pg-of').textContent = `of ${n}`;
  $('#pg-msg').textContent = ''; $('#pg-msg').classList.remove('err');
  setPagesBusy(false);
  $('#pg-dlg').showModal();
}
function setPagesBusy(on) { ['#pg-print', '#pg-save', '#pg-from', '#pg-to', '#pg-this', '#pg-all'].forEach((s) => ($(s).disabled = on)); }
function pageRange() {
  const n = currentPdf.numPages;
  let a = Math.max(1, Math.min(n, parseInt($('#pg-from').value) || 1));
  let b = Math.max(1, Math.min(n, parseInt($('#pg-to').value) || a));
  if (a > b) [a, b] = [b, a];
  $('#pg-from').value = a; $('#pg-to').value = b;
  return [a, b];
}
async function pagesAction(kind) {
  const [a, b] = pageRange();
  const d = IDX.byId.get(state.openId);
  const msgEl = $('#pg-msg'); msgEl.classList.remove('err');
  const count = b - a + 1;
  if (kind === 'print' && count > 60) { msgEl.textContent = 'Please print 60 pages or fewer at a time.'; msgEl.classList.add('err'); return; }
  setPagesBusy(true);
  try {
    if (kind === 'save') {
      msgEl.textContent = 'Preparing PDF…';
      const { PDFDocument } = await import('./vendor/pdf-lib.esm.min.js');
      const src = await PDFDocument.load(await getPdfBytes(d.id), { ignoreEncryption: true, updateMetadata: false });
      const out = await PDFDocument.create();
      const copied = await out.copyPages(src, Array.from({ length: count }, (_, i) => a - 1 + i));
      copied.forEach((p) => out.addPage(p));
      out.setTitle(`${d.type} ${d.label} - ${a === b ? `page ${a}` : `pages ${a}-${b}`}`);
      const bytes = await out.save();
      const stem = d.file.replace(/\.pdf$/i, '');
      saveBlob(new Blob([bytes], { type: 'application/pdf' }), `${stem} - ${a === b ? `page ${a}` : `pages ${a}-${b}`}.pdf`);
      msgEl.textContent = `Saved ${count} page${count > 1 ? 's' : ''}.`;
    } else {
      const root = $('#print-root'); root.innerHTML = '';
      for (let p = a; p <= b; p++) {
        msgEl.textContent = `Preparing page ${p - a + 1} of ${count}…`;
        const pg = await currentPdf.getPage(p);
        const vp = pg.getViewport({ scale: 2 });
        const c = document.createElement('canvas'); c.width = vp.width; c.height = vp.height;
        await pg.render({ canvas: c, canvasContext: c.getContext('2d'), viewport: vp }).promise;
        const blob = await new Promise((r) => c.toBlob(r, 'image/jpeg', 0.88));
        const img = new Image(); img.src = URL.createObjectURL(blob); img.alt = `Page ${p}`;
        await img.decode().catch(() => {});
        root.appendChild(img);
      }
      msgEl.textContent = '';
      $('#pg-dlg').close();
      setTimeout(() => window.print(), 50);
    }
  } catch (e) {
    console.error(e);
    msgEl.textContent = 'Those pages could not be prepared. Please try again.'; msgEl.classList.add('err');
  } finally { setPagesBusy(false); }
}

/* ---------------- phones & tablets ---------------- */
const phoneMQ = window.matchMedia('(max-width: 560px)');
function initPhone() {
  const setPh = () => { $('#q').placeholder = phoneMQ.matches ? 'Search all documents' : 'Search every page — e.g. clambake, “striped bass”, fluke'; };
  setPh(); phoneMQ.addEventListener?.('change', setPh);

  // filters sheet
  const openSheet = (on) => {
    document.body.classList.toggle('sheet-open', on);
    $('#sheet-bg').hidden = !on;
    $('#filters-btn').setAttribute('aria-expanded', String(on));
  };
  $('#filters-btn').addEventListener('click', () => openSheet(!document.body.classList.contains('sheet-open')));
  $('#sheet-done').addEventListener('click', () => openSheet(false));
  $('#sheet-bg').addEventListener('click', () => openSheet(false));
  document.querySelectorAll('[data-view]').forEach((b) => b.addEventListener('click', updateFilterBtn));
  ['#y-from', '#y-to', '#sort'].forEach((s) => $(s).addEventListener('change', updateFilterBtn));
  updateFilterBtn();

  // viewer "more" menu
  const menu = $('#v-menu'), more = $('#v-more');
  const showMenu = (on) => { menu.hidden = !on; more.setAttribute('aria-expanded', String(on)); };
  more.addEventListener('click', (e) => { e.stopPropagation(); showMenu(menu.hidden); });
  menu.addEventListener('click', (e) => {
    const b = e.target.closest('[data-act]'); if (!b) return;
    showMenu(false);
    ({ zin: () => { state.zoomed = true; viewer.increaseScale(); }, zout: () => { state.zoomed = true; viewer.decreaseScale(); }, fit: () => setFit('width'), fitpage: () => setFit('page'),
       link: showLink, pages: showPagesDialog, dl: download })[b.dataset.act]?.();
  });
  document.addEventListener('click', (e) => { if (!menu.hidden && !menu.contains(e.target)) showMenu(false); });

  initPinch();
}
function updateFilterBtn() {
  const parts = [];
  if (state.view === 'timeline') parts.push('Timeline');
  if (yearText()) parts.push(yearText());
  const sortName = { oldest: 'Oldest first', newest: state.q ? 'Newest first' : '', relevance: '' }[state.sort];
  if (sortName) parts.push(sortName);
  $('#filters-sum').textContent = parts.join(' · ');
  $('#filters-btn').classList.toggle('on', parts.length > 0);
}
// two-finger pinch to zoom the page (the browser's own pinch would zoom the whole app)
function initPinch() {
  const c = $('#v-container'), inner = $('#v-pdf');
  let g = null;
  const dist = (t) => Math.hypot(t[0].clientX - t[1].clientX, t[0].clientY - t[1].clientY);
  c.addEventListener('touchstart', (e) => {
    if (e.touches.length !== 2 || !viewer || !currentPdf) return;
    const r = c.getBoundingClientRect();
    const mx = (e.touches[0].clientX + e.touches[1].clientX) / 2 - r.left, my = (e.touches[0].clientY + e.touches[1].clientY) / 2 - r.top;
    g = { d: dist(e.touches), scale: viewer.currentScale, mx, my, ox: c.scrollLeft + mx, oy: c.scrollTop + my, ratio: 1 };
    inner.style.transformOrigin = `${g.ox - inner.offsetLeft}px ${g.oy - inner.offsetTop}px`;
    inner.style.willChange = 'transform';
  }, { passive: true });
  c.addEventListener('touchmove', (e) => {
    if (!g || e.touches.length !== 2) return;
    e.preventDefault();
    g.ratio = Math.min(5 / g.scale, Math.max(0.4 / g.scale, dist(e.touches) / g.d));
    inner.style.transform = `scale(${g.ratio})`;
  }, { passive: false });
  const end = () => {
    if (!g) return;
    const { ratio, scale, ox, oy, mx, my } = g; g = null;
    inner.style.transform = ''; inner.style.willChange = '';
    if (Math.abs(ratio - 1) < 0.02) return;
    state.zoomed = true; viewer.currentScale = scale * ratio;
    requestAnimationFrame(() => { c.scrollLeft = ox * ratio - mx; c.scrollTop = oy * ratio - my; kick(); });
  };
  c.addEventListener('touchend', (e) => { if (e.touches.length < 2) end(); });
  c.addEventListener('touchcancel', end);
}

boot();
