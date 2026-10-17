/* FEROX//GUI client engine.
 *
 * Live-sorting research conclusions implemented here:
 *  1. NEVER insert rows mid-list while the user is looking at a sorted view —
 *     rows jump under the cursor. If sort != (ts asc), new rows are staged and
 *     surfaced via a "N NEW — PULL" chip (frozen view / pull-to-update).
 *  2. ts-asc view is append-only => safe to live-update incrementally.
 *  3. Filters are evaluated incrementally (per new row), never re-scanned over
 *     the whole store per frame; full re-evaluation only on user action.
 *  4. Rendering is windowed (virtual list) + batched with requestAnimationFrame.
 *  5. Row store is bounded (ring eviction) so memory cannot grow without end.
 */

"use strict";

// ------------------------------------------------------------------ state

const ROW_H = 30;
const MAX_ROWS = 120000; // ring-evict oldest beyond this
const LIVE_RING = 600;
const LIVE_BATCH_ROWS = 2000;

const S = {
  rows: [],
  idx: [],
  sortKey: "ts",
  sortDir: "asc",
  statusFilter: "all",
  q: "",
  anomalyOnly: false,
  pending: 0,
  live: [],
  scanId: null,
  scans: [],
  wordlists: [],
  rateWindow: [],
  renderQueued: false,
};

const $ = (id) => document.getElementById(id);

// ------------------------------------------------------------------ utils

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function copyText(text) {
  const label =
    text.includes("\n") ? `copied ${text.split("\n").length} urls` : `copied ${text}`;
  const done = () => flash(label);
  const fallback = () => {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand("copy");
      done();
    } catch {
      flash("copy failed");
    }
    ta.remove();
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done).catch(fallback);
  } else {
    fallback();
  }
}

function fmtBytes(n) {
  if (n == null) return "—";
  if (n < 1024) return `${n}B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)}K`;
  return `${(n / 1048576).toFixed(1)}M`;
}

function fmtDur(sec) {
  sec = Math.max(0, Math.round(sec));
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  return `${m}m${String(sec % 60).padStart(2, "0")}s`;
}

function statusClass(st) {
  if (st >= 500) return "err";
  if (st >= 200 && st < 300) return "ok";
  return "dim";
}

// ------------------------------------------------------------------ store

function matchesFilter(r) {
  if (S.anomalyOnly && !(r.anomaly_score > 0.5)) return false;
  if (S.statusFilter !== "all") {
    const cls = String(r.status)[0];
    if (cls !== S.statusFilter) return false;
  }
  if (S.q && !r.url.toLowerCase().includes(S.q)) return false;
  return true;
}

const CMP = {
  ts: (a, b) => a.id - b.id,
  status: (a, b) => a.status - b.status,
  size: (a, b) => a.content_length - b.content_length,
  words: (a, b) => a.word_count - b.word_count,
  lines: (a, b) => a.line_count - b.line_count,
  url: (a, b) => a.url.localeCompare(b.url),
  score: (a, b) => a.anomaly_score - b.anomaly_score,
};

function rebuildIndex() {
  S.idx = [];
  for (let i = 0; i < S.rows.length; i++) {
    if (matchesFilter(S.rows[i])) S.idx.push(i);
  }
  const cmp = CMP[S.sortKey] || CMP.ts;
  const dir = S.sortDir === "desc" ? -1 : 1;
  S.idx.sort((ia, ib) => dir * cmp(S.rows[ia], S.rows[ib]) || (ia - ib) * dir);
  S.pending = 0;
  updatePendingChip();
}

function isAppendSafe() {
  return S.sortKey === "ts" && S.sortDir === "asc";
}

function ingest(rows) {
  if (!rows || !rows.length) return;
  for (const r of rows) {
    r.id = r.id ?? ++ingest.seq;
    if (S.rows.length >= MAX_ROWS) {
      // ring eviction: drop the oldest chunk, lazily fix indexes
      S.rows.splice(0, 20000);
      S.idx = S.idx.map((x) => x - 20000).filter((x) => x >= 0);
    }
    S.rows.push(r);
    if (isAppendSafe()) {
      if (matchesFilter(r)) S.idx.push(S.rows.length - 1);
    }
    S.live.push(r);
    if (S.live.length > LIVE_RING) S.live.splice(0, S.live.length - LIVE_RING);
    S.rateWindow.push(Date.now());
  }
  if (!isAppendSafe()) {
    S.pending += rows.length;
    updatePendingChip();
  }
  scheduleRender();
}
ingest.seq = 0;

function updatePendingChip() {
  const chip = $("pending-chip");
  if (S.pending > 0) {
    chip.textContent = `${S.pending.toLocaleString()} NEW — PULL ▼`;
    chip.classList.remove("hidden");
  } else {
    chip.classList.add("hidden");
  }
}

// ------------------------------------------------------------------ render

function scheduleRender() {
  if (S.renderQueued) return;
  S.renderQueued = true;
  requestAnimationFrame(() => {
    S.renderQueued = false;
    renderActiveView();
  });
}

function renderActiveView() {
  const view = document.querySelector(".view.active")?.id || "view-live";
  if (view === "view-live") renderLive();
  else if (view === "view-results") renderResults();
  else if (view === "view-anomalies") renderAnomalies();
  renderStats();
}

function renderStats() {
  $("live-count").textContent = S.rows.length.toLocaleString();
  const now = Date.now();
  S.rateWindow = S.rateWindow.filter((t) => now - t < 5000);
  $("live-rate").textContent = `${Math.round(S.rateWindow.length / 5)}/s`;
  if (S.scan && S.scan.started_at) {
    const end = S.scan.finished_at || now / 1000;
    $("live-elapsed").textContent = fmtDur(end - S.scan.started_at);
  }
}

function renderLive() {
  const feed = $("live-feed");
  const pin = $("live-pin").checked;
  const atBottom =
    feed.scrollHeight - feed.scrollTop - feed.clientHeight < 60;

  const html = S.live
    .map((r) => {
      const cls = r.status >= 500 ? "st-5" : r.status >= 200 && r.status < 300
        ? "st-2" : r.status >= 300 && r.status < 400 ? "st-3" : "st-4";
      const tag = r.anomaly_score > 0.5
        ? `<span class="tag">⚠ ${esc(r.anomaly_tags || "anomaly")}</span>` : "";
      return `<div class="line" data-url="${esc(r.url)}"><span class="st ${cls}">${r.status}</span>` +
        `<span>${esc(r.url)}</span>` +
        `<span class="tag">${fmtBytes(r.content_length)}</span>${tag}</div>`;
    })
    .join("");
  feed.innerHTML = html;
  if (pin && atBottom) feed.scrollTop = feed.scrollHeight;
}

function renderResults() {
  const scroll = $("res-scroll");
  const total = S.idx.length;
  $("res-spacer").style.height = `${total * ROW_H}px`;
  $("res-count").textContent = total.toLocaleString();

  const first = Math.max(0, Math.floor(scroll.scrollTop / ROW_H) - 6);
  const visible = Math.ceil(scroll.clientHeight / ROW_H) + 12;
  const rowsEl = $("res-rows");
  rowsEl.style.transform = `translateY(${first * ROW_H}px)`;

  let html = "";
  for (let i = first; i < Math.min(first + visible, total); i++) {
    const r = S.rows[S.idx[i]];
    if (!r) continue;
    const flags = (r.anomaly_tags || "").split(",").filter(Boolean).join(" · ");
    html +=
      `<div class="r" data-url="${esc(r.url)}" style="top:${(i - first) * ROW_H}px">` +
      `<span class="c1"><span class="badge ${statusClass(r.status)}">${r.status}</span></span>` +
      `<span class="c2">${fmtBytes(r.content_length)}</span>` +
      `<span class="c3">${r.word_count}</span>` +
      `<span class="c4">${r.line_count}</span>` +
      `<span class="c5" title="${esc(r.url)}">${esc(r.url)}</span>` +
      `<span class="c6">${r.anomaly_score > 0 ? `<span class="score-bar" style="width:${Math.round(r.anomaly_score * 60)}px"></span>` : ""}</span>` +
      `<span class="c7">${esc(flags)}</span>` +
      `<button class="row-copy" title="copy url">COPY</button>` +
      `</div>`;
  }
  rowsEl.innerHTML = html;
}

function renderAnomalies() {
  const rows = S.rows
    .filter((r) => r.anomaly_score > 0.5)
    .sort((a, b) => b.anomaly_score - a.anomaly_score)
    .slice(0, 500);
  $("anom-count").textContent = rows.length.toLocaleString();
  $("anom-rows").innerHTML = rows
    .map(
      (r) =>
        `<div class="sr" data-url="${esc(r.url)}">` +
        `<span class="c6"><span class="score-bar" style="width:${Math.round(r.anomaly_score * 60)}px"></span></span>` +
        `<span class="c1"><span class="badge ${statusClass(r.status)}">${r.status}</span></span>` +
        `<span class="c2">${fmtBytes(r.content_length)}</span>` +
        `<span class="c5">${esc(r.url)}</span>` +
        `<span class="c7">${esc(r.anomaly_tags || "")}</span>` +
        `<button class="row-copy" title="copy url">COPY</button></div>`
    )
    .join("");
}

// ------------------------------------------------------------------ SSE

function connectSSE() {
  const es = new EventSource("/api/stream");
  es.onmessage = (e) => {
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }
    if (msg.type === "batch" && msg.scan_id === S.scanId) {
      ingest(msg.rows);
    } else if (msg.type === "status") {
      refreshScan(msg.scan_id);
    }
  };
  es.onerror = () => { /* EventSource auto-reconnects */ };
}

// ------------------------------------------------------------------ api

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    const t = await res.text().catch(() => "");
    throw new Error(`${res.status}: ${t || res.statusText}`);
  }
  return res.status === 204 ? null : res.json();
}

async function loadScans() {
  S.scans = await api("/api/scans");
  $("hist-count").textContent = S.scans.length;
  $("hist-rows").innerHTML = S.scans
    .map((s) => {
      const d = new Date(s.created_at * 1000).toISOString().slice(0, 19).replace("T", " ");
      return `<div class="sr"><span class="c1">#${s.id}</span>` +
        `<span class="c5">${esc(s.target)}</span>` +
        `<span class="c2">${esc(s.wordlist)}</span>` +
        `<span class="c1"><span class="badge ${s.status === "running" ? "ok" : "dim"}">${s.status}</span></span>` +
        `<span class="c2">${s.rows_total}</span>` +
        `<span class="c3">${d}</span>` +
        `<span><button class="btn ghost" data-load="${s.id}">LOAD</button> ` +
        `<button class="btn ghost" data-del="${s.id}">DEL</button></span></div>`;
    })
    .join("");
}

async function loadWordlists() {
  S.wordlists = await api("/api/wordlists");
  $("wl-rows").innerHTML = S.wordlists
    .map(
      (w) =>
        `<div class="sr"><span class="c5">${esc(w.name)}</span>` +
        `<span class="c2">${w.kind}</span>` +
        `<span class="c2">${w.words.toLocaleString()} words</span>` +
        `<span>${w.kind === "uploaded" ? `<button class="btn ghost" data-delwl="${esc(w.name)}">DEL</button>` : "—"}</span></div>`
    )
    .join("");
  const sel = $("f-wordlist");
  sel.innerHTML = S.wordlists
    .map((w) => `<option value="${esc(w.name)}">${esc(w.name)} (${w.words})</option>`)
    .join("");
}

async function loadScanRows(scanId) {
  S.rows = [];
  S.idx = [];
  S.live = [];
  S.scanId = scanId;
  let offset = 0;
  for (;;) {
    const page = await api(
      `/api/scans/${scanId}/results?limit=${LIVE_BATCH_ROWS}&offset=${offset}&sort=ts&direction=asc`
    );
    ingest(page.rows);
    offset += page.rows.length;
    if (!page.rows.length || offset >= Math.min(page.total, 200000)) break;
  }
  S.scan = await api(`/api/scans/${scanId}`);
  rebuildIndex();
  updatePill();
  scheduleRender();
}

async function refreshScan(scanId) {
  if (scanId !== S.scanId) {
    loadScans();
    return;
  }
  S.scan = await api(`/api/scans/${scanId}`);
  updatePill();
  renderStats();
  loadScans();
}

function updatePill() {
  const pill = $("scan-pill");
  const st = S.scan?.status || "idle";
  pill.textContent = `SCAN #${S.scanId ?? "—"} · ${st.toUpperCase()}`;
  pill.className = "pill" + (st === "running" ? " live" : st === "error" ? " error" : "");
  $("stop-btn").disabled = st !== "running";
  $("live-target").textContent = S.scan?.target || "—";
}

// ------------------------------------------------------------------ events

function bindUI() {
  // tabs
  document.querySelectorAll(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
      btn.classList.add("active");
      $(`view-${btn.dataset.view}`).classList.add("active");
      if (btn.dataset.view === "history") loadScans();
      if (btn.dataset.view === "wordlists") loadWordlists();
      scheduleRender();
    });
  });

  // result sorting — freeze semantics documented in head comment
  document.querySelectorAll("#res-table th.sortable").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      if (S.sortKey === key) S.sortDir = S.sortDir === "asc" ? "desc" : "asc";
      else { S.sortKey = key; S.sortDir = key === "url" ? "asc" : "desc"; }
      document.querySelectorAll("#res-table th").forEach((h) => h.classList.remove("sorted"));
      th.classList.add("sorted");
      th.textContent = th.textContent.replace(/[▲▼]/g, "").trim() +
        (S.sortDir === "asc" ? " ▲" : " ▼");
      rebuildIndex();
      scheduleRender();
    });
  });

  // status class chips
  $("status-chips").addEventListener("click", (e) => {
    const chip = e.target.closest(".chip");
    if (!chip) return;
    document.querySelectorAll("#status-chips .chip").forEach((c) => c.classList.remove("active"));
    chip.classList.add("active");
    S.statusFilter = chip.dataset.status;
    rebuildIndex();
    scheduleRender();
  });

  let searchTimer;
  $("search").addEventListener("input", (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      S.q = e.target.value.trim().toLowerCase();
      rebuildIndex();
      scheduleRender();
    }, 150);
  });

  $("anomaly-only").addEventListener("change", (e) => {
    S.anomalyOnly = e.target.checked;
    rebuildIndex();
    scheduleRender();
  });

  $("refresh-btn").addEventListener("click", () => { rebuildIndex(); scheduleRender(); });
  $("pending-chip").addEventListener("click", () => { rebuildIndex(); scheduleRender(); });

  // bulk copy: exactly what the current view shows (respects sort + filters)
  $("copy-all-btn").addEventListener("click", () => {
    const urls = S.idx.map((i) => S.rows[i].url).join("\n");
    if (urls) copyText(urls);
    else flash("nothing to copy");
  });

  // virtual scroll
  let scrollQueued = false;
  $("res-scroll").addEventListener("scroll", () => {
    if (scrollQueued) return;
    scrollQueued = true;
    requestAnimationFrame(() => {
      scrollQueued = false;
      renderResults();
    });
  });

  // copy url on row click
  document.body.addEventListener("click", (e) => {
    const row = e.target.closest("[data-url]");
    if (row) {
      copyText(row.dataset.url);
      return;
    }
    const load = e.target.closest("[data-load]");
    if (load) { loadScanRows(Number(load.dataset.load)); return; }
    const del = e.target.closest("[data-del]");
    if (del) {
      api(`/api/scans/${del.dataset.del}`, { method: "DELETE" }).then(loadScans);
      return;
    }
    const delwl = e.target.closest("[data-delwl]");
    if (delwl) {
      api(`/api/wordlists/${encodeURIComponent(delwl.dataset.delwl)}`, { method: "DELETE" })
        .then(loadWordlists);
    }
  });

  // stop
  $("stop-btn").addEventListener("click", async () => {
    if (!S.scanId) return;
    await api(`/api/scans/${S.scanId}/stop`, { method: "POST" }).catch(() => {});
    refreshScan(S.scanId);
  });

  // reanalyze
  $("reanalyze-btn").addEventListener("click", async () => {
    if (!S.scanId) return;
    flash("re-analyzing…");
    const res = await api(`/api/scans/${S.scanId}/reanalyze`, { method: "POST" }).catch((e) => ({ error: String(e) }));
    flash(res?.error || `updated ${res?.updated ?? 0} rows`);
    if (!res?.error) await loadScanRows(S.scanId);
  });

  // wordlist upload
  $("wl-file").addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    await uploadWordlist(file);
    e.target.value = "";
  });
  const drop = $("wl-drop");
  drop.addEventListener("dragover", (e) => e.preventDefault());
  drop.addEventListener("drop", async (e) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file) await uploadWordlist(file);
  });

  // scan form
  $("scan-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      target: $("f-target").value.trim(),
      wordlist: $("f-wordlist").value,
      threads: Number($("f-threads").value),
      depth: Number($("f-depth").value),
      timeout: Number($("f-timeout").value),
      rate_limit: Number($("f-rate").value),
      extensions: $("f-ext").value.split(",").map((s) => s.trim()).filter(Boolean),
      methods: $("f-methods").value.split(",").map((s) => s.trim()).filter(Boolean),
      extra_args: $("f-extra").value.trim(),
      insecure: $("f-insecure").checked,
      redirects: $("f-redirects").checked,
      add_slash: $("f-slash").checked,
      no_recursion: $("f-norec").checked,
    };
    try {
      const res = await api("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      S.rows = []; S.idx = []; S.live = []; S.pending = 0;
      ingest.seq = 0;
      S.scanId = res.id;
      S.scan = await api(`/api/scans/${res.id}`);
      updatePill();
      loadScans();
      document.querySelector('[data-view="live"]').click();
      flash("scan started");
    } catch (err) {
      $("form-msg").textContent = String(err.message || err);
    }
  });

  // argv preview (cosmetic)
  $("scan-form").addEventListener("input", updateArgvPreview);
  updateArgvPreview();
}

async function uploadWordlist(file) {
  const name = file.name.replace(/[^\w.-]/g, "_");
  await api(`/api/wordlists?name=${encodeURIComponent(name)}`, {
    method: "POST",
    body: file,
  });
  await loadWordlists();
  flash(`uploaded ${name}`);
}

function updateArgvPreview() {
  const ext = $("f-ext").value.trim();
  const parts = [
    "feroxbuster",
    "-u", $("f-target").value.trim() || "<target>",
    "--silent", "--json",
    "-w", `/wordlists/${$("f-wordlist").value || "common.txt"}`,
    "-t", $("f-threads").value || "50",
    "-d", $("f-depth").value || "2",
  ];
  if (ext) ext.split(",").filter(Boolean).forEach((e) => parts.push("-x", e.trim()));
  const m = $("f-methods").value.trim();
  if (m) parts.push("-m", ...m.split(",").map((s) => s.trim()));
  if (Number($("f-rate").value) > 0) parts.push("--rate-limit", $("f-rate").value);
  if ($("f-insecure").checked) parts.push("-k");
  if ($("f-redirects").checked) parts.push("-r");
  if ($("f-slash").checked) parts.push("-f");
  if ($("f-norec").checked) parts.push("-n");
  if ($("f-extra").value.trim()) parts.push($("f-extra").value.trim());
  $("argv-preview").textContent = "$ " + parts.join(" ");
}

let flashTimer;
function flash(msg) {
  const el = $("toast");
  el.textContent = msg;
  el.classList.remove("hidden");
  clearTimeout(flashTimer);
  flashTimer = setTimeout(() => el.classList.add("hidden"), 2500);
}

// ------------------------------------------------------------------ boot

connectSSE();
bindUI();
loadWordlists();
loadScans().then(() => {
  if (S.scans.length) loadScanRows(S.scans[0].id);
});
