// RuField MFS dashboard — vanilla JS, no framework, no build step.
//
// Consumes the /events SSE stream (meta → frame* → done, looping) and renders:
//   1. live room state (fused inferences)
//   2. a scrolling event log with modality + privacy-class badges
//   3. a fusion graph (supporting / contradicting edges per inference)
//   4. run-integrity stats
//   5. a provenance-receipt modal (click any event)
//
// The banner is honest by construction: it is set from /api/source (SYNTHETIC /
// LIVE / DISCONNECTED) and the SSE `meta` event, so it always matches the data
// actually being displayed. Live mode renders ONLY receipt-verified events.

"use strict";

const $ = (id) => document.getElementById(id);
const el = (tag, cls, html) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html !== undefined) e.innerHTML = html;
  return e;
};
const esc = (s) =>
  String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

// All events seen so far, keyed by event_id, so the receipt modal can look them up.
const EVENTS = new Map();

const pcBadge = (pc) => `<span class="pc pc-${esc(pc.class)}" title="privacy class level ${pc.level}">${esc(pc.class)}</span>`;
const modTag = (m, label) => `<span class="mod mod-${esc(m)}">${esc(label || m)}</span>`;

function setStatus(state, text) {
  const dot = $("status-dot");
  dot.className = state; // '', 'live', 'done'
  $("status-text").textContent = text;
}

// ---- Source banner (honesty) ----------------------------------------------
// Drives the persistent banner from the server's single source of truth. The
// three states are visually distinct and never interchangeable:
//   synthetic    → amber "SYNTHETIC — simulated sensors, no hardware"
//   live         → green  "LIVE — <upstream>"  (real, receipt-verified)
//   disconnected → red    "DISCONNECTED — <upstream> unreachable"
let SOURCE = "synthetic";
function applyBanner(banner) {
  const b = $("source-banner");
  if (!b || !banner) return;
  const state = banner.state || "synthetic";
  b.dataset.state = state;
  const label = banner.label || "";
  if (state === "synthetic") {
    b.textContent =
      "⚠ SYNTHETIC — simulated sensors, no hardware. Every signal below is a deterministic simulator replay, not a live sensor.";
  } else if (state === "live") {
    b.textContent = `● ${label} — REAL upstream FieldEvents, receipt-verified on ingest. No camera, no identity.`;
  } else {
    b.textContent = `✕ ${label}. Live source selected but no events received — NOT falling back to synthetic.`;
  }
}

async function loadSource() {
  try {
    const r = await fetch("/api/source");
    const s = await r.json();
    SOURCE = s.source || "synthetic";
    // `banner` may be {state, upstream}; normalize a label for the UI.
    const banner = s.banner || { state: SOURCE };
    banner.label = banner.label || s.banner_label;
    applyBanner(banner);
  } catch (_) {
    /* leave the default SYNTHETIC banner in place */
  }
}

// ---- Room state -----------------------------------------------------------
function renderRoomState(inferences) {
  const grid = $("state-grid");
  // Stable ordering: known labels first, then any extras alphabetically.
  const ORDER = [
    "person_present", "sitting", "sleeping", "breathing",
    "nocturnal_scratch", "bed_exit", "room_transition",
  ];
  const byLabel = new Map(inferences.map((i) => [i.label, i]));
  const labels = ORDER.concat(
    [...byLabel.keys()].filter((l) => !ORDER.includes(l)).sort()
  );

  grid.innerHTML = "";
  for (const label of labels) {
    const inf = byLabel.get(label);
    const active = !!inf;
    const conf = active ? inf.confidence : 0;
    const card = el("div", "state-card" + (active ? " active" : ""));
    const pc = active ? " " + pcBadge(inf.privacy) : "";
    card.innerHTML =
      `<div class="label">${esc(prettyLabel(label))}${pc}</div>` +
      `<div class="conf">${(conf * 100).toFixed(0)}<span style="font-size:12px">%</span></div>` +
      `<div class="bar"><i style="width:${(conf * 100).toFixed(0)}%"></i></div>`;
    grid.appendChild(card);
  }
}

const prettyLabel = (l) =>
  l.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

// ---- Event log ------------------------------------------------------------
function appendEvents(events) {
  const log = $("event-log");
  for (const ev of events) {
    EVENTS.set(ev.event_id, ev);
    const truth = ev.truth_labels.length
      ? `<div class="truth"><b>truth:</b> ${ev.truth_labels.map(esc).join(", ")}</div>`
      : `<div class="truth">truth: (empty room)</div>`;
    const node = el("div", "ev");
    node.dataset.eid = ev.event_id;
    // Per-event verified ✓/✗ badge. Unverified (forged/tampered) events are
    // shown but visibly flagged — they are NOT fused into trusted inferences.
    const verified = ev.receipt && ev.receipt.verified;
    const vbadge = verified
      ? `<span class="verify-ok" title="provenance receipt verified">✓</span>`
      : `<span class="verify-bad" title="receipt NOT verified — flagged, not fused">✗ unverified</span>`;
    if (!verified) node.classList.add("ev-unverified");
    node.innerHTML =
      `<div class="row1">` +
      vbadge +
      modTag(ev.modality, ev.modality_label) +
      pcBadge(ev.privacy) +
      `<span class="eid">${esc(ev.event_id)}</span>` +
      `<span class="conf">conf ${(ev.confidence * 100).toFixed(0)}%</span>` +
      `</div>` + truth;
    node.addEventListener("click", () => openReceipt(ev.event_id));
    log.prepend(node);
  }
  // Cap DOM size so a long-running loop does not grow unbounded.
  while (log.children.length > 60) log.removeChild(log.lastChild);
}

// ---- Fusion graph ---------------------------------------------------------
function renderGraph(inferences) {
  const g = $("graph");
  g.innerHTML = "";
  if (!inferences.length) {
    g.appendChild(el("div", "sub", "No active inferences this tick."));
    return;
  }
  for (const inf of inferences) {
    const node = el("div", "inf");
    const sup = inf.supporting_events.length
      ? `supports → ${inf.supporting_events.map((e) => `<code>${esc(short(e))}</code>`).join(" ")}`
      : "supports → (none)";
    const con = inf.contradicting_events.length
      ? `<span class="contra">contradicts → ${inf.contradicting_events.map((e) => `<code>${esc(short(e))}</code>`).join(" ")}</span>`
      : "";
    node.innerHTML =
      `<div class="head"><span class="name">${esc(prettyLabel(inf.label))}</span>` +
      pcBadge(inf.privacy) +
      `<span class="model">${esc(inf.model_id)} · ${(inf.confidence * 100).toFixed(0)}%</span></div>` +
      `<div class="edges">${sup}${con ? "<br>" + con : ""}</div>`;
    g.appendChild(node);
  }
}
const short = (id) => (id.length > 18 ? id.slice(0, 8) + "…" + id.slice(-4) : id);

// ---- Meta / run integrity -------------------------------------------------
function renderMeta(meta) {
  const grid = $("meta-grid");
  const violationsClass = meta.privacy_violations === 0 ? "good" : "bad";
  const covClass = Math.abs(meta.provenance_coverage_pct - 100) < 1e-9 ? "good" : "bad";
  const stats = [
    ["modalities", meta.modalities.length, ""],
    ["events total", meta.events_total, ""],
    ["distinct inferences", meta.distinct_inferences.length, ""],
    ["privacy violations", meta.privacy_violations, violationsClass],
    ["provenance coverage", meta.provenance_coverage_pct.toFixed(0) + "%", covClass],
    ["seed", meta.seed, ""],
  ];
  grid.innerHTML = "";
  for (const [k, v, cls] of stats) {
    const s = el("div", "stat");
    s.innerHTML = `<div class="k">${esc(k)}</div><div class="v ${cls}">${esc(v)}</div>`;
    grid.appendChild(s);
  }
  $("spec-line").textContent = `spec ${meta.spec_version} · SYNTHETIC`;
}

// Live meta carries only the banner/source (no deterministic run aggregates).
function renderLiveMeta(meta) {
  applyBanner(meta.banner || { state: "live", label: meta.banner_label });
  $("spec-line").textContent = `spec ${meta.spec_version} · LIVE`;
  const up = meta.upstream || "upstream";
  setStatus("live", `live · ${up}`);
}

// Update the integrity panel from a live frame's verification counters.
function renderLiveIntegrity(verified, unverified) {
  const grid = $("meta-grid");
  const unvClass = unverified === 0 ? "good" : "bad";
  const stats = [
    ["source", "LIVE", "good"],
    ["verified events", verified, "good"],
    ["unverified (flagged, not fused)", unverified, unvClass],
  ];
  grid.innerHTML = "";
  for (const [k, v, cls] of stats) {
    const s = el("div", "stat");
    s.innerHTML = `<div class="k">${esc(k)}</div><div class="v ${cls}">${esc(v)}</div>`;
    grid.appendChild(s);
  }
}

// ---- Receipt modal --------------------------------------------------------
function openReceipt(eventId) {
  const ev = EVENTS.get(eventId);
  if (!ev) return;
  const r = ev.receipt;
  $("modal-title").textContent = "Provenance Receipt";
  $("modal-sub").innerHTML =
    `${modTag(ev.modality, ev.modality_label)} ${pcBadge(ev.privacy)} <span class="eid">${esc(ev.event_id)}</span>`;
  const verified = r.verified
    ? `<span class="verify-ok">✓ verified</span>`
    : `<span class="verify-bad">✗ NOT verified</span>`;
  const fusable = r.fusable
    ? `<span class="verify-ok">✓ fusable (§11)</span>`
    : `<span class="verify-bad">✗ not fusable</span>`;
  const rows = [
    ["signature", verified],
    ["fusability", fusable],
    ["synthetic", r.synthetic ? "true (simulator-flagged)" : "false"],
    ["raw hash", esc(r.raw_hash)],
    ["firmware hash", esc(r.firmware_hash)],
    ["model id", esc(r.model_id)],
    ["calibration id", esc(r.calibration_id)],
    ["signer pubkey", esc(r.signer_pubkey_hex || "—")],
    ["signature", esc(r.signature_hex || "—")],
  ];
  $("modal-body").innerHTML = rows
    .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`)
    .join("");
  $("modal-backdrop").classList.add("open");
}
function closeReceipt() {
  $("modal-backdrop").classList.remove("open");
}

// ---- SSE wiring -----------------------------------------------------------
function connect() {
  const src = new EventSource("/events");

  src.addEventListener("meta", (e) => {
    const meta = JSON.parse(e.data);
    if (meta.source === "live") {
      renderLiveMeta(meta);
    } else {
      renderMeta(meta);
      setStatus("live", `streaming · ${meta.total_frames} ticks · seed ${meta.seed}`);
    }
  });

  src.addEventListener("frame", (e) => {
    const payload = JSON.parse(e.data);
    // Synthetic frames are bare TickFrames; live frames wrap one in
    // {frame, verified_count, unverified_count}. Normalize both.
    const f = payload.frame ? payload.frame : payload;
    appendEvents(f.events);
    renderRoomState(f.inferences);
    renderGraph(f.inferences);
    if (payload.frame) {
      renderLiveIntegrity(payload.verified_count, payload.unverified_count);
      setStatus("live", "live · receiving upstream events");
    }
  });

  src.addEventListener("done", () => {
    setStatus("done", "demo complete — looping");
  });

  src.onerror = () => {
    // In live mode a transport error means we are not currently receiving the
    // upstream — surface DISCONNECTED honestly instead of implying live data.
    if (SOURCE === "live") {
      setStatus("", "disconnected — upstream not streaming");
    } else {
      setStatus("", "reconnecting…");
    }
  };
}

window.addEventListener("DOMContentLoaded", async () => {
  $("modal-close").addEventListener("click", closeReceipt);
  $("modal-backdrop").addEventListener("click", (e) => {
    if (e.target === $("modal-backdrop")) closeReceipt();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeReceipt();
  });
  // Establish the honest banner before opening the stream.
  await loadSource();
  connect();
});
