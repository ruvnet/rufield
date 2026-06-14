// RuField MFS dashboard — vanilla JS, no framework, no build step.
//
// Consumes the /events SSE stream (meta → frame* → done, looping) and renders:
//   1. live room state (fused inferences)
//   2. a scrolling event log with modality + privacy-class badges
//   3. a fusion graph (supporting / contradicting edges per inference)
//   4. run-integrity stats
//   5. a provenance-receipt modal (click any event)
//
// Everything shown is SYNTHETIC — the banner says so and we never imply live
// hardware.

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
    node.innerHTML =
      `<div class="row1">` +
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
    renderMeta(meta);
    setStatus("live", `streaming · ${meta.total_frames} ticks · seed ${meta.seed}`);
  });

  src.addEventListener("frame", (e) => {
    const f = JSON.parse(e.data);
    appendEvents(f.events);
    renderRoomState(f.inferences);
    renderGraph(f.inferences);
  });

  src.addEventListener("done", () => {
    setStatus("done", "demo complete — looping");
  });

  src.onerror = () => {
    setStatus("", "reconnecting…");
  };
}

window.addEventListener("DOMContentLoaded", () => {
  $("modal-close").addEventListener("click", closeReceipt);
  $("modal-backdrop").addEventListener("click", (e) => {
    if (e.target === $("modal-backdrop")) closeReceipt();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeReceipt();
  });
  connect();
});
