//! Drives the deterministic `SyntheticSim` → `RuFieldFusion` pipeline and
//! captures it as serializable, tick-grouped frames the dashboard can render.
//!
//! This module **does not reinvent the pipeline** — it runs exactly the same
//! `run_demo` → `RuFieldFusion::ingest`/`infer` flow the benchmark
//! (`rufield-bench`) uses, and snapshots the result tick-by-tick so the viewer
//! can replay it at a watchable cadence. Every number here is **SYNTHETIC**.

use rufield_core::{
    Destination, FieldEvent, FieldInference, FusionEngine, InferenceQuery, PrivacyClass,
    PrivacyDecision, PrivacyGuard,
};
use rufield_fusion::{EdgeKind, RuFieldFusion};
use rufield_privacy::DefaultPrivacyGuard;
use rufield_provenance::{is_fusable, verify_event};
use serde::Serialize;
use std::collections::BTreeSet;

/// The privacy-class badge label (P0–P5) plus its level, used by the UI.
#[derive(Debug, Clone, Serialize)]
pub struct PrivacyBadge {
    /// The `P0`..`P5` string code.
    pub class: String,
    /// Numeric level 0..=5.
    pub level: u8,
}

impl From<PrivacyClass> for PrivacyBadge {
    fn from(p: PrivacyClass) -> Self {
        PrivacyBadge {
            class: format!("P{}", p.level()),
            level: p.level(),
        }
    }
}

/// A signed provenance receipt as shown in the receipt viewer.
#[derive(Debug, Clone, Serialize)]
pub struct ReceiptView {
    /// `sha256:` of the raw measurement.
    pub raw_hash: String,
    /// `sha256:` of the producing firmware.
    pub firmware_hash: String,
    /// Model id that produced derived features.
    pub model_id: String,
    /// Calibration receipt id.
    pub calibration_id: String,
    /// Whether this event is simulator-flagged (always true in v0.1).
    pub synthetic: bool,
    /// Hex ed25519 signature, if present.
    pub signature_hex: Option<String>,
    /// Hex ed25519 signer public key, if present.
    pub signer_pubkey_hex: Option<String>,
    /// Whether the signature verifies against the event (`verify_event`).
    pub verified: bool,
    /// Whether the event passes the §11 fusability invariant.
    pub fusable: bool,
}

impl ReceiptView {
    /// Build a receipt view from an event, computing the verified ✓/✗ and
    /// §11-fusable flags. Shared by the synthetic and live-ingest paths.
    #[must_use]
    pub fn from_event(ev: &FieldEvent) -> Self {
        ReceiptView {
            raw_hash: ev.provenance.raw_hash.clone(),
            firmware_hash: ev.provenance.firmware_hash.clone(),
            model_id: ev.provenance.model_id.clone(),
            calibration_id: ev.provenance.calibration_id.clone(),
            synthetic: ev.provenance.synthetic,
            signature_hex: ev.provenance.signature_hex.clone(),
            signer_pubkey_hex: ev.provenance.signer_pubkey_hex.clone(),
            verified: verify_event(ev).is_ok(),
            fusable: is_fusable(ev),
        }
    }
}

/// One event as rendered in the scrolling event log.
#[derive(Debug, Clone, Serialize)]
pub struct EventView {
    /// Stable event id.
    pub event_id: String,
    /// Capture timestamp (ns since epoch).
    pub timestamp_ns: u64,
    /// Modality string code (`wifi_csi` / `mmwave_radar` / `infrared_thermal`).
    pub modality: String,
    /// Human label for the modality.
    pub modality_label: String,
    /// Device id of the emitting sensor.
    pub device_id: String,
    /// Zone the observation belongs to.
    pub zone_id: Option<String>,
    /// Observation confidence.
    pub confidence: f32,
    /// Privacy-class badge (P0–P5).
    pub privacy: PrivacyBadge,
    /// Ground-truth labels (SYNTHETIC — scored against, never fused).
    pub truth_labels: Vec<String>,
    /// Signed provenance receipt.
    pub receipt: ReceiptView,
}

/// A single fused inference as rendered in the room-state + fusion-graph panels.
#[derive(Debug, Clone, Serialize)]
pub struct InferenceView {
    /// Inference label (e.g. `person_present`).
    pub label: String,
    /// Confidence `0.0..=1.0`.
    pub confidence: f32,
    /// Privacy-class badge of the inference.
    pub privacy: PrivacyBadge,
    /// Event ids supporting this inference (fusion-graph edges).
    pub supporting_events: Vec<String>,
    /// Event ids contradicting this inference.
    pub contradicting_events: Vec<String>,
    /// Rule / model id that produced it.
    pub model_id: String,
}

impl From<&FieldInference> for InferenceView {
    fn from(i: &FieldInference) -> Self {
        InferenceView {
            label: i.label.clone(),
            confidence: i.confidence,
            privacy: i.privacy_class.into(),
            supporting_events: i.supporting_events.clone(),
            contradicting_events: i.contradicting_events.clone(),
            model_id: i.model_id.clone(),
        }
    }
}

/// One tick of the demo: the events that arrived this tick and the room state
/// the fusion engine produced after ingesting them.
#[derive(Debug, Clone, Serialize)]
pub struct TickFrame {
    /// Zero-based tick index in the demo sequence.
    pub tick: usize,
    /// Capture timestamp shared by every event in this tick.
    pub timestamp_ns: u64,
    /// Events that arrived during this tick (one per modality).
    pub events: Vec<EventView>,
    /// Fused room-state inferences current after this tick.
    pub inferences: Vec<InferenceView>,
}

/// The complete deterministic run: metadata + every tick frame.
#[derive(Debug, Clone, Serialize)]
pub struct RunData {
    /// Wire spec version.
    pub spec_version: String,
    /// Always true — every signal is synthetic, no hardware involved.
    pub synthetic: bool,
    /// Seed that anchors determinism.
    pub seed: u64,
    /// Total events across all ticks.
    pub events_total: usize,
    /// Distinct modalities present.
    pub modalities: Vec<String>,
    /// Distinct inference labels produced across the whole run.
    pub distinct_inferences: Vec<String>,
    /// Count of events transmitted above the P2 network ceiling (target 0).
    pub privacy_violations: u32,
    /// Provenance coverage percentage (target 100).
    pub provenance_coverage_pct: f64,
    /// The per-tick frames in deterministic order.
    pub frames: Vec<TickFrame>,
}

/// Produce the full deterministic run for a fixed `seed`.
///
/// Streams the `SyntheticSim` demo through `RuFieldFusion`, grouping events by
/// tick (their shared timestamp) and snapshotting the fused inferences after
/// each tick — exactly mirroring the benchmark runner's flow.
#[must_use]
pub fn build_run(seed: u64) -> RunData {
    use rufield_adapters::{run_demo, SimConfig};

    let cfg = SimConfig { seed, ..SimConfig::default() };
    let sim_events = run_demo(&cfg);

    // Group by tick (shared timestamp), preserving first-seen order.
    let mut tick_order: Vec<u64> = Vec::new();
    let mut by_tick: std::collections::BTreeMap<u64, Vec<&rufield_adapters::SimEvent>> =
        std::collections::BTreeMap::new();
    for se in &sim_events {
        let ts = se.event.timestamp_ns;
        if !by_tick.contains_key(&ts) {
            tick_order.push(ts);
        }
        by_tick.entry(ts).or_default().push(se);
    }

    let guard = DefaultPrivacyGuard::default();
    let mut engine = RuFieldFusion::new();

    let mut frames: Vec<TickFrame> = Vec::with_capacity(tick_order.len());
    let mut modalities: BTreeSet<String> = BTreeSet::new();
    let mut distinct: BTreeSet<String> = BTreeSet::new();
    let mut prov_ok: usize = 0;
    let mut privacy_violations: u32 = 0;

    for (tick, ts) in tick_order.iter().enumerate() {
        let batch = &by_tick[ts];
        let mut event_views = Vec::with_capacity(batch.len());

        for se in batch {
            let ev = &se.event;
            modalities.insert(ev.sensor.modality.clone());

            if is_fusable(ev) {
                prov_ok += 1;
            }
            // Privacy guard check (mirrors the benchmark): an event above the
            // P2 default ceiling denied for network transmission is a violation.
            let decision =
                guard.authorize(ev.observation.privacy_class, Destination::Network, false, false);
            if matches!(decision, PrivacyDecision::Deny(_))
                && ev.observation.privacy_class > PrivacyClass::P2
            {
                privacy_violations += 1;
            }

            event_views.push(EventView {
                event_id: ev.event_id.clone(),
                timestamp_ns: ev.timestamp_ns,
                modality: ev.sensor.modality.clone(),
                modality_label: modality_label(&ev.sensor.modality),
                device_id: ev.sensor.device_id.clone(),
                zone_id: ev.observation.zone_id.clone(),
                confidence: ev.observation.confidence,
                privacy: ev.observation.privacy_class.into(),
                truth_labels: ev.observation.labels.clone(),
                receipt: ReceiptView::from_event(ev),
            });

            // Ingest into the fusion engine (drives the live room state + graph).
            let _ = engine.ingest(ev.clone());
        }

        let produced = engine.infer(&InferenceQuery::all()).unwrap_or_default();
        for inf in &produced {
            distinct.insert(inf.label.clone());
        }
        let inference_views: Vec<InferenceView> =
            produced.iter().map(InferenceView::from).collect();

        frames.push(TickFrame {
            tick,
            timestamp_ns: *ts,
            events: event_views,
            inferences: inference_views,
        });
    }

    // Sanity: the fusion graph recorded observed_by edges for provenance.
    debug_assert!(engine.graph().edges_of(EdgeKind::ObservedBy).len() == sim_events.len());

    let coverage = if sim_events.is_empty() {
        100.0
    } else {
        (prov_ok as f64 / sim_events.len() as f64) * 100.0
    };

    RunData {
        spec_version: rufield_core::SPEC_VERSION.to_string(),
        synthetic: true,
        seed,
        events_total: sim_events.len(),
        modalities: modalities.into_iter().collect(),
        distinct_inferences: distinct.into_iter().collect(),
        privacy_violations,
        provenance_coverage_pct: coverage,
        frames,
    }
}

/// Human-readable label for a modality string code.
fn modality_label(code: &str) -> String {
    match code {
        "wifi_csi" => "WiFi CSI",
        "mmwave_radar" => "mmWave Radar",
        "infrared_thermal" => "Infrared Thermal",
        other => other,
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_is_deterministic_for_fixed_seed() {
        let a = serde_json::to_string(&build_run(2026)).unwrap();
        let b = serde_json::to_string(&build_run(2026)).unwrap();
        assert_eq!(a, b, "same seed must yield byte-identical run JSON");
    }

    #[test]
    fn run_has_three_modalities_each_with_privacy_and_receipt() {
        let run = build_run(2026);
        assert_eq!(run.modalities.len(), 3, "expected 3 modalities");
        for want in ["wifi_csi", "mmwave_radar", "infrared_thermal"] {
            assert!(run.modalities.iter().any(|m| m == want), "missing {want}");
        }
        let mut seen_mods: BTreeSet<String> = BTreeSet::new();
        for frame in &run.frames {
            for ev in &frame.events {
                seen_mods.insert(ev.modality.clone());
                // Every event carries a privacy class badge...
                assert!(ev.privacy.level <= 5);
                // ...and a provenance receipt with the four content hashes.
                assert!(ev.receipt.raw_hash.starts_with("sha256:"));
                assert!(ev.receipt.firmware_hash.starts_with("sha256:"));
                assert!(ev.receipt.signature_hex.is_some(), "event must be signed");
                assert!(ev.receipt.verified, "signature must verify");
                assert!(ev.receipt.fusable, "event must be §11-fusable");
            }
        }
        // ≥1 event per modality.
        assert_eq!(seen_mods.len(), 3);
    }

    #[test]
    fn run_produces_at_least_five_room_state_inferences() {
        let run = build_run(2026);
        assert!(
            run.distinct_inferences.len() >= 5,
            "expected >=5 distinct inferences, got {}: {:?}",
            run.distinct_inferences.len(),
            run.distinct_inferences
        );
    }

    #[test]
    fn run_keeps_privacy_and_provenance_invariants() {
        let run = build_run(2026);
        assert_eq!(run.privacy_violations, 0, "no privacy violations");
        assert!((run.provenance_coverage_pct - 100.0).abs() < 1e-9);
        assert!(run.synthetic, "run must be flagged synthetic");
    }

    #[test]
    fn frames_are_tick_ordered() {
        let run = build_run(7);
        for (i, frame) in run.frames.iter().enumerate() {
            assert_eq!(frame.tick, i, "frame tick indices must be sequential");
        }
        // Timestamps strictly increasing across frames.
        for w in run.frames.windows(2) {
            assert!(w[1].timestamp_ns > w[0].timestamp_ns);
        }
    }
}
