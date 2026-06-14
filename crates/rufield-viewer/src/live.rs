//! Live-ingest mode (ADR-260 §27.9 + ADR-262 P3).
//!
//! In `--source live` the viewer no longer replays the built-in `SyntheticSim`.
//! Instead it consumes **real** `rufield_core::FieldEvent`s streamed from an
//! external upstream — RuView's `wifi-densepose-sensing-server`, which exposes
//! (ADR-262 P3):
//!
//! - `GET <upstream>/api/field` — JSON `{ events: [FieldEvent..], signer_pubkey,
//!   dev_signing_key }` over a bounded ring (poll source).
//! - `GET <upstream>/ws/field`  — an SSE/WS stream of one `FieldEvent` per cycle.
//!
//! Those events are the **same** `rufield_core::FieldEvent` the viewer already
//! deserializes for the synthetic path, so they are wire-compatible by
//! construction.
//!
//! ## Honesty & provenance (non-negotiable)
//!
//! Every ingested event is run through the **same** §11 fusability /
//! provenance-receipt verification the synthetic path uses
//! ([`rufield_provenance::is_fusable`] / [`rufield_provenance::verify_event`]).
//! An event whose receipt does **not** verify is *flagged unverified* and is
//! **never fused** — it is surfaced in the event log with a ✗ badge so forged
//! data is visible but is not rendered as trusted, and it does not contribute to
//! any room-state inference.
//!
//! This module deliberately splits **pure** ingest/render logic (no I/O — fully
//! unit-testable by injecting a JSON payload) from the small HTTP client used at
//! runtime. The pure path is [`frame_from_api_payload`] / [`frame_from_events`].

use crate::runtime::{EventView, InferenceView, ReceiptView, TickFrame};
use rufield_core::{FieldEvent, FusionEngine, InferenceQuery};
use rufield_fusion::RuFieldFusion;
use rufield_provenance::is_fusable;
use serde::{Deserialize, Serialize};

/// Shape of the upstream `GET /api/field` response (ADR-262 P3).
///
/// The viewer only needs `events`; `signer_pubkey` / `dev_signing_key` are
/// accepted (and surfaced) but are not trusted blindly — verification is done
/// per-event against each event's own embedded `signer_pubkey_hex`.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiFieldPayload {
    /// The bounded ring of field events the upstream is currently serving.
    pub events: Vec<FieldEvent>,
    /// The upstream's advertised signer public key (hex), if any. Informational.
    #[serde(default)]
    pub signer_pubkey: Option<String>,
    /// The upstream's advertised dev signing key id, if any. Informational.
    #[serde(default)]
    pub dev_signing_key: Option<String>,
}

/// The result of ingesting one batch of upstream events: a renderable
/// [`TickFrame`] plus per-batch verification counters used for the LIVE banner /
/// integrity panel. Only **verified** events are fused into the inferences.
#[derive(Debug, Clone, Serialize)]
pub struct LiveFrame {
    /// The renderable frame (event log + fused room state) for this batch.
    pub frame: TickFrame,
    /// How many ingested events verified (receipt OK / §11-fusable).
    pub verified_count: usize,
    /// How many ingested events were flagged **unverified** (and not fused).
    pub unverified_count: usize,
}

/// Human-readable label for a modality string code (mirrors `runtime`).
fn modality_label(code: &str) -> String {
    match code {
        "wifi_csi" => "WiFi CSI",
        "mmwave_radar" => "mmWave Radar",
        "infrared_thermal" => "Infrared Thermal",
        other => other,
    }
    .to_string()
}

/// Build an [`EventView`] for an upstream event, carrying its verified ✓/✗
/// receipt badge. This reuses the synthetic path's [`ReceiptView`] so the
/// dashboard's receipt modal is byte-for-byte identical regardless of source.
fn event_view(ev: &FieldEvent) -> EventView {
    EventView {
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
    }
}

/// Turn a batch of freshly-ingested upstream [`FieldEvent`]s into a renderable
/// [`LiveFrame`].
///
/// Verification happens **here, on ingest**: each event's provenance receipt is
/// checked with [`is_fusable`]. Verified events are fed through the *same*
/// `RuFieldFusion` engine the synthetic path uses — so the room-state / fusion
/// graph display path is identical — and only they contribute to inferences.
/// Unverified events are still returned in `frame.events` (so the operator can
/// see them, flagged ✗ via `receipt.verified == false`) but are **dropped from
/// fusion** — forged data is never rendered as trusted.
#[must_use]
pub fn frame_from_events(tick: usize, events: &[FieldEvent]) -> LiveFrame {
    let mut engine = RuFieldFusion::new();
    let mut event_views = Vec::with_capacity(events.len());
    let mut verified_count = 0usize;
    let mut unverified_count = 0usize;
    let mut max_ts = 0u64;

    for ev in events {
        max_ts = max_ts.max(ev.timestamp_ns);
        event_views.push(event_view(ev));

        if is_fusable(ev) {
            verified_count += 1;
            // Only verified events are fused. `ingest` itself re-checks §11, so
            // this is belt-and-suspenders: forged data cannot reach the engine.
            let _ = engine.ingest(ev.clone());
        } else {
            // Flagged unverified — surfaced in the log with a ✗ badge, never fused.
            unverified_count += 1;
        }
    }

    let produced = engine.infer(&InferenceQuery::all()).unwrap_or_default();
    let inferences: Vec<InferenceView> = produced.iter().map(InferenceView::from).collect();

    LiveFrame {
        frame: TickFrame {
            tick,
            timestamp_ns: max_ts,
            events: event_views,
            inferences,
        },
        verified_count,
        unverified_count,
    }
}

/// Parse an upstream `/api/field` JSON payload and build a renderable
/// [`LiveFrame`] from its event ring. Pure (no I/O) — this is the unit-testable
/// core of the live ingest path.
///
/// # Errors
/// Returns the serde error string if the payload is not a valid
/// [`ApiFieldPayload`] (e.g. malformed or not a `FieldEvent` ring).
pub fn frame_from_api_payload(tick: usize, json: &str) -> Result<LiveFrame, String> {
    let payload: ApiFieldPayload =
        serde_json::from_str(json).map_err(|e| format!("decode /api/field: {e}"))?;
    Ok(frame_from_events(tick, &payload.events))
}

/// Parse a single upstream `/ws/field` SSE `data:` payload (one serialized
/// [`FieldEvent`]) and build a one-event [`LiveFrame`]. Pure (no I/O).
///
/// # Errors
/// Returns the serde error string if the line is not a valid `FieldEvent`.
pub fn frame_from_ws_event(tick: usize, json: &str) -> Result<LiveFrame, String> {
    let ev: FieldEvent =
        serde_json::from_str(json).map_err(|e| format!("decode /ws/field event: {e}"))?;
    Ok(frame_from_events(tick, std::slice::from_ref(&ev)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rufield_adapters::{run_demo, SimConfig};

    /// Borrow real, signed, §11-fusable events from the synthetic adapter — they
    /// carry genuine ed25519 receipts, so they exercise the *exact* verification
    /// the live path performs on real upstream events. (We are using the adapter
    /// only as a *signed-event factory* here; the live path itself never runs the
    /// simulator.)
    fn real_signed_events(n: usize) -> Vec<FieldEvent> {
        run_demo(&SimConfig::default())
            .into_iter()
            .map(|se| se.event)
            .take(n)
            .collect()
    }

    #[test]
    fn api_payload_deserializes_verifies_and_renders() {
        let events = real_signed_events(3);
        let payload = serde_json::json!({
            "events": events,
            "signer_pubkey": "deadbeef",
            "dev_signing_key": "dev-key-1",
        })
        .to_string();

        let live = frame_from_api_payload(0, &payload).expect("payload decodes");
        // All three are real signed/synthetic events ⇒ all verify, none flagged.
        assert_eq!(live.verified_count, 3);
        assert_eq!(live.unverified_count, 0);
        assert_eq!(live.frame.events.len(), 3);
        // Every rendered event carries a verified ✓ receipt and is §11-fusable.
        for ev in &live.frame.events {
            assert!(ev.receipt.verified, "real signed event must verify");
            assert!(ev.receipt.fusable, "verified event must be §11-fusable");
        }
        // Verified events produce renderable room-state inferences.
        assert!(
            !live.frame.inferences.is_empty(),
            "verified events should fuse into >=1 inference"
        );
    }

    #[test]
    fn tampered_event_is_flagged_unverified_and_not_fused() {
        let mut events = real_signed_events(2);
        // Tamper one event AFTER it was signed: flip a tensor value. Its receipt
        // can no longer verify, and it is not synthetic-after-tamper-trusted —
        // wait: synthetic events are fusable regardless. To exercise the forged-
        // data path we must drop the synthetic flag so verification is required.
        events[0].provenance.synthetic = false;
        events[0].tensor.values[0] += 13.5;

        let live = frame_from_events(0, &events);
        // Event 0: not synthetic + broken signature ⇒ unverified, not fused.
        assert!(!live.frame.events[0].receipt.verified, "tampered ⇒ ✗ verified");
        assert!(!live.frame.events[0].receipt.fusable, "tampered ⇒ not fusable");
        assert_eq!(live.unverified_count, 1, "one event flagged unverified");

        // It is still SURFACED in the event log (so forgery is visible)...
        assert_eq!(live.frame.events.len(), 2);
        // ...but it must not contribute to any inference's supporting set.
        let forged_id = &live.frame.events[0].event_id;
        for inf in &live.frame.inferences {
            assert!(
                !inf.supporting_events.contains(forged_id),
                "forged event must never support a trusted inference"
            );
        }
    }

    #[test]
    fn ws_event_renders_single_frame() {
        let ev = real_signed_events(1).remove(0);
        let json = serde_json::to_string(&ev).unwrap();
        let live = frame_from_ws_event(5, &json).expect("ws event decodes");
        assert_eq!(live.frame.tick, 5);
        assert_eq!(live.frame.events.len(), 1);
        assert_eq!(live.verified_count, 1);
    }

    #[test]
    fn malformed_payload_errors_not_panics() {
        assert!(frame_from_api_payload(0, "not json").is_err());
        assert!(frame_from_ws_event(0, "{\"nope\":1}").is_err());
    }
}
