//! The per-datagram ingest pipeline (ADR-265 §4): envelope detection
//! (v1 CBOR / v2 compact / fragments) → reassembly → ingest (registry +
//! signature + anti-replay) → calibration → drift → WorldGraph → durable
//! store → local alert rules → biome admission.

use crate::state::Inner;
use rucelium_abi::RvEnvSampleV1;
use rucelium_core::{
    EnvSample, EnvironmentalEvent, EventKind, EvidenceRef, SensorModality, Severity, SPEC_VERSION,
};
use rucelium_transport::{to_v1, CompactEnvV2, COMPACT_ENV_MAGIC, FRAG_MAGIC};

/// Water-level threshold (metres) for the local flood alert rule — same
/// value as the ADR-264 §14 acceptance benchmark.
pub const WATER_ALERT_LEVEL_M: f64 = 1.6;

/// Quality floor for water-quality samples; below it the sample raises an
/// anomaly alert (sensor likely degraded or fouled).
pub const WATER_ALERT_MIN_QUALITY: f32 = 0.2;

/// Link-layer sender hint for the fragment reassembler. UDP v0.1 uses a
/// single shared sender id (`0`): the daemon cannot trust source addresses
/// (trivially spoofable) and the payload's own signature + sequence window
/// provide end-to-end integrity and dedup. Senders must therefore choose
/// distinct `msg_id`s while fragmenting concurrently — the synthetic
/// simulator does (one global counter). Real LoRaWAN deployments would pass
/// a DevAddr-derived hint instead.
const UDP_SENDER: u64 = 0;

/// What one received datagram amounted to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessOutcome {
    /// A sample was fully accepted: verified, calibrated, stored, graphed,
    /// and offered to the biome.
    Accepted,
    /// The datagram (or the message it completed) was rejected; the string
    /// is the human-readable reason. Rejection is final — the gateway never
    /// repairs or forwards unverified data (ADR-264 §12).
    Rejected(String),
    /// A fragment was absorbed; the message is not yet complete.
    Fragment,
}

/// Process one received datagram at `received_ns`, updating every pipeline
/// component and the datagram-level counters exactly once per datagram.
pub fn process_datagram(inner: &mut Inner, datagram: &[u8], received_ns: u64) -> ProcessOutcome {
    let outcome = dispatch(inner, datagram, received_ns);
    match &outcome {
        ProcessOutcome::Accepted => inner.datagrams.accepted += 1,
        ProcessOutcome::Rejected(_) => inner.datagrams.rejected += 1,
        ProcessOutcome::Fragment => inner.datagrams.fragments += 1,
    }
    outcome
}

/// Dispatch on the first byte: `0xF7` fragment, `0xC2` compact envelope v2,
/// anything else (in practice `0x83`, the CBOR array(3) head) a v1 envelope.
/// Recurses (depth ≤ 1) when a fragment completes a message.
fn dispatch(inner: &mut Inner, datagram: &[u8], received_ns: u64) -> ProcessOutcome {
    match datagram.first() {
        None => ProcessOutcome::Rejected("empty datagram".to_string()),
        Some(&FRAG_MAGIC) => match inner.reassembler.offer(UDP_SENDER, datagram, received_ns) {
            Ok(Some(message)) => dispatch(inner, &message, received_ns),
            Ok(None) => ProcessOutcome::Fragment,
            Err(e) => ProcessOutcome::Rejected(format!("fragment: {e}")),
        },
        Some(&COMPACT_ENV_MAGIC) => ingest_compact(inner, datagram, received_ns),
        Some(_) => ingest_v1(inner, datagram, received_ns),
    }
}

/// Compact envelope v2: parse, look the registry key up by the `node_id`
/// inside the payload, rehydrate to v1 ([`to_v1`]), and feed the encoded v1
/// bytes through the unchanged ingest pipeline (which re-verifies the
/// signature against the registry key — a forged `node_id` merely selects a
/// key the signature cannot match).
fn ingest_compact(inner: &mut Inner, datagram: &[u8], received_ns: u64) -> ProcessOutcome {
    let env = match CompactEnvV2::parse(datagram) {
        Ok(e) => e,
        Err(e) => return ProcessOutcome::Rejected(format!("compact envelope: {e}")),
    };
    let wire = match RvEnvSampleV1::parse(&env.payload) {
        Ok(w) => w,
        Err(e) => return ProcessOutcome::Rejected(format!("compact payload: {e}")),
    };
    let Some(device) = inner.ingest.registry().get(wire.node_id) else {
        return ProcessOutcome::Rejected(format!(
            "compact envelope from unknown device {}",
            wire.node_id
        ));
    };
    let record = to_v1(&env, device.pubkey);
    ingest_v1(inner, &record.encode(), received_ns)
}

/// Feed v1 envelope bytes through ingest and, on acceptance, the rest of the
/// pipeline: calibration, drift, WorldGraph, durable store, alert rule,
/// biome admission.
fn ingest_v1(inner: &mut Inner, envelope: &[u8], received_ns: u64) -> ProcessOutcome {
    // `ingest` yields a sealed `VerifiedEnvSample`: the only type the biome
    // layer accepts, and the only one the ingest pipeline can mint.
    let mut sample = match inner.ingest.ingest(envelope, received_ns) {
        Ok(s) => s,
        Err(reason) => return ProcessOutcome::Rejected(reason.to_string()),
    };

    // Calibration: `Uncalibrated` is fine (quality already penalised by the
    // calibrator); a hard error is counted and the sample stays raw — the
    // gateway never invents a correction (ADR-264 §12 item 6). `modify`
    // applies the correction *through* the seal: the change is committed only
    // if the transformed sample still validates, so calibration can neither
    // break the seal nor smuggle an invalid sample past it.
    let calibrated = sample.modify(|s| inner.calibrator.apply(&inner.calibration, s, received_ns));
    match calibrated {
        Ok(Ok(_)) => {}
        // Either the calibrator rejected the record, or the corrected sample
        // failed re-validation. Both leave the sample untouched.
        Ok(Err(_)) | Err(_) => inner.calibration_errors += 1,
    }

    // Read-only view of the sealed sample for everything downstream that
    // works on plain `EnvSample`s (graph, store, projection, alert rules).
    let view = sample.sample().clone();

    // Drift: the daemon has no co-located anchor model yet, so real traffic
    // feeds residual 0.0 — the call is kept so quarantine state (set by any
    // future anchor feed or by tests) stays visible in /api/stats and no node
    // can silently leave quarantine (sticky by design).
    let _ = inner.drift.observe(view.node_id, 0.0);

    // WorldGraph registration (idempotent) before storage.
    inner.graph.register_observation(&view);

    // Storage strips the seal by design: a sample read back from disk is
    // untrusted bytes again, and re-earning verification requires the
    // original signed envelope (`IngestPipeline::reverify_stored`).
    if let Err(e) = inner.obs.append(&view) {
        return ProcessOutcome::Rejected(format!("observation store append: {e}"));
    }

    maybe_alert(inner, &view, received_ns);

    // Biome admission last; duplicates are counted inside the biome.
    let _ = inner.biome.accept(sample);
    ProcessOutcome::Accepted
}

/// Local alert rule (ADR-265 §4): a water-quality sample above
/// [`WATER_ALERT_LEVEL_M`] raises a `FloodRisk` warning; one below
/// [`WATER_ALERT_MIN_QUALITY`] quality raises an `Anomaly` watch. The event
/// is biome-signed and appended to the durable event store.
fn maybe_alert(inner: &mut Inner, sample: &EnvSample, received_ns: u64) {
    if sample.modality != SensorModality::WaterQuality {
        return;
    }
    let flood = sample.value > WATER_ALERT_LEVEL_M;
    let degraded = sample.quality < WATER_ALERT_MIN_QUALITY;
    if !flood && !degraded {
        return;
    }
    let (kind, severity, message) = if flood {
        (
            EventKind::FloodRisk,
            Severity::Warning,
            format!(
                "water level {:.2} m above flood threshold {WATER_ALERT_LEVEL_M} m",
                sample.value
            ),
        )
    } else {
        (
            EventKind::Anomaly,
            Severity::Watch,
            format!(
                "water-quality sample quality {:.2} below floor {WATER_ALERT_MIN_QUALITY}",
                sample.quality
            ),
        )
    };
    let mut event = EnvironmentalEvent {
        spec_version: SPEC_VERSION.into(),
        event_id: format!(
            "alert:{}:{}:{}",
            inner.biome.config().biome_id,
            sample.node_id,
            sample.sequence
        ),
        biome_id: inner.biome.config().biome_id.clone(),
        kind,
        severity,
        modality: SensorModality::WaterQuality,
        geo: sample.geo,
        window_start_ns: sample.measured_ns,
        window_end_ns: sample.measured_ns,
        detected_ns: received_ns,
        evidence: vec![EvidenceRef {
            node_id: sample.node_id,
            sequence: sample.sequence,
        }],
        confidence: 0.9,
        // Bind the cited observation CONTENT into the signature
        // (ADR-266 §3.1), not just its (node, sequence) identity.
        evidence_digest: Some(rucelium_core::evidence_digest(&[sample])),
        message,
        signature_hex: None,
        signer_pubkey_hex: None,
    };
    inner.biome.sign_event(&mut event);
    match inner.events.append(&event) {
        Ok(_) => inner.alerts += 1,
        Err(e) => eprintln!("gateway: event store append failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::testutil::test_inner;
    use rucelium_abi::{NodeSigner, RV_ENV_SCHEMA_V1};
    use rucelium_federation::verify_event;
    use rucelium_transport::{fragment_compact, sign_compact};

    const SEED: &[u8; 32] = b"rucelium-gateway-test-seed-32b!!";
    const NODE_A: u64 = 0x5C00_0000_0000_0001;
    const NODE_B: u64 = 0x5C00_0000_0000_0002;
    const TS: u64 = 1_754_000_000_000_000_000;
    const RECV: u64 = TS + 1_000_000;

    fn wire(node_id: u64, sequence: u32, modality: SensorModality, value: f64) -> RvEnvSampleV1 {
        RvEnvSampleV1 {
            schema_version: RV_ENV_SCHEMA_V1,
            sensor_type: modality.code(),
            flags: 0,
            node_id,
            timestamp_ns: TS,
            sequence,
            latitude_e7: 514_778_216,
            longitude_e7: -14_767,
            altitude_mm: 46_000,
            value_q16: (value * 65_536.0).round() as i32,
            quality_q15: 0x7000, // 0.875
            battery_mv: 3_600,
            calibration_id: 0, // uncalibrated: quality penalised, no record needed
        }
    }

    fn signer(node_id: u64) -> NodeSigner {
        NodeSigner::for_node(SEED, node_id)
    }

    fn v1_envelope(node_id: u64, sequence: u32) -> Vec<u8> {
        signer(node_id)
            .sign_sample(&wire(node_id, sequence, SensorModality::SoilMoisture, 27.5))
            .encode()
    }

    fn inner_with_node(tag: &str) -> Inner {
        let mut inner = test_inner(tag);
        inner.ingest.registry_mut().register(
            NODE_A,
            signer(NODE_A).public_key(),
            "sha256:fw-a".into(),
        );
        inner
    }

    #[test]
    fn genuine_v1_envelope_accepted_end_to_end() {
        let mut inner = inner_with_node("v1-ok");
        let out = process_datagram(&mut inner, &v1_envelope(NODE_A, 1), RECV);
        assert_eq!(out, ProcessOutcome::Accepted);
        assert_eq!(inner.ingest.stats().accepted, 1);
        assert_eq!(inner.obs.len(), 1);
        assert!(inner.graph.node(&format!("sensor/{NODE_A}")).is_some());
        assert_eq!(inner.biome.accepted_count(), 1);
        assert_eq!(inner.datagrams.accepted, 1);
        // Uncalibrated: quality penalised, value untouched.
        let stored = &inner.obs.recent(1).unwrap()[0];
        assert!(stored.provenance.verified);
        assert!((stored.value - 27.5).abs() < 1e-4);
        assert!((stored.quality - 0.875 * 0.5).abs() < 1e-6);
    }

    #[test]
    fn compact_v2_envelope_accepted() {
        let mut inner = inner_with_node("v2-ok");
        let w = wire(NODE_A, 1, SensorModality::SoilMoisture, 27.5);
        let env = sign_compact(&signer(NODE_A), &w.encode());
        let out = process_datagram(&mut inner, &env.encode(), RECV);
        assert_eq!(out, ProcessOutcome::Accepted);
        assert_eq!(inner.ingest.stats().accepted, 1);
        assert_eq!(inner.obs.len(), 1);
    }

    #[test]
    fn fragmented_compact_envelope_reassembles_out_of_order() {
        let mut inner = inner_with_node("frag-ok");
        let w = wire(NODE_A, 1, SensorModality::SoilMoisture, 27.5);
        let env = sign_compact(&signer(NODE_A), &w.encode());
        let frames = fragment_compact(&env, 7);
        assert_eq!(frames.len(), 3);
        // Out of order: 2, 0, then 1 completes.
        assert_eq!(
            process_datagram(&mut inner, &frames[2], RECV),
            ProcessOutcome::Fragment
        );
        assert_eq!(
            process_datagram(&mut inner, &frames[0], RECV),
            ProcessOutcome::Fragment
        );
        assert_eq!(
            process_datagram(&mut inner, &frames[1], RECV),
            ProcessOutcome::Accepted
        );
        assert_eq!(inner.obs.len(), 1);
        assert_eq!(inner.datagrams.fragments, 2);
        assert_eq!(inner.datagrams.accepted, 1);
    }

    #[test]
    fn tampered_envelope_rejected() {
        let mut inner = inner_with_node("tamper");
        let mut env = v1_envelope(NODE_A, 1);
        let mid = env.len() / 2;
        env[mid] ^= 0x01;
        let out = process_datagram(&mut inner, &env, RECV);
        assert!(matches!(out, ProcessOutcome::Rejected(_)), "{out:?}");
        assert_eq!(inner.ingest.stats().accepted, 0);
        assert_eq!(inner.obs.len(), 0);
        assert_eq!(inner.datagrams.rejected, 1);
    }

    #[test]
    fn unknown_node_compact_rejected_before_ingest() {
        let mut inner = inner_with_node("unknown");
        let w = wire(NODE_B, 1, SensorModality::SoilMoisture, 27.5);
        let env = sign_compact(&signer(NODE_B), &w.encode());
        let out = process_datagram(&mut inner, &env.encode(), RECV);
        match out {
            ProcessOutcome::Rejected(msg) => assert!(msg.contains("unknown device"), "{msg}"),
            other => panic!("expected rejection, got {other:?}"),
        }
        assert_eq!(inner.obs.len(), 0);
    }

    #[test]
    fn replayed_datagram_rejected_as_replay() {
        let mut inner = inner_with_node("replay");
        let env = v1_envelope(NODE_A, 9);
        assert_eq!(
            process_datagram(&mut inner, &env, RECV),
            ProcessOutcome::Accepted
        );
        match process_datagram(&mut inner, &env, RECV) {
            ProcessOutcome::Rejected(msg) => assert!(msg.contains("replayed"), "{msg}"),
            other => panic!("expected replay rejection, got {other:?}"),
        }
        assert_eq!(inner.ingest.stats().replay, 1);
        assert_eq!(inner.obs.len(), 1);
        assert_eq!(inner.biome.accepted_count(), 1);
    }

    #[test]
    fn empty_and_garbage_datagrams_rejected() {
        let mut inner = inner_with_node("garbage");
        assert!(matches!(
            process_datagram(&mut inner, &[], RECV),
            ProcessOutcome::Rejected(_)
        ));
        assert!(matches!(
            process_datagram(&mut inner, b"\x83garbage", RECV),
            ProcessOutcome::Rejected(_)
        ));
        assert_eq!(inner.datagrams.rejected, 2);
    }

    #[test]
    fn water_level_over_threshold_raises_signed_flood_alert() {
        let mut inner = inner_with_node("alert");
        let w = wire(NODE_A, 1, SensorModality::WaterQuality, 1.8);
        let env = signer(NODE_A).sign_sample(&w).encode();
        assert_eq!(
            process_datagram(&mut inner, &env, RECV),
            ProcessOutcome::Accepted
        );
        assert_eq!(inner.alerts, 1);
        let events = inner.events.iter().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::FloodRisk);
        assert!(
            verify_event(&events[0]),
            "alert must carry a biome signature"
        );
        // A calm reading raises nothing further.
        let calm = signer(NODE_A)
            .sign_sample(&wire(NODE_A, 2, SensorModality::WaterQuality, 1.0))
            .encode();
        process_datagram(&mut inner, &calm, RECV);
        assert_eq!(inner.alerts, 1);
    }
}
