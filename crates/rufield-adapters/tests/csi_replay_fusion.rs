//! Integration test: drive the RuField fusion engine with **real captured WiFi
//! CSI** replayed through [`CsiReplayAdapter`].
//!
//! Honesty: this proves "RuField ingests real WiFi CSI and produces fused events
//! from it" — NOT an accuracy claim. The recording is unlabeled; the
//! motion/presence output is a physically-grounded CSI-variance proxy.

use rufield_adapters::CsiReplayAdapter;
use rufield_core::{FieldAdapter, FusionEngine, InferenceQuery, PrivacyClass};
use rufield_fusion::RuFieldFusion;
use rufield_provenance::{is_fusable, verify_event};

const MEDIUM: &str = include_str!("fixtures/real_csi_medium.jsonl");
const SMALL: &str = include_str!("fixtures/real_csi_small.jsonl");

#[test]
fn small_fixture_yields_three_well_formed_events() {
    let mut adapter = CsiReplayAdapter::from_jsonl(SMALL).expect("parse small fixture");
    adapter.calibrate("unit_zone").expect("calibrate");

    let mut events = Vec::new();
    while let Some(ev) = adapter.next_event().expect("next_event") {
        events.push(ev);
    }
    assert_eq!(events.len(), 3, "small fixture has 3 real CSI frames");

    let mut prev_ts = 0u64;
    for ev in &events {
        assert_eq!(ev.tensor.modality, rufield_core::Modality::WifiCsi);
        assert!(ev.timestamp_ns > prev_ts, "real timestamps are monotonic");
        prev_ts = ev.timestamp_ns;
        assert!(verify_event(ev).is_ok(), "event signature verifies");
        assert!(is_fusable(ev), "event is fusable via real signature");
        ev.tensor.validate().expect("tensor structurally valid");
        let p = ev.observation.privacy_class;
        assert!(p == PrivacyClass::P1 || p == PrivacyClass::P2);
    }
}

#[test]
fn medium_fixture_drives_fusion_to_at_least_one_inference() {
    let mut adapter = CsiReplayAdapter::from_jsonl(MEDIUM).expect("parse medium fixture");
    let receipt = adapter.calibrate("living_room").expect("calibrate");
    assert!(receipt.data_hash.starts_with("sha256:"));

    let frames = adapter.frame_count();
    assert_eq!(frames, 199, "medium fixture has 199 real CSI frames");

    let events = adapter.collect_events().expect("collect real CSI events");
    assert_eq!(events.len(), 199);

    // Every real-CSI event must be well-formed + signed.
    let mut motion = 0usize;
    let mut presence = 0usize;
    for ev in &events {
        assert!(verify_event(ev).is_ok());
        assert!(is_fusable(ev));
        assert!(!ev.provenance.synthetic, "data is real, not synthetic");
        if ev.observation.labels.iter().any(|l| l == "motion_proxy") {
            motion += 1;
        }
        if ev.observation.labels.iter().any(|l| l == "presence_proxy") {
            presence += 1;
        }
    }

    // Feed the real CSI events through the fusion engine and collect inferences.
    let mut engine = RuFieldFusion::new();
    let mut inferences = std::collections::BTreeMap::<String, usize>::new();
    for ev in events {
        engine.ingest(ev).expect("real CSI event ingests");
        for inf in engine.infer(&InferenceQuery::all()).expect("infer") {
            *inferences.entry(inf.label).or_default() += 1;
        }
    }

    let total_inferences: usize = inferences.values().sum();

    // The win: real CSI produced >= 1 fused inference (presence/motion).
    assert!(
        total_inferences >= 1,
        "expected >=1 fused inference from real CSI, got {total_inferences}; \
         motion_proxy frames={motion}, presence_proxy frames={presence}"
    );

    // Honest, reproducible summary (replay + unlabeled — NOT an accuracy claim).
    eprintln!("--- CsiReplayAdapter over REAL captured WiFi CSI (replay, unlabeled) ---");
    eprintln!("frames parsed:            {frames}");
    eprintln!("motion_proxy flagged:     {motion}");
    eprintln!("presence_proxy flagged:   {presence}");
    eprintln!("fused inferences (total): {total_inferences}");
    eprintln!("inference labels:         {inferences:?}");
    eprintln!(
        "NOTE: motion/presence are a physically-grounded CSI-variance PROXY on \
         UNLABELED data — NOT validated accuracy. Replay from file, not live HW."
    );
}

#[test]
fn medium_fixture_event_stream_is_byte_identical_across_runs() {
    let run = || {
        let mut a = CsiReplayAdapter::from_jsonl(MEDIUM).unwrap();
        a.calibrate("z").unwrap();
        a.collect_events().unwrap()
    };
    let first = run();
    let second = run();
    assert_eq!(first.len(), second.len());
    for (x, y) in first.iter().zip(second.iter()) {
        // Full FieldEvent equality incl. tensor values, observation, signature.
        assert_eq!(x, y, "same fixture ⇒ byte-identical event stream");
    }
}
