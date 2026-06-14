//! Camera-free room-intelligence example (the README "Usage" snippet, runnable).
//!
//!   cargo run -p rufield-bench --example room_intelligence
//!
//! Streams the synthetic demo, fuses room-state inferences, and demonstrates
//! the privacy guard. All signals are SYNTHETIC — no hardware.

use rufield_adapters::{run_demo, SimConfig};
use rufield_core::{
    Destination, FusionEngine, InferenceQuery, PrivacyClass, PrivacyDecision, PrivacyGuard,
};
use rufield_fusion::RuFieldFusion;
use rufield_privacy::DefaultPrivacyGuard;
use rufield_provenance::is_fusable;

fn main() {
    // 1. Deterministic synthetic stream (3 modalities, signed events).
    let config = SimConfig {
        seed: 2026,
        ..SimConfig::default()
    };
    let events = run_demo(&config);
    println!(
        "streamed {} synthetic events across 3 modalities (SYNTHETIC)\n",
        events.len()
    );

    // 2. Fuse — rejecting any non-fusable event (§11 invariant).
    let mut engine = RuFieldFusion::new();
    for se in &events {
        assert!(is_fusable(&se.event));
        engine.ingest(se.event.clone()).unwrap();
    }

    // 3. Read fused room-state inferences.
    println!("room-state inferences at end of sequence:");
    for inf in engine.infer(&InferenceQuery::all()).unwrap() {
        println!(
            "  {:<18} conf={:.2} privacy={:?} model={} supported_by={} events",
            inf.label,
            inf.confidence,
            inf.privacy_class,
            inf.model_id,
            inf.supporting_events.len(),
        );
    }

    // 4. Privacy guard demonstrations.
    println!("\nprivacy guard:");
    let guard = DefaultPrivacyGuard::default();

    let p0 = guard.authorize(PrivacyClass::P0, Destination::Network, false, false);
    assert!(matches!(p0, PrivacyDecision::Deny(_)));
    println!("  P0 raw frame -> network: {p0:?}");

    let p4_no = guard.authorize(PrivacyClass::P4, Destination::Network, false, false);
    assert!(matches!(p4_no, PrivacyDecision::RequiresConsent(_)));
    println!("  P4 breathing (no consent): {p4_no:?}");

    let p4_yes = guard.authorize(PrivacyClass::P4, Destination::Network, true, false);
    assert!(matches!(p4_yes, PrivacyDecision::Allow));
    println!("  P4 breathing (with consent): {p4_yes:?}");
}
