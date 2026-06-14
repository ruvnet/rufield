//! # rufield-bench
//!
//! Deterministic benchmark runner for RuField MFS v0.1 (ADR-260 §18 / §27 /
//! §31). Streams the `SyntheticSim` demo through the fusion engine and scores:
//!
//! - per-task **F1** vs the simulator's ground-truth labels (**SYNTHETIC** —
//!   not field accuracy),
//! - per-event pipeline **p95 latency** (target < 100 ms),
//! - **provenance coverage** (% events with a verifiable / synthetic receipt),
//! - **privacy violations** (events transmitted above the P2 default ceiling).
//!
//! The report is deterministic: the same seed yields identical scores
//! (latency is wall-clock and therefore the only non-deterministic field).

#![doc(html_root_url = "https://docs.rs/rufield-bench/0.1.0")]

pub mod metrics;
pub mod report;
pub mod runner;

pub use report::{BenchReport, TaskScore};
pub use runner::run;

#[cfg(test)]
mod acceptance {
    //! ADR-260 §31 Benchmark Acceptance Test, as an executable test.
    //!
    //! > Given a room with WiFi CSI, mmWave radar, and thermal IR sensors
    //! > When a person enters, sits, breathes, exits bed, and leaves
    //! > Then RuField emits signed events
    //! > And classifies room state without a camera
    //! > And keeps all default network events at P2 or below
    //! > And produces p95 latency below 100 ms
    //! > And produces a deterministic benchmark report

    use super::*;
    use rufield_adapters::{run_demo, SimConfig};
    use rufield_core::PrivacyClass;
    use rufield_provenance::{is_fusable, verify_event};

    #[test]
    fn section31_acceptance() {
        let seed = 2026;
        let cfg = SimConfig { seed, ..SimConfig::default() };
        let events = run_demo(&cfg);

        // (1) Three modalities stream into one event graph.
        let modalities: std::collections::BTreeSet<_> =
            events.iter().map(|e| e.modality).collect();
        assert_eq!(modalities.len(), 3, "expected 3 modalities");

        // (2) Every event has a privacy class; (3) every event has a verifiable
        // provenance receipt (signed) AND is fusable.
        for se in &events {
            // privacy_class is a non-Option enum field — its presence is
            // guaranteed by the type; assert it is at/below P2 by default.
            assert!(
                se.event.observation.privacy_class <= PrivacyClass::P2,
                "default observation must be <= P2"
            );
            assert!(
                se.event.provenance.signature_hex.is_some(),
                "every event is signed"
            );
            assert!(verify_event(&se.event).is_ok(), "signature verifies");
            assert!(is_fusable(&se.event), "event is fusable (§11)");
        }

        // Run the full benchmark.
        let report = run(seed);

        // RuField classifies room state without a camera:
        // (4) >= 5 distinct inferences produced.
        assert!(
            report.distinct_inferences >= 5,
            "expected >=5 distinct inferences, got {}",
            report.distinct_inferences
        );

        // And keeps all default network events at P2 or below:
        // privacy_violations counts events emitted above the P2 ceiling.
        assert_eq!(report.privacy_violations, 0, "no privacy violations");

        // (5) p95 latency below 100 ms.
        assert!(
            report.p95_latency_ms < 100.0,
            "p95 latency must be < 100ms, got {}",
            report.p95_latency_ms
        );

        // (3') provenance coverage 100%.
        assert!(
            (report.provenance_coverage_pct - 100.0).abs() < 1e-9,
            "provenance coverage must be 100%, got {}",
            report.provenance_coverage_pct
        );

        // (6) deterministic benchmark report across two runs (everything but
        // the wall-clock latency fields).
        let a = run(seed);
        let b = run(seed);
        assert_eq!(a.tasks, b.tasks, "task scores deterministic");
        assert_eq!(a.distinct_inferences, b.distinct_inferences);
        assert_eq!(a.provenance_coverage_pct, b.provenance_coverage_pct);
        assert_eq!(a.privacy_violations, b.privacy_violations);
        assert_eq!(a.events_total, b.events_total);
    }
}
