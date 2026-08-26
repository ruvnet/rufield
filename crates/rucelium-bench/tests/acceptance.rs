//! ADR-264 §14 acceptance test: the 64-node biome pilot passes when all
//! eight criteria hold, and the report is deterministic across two runs at
//! the same seed. All numbers are **SYNTHETIC** (deterministic simulator).

use rucelium_bench::{run, SimConfig};

/// The full §14 acceptance run: 64 nodes, 30 days, 7 offline days, attacks,
/// drift, revocation — every criterion must pass.
#[test]
fn adr_264_section_14_acceptance() {
    let report = run(SimConfig::default());

    assert!(report.synthetic, "the report must be labelled SYNTHETIC");
    assert_eq!(report.nodes, 64);
    assert_eq!(report.days, 30);
    assert_eq!(report.offline_days, 7);
    assert_eq!(report.criteria.len(), 8, "all eight §14 criteria evaluated");

    for c in &report.criteria {
        assert!(
            c.pass,
            "criterion {} ({}) failed: value={} target={}",
            c.number, c.name, c.value, c.target
        );
    }
    assert!(report.accepted_all());

    // Structural cross-checks beyond the pass/fail flags.
    assert_eq!(
        report.attacks_rejected, report.attacks_injected,
        "every tampered/replayed/forged/post-revocation packet rejected"
    );
    assert!(
        report.attacks_injected > 0,
        "attacks were actually injected"
    );
    assert_eq!(
        report.restore_duplicates, 0,
        "outage restore is duplicate-free"
    );
    assert!(report.restored_after_outage > 0, "outage data was restored");
    assert!(report.usable_calibrated_pct >= 95.0);
    assert_eq!(report.quarantined_nodes, 1, "exactly the drifting node");
    assert!(
        report.contradictions >= 1,
        "RF disagreement recorded, not believed"
    );
    assert_eq!(
        report.commands_executed, 2,
        "governed control path executed"
    );
    assert_eq!(
        report.proposals_rejected, 1,
        "unauthorized proposal stopped"
    );
    assert!(report.anomaly_alerts > 0);
    assert!(report.p95_alert_ms < 500.0);
}

/// Determinism: two runs at the same seed produce identical reports
/// (wall-clock latency fields excluded). Uses a reduced biome so the double
/// run stays fast; determinism is a property of the pipeline, not the scale.
#[test]
fn same_seed_same_report() {
    let cfg = SimConfig {
        nodes: 16,
        days: 10,
        sample_interval_s: 3600,
        offline_start_day: 3,
        offline_days: 2,
        drift_node: 2,
        drift_start_day: 1,
        compromised_node: 5,
        revoke_day: 6,
        anomaly_day: 8,
        ..SimConfig::default()
    };
    let a = run(cfg.clone());
    let b = run(cfg);
    assert_eq!(
        a.deterministic_fingerprint(),
        b.deterministic_fingerprint(),
        "same seed must yield an identical deterministic report"
    );
}

/// A different seed changes the data but not the verdict: the §14 criteria
/// must be seed-robust.
#[test]
fn different_seed_still_accepts() {
    let report = run(SimConfig {
        seed: 7,
        ..SimConfig::default()
    });
    assert!(report.accepted_all(), "acceptance must not be seed-tuned");
}
