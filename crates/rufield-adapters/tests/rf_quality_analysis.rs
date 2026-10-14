use rufield_adapters::rf_quality_analysis::{AnalysisStatus, RfQualityAnalyzer, BASELINE_WINDOWS};
use rufield_adapters::rf_spectrum_quality::{RfDiagnostic, SourceKind};
fn record(index: u64, power: f64) -> RfDiagnostic {
    RfDiagnostic {
        schema: "ruview.rf_diagnostics.v1".into(),
        source_kind: SourceKind::Synthetic,
        source_id: "w1700k".into(),
        observed_monotonic_ns: 1_000_000 + index * 10_000_000,
        run: 1,
        slot_index: index,
        sample_start: None,
        sample_rate_hz: 40_000_000,
        center_frequency_hz: Some(2_412_000_000),
        config_verified: false,
        valid: false,
        invalid_reasons: vec!["configuration_unverified".into()],
        sample_count: 2048,
        rms_dbfs: Some(power),
        rail_fraction: Some(0.0),
        missing_samples: 0,
        event_count: 0,
        overrun_slices: 0,
        ttl_ms: 1000,
    }
}
fn warmed() -> RfQualityAnalyzer {
    let mut a = RfQualityAnalyzer::new();
    for i in 0..BASELINE_WINDOWS as u64 {
        a.analyze(&record(i, -30.0)).unwrap();
    }
    a
}
#[test]
fn median_rejects_outliers_and_frozen_baseline_detects_rise() {
    let mut a = RfQualityAnalyzer::new();
    for i in 0..16 {
        let report = a
            .analyze(&record(i, if i == 0 { 0.0 } else { -30.0 }))
            .unwrap();
        assert!(!report.power_rise);
        assert_eq!(report.confidence, 0.0);
        assert!(!report.valid);
    }
    for i in 16..40 {
        let report = a.analyze(&record(i, -20.0)).unwrap();
        assert_eq!(report.status, AnalysisStatus::Compared);
        assert_eq!(report.baseline_dbfs, Some(-30.0));
        assert_eq!(report.delta_db, Some(10.0));
        assert!(report.power_rise);
        assert_eq!(report.baseline_windows, 16);
        assert_eq!(report.cause, "unknown");
        assert_eq!(report.key.source_kind, SourceKind::Synthetic);
    }
}
#[test]
fn threshold_is_inclusive_and_no_warmup_alerts() {
    let mut a = warmed();
    assert!(!a.analyze(&record(16, -24.01)).unwrap().power_rise);
    assert!(a.analyze(&record(17, -24.0)).unwrap().power_rise);
    assert!(!a.analyze(&record(18, -40.0)).unwrap().power_rise);
}
#[test]
fn quality_issues_clear_baseline_and_never_raise_alerts() {
    for issue in [
        "lost",
        "event",
        "overrun",
        "stale",
        "tag_mismatch",
        "run_change",
        "rail",
    ] {
        let mut a = warmed();
        let mut d = record(16, -10.0);
        match issue {
            "lost" => d.missing_samples = 2048,
            "event" => d.event_count = 1,
            "overrun" => d.overrun_slices = 1,
            "rail" => d.rail_fraction = Some(0.1),
            _ => d.invalid_reasons.push(issue.into()),
        }
        let r = a.analyze(&d).unwrap();
        assert_eq!(r.status, AnalysisStatus::Abstained, "{issue}");
        assert!(!r.power_rise);
        assert!(!r.issues.is_empty());
        let next = a.analyze(&record(17, -30.0)).unwrap();
        assert_eq!(next.status, AnalysisStatus::WarmingUp);
        assert_eq!(next.baseline_windows, 1);
    }
}

#[test]
fn configuration_changes_cannot_reuse_channel_baselines() {
    for field in ["run", "rate", "center"] {
        let mut a = warmed();
        let mut d = record(16, -10.0);
        match field {
            "run" => d.run = 2,
            "rate" => d.sample_rate_hz = 80_000_000,
            _ => d.center_frequency_hz = Some(5_180_000_000),
        }
        let r = a.analyze(&d).unwrap();
        assert_eq!(r.status, AnalysisStatus::Abstained);
        assert_eq!(r.abstention_reasons, vec!["run_or_configuration_change"]);
        // Returning to the old key is another reset, not baseline restoration.
        assert_eq!(
            a.analyze(&record(17, -10.0)).unwrap().status,
            AnalysisStatus::Abstained
        );
        assert_eq!(a.analyze(&record(18, -10.0)).unwrap().baseline_windows, 1);
    }
}
#[test]
fn bad_time_or_sequence_abstains_without_claiming_wallclock_freshness() {
    for condition in ["backward", "duplicate", "gap", "slot", "zero"] {
        let mut a = warmed();
        let mut d = record(16, -10.0);
        match condition {
            "backward" => d.observed_monotonic_ns = 10,
            "duplicate" => d.observed_monotonic_ns = record(15, 0.0).observed_monotonic_ns,
            "gap" => d.observed_monotonic_ns = 2_000_000_000,
            "zero" => d.observed_monotonic_ns = 0,
            _ => d.slot_index = 15,
        }
        let r = a.analyze(&d).unwrap();
        assert_eq!(r.status, AnalysisStatus::Abstained, "{condition}");
        assert!(!r.power_rise);
        assert!(r.delta_db.is_none());
    }
}
#[test]
fn unknown_config_missing_signal_and_source_modes_stay_separate() {
    let mut a = warmed();
    let mut d = record(16, -10.0);
    d.source_kind = SourceKind::Live;
    let r = a.analyze(&d).unwrap();
    assert_eq!(r.status, AnalysisStatus::WarmingUp);
    assert_eq!(a.stream_count(), 2);
    d = record(17, -10.0);
    d.center_frequency_hz = None;
    assert_eq!(a.analyze(&d).unwrap().status, AnalysisStatus::Abstained);
    d = record(18, -10.0);
    d.rms_dbfs = None;
    assert_eq!(a.analyze(&d).unwrap().status, AnalysisStatus::Abstained);
    a.reset();
    assert_eq!(a.stream_count(), 0);
}
#[test]
fn long_stream_memory_remains_bounded_and_rejected_input_does_not_mutate() {
    let mut a = warmed();
    for i in 16..10_000 {
        assert_eq!(a.analyze(&record(i, -30.0)).unwrap().baseline_windows, 16);
    }
    assert_eq!(a.stream_count(), 1);
    let mut d = record(10_000, -30.0);
    d.valid = true;
    assert!(a.analyze(&d).is_err());
    let r = a.analyze(&record(10_000, -30.0)).unwrap();
    assert_eq!(r.status, AnalysisStatus::Compared);
}

#[test]
fn cli_streams_advisory_reports_and_fails_on_malformed_input() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let binary = env!("CARGO_BIN_EXE_rf-diagnostics-analyze");
    let mut child = Command::new(binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut input = child.stdin.take().unwrap();
        for i in 0..17 {
            let d = record(i, if i < 16 { -30.0 } else { -20.0 });
            serde_json::to_writer(&mut input, &d).unwrap();
            input.write_all(b"\n").unwrap();
        }
    }
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    let output = String::from_utf8(result.stdout).unwrap();
    let rows: Vec<serde_json::Value> = output
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(rows.len(), 17);
    assert_eq!(rows[16]["power_rise"], true);
    assert_eq!(rows[16]["valid"], false);
    assert_eq!(rows[16]["confidence"], 0.0);
    assert_eq!(rows[16]["key"]["source_kind"], "synthetic");
    let mut child = Command::new(binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"{\"raw_iq\":[1,2]}\n")
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
}

#[test]
fn skipped_slots_clear_warmed_baseline_before_power_comparison() {
    let mut analyzer = warmed();
    let mut skipped = record(16, -10.0);
    skipped.slot_index = 100;
    let report = analyzer.analyze(&skipped).unwrap();
    assert_eq!(report.status, AnalysisStatus::Abstained);
    assert_eq!(report.abstention_reasons, vec!["slot_gap"]);
    assert!(!report.power_rise);
    assert!(report.delta_db.is_none());
    assert!(report.baseline_dbfs.is_none());
    assert_eq!(report.baseline_windows, 0);
    let mut next = record(17, -10.0);
    next.slot_index = 101;
    let report = analyzer.analyze(&next).unwrap();
    assert_eq!(report.status, AnalysisStatus::WarmingUp);
    assert_eq!(report.baseline_windows, 1);
    assert!(!report.power_rise);
}
