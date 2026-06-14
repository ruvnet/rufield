//! Deterministic benchmark runner (ADR-260 §18 / §27 / §31).
//!
//! Streams the `SyntheticSim` demo through the fusion engine, scoring produced
//! inferences against the simulator's own ground-truth labels (SYNTHETIC),
//! measuring per-event pipeline latency (p95), provenance coverage, and privacy
//! violations. Output is fully deterministic for a fixed seed.

use crate::metrics::{percentile_ns, Confusion};
use crate::report::{BenchReport, TaskScore};
use rufield_adapters::{run_demo, SimConfig, SimEvent};
use rufield_core::{
    Destination, FusionEngine, InferenceQuery, PrivacyClass, PrivacyDecision, PrivacyGuard,
    SPEC_VERSION,
};
use rufield_fusion::RuFieldFusion;
use rufield_privacy::DefaultPrivacyGuard;
use rufield_provenance::is_fusable;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

/// How a task is scored.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Sustained state — scored per-tick.
    State,
    /// Discrete transition event — scored per truth-segment with tolerance.
    Event,
}

/// `(task, truth_label, produced_label, target_f1, kind)`.
const SCORED_TASKS: &[(&str, &str, &str, f32, Kind)] = &[
    ("presence", "person_present", "person_present", 0.90, Kind::State),
    ("breathing", "breathing", "breathing", 0.80, Kind::State),
    ("nocturnal_scratch", "nocturnal_scratch", "nocturnal_scratch", 0.75, Kind::State),
    ("bed_exit", "bed_exit", "bed_exit", 0.90, Kind::Event),
    ("room_transition", "room_transition", "room_transition", 0.85, Kind::Event),
];

/// Tolerance (in ticks) for matching a detected event to a truth segment.
const EVENT_TOLERANCE_TICKS: usize = 2;

/// Group a flat interleaved stream into per-tick batches keyed by timestamp.
fn group_by_tick(events: &[SimEvent]) -> Vec<Vec<&SimEvent>> {
    let mut order: Vec<u64> = Vec::new();
    let mut map: BTreeMap<u64, Vec<&SimEvent>> = BTreeMap::new();
    for se in events {
        let ts = se.event.timestamp_ns;
        map.entry(ts).or_default().push(se);
        if !order.contains(&ts) {
            order.push(ts);
        }
    }
    order.into_iter().map(|ts| map[&ts].clone()).collect()
}

/// Score an event task from per-tick predicted/truth booleans using segment
/// matching: each contiguous truth run is one event; a TP if any prediction
/// falls within the run ± tolerance; predictions outside any run are FPs.
fn score_event_task(predicted: &[bool], truth: &[bool]) -> Confusion {
    let mut c = Confusion::default();
    let n = predicted.len();

    // Identify truth segments (contiguous runs of true).
    let mut segments: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < n {
        if truth[i] {
            let start = i;
            while i < n && truth[i] {
                i += 1;
            }
            segments.push((start, i - 1));
        } else {
            i += 1;
        }
    }

    // Mark which prediction ticks are "consumed" by matching a segment.
    let mut pred_matched = vec![false; n];
    for &(s, e) in &segments {
        let lo = s.saturating_sub(EVENT_TOLERANCE_TICKS);
        let hi = (e + EVENT_TOLERANCE_TICKS).min(n.saturating_sub(1));
        let mut hit = false;
        for (t, &p) in predicted.iter().enumerate().take(hi + 1).skip(lo) {
            if p {
                hit = true;
                pred_matched[t] = true;
            }
        }
        if hit {
            c.tp += 1;
        } else {
            c.fn_ += 1;
        }
    }

    // Any predicted tick not matched to a segment is a false positive — but
    // collapse contiguous unmatched predictions into a single FP event.
    let mut j = 0;
    while j < n {
        if predicted[j] && !pred_matched[j] {
            c.fp += 1;
            while j < n && predicted[j] && !pred_matched[j] {
                j += 1;
            }
        } else {
            j += 1;
        }
    }
    c
}

/// Run the benchmark and produce a deterministic report.
#[must_use]
pub fn run(seed: u64) -> BenchReport {
    let config = SimConfig {
        seed,
        ..SimConfig::default()
    };
    let events = run_demo(&config);

    let modalities: BTreeSet<_> = events.iter().map(|e| e.modality).collect();
    let guard = DefaultPrivacyGuard::default();

    let mut engine = RuFieldFusion::new();
    let mut latencies_ns: Vec<u64> = Vec::with_capacity(events.len());

    let mut prov_ok: u32 = 0;
    let mut privacy_violations: u32 = 0;
    let mut distinct_inferences: BTreeSet<String> = BTreeSet::new();

    // Per-task per-tick predicted/truth series.
    let mut series: BTreeMap<&str, (Vec<bool>, Vec<bool>)> =
        SCORED_TASKS.iter().map(|t| (t.0, (Vec::new(), Vec::new()))).collect();

    let ticks = group_by_tick(&events);

    for batch in ticks {
        for se in &batch {
            if is_fusable(&se.event) {
                prov_ok += 1;
            }
            let decision = guard.authorize(
                se.event.observation.privacy_class,
                Destination::Network,
                false,
                false,
            );
            if matches!(decision, PrivacyDecision::Deny(_))
                && se.event.observation.privacy_class > PrivacyClass::P2
            {
                privacy_violations += 1;
            }

            let start = Instant::now();
            let _ = engine.ingest(se.event.clone());
            latencies_ns.push(start.elapsed().as_nanos() as u64);
        }

        let produced = engine.infer(&InferenceQuery::all()).unwrap_or_default();
        let produced_labels: BTreeSet<String> =
            produced.iter().map(|i| i.label.clone()).collect();
        for l in &produced_labels {
            distinct_inferences.insert(l.clone());
        }
        let truth_labels: BTreeSet<String> = batch
            .iter()
            .flat_map(|se| se.event.observation.labels.iter().cloned())
            .collect();

        for (task, truth_label, produced_label, _t, _k) in SCORED_TASKS {
            let entry = series.get_mut(task).unwrap();
            entry.0.push(produced_labels.contains(*produced_label));
            entry.1.push(truth_labels.contains(*truth_label));
        }
    }

    let tasks: Vec<TaskScore> = SCORED_TASKS
        .iter()
        .map(|(task, _t, _p, target, kind)| {
            let (pred, truth) = &series[task];
            let conf = match kind {
                Kind::State => {
                    let mut c = Confusion::default();
                    for (p, t) in pred.iter().zip(truth.iter()) {
                        c.record(*p, *t);
                    }
                    c
                }
                Kind::Event => score_event_task(pred, truth),
            };
            let f1 = conf.f1();
            TaskScore {
                task: (*task).to_string(),
                metric: "f1".into(),
                value: f1,
                target: *target,
                meets_target: f1 >= *target,
            }
        })
        .collect();

    let p95_ns = percentile_ns(&latencies_ns, 0.95);
    let p50_ns = percentile_ns(&latencies_ns, 0.50);
    let coverage = if events.is_empty() {
        100.0
    } else {
        (prov_ok as f64 / events.len() as f64) * 100.0
    };

    BenchReport {
        spec_version: SPEC_VERSION.to_string(),
        synthetic: true,
        seed,
        events_total: events.len(),
        modalities: modalities.len(),
        distinct_inferences: distinct_inferences.len(),
        tasks,
        p95_latency_ms: p95_ns as f64 / 1_000_000.0,
        p50_latency_ms: p50_ns as f64 / 1_000_000.0,
        provenance_coverage_pct: coverage,
        privacy_violations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_is_deterministic_across_runs() {
        let a = run(42);
        let b = run(42);
        assert_eq!(a.tasks, b.tasks);
        assert_eq!(a.events_total, b.events_total);
        assert_eq!(a.modalities, b.modalities);
        assert_eq!(a.distinct_inferences, b.distinct_inferences);
        assert_eq!(a.provenance_coverage_pct, b.provenance_coverage_pct);
        assert_eq!(a.privacy_violations, b.privacy_violations);
        assert_eq!(strip_latency(&a.to_json()), strip_latency(&b.to_json()));
    }

    fn strip_latency(json: &str) -> String {
        json.lines()
            .filter(|l| !l.contains("latency_ms"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn three_modalities_present() {
        assert_eq!(run(1).modalities, 3);
    }

    #[test]
    fn at_least_five_distinct_inferences() {
        let r = run(1);
        assert!(r.distinct_inferences >= 5, "got {}", r.distinct_inferences);
    }

    #[test]
    fn provenance_coverage_is_full() {
        assert!((run(1).provenance_coverage_pct - 100.0).abs() < 1e-9);
    }

    #[test]
    fn no_privacy_violations() {
        assert_eq!(run(1).privacy_violations, 0);
    }

    #[test]
    fn p95_under_100ms() {
        let r = run(1);
        assert!(r.p95_latency_ms < 100.0, "p95={}", r.p95_latency_ms);
    }

    #[test]
    fn event_scoring_segment_logic() {
        // Truth: one event over ticks 3..=5. Prediction at tick 4 ⇒ TP, no FP.
        let truth = vec![false, false, false, true, true, true, false];
        let pred = vec![false, false, false, false, true, false, false];
        let c = score_event_task(&pred, &truth);
        assert_eq!(c.tp, 1);
        assert_eq!(c.fp, 0);
        assert_eq!(c.fn_, 0);
    }

    #[test]
    fn event_scoring_false_positive() {
        // Prediction far from any truth segment ⇒ FP.
        let truth = vec![false, false, false, false];
        let pred = vec![true, false, false, false];
        let c = score_event_task(&pred, &truth);
        assert_eq!(c.fp, 1);
        assert_eq!(c.tp, 0);
    }
}
