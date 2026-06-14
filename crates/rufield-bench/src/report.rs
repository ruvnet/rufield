//! The deterministic benchmark report (ADR-260 §18 / §27.6). Serializes to
//! stable JSON and renders a human table. All F1 numbers are **SYNTHETIC** —
//! scored against the simulator's own ground-truth labels, NOT field accuracy.

use serde::{Deserialize, Serialize};

/// Per-task score line.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskScore {
    /// Task name (e.g. `presence`).
    pub task: String,
    /// Metric kind (`f1` for v0.1 scored tasks).
    pub metric: String,
    /// Measured value (SYNTHETIC).
    pub value: f32,
    /// Target from ADR-260 §18.
    pub target: f32,
    /// Whether the measured value meets the target.
    pub meets_target: bool,
}

/// The full report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchReport {
    /// Spec version the run targets.
    pub spec_version: String,
    /// Always true — these numbers come from the synthetic simulator.
    pub synthetic: bool,
    /// PRNG seed used (determinism anchor).
    pub seed: u64,
    /// Total events processed.
    pub events_total: usize,
    /// Distinct modalities present.
    pub modalities: usize,
    /// Distinct inference labels produced.
    pub distinct_inferences: usize,
    /// Per-task F1 scores (SYNTHETIC).
    pub tasks: Vec<TaskScore>,
    /// p95 per-event pipeline latency in milliseconds.
    pub p95_latency_ms: f64,
    /// p50 latency in milliseconds (context).
    pub p50_latency_ms: f64,
    /// Provenance coverage: fraction of events with a verifiable/synthetic
    /// receipt, percent.
    pub provenance_coverage_pct: f64,
    /// Number of events transmitted above the privacy policy ceiling.
    pub privacy_violations: u32,
}

impl BenchReport {
    /// Render the report as a human-readable table. The SYNTHETIC label is
    /// printed prominently so no one mistakes these for field-validated numbers.
    #[must_use]
    pub fn to_table(&self) -> String {
        let mut s = String::new();
        s.push_str("================ RuField MFS v0.1 — Deterministic Benchmark Report ================\n");
        s.push_str(&format!(
            "spec={}  seed={}  events={}  modalities={}  distinct_inferences={}\n",
            self.spec_version, self.seed, self.events_total, self.modalities, self.distinct_inferences
        ));
        s.push_str("ALL METRICS ARE *SYNTHETIC* — scored vs the simulator's own ground-truth labels.\n");
        s.push_str("They demonstrate the pipeline scores correctly against known truth; they are\n");
        s.push_str("NOT field-validated accuracy. No hardware is involved in v0.1.\n");
        s.push_str("-----------------------------------------------------------------------------------\n");
        s.push_str(&format!(
            "{:<20} {:>8} {:>10} {:>10} {:>8}\n",
            "TASK (SYNTHETIC)", "METRIC", "VALUE", "TARGET", "MEETS"
        ));
        for t in &self.tasks {
            s.push_str(&format!(
                "{:<20} {:>8} {:>10.3} {:>10.3} {:>8}\n",
                t.task,
                t.metric,
                t.value,
                t.target,
                if t.meets_target { "yes" } else { "NO" }
            ));
        }
        s.push_str("-----------------------------------------------------------------------------------\n");
        s.push_str(&format!(
            "p50 latency:          {:.4} ms\n",
            self.p50_latency_ms
        ));
        s.push_str(&format!(
            "p95 latency:          {:.4} ms   (target < 100 ms: {})\n",
            self.p95_latency_ms,
            if self.p95_latency_ms < 100.0 { "PASS" } else { "FAIL" }
        ));
        s.push_str(&format!(
            "provenance coverage:  {:.1} %      (target 100%: {})\n",
            self.provenance_coverage_pct,
            if (self.provenance_coverage_pct - 100.0).abs() < 1e-6 {
                "PASS"
            } else {
                "FAIL"
            }
        ));
        s.push_str(&format!(
            "privacy violations:   {}          (target 0: {})\n",
            self.privacy_violations,
            if self.privacy_violations == 0 { "PASS" } else { "FAIL" }
        ));
        s.push_str("===================================================================================\n");
        s
    }

    /// Stable, pretty JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("report serializes")
    }
}
