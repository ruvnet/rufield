//! The deterministic biome benchmark report (ADR-264 §14). Serializes to
//! stable JSON and renders a human table. All numbers are **SYNTHETIC** —
//! produced by the deterministic biome simulator, NOT a field deployment.

use serde::{Deserialize, Serialize};

/// One acceptance criterion line (ADR-264 §14).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Criterion {
    /// Criterion number (1–8).
    pub number: u8,
    /// Short name.
    pub name: String,
    /// Measured value, rendered.
    pub value: String,
    /// Target, rendered.
    pub target: String,
    /// Whether the criterion passes.
    pub pass: bool,
}

/// The full biome benchmark report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BiomeReport {
    /// Spec version the run targets.
    pub spec_version: String,
    /// Always true — these numbers come from the synthetic biome simulator.
    pub synthetic: bool,
    /// PRNG seed used (determinism anchor).
    pub seed: u64,
    /// Simulated nodes.
    pub nodes: u32,
    /// Simulated days.
    pub days: u32,
    /// Consecutive simulated offline days survived.
    pub offline_days: u32,
    /// Total emissions processed (genuine + adversarial).
    pub emissions_total: usize,
    /// Genuine samples accepted end-to-end.
    pub accepted: u64,
    /// Adversarial emissions injected (tamper + replay + forged key +
    /// post-revocation).
    pub attacks_injected: u64,
    /// Adversarial emissions rejected (must equal `attacks_injected`).
    pub attacks_rejected: u64,
    /// Samples restored from the outage buffer after reconnect.
    pub restored_after_outage: u64,
    /// Duplicate samples admitted during restore (must be 0).
    pub restore_duplicates: u64,
    /// Fraction of accepted observations that are usable and calibrated, %.
    pub usable_calibrated_pct: f64,
    /// Accepted observations mapped into the WorldGraph, %.
    pub worldgraph_coverage_pct: f64,
    /// Accepted observations projected into SensorThings entities, %.
    pub sensorthings_coverage_pct: f64,
    /// p50 per-emission gateway pipeline latency, ms (wall clock, in-process).
    pub p50_pipeline_ms: f64,
    /// p95 per-emission gateway pipeline latency, ms.
    pub p95_pipeline_ms: f64,
    /// p95 anomaly-sample → local alert latency, ms (target < 500).
    pub p95_alert_ms: f64,
    /// Local alerts raised for the injected anomaly.
    pub anomaly_alerts: u64,
    /// Node index quarantined for drift (quarantine, never silent correction).
    pub quarantined_nodes: u64,
    /// Samples accepted from OTHER nodes after the compromised device was
    /// revoked (biome continuity through revocation).
    pub accepted_after_revocation: u64,
    /// WorldGraph contradiction edges recorded (RF vs physical evidence).
    pub contradictions: u64,
    /// Governed control-path commands executed with receipts.
    pub commands_executed: u64,
    /// Governed control-path proposals rejected by a gate.
    pub proposals_rejected: u64,
    /// The eight §14 acceptance criteria.
    pub criteria: Vec<Criterion>,
}

impl BiomeReport {
    /// Whether every §14 criterion passes.
    #[must_use]
    pub fn accepted_all(&self) -> bool {
        !self.criteria.is_empty() && self.criteria.iter().all(|c| c.pass)
    }

    /// The deterministic portion of the report — everything except wall-clock
    /// latency measurements. Two runs at the same seed must agree on this
    /// exactly.
    #[must_use]
    pub fn deterministic_fingerprint(&self) -> String {
        let mut r = self.clone();
        r.p50_pipeline_ms = 0.0;
        r.p95_pipeline_ms = 0.0;
        r.p95_alert_ms = 0.0;
        // Latency-derived criterion values are re-rendered without numbers.
        for c in &mut r.criteria {
            if c.name.contains("latency") || c.name.contains("alert") {
                c.value = String::from("<wall-clock>");
            }
        }
        serde_json::to_string(&r).expect("report serializes")
    }

    /// Render the report as a human-readable table with the SYNTHETIC label
    /// printed prominently.
    #[must_use]
    pub fn to_table(&self) -> String {
        let mut s = String::new();
        s.push_str(
            "====== RuCelium v0.1 — Fabric Reference-Model Acceptance (ADR-264 §14, SYNTHETIC) ======\n",
        );
        s.push_str(&format!(
            "spec={}  seed={}  nodes={}  days={}  offline_days={}  emissions={}\n",
            self.spec_version,
            self.seed,
            self.nodes,
            self.days,
            self.offline_days,
            self.emissions_total
        ));
        s.push_str(
            "ALL NUMBERS ARE *SYNTHETIC* — a deterministic biome simulator, not a field pilot.\n",
        );
        s.push_str(
            "This scores the fabric REFERENCE MODEL (in-memory library components: signatures,\n",
        );
        s.push_str(
            "replay windows, dedup, quarantine, revocation, projection) against known ground\n",
        );
        s.push_str(
            "truth. It does NOT exercise the runtime path (store/transport/gateway daemon),\n",
        );
        s.push_str("which has its own end-to-end and restart-attack tests in rucelium-gateway.\n");
        s.push_str(
            "----------------------------------------------------------------------------------------\n",
        );
        s.push_str(&format!(
            "{:<3} {:<38} {:>16} {:>14} {:>6}\n",
            "#", "CRITERION (SYNTHETIC)", "VALUE", "TARGET", "PASS"
        ));
        for c in &self.criteria {
            s.push_str(&format!(
                "{:<3} {:<38} {:>16} {:>14} {:>6}\n",
                c.number,
                c.name,
                c.value,
                c.target,
                if c.pass { "yes" } else { "NO" }
            ));
        }
        s.push_str(
            "----------------------------------------------------------------------------------------\n",
        );
        s.push_str(&format!(
            "accepted={}  attacks {}/{} rejected  restored={} (dup={})  usable={:.2}%\n",
            self.accepted,
            self.attacks_rejected,
            self.attacks_injected,
            self.restored_after_outage,
            self.restore_duplicates,
            self.usable_calibrated_pct
        ));
        s.push_str(&format!(
            "pipeline p50={:.4} ms p95={:.4} ms   alert p95={:.4} ms\n",
            self.p50_pipeline_ms, self.p95_pipeline_ms, self.p95_alert_ms
        ));
        s.push_str(&format!(
            "quarantined={}  contradictions={}  commands_executed={}  proposals_rejected={}\n",
            self.quarantined_nodes,
            self.contradictions,
            self.commands_executed,
            self.proposals_rejected
        ));
        s.push_str(&format!(
            "ACCEPTANCE: {}\n",
            if self.accepted_all() {
                "PASS — all ADR-264 §14 criteria met (SYNTHETIC)"
            } else {
                "FAIL"
            }
        ));
        s.push_str(
            "========================================================================================\n",
        );
        s
    }

    /// Stable, pretty JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("report serializes")
    }
}
