//! Bounded advisory receiver diagnostics. These reports never assert presence,
//! interference causality, calibration, authenticated origin or capture freshness.
use crate::rf_spectrum_quality::{RfDiagnostic, SourceKind};
use serde::Serialize;
use std::io;

pub const BASELINE_WINDOWS: usize = 16;
pub const MAX_STREAMS: usize = 32;
pub const POWER_RISE_DB: f64 = 6.0;
const MAX_CONTIGUOUS_GAP_NS: u64 = 1_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QualityKey {
    pub source_id: String,
    pub source_kind: SourceKind,
    pub run: u64,
    pub sample_rate_hz: u64,
    pub center_frequency_hz: Option<u64>,
}
impl From<&RfDiagnostic> for QualityKey {
    fn from(d: &RfDiagnostic) -> Self {
        Self {
            source_id: d.source_id.clone(),
            source_kind: d.source_kind.clone(),
            run: d.run,
            sample_rate_hz: d.sample_rate_hz,
            center_frequency_hz: d.center_frequency_hz,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    WarmingUp,
    BaselineReady,
    Compared,
    Abstained,
}
#[derive(Debug, Clone, Serialize)]
pub struct QualityReport {
    pub schema: &'static str,
    pub key: QualityKey,
    pub observed_monotonic_ns: u64,
    pub status: AnalysisStatus,
    pub trust: &'static str,
    pub valid: bool,
    pub confidence: f64,
    pub cause: &'static str,
    pub baseline_windows: usize,
    pub baseline_dbfs: Option<f64>,
    pub delta_db: Option<f64>,
    pub power_rise: bool,
    pub issues: Vec<String>,
    pub abstention_reasons: Vec<String>,
    pub limitations: [&'static str; 3],
}
struct StreamState {
    key: QualityKey,
    last_ns: u64,
    last_slot: u64,
    warmup: Vec<f64>,
    baseline: Option<f64>,
}
impl StreamState {
    fn new(key: QualityKey) -> Self {
        Self {
            key,
            last_ns: 0,
            last_slot: 0,
            warmup: Vec::with_capacity(BASELINE_WINDOWS),
            baseline: None,
        }
    }
    fn reset_baseline(&mut self) {
        self.warmup.clear();
        self.baseline = None;
    }
}
/// At most MAX_STREAMS states, each at most BASELINE_WINDOWS scalars.
/// A configuration change discards the prior baseline; switching back does not
/// restore it. Call reset() at recording boundaries or to start a new baseline.
pub struct RfQualityAnalyzer {
    streams: Vec<StreamState>,
}
impl Default for RfQualityAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
impl RfQualityAnalyzer {
    pub fn new() -> Self {
        Self {
            streams: Vec::new(),
        }
    }
    pub fn reset(&mut self) {
        self.streams.clear();
    }
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }
    pub fn analyze(&mut self, d: &RfDiagnostic) -> io::Result<QualityReport> {
        d.validate()?;
        let key = QualityKey::from(d);
        let mut report = QualityReport {
            schema: "rufield.rf_quality_analysis.v1",
            key: key.clone(),
            observed_monotonic_ns: d.observed_monotonic_ns,
            status: AnalysisStatus::Abstained,
            trust: "unverified_advisory",
            valid: false,
            confidence: 0.0,
            cause: "unknown",
            baseline_windows: 0,
            baseline_dbfs: None,
            delta_db: None,
            power_rise: false,
            issues: Vec::new(),
            abstention_reasons: Vec::new(),
            limitations: [
                "configuration_unverified",
                "not_presence_or_interference_evidence",
                "producer_monotonic_clock_not_authenticated_capture_time",
            ],
        };
        for reason in &d.invalid_reasons {
            if reason != "configuration_unverified" {
                report.issues.push(reason.clone());
            }
        }
        for (present, reason) in [
            (d.missing_samples != 0, "lost"),
            (d.event_count != 0, "event"),
            (d.overrun_slices != 0, "overrun"),
            (d.rail_fraction.is_some_and(|v| v > 0.0), "rail_samples"),
        ] {
            if present && !report.issues.iter().any(|s| s == reason) {
                report.issues.push(reason.into());
            }
        }
        let position = self
            .streams
            .iter()
            .position(|s| s.key.source_id == key.source_id && s.key.source_kind == key.source_kind);
        let i = if let Some(i) = position {
            i
        } else {
            if self.streams.len() >= MAX_STREAMS {
                report.abstention_reasons.push("stream_capacity".into());
                return Ok(report);
            }
            self.streams.push(StreamState::new(key.clone()));
            self.streams.len() - 1
        };
        let state = &mut self.streams[i];
        if state.key != key {
            *state = StreamState::new(key);
            report
                .abstention_reasons
                .push("run_or_configuration_change".into());
        } else if state.last_ns != 0 {
            if d.observed_monotonic_ns <= state.last_ns {
                report
                    .abstention_reasons
                    .push("nonincreasing_timestamp".into());
            } else if d.observed_monotonic_ns - state.last_ns > MAX_CONTIGUOUS_GAP_NS {
                report.abstention_reasons.push("timestamp_gap".into());
            }
            if d.slot_index <= state.last_slot {
                report.abstention_reasons.push("nonincreasing_slot".into());
            } else if state.last_slot.checked_add(1) != Some(d.slot_index) {
                report.abstention_reasons.push("slot_gap".into());
            }
        }
        state.last_ns = d.observed_monotonic_ns;
        state.last_slot = d.slot_index;
        if d.observed_monotonic_ns == 0 {
            report.abstention_reasons.push("zero_timestamp".into());
        }
        if d.sample_rate_hz == 0 || d.center_frequency_hz.is_none() {
            report
                .abstention_reasons
                .push("unknown_channel_configuration".into());
        }
        if d.sample_count == 0 || d.rms_dbfs.is_none() || d.rail_fraction.is_none() {
            report
                .abstention_reasons
                .push("no_power_measurement".into());
        }
        if !report.issues.is_empty() {
            report
                .abstention_reasons
                .push("receiver_quality_issue".into());
        }
        if !report.abstention_reasons.is_empty() {
            state.reset_baseline();
            return Ok(report);
        }
        let value = d.rms_dbfs.expect("checked above");
        if let Some(baseline) = state.baseline {
            report.status = AnalysisStatus::Compared;
            report.baseline_dbfs = Some(baseline);
            report.delta_db = Some(value - baseline);
            report.power_rise = value - baseline >= POWER_RISE_DB;
        } else {
            state.warmup.push(value);
            report.status = AnalysisStatus::WarmingUp;
            if state.warmup.len() == BASELINE_WINDOWS {
                let mut sorted = state.warmup.clone();
                sorted.sort_by(f64::total_cmp);
                let median =
                    (sorted[BASELINE_WINDOWS / 2 - 1] + sorted[BASELINE_WINDOWS / 2]) / 2.0;
                state.baseline = Some(median);
                report.status = AnalysisStatus::BaselineReady;
                report.baseline_dbfs = Some(median);
            }
        }
        report.baseline_windows = state.warmup.len();
        Ok(report)
    }
}
