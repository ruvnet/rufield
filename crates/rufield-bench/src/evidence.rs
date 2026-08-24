//! Machine evaluated promotion report for externally captured evidence.

use crate::artifacts::{ArtifactReceipt, VerifiedArtifacts};
use crate::manifest::{valid_sha256_digest, EvidenceManifest, EvidenceOrigin};
use crate::metrics::{
    binary_auroc, expected_calibration_error, percentile_ns, selective_risk, Confusion,
};
use crate::split::{build_split_plans, represented_folds};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Stable identifier for the promotion policy schema embedded in receipts.
pub const PROMOTION_POLICY_ID: &str = "rufield.promotion.v1";

/// Metrics computed from physical evidence only. When no physical records are
/// present, simulation metrics are included for diagnostics and promotion is
/// unconditionally rejected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceReport {
    /// Dataset identity.
    pub dataset_id: String,
    /// Evaluated task.
    pub task: String,
    /// Total manifest records.
    pub records_total: usize,
    /// Physical records scored for promotion.
    pub physical_records: usize,
    /// Captured hardware records evaluated by replay.
    pub captured_replay_records: usize,
    /// Live hardware records.
    pub live_capture_records: usize,
    /// Simulation records excluded from physical metrics.
    pub simulation_records: usize,
    /// True when reported metrics excluded all simulation records.
    pub metrics_use_physical_only: bool,
    /// Binary F1 at threshold 0.5, with abstentions counted as negative.
    pub f1: f32,
    /// AUROC, absent when either class is missing.
    pub auroc: Option<f32>,
    /// Ten bin expected calibration error.
    pub expected_calibration_error: f32,
    /// Error rate among nonabstained predictions.
    pub selective_risk: Option<f32>,
    /// Fraction of predictions not withheld.
    pub accepted_fraction: f32,
    /// False positive events divided by negative monitoring hours.
    pub false_alarms_per_hour: Option<f64>,
    /// Negative monitoring exposure counted once per session and domain.
    pub negative_monitoring_hours: f64,
    /// End to end p95 latency in milliseconds.
    pub p95_latency_ms: f64,
    /// Fraction of scored records with verified provenance, percent.
    pub provenance_coverage_pct: f64,
    /// Number of privacy policy violations.
    pub privacy_violations: usize,
    /// Overall F1 minus worst domain F1.
    pub cross_domain_degradation: Option<f32>,
    /// Number of distinct reporting domains.
    pub domains: usize,
    /// Domains containing both positive and negative truth.
    pub evaluable_domains: usize,
    /// Distinct diversity units for promotion policy.
    pub diversity: DiversityCounts,
}

/// Dataset diversity summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiversityCounts {
    /// Distinct rooms.
    pub rooms: usize,
    /// Distinct devices.
    pub devices: usize,
    /// Distinct capture days.
    pub days: usize,
    /// Distinct sessions.
    pub sessions: usize,
    /// Distinct known participants.
    pub participants: usize,
}

/// Fully machine evaluated promotion thresholds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromotionPolicy {
    /// Minimum physical records.
    pub minimum_physical_records: usize,
    /// Minimum distinct rooms.
    pub minimum_rooms: usize,
    /// Minimum distinct devices.
    pub minimum_devices: usize,
    /// Minimum distinct capture days.
    pub minimum_days: usize,
    /// Minimum distinct sessions.
    pub minimum_sessions: usize,
    /// Minimum distinct participants.
    pub minimum_participants: usize,
    /// Minimum distinct reporting domains.
    pub minimum_domains: usize,
    /// Requested folds for every leakage axis.
    pub split_folds: usize,
    /// Minimum represented folds in every leakage plan.
    pub minimum_represented_folds: usize,
    /// Required F1 threshold.
    pub minimum_f1: f32,
    /// Required AUROC threshold.
    pub minimum_auroc: f32,
    /// Maximum expected calibration error.
    pub maximum_ece: f32,
    /// Maximum selective risk.
    pub maximum_selective_risk: f32,
    /// Minimum fraction of nonabstained predictions.
    pub minimum_accepted_fraction: f32,
    /// Maximum false alarms per negative monitoring hour.
    pub maximum_false_alarms_per_hour: f64,
    /// Maximum p95 latency in milliseconds.
    pub maximum_p95_latency_ms: f64,
    /// Minimum verified provenance coverage, percent.
    pub minimum_provenance_coverage_pct: f64,
    /// Maximum privacy violations.
    pub maximum_privacy_violations: usize,
    /// Maximum overall to worst domain F1 degradation.
    pub maximum_cross_domain_degradation: f32,
}

impl Default for PromotionPolicy {
    fn default() -> Self {
        Self {
            minimum_physical_records: 100_000,
            minimum_rooms: 3,
            minimum_devices: 3,
            minimum_days: 3,
            minimum_sessions: 3,
            minimum_participants: 3,
            minimum_domains: 3,
            split_folds: 5,
            minimum_represented_folds: 2,
            minimum_f1: 0.80,
            minimum_auroc: 0.85,
            maximum_ece: 0.05,
            maximum_selective_risk: 0.10,
            minimum_accepted_fraction: 0.50,
            maximum_false_alarms_per_hour: 1.0,
            maximum_p95_latency_ms: 100.0,
            minimum_provenance_coverage_pct: 100.0,
            maximum_privacy_violations: 0,
            maximum_cross_domain_degradation: 0.10,
        }
    }
}

/// One failed promotion invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateFailure {
    /// Stable code for automation.
    pub code: String,
    /// Human readable diagnostic with observed and required values.
    pub detail: String,
}

/// Promotion result with no advisory or manual thresholds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromotionDecision {
    /// Stable identifier for the policy schema used by this decision.
    pub policy_id: String,
    /// Exact thresholds evaluated, including caller supplied custom values.
    pub policy: PromotionPolicy,
    /// Verified byte lineage. Omitted unless the receipt matches this manifest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_receipt: Option<ArtifactReceipt>,
    /// True only when every invariant passes.
    pub promotable: bool,
    /// Computed evidence metrics.
    pub report: EvidenceReport,
    /// Empty when promotable.
    pub failures: Vec<GateFailure>,
}

impl PromotionDecision {
    /// Stable JSON for CI artifacts.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("promotion decision serializes")
    }
}

/// Compute a report, excluding simulation whenever physical evidence exists.
#[must_use]
pub fn build_evidence_report(manifest: &EvidenceManifest) -> EvidenceReport {
    let physical: Vec<_> = manifest
        .records
        .iter()
        .filter(|record| record.evidence_origin.is_physical())
        .collect();
    let scored = if physical.is_empty() {
        manifest.records.iter().collect::<Vec<_>>()
    } else {
        physical.clone()
    };

    let probabilities = scored
        .iter()
        .map(|record| (record.predicted_probability, record.ground_truth_positive))
        .collect::<Vec<_>>();
    let selective = scored
        .iter()
        .map(|record| {
            (
                record.predicted_probability,
                record.ground_truth_positive,
                record.abstained,
            )
        })
        .collect::<Vec<_>>();
    let mut confusion = Confusion::default();
    for record in &scored {
        confusion.record(
            !record.abstained && record.predicted_probability >= 0.5,
            record.ground_truth_positive,
        );
    }

    let mut negative_sessions = BTreeMap::new();
    for record in scored.iter().filter(|record| !record.ground_truth_positive) {
        negative_sessions
            .entry((&record.domain_id, &record.session_id))
            .or_insert(record.negative_session_exposure_seconds);
    }
    let negative_seconds = negative_sessions.values().copied().sum::<f64>();
    let false_alarms = scored
        .iter()
        .filter(|record| {
            !record.ground_truth_positive
                && !record.abstained
                && record.predicted_probability >= 0.5
        })
        .count();
    let false_alarms_per_hour =
        (negative_seconds > 0.0).then_some(false_alarms as f64 / (negative_seconds / 3_600.0));

    let latency_ns = scored
        .iter()
        .map(|record| (record.latency_ms * 1_000_000.0).round() as u64)
        .collect::<Vec<_>>();
    let provenance_coverage_pct = if scored.is_empty() {
        0.0
    } else {
        scored
            .iter()
            .filter(|record| record.provenance_verified)
            .count() as f64
            / scored.len() as f64
            * 100.0
    };
    let accepted = scored.iter().filter(|record| !record.abstained).count();

    let mut domain_records: BTreeMap<&str, Vec<_>> = BTreeMap::new();
    for record in &scored {
        domain_records
            .entry(&record.domain_id)
            .or_default()
            .push(*record);
    }
    let evaluable_domain_records = domain_records
        .values()
        .filter(|records| {
            records.iter().any(|record| record.ground_truth_positive)
                && records.iter().any(|record| !record.ground_truth_positive)
        })
        .collect::<Vec<_>>();
    let worst_domain_f1 = evaluable_domain_records
        .iter()
        .map(|records| f1_for_records(records))
        .min_by(f32::total_cmp);
    let cross_domain_degradation = worst_domain_f1.map(|worst| (confusion.f1() - worst).max(0.0));

    EvidenceReport {
        dataset_id: manifest.dataset_id.clone(),
        task: manifest.task.clone(),
        records_total: manifest.records.len(),
        physical_records: physical.len(),
        captured_replay_records: manifest
            .records
            .iter()
            .filter(|record| record.evidence_origin == EvidenceOrigin::CapturedReplay)
            .count(),
        live_capture_records: manifest
            .records
            .iter()
            .filter(|record| record.evidence_origin == EvidenceOrigin::LiveCapture)
            .count(),
        simulation_records: manifest
            .records
            .iter()
            .filter(|record| record.evidence_origin == EvidenceOrigin::Simulation)
            .count(),
        metrics_use_physical_only: !physical.is_empty(),
        f1: confusion.f1(),
        auroc: binary_auroc(&probabilities),
        expected_calibration_error: expected_calibration_error(&probabilities, 10),
        selective_risk: selective_risk(&selective),
        accepted_fraction: if scored.is_empty() {
            0.0
        } else {
            accepted as f32 / scored.len() as f32
        },
        false_alarms_per_hour,
        negative_monitoring_hours: negative_seconds / 3_600.0,
        p95_latency_ms: percentile_ns(&latency_ns, 0.95) as f64 / 1_000_000.0,
        provenance_coverage_pct,
        privacy_violations: scored
            .iter()
            .filter(|record| record.privacy_violation)
            .count(),
        cross_domain_degradation,
        domains: domain_records.len(),
        evaluable_domains: evaluable_domain_records.len(),
        diversity: diversity(&scored),
    }
}

/// Evaluate every promotion threshold and leakage protocol.
#[must_use]
pub fn evaluate_promotion(
    manifest: &EvidenceManifest,
    policy: &PromotionPolicy,
) -> PromotionDecision {
    evaluate_promotion_inner(manifest, policy, None)
}

/// Verify materialized artifact bytes and evaluate the promotion policy.
/// This is the only library path that can return `promotable: true`.
#[must_use]
pub fn evaluate_promotion_with_artifacts(
    manifest: &EvidenceManifest,
    policy: &PromotionPolicy,
    artifacts: &VerifiedArtifacts,
) -> PromotionDecision {
    evaluate_promotion_inner(manifest, policy, Some(artifacts))
}

fn evaluate_promotion_inner(
    manifest: &EvidenceManifest,
    policy: &PromotionPolicy,
    artifacts: Option<&VerifiedArtifacts>,
) -> PromotionDecision {
    let report = build_evidence_report(manifest);
    let mut failures = Vec::new();
    let mut artifact_receipt = None;
    let mut fail = |code: &str, detail: String| {
        failures.push(GateFailure {
            code: code.into(),
            detail,
        });
    };

    let policy_errors = policy_errors(policy);
    if !policy_errors.is_empty() {
        fail("policy_invalid", policy_errors.join("; "));
    }

    if manifest.fixture {
        fail(
            "fixture_dataset",
            "repository fixtures are conformance only and can never promote".into(),
        );
    }
    if manifest
        .evidence_bundle_uri
        .trim()
        .to_ascii_lowercase()
        .starts_with("fixture:")
    {
        fail(
            "external_evidence_missing",
            "promotion requires an immutable external evidence bundle URI".into(),
        );
    }
    if !valid_sha256_digest(&manifest.evidence_bundle_digest) {
        fail(
            "evidence_digest_invalid",
            "evidence bundle digest must be sha256 followed by 64 hexadecimal characters".into(),
        );
    }
    match artifacts {
        None => fail(
            "artifact_bytes_unverified",
            "promotion requires governed bundle and isolation JSON, verified byte digests, and an independently anchored evidence authority signature"
                .into(),
        ),
        Some(artifacts) => {
            if !artifacts.matches_manifest(manifest) {
                fail(
                    "artifact_receipt_mismatch",
                    "verified artifact receipt does not belong to this manifest".into(),
                );
            } else {
                artifact_receipt = Some(artifacts.receipt());
                if let Some((signed_folds, represented_by_axis)) =
                    artifacts.signed_split_evidence()
                {
                    if signed_folds != policy.split_folds {
                        fail(
                            "signed_split_fold_count",
                            format!(
                                "signed split uses {signed_folds} folds, policy requires {}",
                                policy.split_folds
                            ),
                        );
                    }
                    for axis in crate::split::SplitAxis::all() {
                        let represented = represented_by_axis.get(&axis).copied().unwrap_or(0);
                        if represented < policy.minimum_represented_folds {
                            fail(
                                &format!("signed_split_{axis:?}").to_lowercase(),
                                format!(
                                    "signed {axis:?} split represents {represented} folds, requires >= {}",
                                    policy.minimum_represented_folds
                                ),
                            );
                        }
                    }
                }
            }
        }
    }
    if report.physical_records == 0 {
        fail(
            "synthetic_only",
            "no captured replay or live capture records are present".into(),
        );
    }
    threshold_min_usize(
        &mut fail,
        "physical_records",
        report.physical_records,
        policy.minimum_physical_records,
    );
    threshold_min_usize(
        &mut fail,
        "rooms",
        report.diversity.rooms,
        policy.minimum_rooms,
    );
    threshold_min_usize(
        &mut fail,
        "devices",
        report.diversity.devices,
        policy.minimum_devices,
    );
    threshold_min_usize(
        &mut fail,
        "days",
        report.diversity.days,
        policy.minimum_days,
    );
    threshold_min_usize(
        &mut fail,
        "sessions",
        report.diversity.sessions,
        policy.minimum_sessions,
    );
    threshold_min_usize(
        &mut fail,
        "participants",
        report.diversity.participants,
        policy.minimum_participants,
    );
    threshold_min_usize(
        &mut fail,
        "domains",
        report.evaluable_domains,
        policy.minimum_domains,
    );

    let split_artifact_valid = valid_external_artifact(
        manifest.split_assignment_uri.as_deref(),
        manifest.split_assignment_digest.as_deref(),
    );
    let model_lineage_valid = valid_external_artifact(
        manifest.model_lineage_uri.as_deref(),
        manifest.model_lineage_digest.as_deref(),
    );
    if !(split_artifact_valid || model_lineage_valid) {
        fail(
            "training_isolation_evidence_missing",
            "requires an immutable external split assignment or model lineage artifact with SHA256 digest"
                .into(),
        );
    }
    if report.f1 < policy.minimum_f1 {
        fail(
            "f1",
            format!(
                "observed {:.3}, requires >= {:.3}",
                report.f1, policy.minimum_f1
            ),
        );
    }
    match report.auroc {
        Some(value) if value >= policy.minimum_auroc => {}
        Some(value) => fail(
            "auroc",
            format!(
                "observed {value:.3}, requires >= {:.3}",
                policy.minimum_auroc
            ),
        ),
        None => fail(
            "auroc_missing",
            "AUROC requires both positive and negative physical examples".into(),
        ),
    }
    threshold_max_f32(
        &mut fail,
        "expected_calibration_error",
        report.expected_calibration_error,
        policy.maximum_ece,
    );
    match report.selective_risk {
        Some(value) => threshold_max_f32(
            &mut fail,
            "selective_risk",
            value,
            policy.maximum_selective_risk,
        ),
        None => fail(
            "selective_risk_missing",
            "all predictions abstained, so selective risk is undefined".into(),
        ),
    }
    if report.accepted_fraction < policy.minimum_accepted_fraction {
        fail(
            "accepted_fraction",
            format!(
                "observed {:.3}, requires >= {:.3}",
                report.accepted_fraction, policy.minimum_accepted_fraction
            ),
        );
    }
    match report.false_alarms_per_hour {
        Some(value) if value <= policy.maximum_false_alarms_per_hour => {}
        Some(value) => fail(
            "false_alarms_per_hour",
            format!(
                "observed {value:.3}, requires <= {:.3}",
                policy.maximum_false_alarms_per_hour
            ),
        ),
        None => fail(
            "false_alarm_exposure_missing",
            "negative monitoring exposure is required".into(),
        ),
    }
    if report.p95_latency_ms > policy.maximum_p95_latency_ms {
        fail(
            "p95_latency_ms",
            format!(
                "observed {:.3}, requires <= {:.3}",
                report.p95_latency_ms, policy.maximum_p95_latency_ms
            ),
        );
    }
    if report.provenance_coverage_pct < policy.minimum_provenance_coverage_pct {
        fail(
            "provenance_coverage_pct",
            format!(
                "observed {:.3}, requires >= {:.3}",
                report.provenance_coverage_pct, policy.minimum_provenance_coverage_pct
            ),
        );
    }
    if report.privacy_violations > policy.maximum_privacy_violations {
        fail(
            "privacy_violations",
            format!(
                "observed {}, requires <= {}",
                report.privacy_violations, policy.maximum_privacy_violations
            ),
        );
    }
    match report.cross_domain_degradation {
        Some(value) => threshold_max_f32(
            &mut fail,
            "cross_domain_degradation",
            value,
            policy.maximum_cross_domain_degradation,
        ),
        None => fail(
            "cross_domain_degradation_missing",
            "at least one reporting domain is required".into(),
        ),
    }

    let mut split_manifest = manifest.clone();
    if report.physical_records > 0 {
        split_manifest
            .records
            .retain(|record| record.evidence_origin.is_physical());
    }
    match build_split_plans(&split_manifest, policy.split_folds) {
        Ok(plans) => {
            for plan in plans {
                let represented = represented_folds(&plan);
                if represented < policy.minimum_represented_folds {
                    fail(
                        &format!("split_{:?}", plan.axis).to_lowercase(),
                        format!(
                            "{:?} split represents {represented} folds, requires >= {}",
                            plan.axis, policy.minimum_represented_folds
                        ),
                    );
                }
            }
        }
        Err(error) => fail("split_invalid", error.to_string()),
    }

    PromotionDecision {
        policy_id: PROMOTION_POLICY_ID.into(),
        policy: policy.clone(),
        artifact_receipt,
        promotable: failures.is_empty(),
        report,
        failures,
    }
}

fn diversity(records: &[&crate::manifest::EvidenceRecord]) -> DiversityCounts {
    DiversityCounts {
        rooms: records
            .iter()
            .map(|record| &record.room_id)
            .collect::<BTreeSet<_>>()
            .len(),
        devices: records
            .iter()
            .map(|record| &record.device_id)
            .collect::<BTreeSet<_>>()
            .len(),
        days: records
            .iter()
            .map(|record| &record.capture_day)
            .collect::<BTreeSet<_>>()
            .len(),
        sessions: records
            .iter()
            .map(|record| &record.session_id)
            .collect::<BTreeSet<_>>()
            .len(),
        participants: records
            .iter()
            .filter_map(|record| record.participant_id.as_ref())
            .collect::<BTreeSet<_>>()
            .len(),
    }
}

fn f1_for_records(records: &[&crate::manifest::EvidenceRecord]) -> f32 {
    let mut confusion = Confusion::default();
    for record in records {
        confusion.record(
            !record.abstained && record.predicted_probability >= 0.5,
            record.ground_truth_positive,
        );
    }
    confusion.f1()
}

fn policy_errors(policy: &PromotionPolicy) -> Vec<String> {
    let mut errors = Vec::new();
    if policy.minimum_physical_records == 0
        || policy.minimum_rooms == 0
        || policy.minimum_devices == 0
        || policy.minimum_days == 0
        || policy.minimum_sessions == 0
        || policy.minimum_participants == 0
        || policy.minimum_domains == 0
    {
        errors.push("minimum counts must be nonzero".into());
    }
    if policy.split_folds < 2
        || policy.minimum_represented_folds < 2
        || policy.minimum_represented_folds > policy.split_folds
    {
        errors.push("split folds must define at least two represented folds".into());
    }
    for (name, value) in [
        ("minimum_f1", policy.minimum_f1),
        ("minimum_auroc", policy.minimum_auroc),
        ("maximum_ece", policy.maximum_ece),
        ("maximum_selective_risk", policy.maximum_selective_risk),
        (
            "minimum_accepted_fraction",
            policy.minimum_accepted_fraction,
        ),
        (
            "maximum_cross_domain_degradation",
            policy.maximum_cross_domain_degradation,
        ),
    ] {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            errors.push(format!("{name} must be finite and between zero and one"));
        }
    }
    if !policy.maximum_false_alarms_per_hour.is_finite()
        || policy.maximum_false_alarms_per_hour < 0.0
    {
        errors.push("maximum_false_alarms_per_hour must be finite and nonnegative".into());
    }
    if !policy.maximum_p95_latency_ms.is_finite() || policy.maximum_p95_latency_ms <= 0.0 {
        errors.push("maximum_p95_latency_ms must be finite and positive".into());
    }
    if !policy.minimum_provenance_coverage_pct.is_finite()
        || !(0.0..=100.0).contains(&policy.minimum_provenance_coverage_pct)
    {
        errors.push(
            "minimum_provenance_coverage_pct must be finite and between zero and one hundred"
                .into(),
        );
    }
    errors
}

fn valid_external_artifact(uri: Option<&str>, digest: Option<&str>) -> bool {
    match (uri, digest) {
        (Some(uri), Some(digest)) => {
            let uri = uri.trim();
            !uri.is_empty()
                && !uri.to_ascii_lowercase().starts_with("fixture:")
                && valid_sha256_digest(digest)
        }
        _ => false,
    }
}

fn threshold_min_usize(
    fail: &mut impl FnMut(&str, String),
    code: &str,
    observed: usize,
    required: usize,
) {
    if observed < required {
        fail(code, format!("observed {observed}, requires >= {required}"));
    }
}

fn threshold_max_f32(fail: &mut impl FnMut(&str, String), code: &str, observed: f32, maximum: f32) {
    if observed > maximum {
        fail(
            code,
            format!("observed {observed:.3}, requires <= {maximum:.3}"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::EvidenceManifest;

    #[test]
    fn bundled_fixture_can_never_promote() {
        let manifest = EvidenceManifest::from_json(include_str!(
            "../../../fixtures/evidence/synthetic-only.json"
        ))
        .unwrap();
        let decision = evaluate_promotion(&manifest, &PromotionPolicy::default());
        assert!(!decision.promotable);
        let codes = decision
            .failures
            .iter()
            .map(|failure| failure.code.as_str())
            .collect::<BTreeSet<_>>();
        assert!(codes.contains("fixture_dataset"));
        assert!(codes.contains("external_evidence_missing"));
        assert!(codes.contains("synthetic_only"));
        assert!(codes.contains("artifact_bytes_unverified"));
        assert_eq!(decision.report.physical_records, 0);
        assert!(!decision.report.metrics_use_physical_only);
        assert_eq!(decision.policy_id, PROMOTION_POLICY_ID);
        assert_eq!(decision.policy, PromotionPolicy::default());
        assert!(decision.artifact_receipt.is_none());
        assert!(serde_json::to_value(&decision)
            .unwrap()
            .get("artifact_receipt")
            .is_none());
    }

    #[test]
    fn fixture_uri_rejection_is_case_insensitive() {
        let mut manifest = EvidenceManifest::from_json(include_str!(
            "../../../fixtures/evidence/synthetic-only.json"
        ))
        .unwrap();
        manifest.evidence_bundle_uri = "FiXtUrE:synthetic-only".into();
        let decision = evaluate_promotion(&manifest, &PromotionPolicy::default());
        assert!(decision
            .failures
            .iter()
            .any(|failure| failure.code == "external_evidence_missing"));
    }

    #[test]
    fn all_thresholds_are_evaluated_by_code() {
        let policy = PromotionPolicy::default();
        let json = serde_json::to_value(policy).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 19);
    }

    #[test]
    fn custom_policy_values_are_embedded_in_the_decision() {
        let manifest = EvidenceManifest::from_json(include_str!(
            "../../../fixtures/evidence/synthetic-only.json"
        ))
        .unwrap();
        let policy = PromotionPolicy {
            minimum_physical_records: 424_242,
            maximum_ece: 0.04,
            ..PromotionPolicy::default()
        };
        let decision = evaluate_promotion(&manifest, &policy);
        assert_eq!(decision.policy, policy);
        let json = serde_json::to_value(decision).unwrap();
        assert_eq!(json["policy_id"], PROMOTION_POLICY_ID);
        assert_eq!(json["policy"], serde_json::to_value(&policy).unwrap());
    }

    #[test]
    fn only_domains_with_both_truth_classes_are_evaluable() {
        let mut manifest = EvidenceManifest::from_json(include_str!(
            "../../../fixtures/evidence/synthetic-only.json"
        ))
        .unwrap();
        for record in manifest.records.iter_mut().filter(|record| {
            record.ground_truth_positive && record.domain_id != "fixture_domain_01"
        }) {
            record.ground_truth_positive = false;
            record.negative_session_exposure_seconds = 3_600.0;
        }
        manifest.validate().unwrap();
        let decision = evaluate_promotion(&manifest, &PromotionPolicy::default());
        assert_eq!(decision.report.domains, 3);
        assert_eq!(decision.report.evaluable_domains, 1);
        assert!(decision
            .failures
            .iter()
            .any(|failure| failure.code == "domains"));
    }

    #[test]
    fn nonfinite_policy_value_fails_closed() {
        let manifest = EvidenceManifest::from_json(include_str!(
            "../../../fixtures/evidence/synthetic-only.json"
        ))
        .unwrap();
        let policy = PromotionPolicy {
            maximum_ece: f32::NAN,
            ..PromotionPolicy::default()
        };
        let decision = evaluate_promotion(&manifest, &policy);
        assert!(decision
            .failures
            .iter()
            .any(|failure| failure.code == "policy_invalid"));
    }

    #[test]
    fn split_axis_codes_are_stable() {
        assert_eq!(crate::split::SplitAxis::all().len(), 5);
    }

    #[test]
    fn session_exposure_is_counted_once_for_multiple_predictions() {
        let mut manifest = EvidenceManifest::from_json(include_str!(
            "../../../fixtures/evidence/synthetic-only.json"
        ))
        .unwrap();
        let original = manifest
            .records
            .iter_mut()
            .find(|record| record.sample_id == "fixture_002")
            .unwrap();
        original.predicted_probability = 0.9;
        let mut duplicate = original.clone();
        duplicate.sample_id = "fixture_002_second_prediction".into();
        manifest.records.push(duplicate);
        manifest.validate().unwrap();

        let report = build_evidence_report(&manifest);
        assert_eq!(report.negative_monitoring_hours, 3.0);
        assert_eq!(report.false_alarms_per_hour, Some(2.0 / 3.0));
    }

    #[test]
    fn hybrid_simulation_rows_cannot_supply_physical_split_folds() {
        let mut manifest = EvidenceManifest::from_json(include_str!(
            "../../../fixtures/evidence/synthetic-only.json"
        ))
        .unwrap();
        manifest.collection_kind = crate::manifest::CollectionKind::Hybrid;
        manifest.records[0].evidence_origin = EvidenceOrigin::CapturedReplay;
        manifest.validate().unwrap();

        let decision = evaluate_promotion(&manifest, &PromotionPolicy::default());
        let codes = decision
            .failures
            .iter()
            .map(|failure| failure.code.as_str())
            .collect::<BTreeSet<_>>();
        for code in [
            "split_room",
            "split_device",
            "split_day",
            "split_session",
            "split_participant",
        ] {
            assert!(
                codes.contains(code),
                "missing physical only split failure {code}"
            );
        }
    }
}
