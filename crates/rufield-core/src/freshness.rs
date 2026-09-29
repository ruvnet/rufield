//! Deterministic evidence freshness assessment for distributed sensing.
//!
//! A `FieldInference` already carries production and expiry timestamps, but
//! those values do not say how old the supporting sensor evidence was when the
//! result was evaluated. Distributed sensing also needs to distinguish stale
//! evidence, a temporally incoherent cohort, and suspicious future timestamps.
//!
//! This module is deliberately pure. It reads no clock, mutates no trust state,
//! allocates no intermediate collection, and changes no existing wire type.

use serde::{Deserialize, Serialize};

/// Task specific limits used to decide whether supporting evidence is usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessPolicy {
    /// Maximum permitted age of the oldest supporting evidence.
    pub maximum_age_ns: u64,
    /// Maximum permitted span from oldest to newest evidence in one cohort.
    pub maximum_cohort_span_ns: u64,
    /// Maximum permitted positive timestamp skew beyond evaluation time.
    pub maximum_future_skew_ns: u64,
}

/// Deterministic reason assigned to an evidence cohort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessDisposition {
    /// Every configured timing constraint is satisfied.
    Fresh,
    /// At least one timestamp is too far ahead of evaluation time.
    FutureSkew,
    /// The supporting observations span too wide a capture interval.
    IncoherentCohort,
    /// The oldest supporting observation exceeds the task age budget.
    StaleEvidence,
}

/// Auditable timing assessment for one set of supporting evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessAssessment {
    /// Number of supporting timestamps evaluated.
    pub evidence_count: usize,
    /// Oldest supporting capture timestamp.
    pub oldest_evidence_ns: u64,
    /// Newest supporting capture timestamp.
    pub newest_evidence_ns: u64,
    /// Caller supplied evaluation timestamp.
    pub evaluated_at_ns: u64,
    /// Age of the oldest supporting evidence at evaluation time.
    pub oldest_age_ns: u64,
    /// Age of the newest supporting evidence at evaluation time.
    pub newest_age_ns: u64,
    /// Capture span between the oldest and newest supporting evidence.
    pub cohort_span_ns: u64,
    /// Result of applying the supplied policy.
    pub disposition: FreshnessDisposition,
}

impl FreshnessAssessment {
    /// Whether the evidence cohort satisfies every configured timing limit.
    #[must_use]
    pub fn is_fresh(&self) -> bool {
        self.disposition == FreshnessDisposition::Fresh
    }
}

/// Assess source evidence timing without reading a clock or mutating state.
///
/// Returns `None` for an empty evidence set. The caller must not reinterpret
/// absence as freshness.
///
/// Disposition precedence is fail closed and deterministic:
///
/// 1. future skew,
/// 2. incoherent cohort span,
/// 3. stale oldest evidence,
/// 4. fresh.
///
/// Limits are inclusive. Evidence exactly on a configured boundary is accepted.
#[must_use]
pub fn assess_evidence_freshness(
    evidence_times_ns: &[u64],
    evaluated_at_ns: u64,
    policy: FreshnessPolicy,
) -> Option<FreshnessAssessment> {
    let (&first, rest) = evidence_times_ns.split_first()?;
    let mut oldest = first;
    let mut newest = first;

    for &timestamp_ns in rest {
        oldest = oldest.min(timestamp_ns);
        newest = newest.max(timestamp_ns);
    }

    let cohort_span_ns = newest.saturating_sub(oldest);
    let oldest_age_ns = evaluated_at_ns.saturating_sub(oldest);
    let newest_age_ns = evaluated_at_ns.saturating_sub(newest);
    let future_skew_ns = newest.saturating_sub(evaluated_at_ns);

    let disposition = if newest > evaluated_at_ns
        && future_skew_ns > policy.maximum_future_skew_ns
    {
        FreshnessDisposition::FutureSkew
    } else if cohort_span_ns > policy.maximum_cohort_span_ns {
        FreshnessDisposition::IncoherentCohort
    } else if oldest_age_ns > policy.maximum_age_ns {
        FreshnessDisposition::StaleEvidence
    } else {
        FreshnessDisposition::Fresh
    };

    Some(FreshnessAssessment {
        evidence_count: evidence_times_ns.len(),
        oldest_evidence_ns: oldest,
        newest_evidence_ns: newest,
        evaluated_at_ns,
        oldest_age_ns,
        newest_age_ns,
        cohort_span_ns,
        disposition,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> FreshnessPolicy {
        FreshnessPolicy {
            maximum_age_ns: 100,
            maximum_cohort_span_ns: 50,
            maximum_future_skew_ns: 5,
        }
    }

    #[test]
    fn empty_evidence_has_no_assessment() {
        assert!(assess_evidence_freshness(&[], 1_000, policy()).is_none());
    }

    #[test]
    fn exact_policy_boundaries_are_fresh() {
        let assessment = assess_evidence_freshness(&[900, 950], 1_000, policy()).unwrap();
        assert_eq!(assessment.oldest_age_ns, 100);
        assert_eq!(assessment.cohort_span_ns, 50);
        assert_eq!(assessment.disposition, FreshnessDisposition::Fresh);
        assert!(assessment.is_fresh());
    }

    #[test]
    fn stale_oldest_evidence_is_withheld() {
        let assessment = assess_evidence_freshness(&[899, 949], 1_000, policy()).unwrap();
        assert_eq!(assessment.disposition, FreshnessDisposition::StaleEvidence);
        assert!(!assessment.is_fresh());
    }

    #[test]
    fn incoherent_cohort_precedes_staleness() {
        let assessment = assess_evidence_freshness(&[800, 1_000], 1_000, policy()).unwrap();
        assert_eq!(
            assessment.disposition,
            FreshnessDisposition::IncoherentCohort
        );
    }

    #[test]
    fn future_skew_is_fail_closed_and_has_highest_precedence() {
        let assessment = assess_evidence_freshness(&[800, 1_006], 1_000, policy()).unwrap();
        assert_eq!(assessment.disposition, FreshnessDisposition::FutureSkew);
        assert_eq!(assessment.newest_age_ns, 0);
    }

    #[test]
    fn permitted_clock_skew_does_not_manufacture_age() {
        let assessment = assess_evidence_freshness(&[955, 1_005], 1_000, policy()).unwrap();
        assert_eq!(assessment.disposition, FreshnessDisposition::Fresh);
        assert_eq!(assessment.newest_age_ns, 0);
    }

    #[test]
    fn input_order_does_not_change_assessment() {
        let a = assess_evidence_freshness(&[970, 940, 960], 1_000, policy()).unwrap();
        let b = assess_evidence_freshness(&[960, 970, 940], 1_000, policy()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn assessment_round_trips_as_json() {
        let assessment = assess_evidence_freshness(&[970, 940], 1_000, policy()).unwrap();
        let json = serde_json::to_string(&assessment).unwrap();
        let back: FreshnessAssessment = serde_json::from_str(&json).unwrap();
        assert_eq!(assessment, back);
    }
}
