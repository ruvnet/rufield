//! Leakage resistant held out split plans.

use crate::manifest::{EvidenceManifest, EvidenceRecord};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Unit isolated by one evaluation protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitAxis {
    /// No room appears in multiple folds.
    Room,
    /// No device appears in multiple folds.
    Device,
    /// No UTC capture day appears in multiple folds.
    Day,
    /// No session appears in multiple folds.
    Session,
    /// No known participant appears in multiple folds.
    Participant,
}

impl SplitAxis {
    /// Every independently reported held out protocol.
    #[must_use]
    pub fn all() -> [Self; 5] {
        [
            Self::Room,
            Self::Device,
            Self::Day,
            Self::Session,
            Self::Participant,
        ]
    }

    fn key(self, record: &EvidenceRecord) -> Option<&str> {
        match self {
            Self::Room => Some(&record.room_id),
            Self::Device => Some(&record.device_id),
            Self::Day => Some(&record.capture_day),
            Self::Session => Some(&record.session_id),
            Self::Participant => Some(
                record
                    .participant_id
                    .as_deref()
                    .unwrap_or("__unknown_participant__"),
            ),
        }
    }
}

/// Deterministic fold assignment for one held out axis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitPlan {
    /// Grouping unit isolated by this plan.
    pub axis: SplitAxis,
    /// Number of requested folds.
    pub folds: usize,
    /// Sample id to fold index.
    pub assignments: BTreeMap<String, usize>,
}

/// Split construction or validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitError(String);

impl SplitError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for SplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SplitError {}

/// Create five deterministic split protocols. Separate protocols avoid the
/// connected component collapse that occurs when a device moves between rooms
/// or a participant appears on several days, while every named unit remains
/// isolated within its own reported protocol. This prevents overlap in the
/// generated assignments. It cannot prove that a model training pipeline used
/// only its assigned training folds, so promotion separately requires an
/// immutable external split or model lineage artifact.
pub fn build_split_plans(
    manifest: &EvidenceManifest,
    folds: usize,
) -> Result<Vec<SplitPlan>, SplitError> {
    if folds < 2 {
        return Err(SplitError::new("at least two folds are required"));
    }
    let plans = SplitAxis::all()
        .into_iter()
        .map(|axis| {
            let assignments = manifest
                .records
                .iter()
                .map(|record| {
                    // Anonymous participant records form one conservative group.
                    // Treating each missing participant as its sample id would let
                    // anonymous rows manufacture represented participant folds.
                    let group_key = axis.key(record).unwrap_or("__unknown_participant__");
                    (record.sample_id.clone(), stable_fold(group_key, folds))
                })
                .collect();
            SplitPlan {
                axis,
                folds,
                assignments,
            }
        })
        .collect::<Vec<_>>();
    for plan in &plans {
        validate_no_leakage(manifest, plan)?;
    }
    Ok(plans)
}

/// Verify that no grouping key crosses folds and every sample is assigned.
pub fn validate_no_leakage(
    manifest: &EvidenceManifest,
    plan: &SplitPlan,
) -> Result<(), SplitError> {
    if plan.assignments.len() != manifest.records.len() {
        return Err(SplitError::new(
            "split assignment does not cover every sample",
        ));
    }
    let mut groups: BTreeMap<&str, usize> = BTreeMap::new();
    for record in &manifest.records {
        let fold = *plan
            .assignments
            .get(&record.sample_id)
            .ok_or_else(|| SplitError::new("sample missing from split assignment"))?;
        if fold >= plan.folds {
            return Err(SplitError::new("split assignment uses an invalid fold"));
        }
        if let Some(key) = plan.axis.key(record) {
            match groups.insert(key, fold) {
                Some(previous) if previous != fold => {
                    return Err(SplitError::new(format!(
                        "{:?} key {key} leaks across folds",
                        plan.axis
                    )))
                }
                _ => {}
            }
        }
    }
    Ok(())
}

/// Number of represented folds in a plan.
#[must_use]
pub fn represented_folds(plan: &SplitPlan) -> usize {
    plan.assignments
        .values()
        .copied()
        .collect::<BTreeSet<_>>()
        .len()
}

fn stable_fold(value: &str, folds: usize) -> usize {
    // FNV 1a gives stable cross process assignments without another dependency.
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    (hash as usize) % folds
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::EvidenceManifest;

    #[test]
    fn all_five_units_are_isolated() {
        let manifest = EvidenceManifest::from_json(include_str!(
            "../../../fixtures/evidence/synthetic-only.json"
        ))
        .unwrap();
        let plans = build_split_plans(&manifest, 3).unwrap();
        assert_eq!(plans.len(), 5);
        for plan in plans {
            validate_no_leakage(&manifest, &plan).unwrap();
        }
    }

    #[test]
    fn modified_assignment_exposes_leakage() {
        let manifest = EvidenceManifest::from_json(include_str!(
            "../../../fixtures/evidence/synthetic-only.json"
        ))
        .unwrap();
        let mut plan = build_split_plans(&manifest, 3)
            .unwrap()
            .into_iter()
            .find(|plan| plan.axis == SplitAxis::Room)
            .unwrap();
        let same_room: Vec<_> = manifest
            .records
            .iter()
            .filter(|record| record.room_id == "fixture_room_01")
            .collect();
        plan.assignments.insert(same_room[0].sample_id.clone(), 0);
        plan.assignments.insert(same_room[1].sample_id.clone(), 1);
        assert!(validate_no_leakage(&manifest, &plan).is_err());
    }

    #[test]
    fn anonymous_participants_cannot_manufacture_fold_diversity() {
        let mut manifest = EvidenceManifest::from_json(include_str!(
            "../../../fixtures/evidence/synthetic-only.json"
        ))
        .unwrap();
        for record in &mut manifest.records {
            record.participant_id = None;
        }

        let plan = build_split_plans(&manifest, 5)
            .unwrap()
            .into_iter()
            .find(|plan| plan.axis == SplitAxis::Participant)
            .unwrap();

        assert_eq!(represented_folds(&plan), 1);
    }
}
