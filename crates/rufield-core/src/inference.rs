//! Inference query / result / embedding types (ADR-260 §16 / §24).

use crate::privacy::PrivacyClass;
use serde::{Deserialize, Serialize};

/// A query against the fusion engine (ADR-260 §16 `FusionEngine::infer`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceQuery {
    /// Inference labels of interest (empty = all available).
    pub labels: Vec<String>,
    /// Optional zone scope.
    pub zone_id: Option<String>,
    /// Optional anonymous spatial track scope. `None` queries every partition,
    /// including the legacy anonymous partition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_id: Option<String>,
    /// "As of" time, nanoseconds since Unix epoch; `None` = latest.
    pub as_of_ns: Option<u64>,
}

impl InferenceQuery {
    /// Query for all available inferences at the latest time.
    #[must_use]
    pub fn all() -> Self {
        InferenceQuery {
            labels: Vec::new(),
            zone_id: None,
            track_id: None,
            as_of_ns: None,
        }
    }

    /// Query all labels for one anonymous spatial track.
    #[must_use]
    pub fn for_track(track_id: impl Into<String>) -> Self {
        InferenceQuery {
            labels: Vec::new(),
            zone_id: None,
            track_id: Some(track_id.into()),
            as_of_ns: None,
        }
    }
}

/// A single fused inference (ADR-260 §24 — every inference must carry these
/// fields).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldInference {
    /// Inference label (e.g. `person_present`, `bed_exit`).
    pub label: String,
    /// Anonymous spatial track whose evidence produced this inference. `None`
    /// preserves the legacy untracked room-level behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_id: Option<String>,
    /// Confidence `0.0..=1.0`.
    pub confidence: f32,
    /// Event ids supporting this inference.
    pub supporting_events: Vec<String>,
    /// Event ids contradicting this inference.
    pub contradicting_events: Vec<String>,
    /// Privacy class of the inference itself.
    pub privacy_class: PrivacyClass,
    /// Calibration id, if applicable.
    pub calibration_id: Option<String>,
    /// Model / rule id that produced the inference.
    pub model_id: String,
    /// Time the inference was produced, ns since epoch.
    pub produced_ns: u64,
    /// Time the inference expires, ns since epoch.
    pub expires_ns: u64,
}

/// The calibration conditions under which an uncertainty claim is valid.
///
/// This is deliberately separate from [`FieldInference`] so v0.1 producers
/// remain source compatible. New consumers can opt in through
/// [`CalibratedInference`] without treating a legacy scalar confidence as a
/// calibrated probability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibrationContext {
    /// Stable calibration run identifier.
    pub calibration_id: String,
    /// Method used to calibrate the output, for example `split_conformal`.
    pub method: String,
    /// Miscoverage level requested during calibration.
    pub alpha: f32,
    /// Number of exchangeable calibration examples.
    pub sample_count: usize,
    /// Domain in which coverage was measured, such as a room or device set.
    pub domain: String,
    /// Time the calibration artifact was finalized, nanoseconds since Unix epoch.
    pub calibrated_at_ns: u64,
}

/// A set valued classification prediction with an explicit coverage target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PredictionSet {
    /// Labels retained by the calibrated prediction rule.
    pub labels: Vec<String>,
    /// Requested marginal coverage, normally `1.0 - alpha`.
    pub coverage_target: f32,
}

/// A calibrated numeric interval for regression style field estimates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PredictionInterval {
    /// Inclusive lower bound.
    pub lower: f32,
    /// Inclusive upper bound.
    pub upper: f32,
    /// Requested marginal coverage.
    pub coverage_target: f32,
    /// Unit or quantity identifier for the interval.
    pub quantity: String,
}

/// Machine readable reason why a calibrated inference was withheld.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbstentionReason {
    /// The prediction set contains zero or multiple plausible labels.
    AmbiguousPredictionSet,
    /// The input is outside the calibrated operating domain.
    OutOfDistribution,
    /// Calibration evidence is absent, stale, or too small.
    InsufficientCalibration,
    /// A policy layer explicitly withheld the result.
    PolicyWithheld,
}

/// Additive uncertainty metadata for a legacy [`FieldInference`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UncertaintyEnvelope {
    /// Optional set valued classification result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prediction_set: Option<PredictionSet>,
    /// Optional interval valued regression result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prediction_interval: Option<PredictionInterval>,
    /// Out of distribution score in `0.0..=1.0`, where one is most anomalous.
    pub ood_score: f32,
    /// Calibration conditions supporting the uncertainty claim.
    pub calibration: CalibrationContext,
    /// Reason the system abstained, if it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abstention: Option<AbstentionReason>,
}

/// A backwards compatible composition of an inference and uncertainty data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibratedInference {
    /// Original v0.1 inference, unchanged on the wire.
    pub inference: FieldInference,
    /// Explicit calibrated uncertainty metadata.
    pub uncertainty: UncertaintyEnvelope,
}

/// A field embedding produced by a [`crate::traits::FieldEncoder`]
/// (ADR-260 §16). v0.1 carries a plain feature vector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldEmbedding {
    /// Modality string code of the source.
    pub modality: String,
    /// Embedding vector.
    pub vector: Vec<f32>,
    /// Privacy class of the embedding.
    pub privacy_class: PrivacyClass,
    /// Source event id.
    pub source_event_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inference_round_trips() {
        let inf = FieldInference {
            label: "person_present".into(),
            track_id: None,
            confidence: 0.91,
            supporting_events: vec!["e1".into(), "e2".into()],
            contradicting_events: vec![],
            privacy_class: PrivacyClass::P2,
            calibration_id: Some("cal".into()),
            model_id: "rule.person_present".into(),
            produced_ns: 100,
            expires_ns: 200,
        };
        let j = serde_json::to_string(&inf).unwrap();
        let back: FieldInference = serde_json::from_str(&j).unwrap();
        assert_eq!(inf, back);
    }

    #[test]
    fn calibrated_inference_composes_legacy_wire_type() {
        let inf = FieldInference {
            label: "person_present".into(),
            confidence: 0.91,
            supporting_events: vec!["e1".into()],
            contradicting_events: vec![],
            privacy_class: PrivacyClass::P2,
            calibration_id: Some("cal".into()),
            model_id: "rule.person_present".into(),
            produced_ns: 100,
            expires_ns: 200,
        };
        let calibrated = CalibratedInference {
            inference: inf,
            uncertainty: UncertaintyEnvelope {
                prediction_set: Some(PredictionSet {
                    labels: vec!["person_present".into()],
                    coverage_target: 0.9,
                }),
                prediction_interval: None,
                ood_score: 0.03,
                calibration: CalibrationContext {
                    calibration_id: "cal".into(),
                    method: "split_conformal".into(),
                    alpha: 0.1,
                    sample_count: 100,
                    domain: "room_holdout".into(),
                    calibrated_at_ns: 50,
                },
                abstention: None,
            },
        };
        let json = serde_json::to_string(&calibrated).unwrap();
        let back: CalibratedInference = serde_json::from_str(&json).unwrap();
        assert_eq!(calibrated, back);
    }
}
