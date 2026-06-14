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
}
