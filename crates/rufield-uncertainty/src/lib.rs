//! Model independent uncertainty for RuField inferences.
//!
//! The reference implementation uses binary split conformal classification.
//! It wraps the v0.1 [`rufield_core::FieldInference`] instead of changing that
//! wire type. Coverage is a measured property of exchangeable calibration and
//! evaluation data, not a claim that every deployment has the same coverage.

use rufield_core::{
    AbstentionReason, CalibratedInference, CalibrationContext, FieldInference, PredictionSet,
    UncertaintyEnvelope,
};
use std::fmt;

/// One labeled probability used for calibration or coverage evaluation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CalibrationExample {
    /// Probability assigned to the positive label.
    pub positive_probability: f32,
    /// Whether the positive label is true.
    pub positive_truth: bool,
}

/// Fit controls and deployment metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct ConformalConfig {
    /// Desired miscoverage in `(0, 1)`.
    pub alpha: f32,
    /// Minimum examples required before emitting calibrated output.
    pub minimum_samples: usize,
    /// Inputs at or above this OOD score are withheld.
    pub ood_threshold: f32,
    /// Stable calibration identifier.
    pub calibration_id: String,
    /// Exact model identifier whose outputs were calibrated.
    pub model_id: String,
    /// Domain represented by the calibration split.
    pub domain: String,
    /// Time the calibration artifact was finalized, nanoseconds since Unix epoch.
    pub calibrated_at_ns: u64,
}

impl Default for ConformalConfig {
    fn default() -> Self {
        Self {
            alpha: 0.1,
            minimum_samples: 100,
            ood_threshold: 0.8,
            calibration_id: String::new(),
            model_id: String::new(),
            domain: String::new(),
            calibrated_at_ns: 0,
        }
    }
}

/// Errors are explicit so a caller cannot silently reinterpret uncalibrated
/// confidence as a probability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalibrationError {
    /// Alpha must be strictly inside the unit interval.
    InvalidAlpha,
    /// OOD threshold must be inside the unit interval.
    InvalidOodThreshold,
    /// Minimum sample policy must require at least one example.
    InvalidMinimumSamples,
    /// Positive and negative label names must both be nonempty.
    EmptyLabel,
    /// Positive and negative label names must be distinct.
    DuplicateLabels,
    /// The calibrator must bind a nonempty model identifier.
    EmptyModelId,
    /// The calibrator must bind a nonempty calibration identifier.
    EmptyCalibrationId,
    /// Calibration evidence must name a nonempty operating domain.
    EmptyDomain,
    /// The inference label is outside the configured binary task.
    UnknownLabel(String),
    /// The inference came from a different model.
    ModelMismatch { expected: String, actual: String },
    /// The inference carries absent or different calibration lineage.
    CalibrationMismatch {
        expected: String,
        actual: Option<String>,
    },
    /// Too few exchangeable examples were supplied.
    InsufficientSamples { required: usize, actual: usize },
    /// A probability or OOD score was nonfinite or outside the unit interval.
    InvalidProbability,
}

impl fmt::Display for CalibrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAlpha => {
                write!(f, "alpha must be finite and strictly between zero and one")
            }
            Self::InvalidOodThreshold => {
                write!(f, "OOD threshold must be finite and between zero and one")
            }
            Self::InvalidMinimumSamples => {
                write!(f, "minimum calibration samples must be at least one")
            }
            Self::EmptyLabel => write!(f, "positive and negative labels must be nonempty"),
            Self::DuplicateLabels => write!(f, "positive and negative labels must be distinct"),
            Self::EmptyModelId => write!(f, "model id must be nonempty"),
            Self::EmptyCalibrationId => write!(f, "calibration id must be nonempty"),
            Self::EmptyDomain => write!(f, "calibration domain must be nonempty"),
            Self::UnknownLabel(label) => write!(f, "unknown inference label: {label}"),
            Self::ModelMismatch { expected, actual } => {
                write!(f, "model mismatch: expected {expected}, received {actual}")
            }
            Self::CalibrationMismatch { expected, actual } => write!(
                f,
                "calibration mismatch: expected {expected}, received {}",
                actual.as_deref().unwrap_or("none")
            ),
            Self::InsufficientSamples { required, actual } => write!(
                f,
                "insufficient calibration examples: required {required}, received {actual}"
            ),
            Self::InvalidProbability => {
                write!(
                    f,
                    "probabilities and OOD scores must be finite and between zero and one"
                )
            }
        }
    }
}

impl std::error::Error for CalibrationError {}

/// Fitted binary split conformal classifier.
#[derive(Debug, Clone, PartialEq)]
pub struct SplitConformalClassifier {
    positive_label: String,
    negative_label: String,
    model_id: String,
    threshold: f32,
    ood_threshold: f32,
    context: CalibrationContext,
}

impl SplitConformalClassifier {
    /// Fit the finite sample corrected conformal threshold.
    pub fn fit(
        positive_label: impl Into<String>,
        negative_label: impl Into<String>,
        examples: &[CalibrationExample],
        config: ConformalConfig,
    ) -> Result<Self, CalibrationError> {
        let positive_label = positive_label.into();
        let negative_label = negative_label.into();
        if positive_label.trim().is_empty() || negative_label.trim().is_empty() {
            return Err(CalibrationError::EmptyLabel);
        }
        if positive_label == negative_label {
            return Err(CalibrationError::DuplicateLabels);
        }
        if config.model_id.trim().is_empty() {
            return Err(CalibrationError::EmptyModelId);
        }
        if config.calibration_id.trim().is_empty() {
            return Err(CalibrationError::EmptyCalibrationId);
        }
        if config.domain.trim().is_empty() {
            return Err(CalibrationError::EmptyDomain);
        }
        if !config.alpha.is_finite() || !(0.0..1.0).contains(&config.alpha) {
            return Err(CalibrationError::InvalidAlpha);
        }
        if !in_unit_interval(config.ood_threshold) {
            return Err(CalibrationError::InvalidOodThreshold);
        }
        if config.minimum_samples == 0 {
            return Err(CalibrationError::InvalidMinimumSamples);
        }
        if examples.len() < config.minimum_samples {
            return Err(CalibrationError::InsufficientSamples {
                required: config.minimum_samples,
                actual: examples.len(),
            });
        }

        let mut scores = Vec::with_capacity(examples.len());
        for example in examples {
            if !in_unit_interval(example.positive_probability) {
                return Err(CalibrationError::InvalidProbability);
            }
            scores.push(nonconformity(*example));
        }
        scores.sort_by(f32::total_cmp);

        // Finite sample corrected quantile:
        // ceil((n + 1) * (1 - alpha)), clipped to the available order stats.
        let rank = (((examples.len() + 1) as f32 * (1.0 - config.alpha)).ceil() as usize)
            .clamp(1, examples.len());
        let threshold = scores[rank - 1];
        let context = CalibrationContext {
            calibration_id: config.calibration_id,
            method: "binary_split_conformal".into(),
            alpha: config.alpha,
            sample_count: examples.len(),
            domain: config.domain,
            calibrated_at_ns: config.calibrated_at_ns,
        };

        Ok(Self {
            positive_label,
            negative_label,
            model_id: config.model_id,
            threshold,
            ood_threshold: config.ood_threshold,
            context,
        })
    }

    /// Calibrated nonconformity threshold selected during fitting.
    #[must_use]
    pub fn threshold(&self) -> f32 {
        self.threshold
    }

    /// Produce a set valued prediction for a positive label probability.
    pub fn prediction_set(
        &self,
        positive_probability: f32,
    ) -> Result<PredictionSet, CalibrationError> {
        if !in_unit_interval(positive_probability) {
            return Err(CalibrationError::InvalidProbability);
        }
        let mut labels = Vec::with_capacity(2);
        if positive_probability <= self.threshold {
            labels.push(self.negative_label.clone());
        }
        if 1.0 - positive_probability <= self.threshold {
            labels.push(self.positive_label.clone());
        }
        Ok(PredictionSet {
            labels,
            coverage_target: 1.0 - self.context.alpha,
        })
    }

    /// Wrap a legacy inference with calibrated uncertainty and an abstention
    /// decision. The original inference remains byte for byte representable.
    pub fn calibrate(
        &self,
        inference: FieldInference,
        ood_score: f32,
    ) -> Result<CalibratedInference, CalibrationError> {
        if !in_unit_interval(ood_score) {
            return Err(CalibrationError::InvalidProbability);
        }
        if inference.model_id != self.model_id {
            return Err(CalibrationError::ModelMismatch {
                expected: self.model_id.clone(),
                actual: inference.model_id,
            });
        }
        if inference.calibration_id.as_deref() != Some(self.context.calibration_id.as_str()) {
            return Err(CalibrationError::CalibrationMismatch {
                expected: self.context.calibration_id.clone(),
                actual: inference.calibration_id,
            });
        }
        if !in_unit_interval(inference.confidence) {
            return Err(CalibrationError::InvalidProbability);
        }
        let positive_probability = if inference.label == self.positive_label {
            inference.confidence
        } else if inference.label == self.negative_label {
            1.0 - inference.confidence
        } else {
            return Err(CalibrationError::UnknownLabel(inference.label));
        };
        let prediction_set = self.prediction_set(positive_probability)?;
        let abstention = if ood_score >= self.ood_threshold {
            Some(AbstentionReason::OutOfDistribution)
        } else if prediction_set.labels.len() != 1 {
            Some(AbstentionReason::AmbiguousPredictionSet)
        } else {
            None
        };

        Ok(CalibratedInference {
            inference,
            uncertainty: UncertaintyEnvelope {
                prediction_set: Some(prediction_set),
                prediction_interval: None,
                ood_score,
                calibration: self.context.clone(),
                abstention,
            },
        })
    }

    /// Measure empirical marginal coverage on an evaluation split.
    pub fn empirical_coverage(
        &self,
        examples: &[CalibrationExample],
    ) -> Result<f32, CalibrationError> {
        if examples.is_empty() {
            return Err(CalibrationError::InsufficientSamples {
                required: 1,
                actual: 0,
            });
        }
        let mut covered = 0usize;
        for example in examples {
            let set = self.prediction_set(example.positive_probability)?;
            let truth = if example.positive_truth {
                &self.positive_label
            } else {
                &self.negative_label
            };
            if set.labels.iter().any(|label| label == truth) {
                covered += 1;
            }
        }
        Ok(covered as f32 / examples.len() as f32)
    }
}

fn nonconformity(example: CalibrationExample) -> f32 {
    if example.positive_truth {
        1.0 - example.positive_probability
    } else {
        example.positive_probability
    }
}

fn in_unit_interval(value: f32) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rufield_core::{FieldInference, PrivacyClass};

    fn examples(count: usize) -> Vec<CalibrationExample> {
        (0..count)
            .map(|i| {
                let positive = i % 2 == 0;
                CalibrationExample {
                    positive_probability: if positive { 0.91 } else { 0.09 },
                    positive_truth: positive,
                }
            })
            .collect()
    }

    fn config() -> ConformalConfig {
        ConformalConfig {
            alpha: 0.1,
            minimum_samples: 20,
            ood_threshold: 0.8,
            calibration_id: "cal_fixture_1".into(),
            model_id: "fixture_model".into(),
            domain: "held_out_room".into(),
            calibrated_at_ns: 10,
        }
    }

    #[test]
    fn empirical_coverage_meets_fixture_target() {
        let calibrator = SplitConformalClassifier::fit(
            "person_present",
            "person_absent",
            &examples(100),
            config(),
        )
        .unwrap();
        let coverage = calibrator.empirical_coverage(&examples(40)).unwrap();
        assert!(coverage >= 0.9, "fixture coverage={coverage}");
    }

    #[test]
    fn high_ood_score_forces_abstention() {
        let calibrator = SplitConformalClassifier::fit(
            "person_present",
            "person_absent",
            &examples(100),
            config(),
        )
        .unwrap();
        let result = calibrator
            .calibrate(
                FieldInference {
                    label: "person_present".into(),
                    confidence: 0.91,
                    supporting_events: vec!["event_1".into()],
                    contradicting_events: vec![],
                    privacy_class: PrivacyClass::P2,
                    calibration_id: Some("cal_fixture_1".into()),
                    model_id: "fixture_model".into(),
                    produced_ns: 20,
                    expires_ns: 30,
                },
                0.9,
            )
            .unwrap();
        assert_eq!(
            result.uncertainty.abstention,
            Some(AbstentionReason::OutOfDistribution)
        );
    }

    #[test]
    fn insufficient_calibration_is_rejected() {
        let error = SplitConformalClassifier::fit("positive", "negative", &examples(4), config())
            .unwrap_err();
        assert_eq!(
            error,
            CalibrationError::InsufficientSamples {
                required: 20,
                actual: 4
            }
        );
    }

    #[test]
    fn zero_minimum_samples_is_rejected_without_panicking() {
        let mut invalid = config();
        invalid.minimum_samples = 0;
        let error =
            SplitConformalClassifier::fit("positive", "negative", &[], invalid).unwrap_err();
        assert_eq!(error, CalibrationError::InvalidMinimumSamples);
    }

    #[test]
    fn empty_and_duplicate_labels_are_typed_errors() {
        let empty =
            SplitConformalClassifier::fit("", "negative", &examples(100), config()).unwrap_err();
        assert_eq!(empty, CalibrationError::EmptyLabel);

        let duplicate = SplitConformalClassifier::fit(
            "person_present",
            "person_present",
            &examples(100),
            config(),
        )
        .unwrap_err();
        assert_eq!(duplicate, CalibrationError::DuplicateLabels);
    }

    fn inference(label: &str, confidence: f32) -> FieldInference {
        FieldInference {
            label: label.into(),
            confidence,
            supporting_events: vec!["event_1".into()],
            contradicting_events: vec![],
            privacy_class: PrivacyClass::P2,
            calibration_id: Some("cal_fixture_1".into()),
            model_id: "fixture_model".into(),
            produced_ns: 20,
            expires_ns: 30,
        }
    }

    #[test]
    fn negative_label_confidence_maps_to_one_minus_confidence() {
        let calibrator = SplitConformalClassifier::fit(
            "person_present",
            "person_absent",
            &examples(100),
            config(),
        )
        .unwrap();
        let calibrated = calibrator
            .calibrate(inference("person_absent", 0.91), 0.1)
            .unwrap();
        assert_eq!(
            calibrated.uncertainty.prediction_set.unwrap().labels,
            vec!["person_absent"]
        );
    }

    #[test]
    fn model_calibration_and_label_mismatches_fail_closed() {
        let calibrator = SplitConformalClassifier::fit(
            "person_present",
            "person_absent",
            &examples(100),
            config(),
        )
        .unwrap();

        let mut wrong_model = inference("person_present", 0.91);
        wrong_model.model_id = "other_model".into();
        assert!(matches!(
            calibrator.calibrate(wrong_model, 0.1),
            Err(CalibrationError::ModelMismatch { .. })
        ));

        let mut wrong_calibration = inference("person_present", 0.91);
        wrong_calibration.calibration_id = Some("other_calibration".into());
        assert!(matches!(
            calibrator.calibrate(wrong_calibration, 0.1),
            Err(CalibrationError::CalibrationMismatch { .. })
        ));

        let mut missing_calibration = inference("person_present", 0.91);
        missing_calibration.calibration_id = None;
        assert!(matches!(
            calibrator.calibrate(missing_calibration, 0.1),
            Err(CalibrationError::CalibrationMismatch { .. })
        ));

        assert_eq!(
            calibrator
                .calibrate(inference("bed_exit", 0.91), 0.1)
                .unwrap_err(),
            CalibrationError::UnknownLabel("bed_exit".into())
        );
    }

    #[test]
    fn empty_model_and_calibration_bindings_are_rejected() {
        let mut invalid_model = config();
        invalid_model.model_id = " ".into();
        assert_eq!(
            SplitConformalClassifier::fit(
                "person_present",
                "person_absent",
                &examples(100),
                invalid_model,
            )
            .unwrap_err(),
            CalibrationError::EmptyModelId
        );

        let mut invalid_calibration = config();
        invalid_calibration.calibration_id.clear();
        assert_eq!(
            SplitConformalClassifier::fit(
                "person_present",
                "person_absent",
                &examples(100),
                invalid_calibration,
            )
            .unwrap_err(),
            CalibrationError::EmptyCalibrationId
        );

        let mut invalid_domain = config();
        invalid_domain.domain = " ".into();
        assert_eq!(
            SplitConformalClassifier::fit(
                "person_present",
                "person_absent",
                &examples(100),
                invalid_domain,
            )
            .unwrap_err(),
            CalibrationError::EmptyDomain
        );

        let default_without_domain = ConformalConfig {
            model_id: "fixture_model".into(),
            calibration_id: "cal_fixture_1".into(),
            ..ConformalConfig::default()
        };
        assert_eq!(
            SplitConformalClassifier::fit(
                "person_present",
                "person_absent",
                &examples(100),
                default_without_domain,
            )
            .unwrap_err(),
            CalibrationError::EmptyDomain
        );
    }
}
