//! Field tensor — the normalized numeric container (ADR-260 §9).

use crate::error::CoreError;
use crate::modality::{FieldAxis, Modality};
use serde::{Deserialize, Serialize};

/// The current RuField MFS wire spec version.
pub const SPEC_VERSION: &str = "rufield.mfs.v0.1";

/// Normalized numeric container for a sensor observation (ADR-260 §9).
///
/// `values` is row-major flattened over `shape`. The product of `shape` must
/// equal `values.len()` (enforced by [`FieldTensor::validate`] and
/// [`FieldTensor::new`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldTensor {
    /// Wire spec version (`rufield.mfs.v0.1`).
    pub spec_version: String,
    /// Capture time, nanoseconds since Unix epoch.
    pub timestamp_ns: u64,
    /// Source modality.
    pub modality: Modality,
    /// Semantic label for each dimension of `shape` (same length as `shape`).
    pub axes: Vec<FieldAxis>,
    /// Dimensions of the tensor (row-major).
    pub shape: Vec<usize>,
    /// Row-major flattened values; `len() == shape.product()`.
    pub values: Vec<f32>,
    /// Overall confidence in this tensor, `0.0..=1.0`.
    pub confidence: f32,
    /// Estimated noise floor (modality-specific units).
    pub noise_floor: f32,
    /// Calibration receipt id this tensor was produced under, if any.
    pub calibration_id: Option<String>,
    /// Privacy class of the tensor contents.
    pub privacy_class: crate::privacy::PrivacyClass,
}

impl FieldTensor {
    /// Construct a tensor, validating the shape/values invariant and axis count.
    pub fn new(
        timestamp_ns: u64,
        modality: Modality,
        axes: Vec<FieldAxis>,
        shape: Vec<usize>,
        values: Vec<f32>,
        confidence: f32,
        noise_floor: f32,
        calibration_id: Option<String>,
        privacy_class: crate::privacy::PrivacyClass,
    ) -> Result<Self, CoreError> {
        let t = FieldTensor {
            spec_version: SPEC_VERSION.to_string(),
            timestamp_ns,
            modality,
            axes,
            shape,
            values,
            confidence,
            noise_floor,
            calibration_id,
            privacy_class,
        };
        t.validate()?;
        Ok(t)
    }

    /// Number of elements implied by `shape` (1 for a scalar / empty shape).
    #[must_use]
    pub fn element_count(&self) -> usize {
        self.shape.iter().product()
    }

    /// Validate the structural invariants:
    /// `shape.product() == values.len()` and `axes.len() == shape.len()`.
    pub fn validate(&self) -> Result<(), CoreError> {
        let expected = self.element_count();
        if expected != self.values.len() {
            return Err(CoreError::ShapeMismatch {
                expected,
                actual: self.values.len(),
            });
        }
        if self.axes.len() != self.shape.len() {
            return Err(CoreError::AxisRankMismatch {
                axes: self.axes.len(),
                rank: self.shape.len(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::PrivacyClass;

    #[test]
    fn valid_tensor_round_trips() {
        let t = FieldTensor::new(
            1,
            Modality::WifiCsi,
            vec![FieldAxis::Time, FieldAxis::Frequency],
            vec![2, 3],
            vec![0.0, 1.0, 2.0, 3.0, 4.0, 5.0],
            0.9,
            0.01,
            Some("cal_1".into()),
            PrivacyClass::P0,
        )
        .unwrap();
        assert_eq!(t.element_count(), 6);
        let j = serde_json::to_string(&t).unwrap();
        let back: FieldTensor = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn shape_mismatch_rejected() {
        let err = FieldTensor::new(
            1,
            Modality::WifiCsi,
            vec![FieldAxis::Time, FieldAxis::Frequency],
            vec![2, 3],
            vec![0.0, 1.0],
            0.9,
            0.0,
            None,
            PrivacyClass::P0,
        )
        .unwrap_err();
        matches!(err, CoreError::ShapeMismatch { .. });
    }

    #[test]
    fn axis_rank_mismatch_rejected() {
        let err = FieldTensor::new(
            1,
            Modality::WifiCsi,
            vec![FieldAxis::Time],
            vec![2, 3],
            vec![0.0, 1.0, 2.0, 3.0, 4.0, 5.0],
            0.9,
            0.0,
            None,
            PrivacyClass::P0,
        )
        .unwrap_err();
        matches!(err, CoreError::AxisRankMismatch { .. });
    }
}
