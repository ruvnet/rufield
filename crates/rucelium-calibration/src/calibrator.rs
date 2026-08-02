//! Applying calibration records to samples — with rejection, never repair
//! (ADR-264 §12 items 4 and 6).

use crate::error::CalibrationError;
use crate::store::CalibrationStore;
use rucelium_core::{EnvSample, Uncertainty};
use serde::{Deserialize, Serialize};

/// What [`Calibrator::apply`] did to a sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationOutcome {
    /// A calibration record was verified and its affine correction applied.
    Applied {
        /// The record that was applied.
        calibration_id: u32,
    },
    /// The sample carried `calibration_id == 0`: no correction was invented
    /// (ADR-264 §12 item 6); the quality score was penalised instead.
    Uncalibrated,
}

/// Applies verified calibration records to [`EnvSample`]s.
///
/// The calibrator never invents a correction: an uncalibrated sample keeps
/// its raw value and pays a quality penalty; a sample referencing a record
/// that fails any check (unknown, wrong device, wrong modality, expired,
/// broken lineage) is rejected with the sample left **completely untouched**
/// (ADR-264 §12 item 6).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Calibrator {
    /// Multiplier applied to `quality` for uncalibrated samples.
    quality_penalty_uncalibrated: f32,
}

impl Default for Calibrator {
    /// The reference penalty: uncalibrated samples lose half their quality.
    fn default() -> Self {
        Calibrator::new(0.5)
    }
}

impl Calibrator {
    /// Create a calibrator with the given uncalibrated-quality multiplier
    /// (the resulting quality is clamped to `0.0..=1.0`).
    #[must_use]
    pub fn new(quality_penalty_uncalibrated: f32) -> Self {
        Calibrator {
            quality_penalty_uncalibrated,
        }
    }

    /// Apply the sample's referenced calibration record from `store`.
    ///
    /// - `calibration_id == 0` (uncalibrated): multiplies `quality` by the
    ///   penalty, records `"cal:none"` in the provenance lineage, changes
    ///   nothing else, and returns [`CalibrationOutcome::Uncalibrated`].
    /// - Otherwise the record is looked up and checked against the sample's
    ///   node, modality, expiry at `now_ns`, and full lineage
    ///   ([`CalibrationStore::verify_lineage`]). On success the affine
    ///   correction is applied, the uncertainty interval is recentred on the
    ///   corrected value with half-width
    ///   `max(existing half-width, record.uncertainty_half_width())`,
    ///   `"cal:<id>"` is pushed onto the lineage, quality is unchanged, and
    ///   the sample is re-validated.
    ///
    /// On **any** error the sample is left exactly as it was.
    pub fn apply(
        &self,
        store: &CalibrationStore,
        sample: &mut EnvSample,
        now_ns: u64,
    ) -> Result<CalibrationOutcome, CalibrationError> {
        if sample.calibration_id == 0 {
            // Penalise, never correct (§12 item 6).
            sample.quality = (sample.quality * self.quality_penalty_uncalibrated).clamp(0.0, 1.0);
            sample.provenance.lineage.push("cal:none".to_string());
            return Ok(CalibrationOutcome::Uncalibrated);
        }

        let id = sample.calibration_id;
        let record = store.get(id).ok_or(CalibrationError::UnknownRecord(id))?;
        if record.node_id != sample.node_id {
            return Err(CalibrationError::WrongDevice {
                id,
                expected: record.node_id,
                actual: sample.node_id,
            });
        }
        if record.modality != sample.modality {
            return Err(CalibrationError::WrongModality(id));
        }
        if record.is_expired(now_ns) {
            return Err(CalibrationError::Expired {
                id,
                expires_ns: record.expires_ns,
                now_ns,
            });
        }
        store.verify_lineage(id)?;

        // All checks passed; mutate a working copy so a re-validation failure
        // still leaves the caller's sample untouched.
        let mut updated = sample.clone();
        updated.value = record.apply(sample.value);
        let existing_half_width = sample.uncertainty.width() / 2.0;
        let half_width = existing_half_width.max(record.uncertainty_half_width());
        updated.uncertainty = Uncertainty::symmetric(updated.value, half_width);
        updated.provenance.lineage.push(format!("cal:{id}"));
        updated.validate()?;
        *sample = updated;
        Ok(CalibrationOutcome::Applied { calibration_id: id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rucelium_core::{CalibrationRecord, GeoPoint, SampleProvenance, SensorModality};

    fn record() -> CalibrationRecord {
        CalibrationRecord {
            calibration_id: 3,
            node_id: 7,
            modality: SensorModality::Weather,
            method: "anchor_reference".into(),
            reference_station: Some("anchor-01".into()),
            parent_id: None,
            created_ns: 1_000,
            expires_ns: 2_000_000,
            scale_q16: 66_536,       // ≈ 1.0153
            offset_q16: -32_768,     // -0.5
            uncertainty_q16: 26_214, // ≈ 0.4
            data_hash: "sha256:cal".into(),
            signature_hex: None,
            signer_pubkey_hex: None,
        }
    }

    fn store() -> CalibrationStore {
        let mut s = CalibrationStore::new();
        s.insert(record()).unwrap();
        s
    }

    fn sample() -> EnvSample {
        EnvSample {
            node_id: 7,
            sequence: 42,
            measured_ns: 1_000,
            received_ns: 2_000,
            geo: GeoPoint::new(514_778_216, -14_767, 46_000).unwrap(),
            modality: SensorModality::Weather,
            observed_property: "air_temperature".into(),
            unit: "Cel".into(),
            value: 21.5,
            quality: 0.98,
            uncertainty: Uncertainty::symmetric(21.5, 0.3),
            calibration_id: 3,
            flags: 0,
            battery_mv: 3600,
            provenance: SampleProvenance {
                firmware_hash: "sha256:abc".into(),
                signer_pubkey_hex: "00ff".into(),
                verified: true,
                lineage: vec![],
            },
        }
    }

    #[test]
    fn applies_affine_correction_exactly_and_widens_uncertainty() {
        let store = store();
        let cal = Calibrator::default();
        let mut s = sample();
        let raw = s.value;
        let outcome = cal.apply(&store, &mut s, 10_000).unwrap();
        assert_eq!(outcome, CalibrationOutcome::Applied { calibration_id: 3 });
        assert_eq!(s.value, record().apply(raw));
        // Record half-width (≈0.4) exceeds the sample's (0.3), so the
        // interval is recentred with the record's half-width.
        let hw = record().uncertainty_half_width();
        assert!((s.uncertainty.lower - (s.value - hw)).abs() < 1e-12);
        assert!((s.uncertainty.upper - (s.value + hw)).abs() < 1e-12);
        assert_eq!(s.provenance.lineage, vec!["cal:3".to_string()]);
        // Quality is untouched on the calibrated path.
        assert_eq!(s.quality, 0.98);
        s.validate().unwrap();
    }

    #[test]
    fn never_narrows_an_uncertainty_interval() {
        let store = store();
        let cal = Calibrator::default();
        let mut s = sample();
        s.uncertainty = Uncertainty::symmetric(s.value, 1.5); // wider than the record's 0.4
        cal.apply(&store, &mut s, 10_000).unwrap();
        assert!((s.uncertainty.width() - 3.0).abs() < 1e-12);
        assert!((s.uncertainty.lower - (s.value - 1.5)).abs() < 1e-12);
    }

    #[test]
    fn uncalibrated_sample_is_penalised_never_corrected() {
        let store = store();
        let cal = Calibrator::default();
        let mut s = sample();
        s.calibration_id = 0;
        let before = s.clone();
        let outcome = cal.apply(&store, &mut s, 10_000).unwrap();
        assert_eq!(outcome, CalibrationOutcome::Uncalibrated);
        assert_eq!(s.quality, 0.98f32 * 0.5);
        assert_eq!(s.provenance.lineage, vec!["cal:none".to_string()]);
        // Value and uncertainty are untouched — no invented correction.
        assert_eq!(s.value, before.value);
        assert_eq!(s.uncertainty, before.uncertainty);
        s.validate().unwrap();
    }

    #[test]
    fn expired_record_rejects_and_leaves_sample_unchanged() {
        let store = store();
        let cal = Calibrator::default();
        let mut s = sample();
        let before = s.clone();
        let err = cal.apply(&store, &mut s, 2_000_000).unwrap_err();
        assert_eq!(
            err,
            CalibrationError::Expired {
                id: 3,
                expires_ns: 2_000_000,
                now_ns: 2_000_000
            }
        );
        assert_eq!(s, before);
    }

    #[test]
    fn wrong_node_and_wrong_modality_reject_unchanged() {
        let store = store();
        let cal = Calibrator::default();

        let mut s = sample();
        s.node_id = 8;
        let before = s.clone();
        assert_eq!(
            cal.apply(&store, &mut s, 10_000).unwrap_err(),
            CalibrationError::WrongDevice {
                id: 3,
                expected: 7,
                actual: 8
            }
        );
        assert_eq!(s, before);

        let mut s = sample();
        s.modality = SensorModality::SoilMoisture;
        s.observed_property = "soil_volumetric_water_content".into();
        let before = s.clone();
        assert_eq!(
            cal.apply(&store, &mut s, 10_000).unwrap_err(),
            CalibrationError::WrongModality(3)
        );
        assert_eq!(s, before);
    }

    #[test]
    fn unknown_record_rejects_unchanged() {
        let store = store();
        let cal = Calibrator::default();
        let mut s = sample();
        s.calibration_id = 99;
        let before = s.clone();
        assert_eq!(
            cal.apply(&store, &mut s, 10_000).unwrap_err(),
            CalibrationError::UnknownRecord(99)
        );
        assert_eq!(s, before);
    }

    #[test]
    fn outcome_serde_round_trips() {
        let o = CalibrationOutcome::Applied { calibration_id: 3 };
        let j = serde_json::to_string(&o).unwrap();
        let back: CalibrationOutcome = serde_json::from_str(&j).unwrap();
        assert_eq!(o, back);
    }
}
