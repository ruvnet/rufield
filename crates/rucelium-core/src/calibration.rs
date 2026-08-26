//! Signed calibration records with lineage (ADR-264 §12).

use crate::error::EnvError;
use crate::modality::SensorModality;
use serde::{Deserialize, Serialize};

/// One Q16.16 unit (1.0 in fixed point).
pub const Q16_ONE: i32 = 65_536;

/// A calibration record. Records chain via `parent_id` up to a
/// reference-grade anchor (ADR-264 §12 items 1–3); the lineage check lives in
/// `rucelium-calibration`.
///
/// Coefficients are Q16.16 fixed point so the identical affine correction can
/// run on a float-free spore node and on the gateway:
/// `calibrated = raw * scale + offset`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationRecord {
    /// Calibration identity (referenced by `EnvSample::calibration_id`).
    /// 0 is reserved for "uncalibrated" and never a valid record id.
    pub calibration_id: u32,
    /// Device this record calibrates.
    pub node_id: u64,
    /// Modality this record applies to.
    pub modality: SensorModality,
    /// Method: `factory`, `colocation`, or `anchor_reference`.
    pub method: String,
    /// Reference anchor station id, when method used one.
    pub reference_station: Option<String>,
    /// Parent record in the lineage chain (`None` only for anchor-rooted
    /// records, i.e. `method == "anchor_reference"` or `"factory"`).
    pub parent_id: Option<u32>,
    /// Creation time, nanoseconds since Unix epoch.
    pub created_ns: u64,
    /// Expiry time, nanoseconds since Unix epoch.
    pub expires_ns: u64,
    /// Affine scale, Q16.16 (65_536 = 1.0).
    pub scale_q16: i32,
    /// Affine offset, Q16.16, in the sample's unit.
    pub offset_q16: i32,
    /// Half-width of the calibrated measurement uncertainty, Q16.16, in the
    /// sample's unit (requirement 9 of §7.1 — every calibration states the
    /// uncertainty it confers).
    pub uncertainty_q16: i32,
    /// `sha256:` hash of the calibration source data.
    pub data_hash: String,
    /// Hex-encoded ed25519 signature over the record by the calibrating
    /// authority, if signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
    /// Hex-encoded signer public key, if signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_pubkey_hex: Option<String>,
}

impl CalibrationRecord {
    /// Apply the affine correction to a raw value.
    #[must_use]
    pub fn apply(&self, raw: f64) -> f64 {
        raw * (f64::from(self.scale_q16) / f64::from(Q16_ONE))
            + f64::from(self.offset_q16) / f64::from(Q16_ONE)
    }

    /// Stated uncertainty half-width in the sample's unit.
    #[must_use]
    pub fn uncertainty_half_width(&self) -> f64 {
        f64::from(self.uncertainty_q16).abs() / f64::from(Q16_ONE)
    }

    /// Whether the record has expired at `now_ns`.
    #[must_use]
    pub fn is_expired(&self, now_ns: u64) -> bool {
        now_ns >= self.expires_ns
    }

    /// Structural validation.
    pub fn validate(&self) -> Result<(), EnvError> {
        if self.calibration_id == 0 {
            return Err(EnvError::Invalid(
                "calibration_id 0 is reserved for uncalibrated".into(),
            ));
        }
        if self.method.is_empty() {
            return Err(EnvError::MissingField("method"));
        }
        if self.expires_ns <= self.created_ns {
            return Err(EnvError::Invalid(format!(
                "calibration {} expires ({}) at or before creation ({})",
                self.calibration_id, self.expires_ns, self.created_ns
            )));
        }
        if self.scale_q16 == 0 {
            return Err(EnvError::Invalid(
                "calibration scale of 0 would destroy the measurement".into(),
            ));
        }
        if self.data_hash.is_empty() {
            return Err(EnvError::MissingField("data_hash"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> CalibrationRecord {
        CalibrationRecord {
            calibration_id: 3,
            node_id: 7,
            modality: SensorModality::Weather,
            method: "colocation".into(),
            reference_station: Some("anchor-01".into()),
            parent_id: Some(1),
            created_ns: 1_000,
            expires_ns: 2_000_000,
            scale_q16: 66_536,       // ≈ 1.0153
            offset_q16: -32_768,     // -0.5
            uncertainty_q16: 19_661, // ≈ 0.3
            data_hash: "sha256:cal".into(),
            signature_hex: None,
            signer_pubkey_hex: None,
        }
    }

    #[test]
    fn affine_apply_matches_fixed_point() {
        let r = record();
        let got = r.apply(10.0);
        let expect = 10.0 * (66_536.0 / 65_536.0) - 0.5;
        assert!((got - expect).abs() < 1e-9);
        assert!((r.uncertainty_half_width() - 0.3).abs() < 1e-3);
    }

    #[test]
    fn expiry_and_validation() {
        let r = record();
        r.validate().unwrap();
        assert!(!r.is_expired(1_999_999));
        assert!(r.is_expired(2_000_000));

        let mut bad = record();
        bad.calibration_id = 0;
        assert!(bad.validate().is_err());
        let mut bad = record();
        bad.scale_q16 = 0;
        assert!(bad.validate().is_err());
        let mut bad = record();
        bad.expires_ns = bad.created_ns;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn serde_round_trip() {
        let r = record();
        let j = serde_json::to_string(&r).unwrap();
        let back: CalibrationRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
