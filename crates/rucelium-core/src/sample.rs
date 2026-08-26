//! `EnvSample` / `EnvFrame` — the normalized environmental observation and
//! its twelve mandatory attributes (ADR-264 §7.1).

use crate::error::EnvError;
use crate::geo::GeoPoint;
use crate::modality::SensorModality;
use serde::{Deserialize, Serialize};

/// A measurement uncertainty interval bracketing the value
/// (requirement 9 of ADR-264 §7.1). Always absolute, in the sample's unit.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Uncertainty {
    /// Interval lower bound (same unit as the value).
    pub lower: f64,
    /// Interval upper bound (same unit as the value).
    pub upper: f64,
}

impl Uncertainty {
    /// Symmetric interval `value ± half_width`.
    #[must_use]
    pub fn symmetric(value: f64, half_width: f64) -> Self {
        let hw = half_width.abs();
        Uncertainty {
            lower: value - hw,
            upper: value + hw,
        }
    }

    /// Interval width.
    #[must_use]
    pub fn width(&self) -> f64 {
        self.upper - self.lower
    }
}

/// Provenance carried on a normalized sample after gateway ingest
/// (requirements 10–12 of ADR-264 §7.1). The raw signature lives on the wire
/// envelope (`rucelium-abi::SignedEnvRecordV1`); after verification the
/// gateway records who signed and what transformations produced this value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleProvenance {
    /// `sha256:` hash of the firmware measurement implementation.
    pub firmware_hash: String,
    /// Hex-encoded ed25519 public key that signed the wire record.
    pub signer_pubkey_hex: String,
    /// Whether the gateway verified the wire signature at ingest. Samples
    /// with `verified = false` never leave the gateway (ADR-264 §12).
    pub verified: bool,
    /// Derivation lineage: ordered transformation-receipt ids applied since
    /// the raw wire value (e.g. `"cal:42"`, `"unit:q16_to_f64"`). Reproducible
    /// transformation receipts, ADR-264 §12 item 10.
    pub lineage: Vec<String>,
}

/// A single normalized environmental observation (ADR-264 §7.1).
///
/// Carries all twelve mandatory attributes: device identity (`node_id`),
/// sequence number, measurement time, reception time, geospatial reference,
/// unit + observed property, calibration identifier, quality score,
/// uncertainty interval, firmware implementation, signature (via
/// [`SampleProvenance`]), and derivation lineage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvSample {
    /// Producing device identity.
    pub node_id: u64,
    /// Per-device monotonic sequence number.
    pub sequence: u32,
    /// Measurement time, nanoseconds since Unix epoch (device clock domain).
    pub measured_ns: u64,
    /// Gateway reception time, nanoseconds since Unix epoch.
    pub received_ns: u64,
    /// Geospatial reference of the measurement.
    pub geo: GeoPoint,
    /// Sensor modality.
    pub modality: SensorModality,
    /// Observed property (e.g. `air_temperature`, `soil_volumetric_water_content`).
    pub observed_property: String,
    /// UCUM unit code (e.g. `Cel`, `%`, `ug/m3`).
    pub unit: String,
    /// Calibrated value in `unit`.
    pub value: f64,
    /// Quality score `0.0..=1.0` (ADR-264 §12 public quality scores).
    pub quality: f32,
    /// Uncertainty interval bracketing `value`.
    pub uncertainty: Uncertainty,
    /// Calibration record applied to produce `value` (0 = uncalibrated).
    pub calibration_id: u32,
    /// Wire flags (bit 0 = retransmit-after-outage; see `rucelium-abi`).
    pub flags: u16,
    /// Battery level at measurement time, millivolts.
    pub battery_mv: u16,
    /// Provenance: firmware, signer, verification state, lineage.
    pub provenance: SampleProvenance,
}

impl EnvSample {
    /// Validate the twelve-attribute contract. Invalid samples are rejected
    /// at ingest, never repaired (ADR-264 §7.1).
    pub fn validate(&self) -> Result<(), EnvError> {
        self.geo.validate()?;
        if !(0.0..=1.0).contains(&self.quality) || !self.quality.is_finite() {
            return Err(EnvError::QualityOutOfRange(self.quality));
        }
        if !self.value.is_finite()
            || self.uncertainty.lower > self.value
            || self.value > self.uncertainty.upper
        {
            return Err(EnvError::UncertaintyInverted {
                lower: self.uncertainty.lower,
                value: self.value,
                upper: self.uncertainty.upper,
            });
        }
        if self.received_ns < self.measured_ns {
            return Err(EnvError::TimeInverted {
                measured_ns: self.measured_ns,
                received_ns: self.received_ns,
            });
        }
        if self.measured_ns == 0 {
            return Err(EnvError::MissingField("measured_ns"));
        }
        if self.observed_property.is_empty() {
            return Err(EnvError::MissingField("observed_property"));
        }
        if self.unit.is_empty() {
            return Err(EnvError::MissingField("unit"));
        }
        if self.provenance.firmware_hash.is_empty() {
            return Err(EnvError::MissingField("provenance.firmware_hash"));
        }
        if self.provenance.signer_pubkey_hex.is_empty() {
            return Err(EnvError::MissingField("provenance.signer_pubkey_hex"));
        }
        Ok(())
    }

    /// Stable dedup key: a device may never emit two distinct observations
    /// with the same sequence number, so `(node_id, sequence)` identifies a
    /// sample across outage replay (ADR-264 §14 criterion 3).
    #[must_use]
    pub fn dedup_key(&self) -> (u64, u32) {
        (self.node_id, self.sequence)
    }
}

/// A batch of samples from one node (e.g. one ring-buffer flush after an
/// outage). All samples must share `node_id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvFrame {
    /// Producing device identity.
    pub node_id: u64,
    /// Samples, in transmission order.
    pub samples: Vec<EnvSample>,
}

impl EnvFrame {
    /// Validate every sample and the shared-node invariant.
    pub fn validate(&self) -> Result<(), EnvError> {
        for s in &self.samples {
            if s.node_id != self.node_id {
                return Err(EnvError::Invalid(format!(
                    "frame for node {} contains sample from node {}",
                    self.node_id, s.node_id
                )));
            }
            s.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample() -> EnvSample {
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
                lineage: vec!["cal:3".into()],
            },
        }
    }

    #[test]
    fn valid_sample_passes_and_round_trips() {
        let s = sample();
        s.validate().unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: EnvSample = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn each_missing_attribute_is_rejected() {
        let mut s = sample();
        s.quality = 1.5;
        assert!(matches!(s.validate(), Err(EnvError::QualityOutOfRange(_))));

        let mut s = sample();
        s.uncertainty = Uncertainty {
            lower: 22.0,
            upper: 23.0,
        };
        assert!(matches!(
            s.validate(),
            Err(EnvError::UncertaintyInverted { .. })
        ));

        let mut s = sample();
        s.received_ns = 500;
        assert!(matches!(s.validate(), Err(EnvError::TimeInverted { .. })));

        let mut s = sample();
        s.unit.clear();
        assert!(matches!(s.validate(), Err(EnvError::MissingField("unit"))));

        let mut s = sample();
        s.provenance.firmware_hash.clear();
        assert!(matches!(s.validate(), Err(EnvError::MissingField(_))));

        let mut s = sample();
        s.value = f64::NAN;
        assert!(s.validate().is_err());
    }

    #[test]
    fn frame_rejects_foreign_node() {
        let mut f = EnvFrame {
            node_id: 7,
            samples: vec![sample()],
        };
        f.validate().unwrap();
        f.samples[0].node_id = 8;
        assert!(f.validate().is_err());
    }

    #[test]
    fn dedup_key_is_node_and_sequence() {
        assert_eq!(sample().dedup_key(), (7, 42));
    }
}

/// Test-support constructors shared across the crate's unit tests.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    /// A minimal valid sample with a caller-chosen identity and value.
    pub(crate) fn sample_for_digest(node_id: u64, sequence: u32, value: f64) -> EnvSample {
        EnvSample {
            node_id,
            sequence,
            measured_ns: 1_000,
            received_ns: 2_000,
            geo: GeoPoint::new(514_778_216, -14_767, 46_000).unwrap(),
            modality: SensorModality::Weather,
            observed_property: "air_temperature".into(),
            unit: "Cel".into(),
            value,
            quality: 0.98,
            uncertainty: Uncertainty::symmetric(value, 0.3),
            calibration_id: 3,
            flags: 0,
            battery_mv: 3600,
            provenance: SampleProvenance {
                firmware_hash: "sha256:abc".into(),
                signer_pubkey_hex: "00ff".into(),
                verified: true,
                lineage: vec!["cal:3".into()],
            },
        }
    }
}
