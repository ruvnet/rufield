//! Field event, sensor descriptor, observation, calibration receipt
//! (ADR-260 §7 / §20 / §23).

use crate::privacy::PrivacyClass;
use crate::tensor::{FieldTensor, SPEC_VERSION};
use serde::{Deserialize, Serialize};

/// Describes the sensor that produced an event (ADR-260 §7 `sensor`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorDescriptor {
    /// Modality string code (e.g. `wifi_csi`).
    pub modality: String,
    /// Vendor / chip identifier (e.g. `esp32_c6`).
    pub vendor: String,
    /// Stable device id (e.g. `sensor_room_01`).
    pub device_id: String,
    /// Physical placement hint (e.g. `ceiling_corner`).
    pub placement: String,
    /// Clock domain for `timestamp_ns` (e.g. `local_ptp`).
    pub clock_domain: String,
}

/// The interpreted observation derived from a tensor (ADR-260 §20
/// `Observation`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    /// Logical zone id, if known.
    pub zone_id: Option<String>,
    /// Discrete spatial cell `[x, y, z]`.
    pub space_cell: Option<[i32; 3]>,
    /// Range estimate in metres.
    pub range_m: Option<f32>,
    /// Velocity estimate in m/s.
    pub velocity_mps: Option<f32>,
    /// Motion vector `[dx, dy, dz]`.
    pub motion_vector: Option<[f32; 3]>,
    /// Confidence `0.0..=1.0`.
    pub confidence: f32,
    /// Derived non-identity feature scalars (the P1-level encoder output that
    /// the fusion engine reads — e.g. `motion_energy`, `breathing_band`,
    /// `posture_height`, `transient`). This is NOT ground-truth: it is what a
    /// `FieldEncoder` would compute from the tensor.
    #[serde(default)]
    pub features: std::collections::BTreeMap<String, f32>,
    /// Ground-truth or derived labels attached to this observation. In the
    /// synthetic simulator these are the **ground-truth** labels used only by
    /// the benchmark to score against; the fusion engine never reads them.
    pub labels: Vec<String>,
    /// Privacy class of this observation.
    pub privacy_class: PrivacyClass,
}

impl Observation {
    /// Minimal occupancy observation at the given confidence/privacy class.
    #[must_use]
    pub fn occupancy(confidence: f32, privacy_class: PrivacyClass) -> Self {
        Observation {
            zone_id: None,
            space_cell: None,
            range_m: None,
            velocity_mps: None,
            motion_vector: None,
            confidence,
            features: std::collections::BTreeMap::new(),
            labels: Vec::new(),
            privacy_class,
        }
    }
}

/// Provenance block inline on the event (ADR-260 §7 `provenance`). The full
/// signed receipt lives in `rufield-provenance`; this is the on-wire summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceRef {
    /// Hash of the raw measurement (`sha256:...`).
    pub raw_hash: String,
    /// Hash of the producing firmware (`sha256:...`).
    pub firmware_hash: String,
    /// Model identifier that produced derived features.
    pub model_id: String,
    /// Calibration receipt id.
    pub calibration_id: String,
    /// If true, this event is a simulator/replay event and may be fused
    /// without a verified cryptographic receipt (ADR-260 §11 invariant).
    #[serde(default)]
    pub synthetic: bool,
    /// Detached ed25519 signature over the event, hex-encoded, if signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
    /// Hex-encoded ed25519 verifying (public) key, if signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_pubkey_hex: Option<String>,
}

/// A timestamped observation from any ambient field sensor (ADR-260 §7 / §20).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldEvent {
    /// Wire spec version.
    pub spec_version: String,
    /// Unique event id (ULID-style string; deterministic in the simulator).
    pub event_id: String,
    /// Capture time, nanoseconds since Unix epoch.
    pub timestamp_ns: u64,
    /// Producing sensor.
    pub sensor: SensorDescriptor,
    /// Normalized numeric tensor.
    pub tensor: FieldTensor,
    /// Interpreted observation.
    pub observation: Observation,
    /// Provenance summary.
    pub provenance: ProvenanceRef,
}

impl FieldEvent {
    /// Construct a field event with the current spec version.
    #[must_use]
    pub fn new(
        event_id: impl Into<String>,
        timestamp_ns: u64,
        sensor: SensorDescriptor,
        tensor: FieldTensor,
        observation: Observation,
        provenance: ProvenanceRef,
    ) -> Self {
        FieldEvent {
            spec_version: SPEC_VERSION.to_string(),
            event_id: event_id.into(),
            timestamp_ns,
            sensor,
            tensor,
            observation,
            provenance,
        }
    }
}

/// First-class calibration receipt (ADR-260 §23).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibrationReceipt {
    /// Calibration id.
    pub calibration_id: String,
    /// Modality this calibration applies to.
    pub modality: String,
    /// Room / zone the calibration was taken in.
    pub zone_id: String,
    /// Calibration task performed (e.g. `empty_room_baseline`).
    pub task: String,
    /// Capture time, nanoseconds since Unix epoch.
    pub created_ns: u64,
    /// Expiry time, nanoseconds since Unix epoch.
    pub expires_ns: u64,
    /// Hash of the calibration data (`sha256:...`).
    pub data_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modality::{FieldAxis, Modality};

    fn sample_tensor() -> FieldTensor {
        FieldTensor::new(
            1,
            Modality::WifiCsi,
            vec![FieldAxis::Frequency],
            vec![3],
            vec![0.1, 0.2, 0.3],
            0.8,
            0.01,
            Some("room_cal_2026".into()),
            PrivacyClass::P2,
        )
        .unwrap()
    }

    #[test]
    fn event_round_trips() {
        let ev = FieldEvent::new(
            "01J00000000000000000000000",
            1,
            SensorDescriptor {
                modality: "wifi_csi".into(),
                vendor: "esp32_c6".into(),
                device_id: "sensor_room_01".into(),
                placement: "ceiling_corner".into(),
                clock_domain: "local_ptp".into(),
            },
            sample_tensor(),
            Observation::occupancy(0.87, PrivacyClass::P2),
            ProvenanceRef {
                raw_hash: "sha256:abc".into(),
                firmware_hash: "sha256:def".into(),
                model_id: "ruvector_field_encoder_v1".into(),
                calibration_id: "room_cal_2026".into(),
                synthetic: true,
                signature_hex: None,
                signer_pubkey_hex: None,
            },
        );
        let j = serde_json::to_string(&ev).unwrap();
        let back: FieldEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(ev, back);
    }
}
