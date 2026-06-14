//! # rufield-core
//!
//! Core data model for **RuField MFS** — the RuField Multimodal Field Sensing
//! Specification (ADR-260). Defines the wire types (`FieldEvent`,
//! `FieldTensor`, `Observation`, `ProvenanceRef`, `CalibrationReceipt`,
//! `FieldInference`, `FieldEmbedding`), the `Modality`/`FieldAxis`/`PrivacyClass`
//! enums, and the `FieldAdapter`/`FieldEncoder`/`FusionEngine`/`PrivacyGuard`
//! traits.
//!
//! All numbers produced by the v0.1 reference stack come from a deterministic
//! **synthetic simulator** — there is no hardware in this stack. Nothing here
//! claims field-validated accuracy.

#![doc(html_root_url = "https://docs.rs/rufield-core/0.1.0")]

pub mod error;
pub mod event;
pub mod inference;
pub mod modality;
pub mod privacy;
pub mod tensor;
pub mod traits;

pub use error::CoreError;
pub use event::{
    CalibrationReceipt, FieldEvent, Observation, ProvenanceRef, SensorDescriptor,
};
pub use inference::{FieldEmbedding, FieldInference, InferenceQuery};
pub use modality::{FieldAxis, Modality};
pub use privacy::PrivacyClass;
pub use tensor::{FieldTensor, SPEC_VERSION};
pub use traits::{
    AdapterCapabilities, Destination, FieldAdapter, FieldEncoder, FusionEngine,
    PrivacyDecision, PrivacyGuard,
};

#[cfg(test)]
mod spec_json_tests {
    use super::*;

    /// ADR-260 §7 — the canonical Field Event JSON example must round-trip
    /// through our `FieldEvent` type. The §7 example uses a compact inline
    /// `field` block (sensor PHY descriptor) rather than a full numeric tensor;
    /// our wire type carries a real `FieldTensor`, so we assert round-trip on a
    /// faithful representation of the §7 fields (sensor, observation,
    /// provenance) plus a concrete tensor.
    #[test]
    fn section7_example_round_trips() {
        let json = r#"{
          "spec_version": "rufield.mfs.v0.1",
          "event_id": "01J00000000000000000000000",
          "timestamp_ns": 1791986400000000000,
          "sensor": {
            "modality": "wifi_csi",
            "vendor": "esp32_c6",
            "device_id": "sensor_room_01",
            "placement": "ceiling_corner",
            "clock_domain": "local_ptp"
          },
          "tensor": {
            "spec_version": "rufield.mfs.v0.1",
            "timestamp_ns": 1791986400000000000,
            "modality": "wifi_csi",
            "axes": ["frequency", "amplitude"],
            "shape": [2, 2],
            "values": [0.1, 0.2, 0.3, 0.4],
            "confidence": 0.87,
            "noise_floor": 0.02,
            "calibration_id": "room_cal_2026_06_14",
            "privacy_class": "P2"
          },
          "observation": {
            "zone_id": "room_01",
            "space_cell": [4, 2, 1],
            "range_m": 3.42,
            "velocity_mps": 0.18,
            "motion_vector": [0.12, -0.03, 0.0],
            "confidence": 0.87,
            "labels": ["person_present"],
            "privacy_class": "P2"
          },
          "provenance": {
            "raw_hash": "sha256:raw_measurement_hash",
            "firmware_hash": "sha256:firmware_hash",
            "model_id": "ruvector_field_encoder_v1",
            "calibration_id": "room_cal_2026_06_14",
            "synthetic": false
          }
        }"#;

        let ev: FieldEvent = serde_json::from_str(json).expect("parse §7 example");
        assert_eq!(ev.spec_version, SPEC_VERSION);
        assert_eq!(ev.sensor.modality, "wifi_csi");
        assert_eq!(ev.observation.privacy_class, PrivacyClass::P2);
        assert_eq!(ev.tensor.modality, Modality::WifiCsi);
        ev.tensor.validate().expect("tensor valid");

        // Re-serialize and parse again: stable round-trip.
        let s = serde_json::to_string(&ev).unwrap();
        let back: FieldEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
    }
}
