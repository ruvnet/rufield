//! Modality registry (ADR-260 §8) and field tensor axes (§9).

use serde::{Deserialize, Serialize};

/// The 15 sensing modalities defined in the RuField MFS modality registry
/// (ADR-260 §8). Each maps to a stable numeric code on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    /// 1 — WiFi Channel State Information (ESP32 C6, Intel BE200, AP CSI).
    WifiCsi,
    /// 2 — WiFi Channel Impulse Response.
    WifiCir,
    /// 3 — WiFi Beamforming Feedback.
    WifiBfld,
    /// 4 — UWB HRP ranging (IEEE 802.15.4z).
    UwbHrp,
    /// 5 — Bluetooth Channel Sounding (phase + timing primitives).
    BleChannelSounding,
    /// 6 — mmWave range-Doppler radar.
    MmwaveRadar,
    /// 7 — Ultrasonic echo / time-of-flight.
    Ultrasonic,
    /// 8 — Subsonic structural vibration / room resonance.
    Subsonic,
    /// 9 — Thermal array or passive IR.
    InfraredThermal,
    /// 10 — Reflected (active) infrared.
    ActiveInfrared,
    /// 11 — Phase-based optical range (lidar).
    LidarPhase,
    /// 12 — NV diamond / OPM magnetic field trace.
    QuantumMagnetic,
    /// 13 — Atom interferometer / precision IMU.
    QuantumInertial,
    /// 14 — Optional visual event stream.
    EventCamera,
    /// 15 — Simulator or replay source.
    SyntheticSim,
}

impl Modality {
    /// Stable numeric registry code (ADR-260 §8, 1-indexed).
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Modality::WifiCsi => 1,
            Modality::WifiCir => 2,
            Modality::WifiBfld => 3,
            Modality::UwbHrp => 4,
            Modality::BleChannelSounding => 5,
            Modality::MmwaveRadar => 6,
            Modality::Ultrasonic => 7,
            Modality::Subsonic => 8,
            Modality::InfraredThermal => 9,
            Modality::ActiveInfrared => 10,
            Modality::LidarPhase => 11,
            Modality::QuantumMagnetic => 12,
            Modality::QuantumInertial => 13,
            Modality::EventCamera => 14,
            Modality::SyntheticSim => 15,
        }
    }

    /// All 15 modalities in registry order.
    #[must_use]
    pub fn all() -> [Modality; 15] {
        [
            Modality::WifiCsi,
            Modality::WifiCir,
            Modality::WifiBfld,
            Modality::UwbHrp,
            Modality::BleChannelSounding,
            Modality::MmwaveRadar,
            Modality::Ultrasonic,
            Modality::Subsonic,
            Modality::InfraredThermal,
            Modality::ActiveInfrared,
            Modality::LidarPhase,
            Modality::QuantumMagnetic,
            Modality::QuantumInertial,
            Modality::EventCamera,
            Modality::SyntheticSim,
        ]
    }
}

/// A semantic axis of a [`crate::FieldTensor`] (ADR-260 §9). Axes label the
/// dimensions of the tensor so consumers can interpret the numeric values
/// without out-of-band knowledge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldAxis {
    /// Time samples.
    Time,
    /// Frequency / subcarrier bins.
    Frequency,
    /// Phase component.
    Phase,
    /// Amplitude component.
    Amplitude,
    /// Range bins (radar / ToF).
    Range,
    /// Velocity / Doppler bins.
    Velocity,
    /// Angle-of-arrival bins.
    Angle,
    /// Temperature (thermal IR).
    Temperature,
    /// Structural vibration.
    Vibration,
    /// Per-element uncertainty.
    Uncertainty,
    /// Spatial channel / antenna index.
    Channel,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modality_has_15_variants() {
        assert_eq!(Modality::all().len(), 15);
    }

    #[test]
    fn modality_codes_are_1_to_15_unique() {
        let codes: Vec<u8> = Modality::all().iter().map(|m| m.code()).collect();
        assert_eq!(codes, (1..=15).collect::<Vec<u8>>());
    }

    #[test]
    fn modality_serde_snake_case() {
        let j = serde_json::to_string(&Modality::WifiCsi).unwrap();
        assert_eq!(j, "\"wifi_csi\"");
        let m: Modality = serde_json::from_str("\"mmwave_radar\"").unwrap();
        assert_eq!(m, Modality::MmwaveRadar);
    }
}
