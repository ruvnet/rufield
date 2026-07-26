//! Modality registry (ADR-260 §8) and field tensor axes (§9).

use crate::error::CoreError;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// The sensing modalities defined in the RuField MFS modality registry
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
    /// 16 — Rydberg-atom electric-field vector receiver.
    QuantumRf,
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
            Modality::QuantumRf => 16,
        }
    }

    /// Canonical string used by serde and the MFS wire format.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Modality::WifiCsi => "wifi_csi",
            Modality::WifiCir => "wifi_cir",
            Modality::WifiBfld => "wifi_bfld",
            Modality::UwbHrp => "uwb_hrp",
            Modality::BleChannelSounding => "ble_channel_sounding",
            Modality::MmwaveRadar => "mmwave_radar",
            Modality::Ultrasonic => "ultrasonic",
            Modality::Subsonic => "subsonic",
            Modality::InfraredThermal => "infrared_thermal",
            Modality::ActiveInfrared => "active_infrared",
            Modality::LidarPhase => "lidar_phase",
            Modality::QuantumMagnetic => "quantum_magnetic",
            Modality::QuantumInertial => "quantum_inertial",
            Modality::EventCamera => "event_camera",
            Modality::SyntheticSim => "synthetic_sim",
            Modality::QuantumRf => "quantum_rf",
        }
    }

    /// Resolve a stable numeric registry code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Modality::WifiCsi),
            2 => Some(Modality::WifiCir),
            3 => Some(Modality::WifiBfld),
            4 => Some(Modality::UwbHrp),
            5 => Some(Modality::BleChannelSounding),
            6 => Some(Modality::MmwaveRadar),
            7 => Some(Modality::Ultrasonic),
            8 => Some(Modality::Subsonic),
            9 => Some(Modality::InfraredThermal),
            10 => Some(Modality::ActiveInfrared),
            11 => Some(Modality::LidarPhase),
            12 => Some(Modality::QuantumMagnetic),
            13 => Some(Modality::QuantumInertial),
            14 => Some(Modality::EventCamera),
            15 => Some(Modality::SyntheticSim),
            16 => Some(Modality::QuantumRf),
            _ => None,
        }
    }

    /// All 16 modalities in registry order.
    #[must_use]
    pub fn all() -> [Modality; 16] {
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
            Modality::QuantumRf,
        ]
    }
}

impl fmt::Display for Modality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Modality {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::all()
            .into_iter()
            .find(|modality| modality.as_str() == value)
            .ok_or_else(|| CoreError::Invalid(format!("unknown modality {value:?}")))
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
    /// Cartesian vector component; indices conventionally represent x, y, z.
    CartesianComponent,
    /// Complex value component; indices conventionally represent real, imaginary.
    ComplexComponent,
    /// Ambiguous direction candidate; indices conventionally represent +k, -k.
    DirectionCandidate,
}

impl FieldAxis {
    /// Canonical string used by serde and the MFS wire format.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            FieldAxis::Time => "time",
            FieldAxis::Frequency => "frequency",
            FieldAxis::Phase => "phase",
            FieldAxis::Amplitude => "amplitude",
            FieldAxis::Range => "range",
            FieldAxis::Velocity => "velocity",
            FieldAxis::Angle => "angle",
            FieldAxis::Temperature => "temperature",
            FieldAxis::Vibration => "vibration",
            FieldAxis::Uncertainty => "uncertainty",
            FieldAxis::Channel => "channel",
            FieldAxis::CartesianComponent => "cartesian_component",
            FieldAxis::ComplexComponent => "complex_component",
            FieldAxis::DirectionCandidate => "direction_candidate",
        }
    }
}

impl fmt::Display for FieldAxis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FieldAxis {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "time" => Ok(FieldAxis::Time),
            "frequency" => Ok(FieldAxis::Frequency),
            "phase" => Ok(FieldAxis::Phase),
            "amplitude" => Ok(FieldAxis::Amplitude),
            "range" => Ok(FieldAxis::Range),
            "velocity" => Ok(FieldAxis::Velocity),
            "angle" => Ok(FieldAxis::Angle),
            "temperature" => Ok(FieldAxis::Temperature),
            "vibration" => Ok(FieldAxis::Vibration),
            "uncertainty" => Ok(FieldAxis::Uncertainty),
            "channel" => Ok(FieldAxis::Channel),
            "cartesian_component" => Ok(FieldAxis::CartesianComponent),
            "complex_component" => Ok(FieldAxis::ComplexComponent),
            "direction_candidate" => Ok(FieldAxis::DirectionCandidate),
            _ => Err(CoreError::Invalid(format!("unknown field axis {value:?}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modality_has_16_variants() {
        assert_eq!(Modality::all().len(), 16);
    }

    #[test]
    fn modality_codes_are_1_to_16_unique_and_reversible() {
        let codes: Vec<u8> = Modality::all().iter().map(|m| m.code()).collect();
        assert_eq!(codes, (1..=16).collect::<Vec<u8>>());
        for modality in Modality::all() {
            assert_eq!(Modality::from_code(modality.code()), Some(modality));
        }
        assert_eq!(Modality::from_code(0), None);
        assert_eq!(Modality::from_code(17), None);
    }

    #[test]
    fn modality_string_and_serde_mappings_are_consistent() {
        for modality in Modality::all() {
            assert_eq!(modality.to_string(), modality.as_str());
            assert_eq!(modality.as_str().parse::<Modality>().unwrap(), modality);
            assert_eq!(
                serde_json::to_string(&modality).unwrap(),
                format!("\"{}\"", modality.as_str())
            );
            let decoded: Modality = serde_json::from_str(&format!("\"{}\"", modality.as_str()))
                .expect("canonical modality should deserialize");
            assert_eq!(decoded, modality);
        }
        assert!("quantum-rf".parse::<Modality>().is_err());
    }

    #[test]
    fn quantum_rf_registry_contract_is_stable() {
        assert_eq!(Modality::QuantumRf.code(), 16);
        assert_eq!(Modality::QuantumRf.as_str(), "quantum_rf");
        assert_eq!(
            serde_json::to_string(&Modality::QuantumRf).unwrap(),
            "\"quantum_rf\""
        );
    }

    #[test]
    fn field_axis_string_and_serde_mappings_are_consistent() {
        let axes = [
            FieldAxis::Time,
            FieldAxis::Frequency,
            FieldAxis::Phase,
            FieldAxis::Amplitude,
            FieldAxis::Range,
            FieldAxis::Velocity,
            FieldAxis::Angle,
            FieldAxis::Temperature,
            FieldAxis::Vibration,
            FieldAxis::Uncertainty,
            FieldAxis::Channel,
            FieldAxis::CartesianComponent,
            FieldAxis::ComplexComponent,
            FieldAxis::DirectionCandidate,
        ];

        for axis in axes {
            assert_eq!(axis.to_string(), axis.as_str());
            assert_eq!(axis.as_str().parse::<FieldAxis>().unwrap(), axis);
            assert_eq!(
                serde_json::to_string(&axis).unwrap(),
                format!("\"{}\"", axis.as_str())
            );
        }
        assert!("cartesian-component".parse::<FieldAxis>().is_err());
    }
}
