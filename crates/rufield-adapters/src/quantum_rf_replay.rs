//! Deterministic replay adapter for vector Rydberg quantum RF measurements.
//!
//! The default output is a derived P1 antipodal bearing tensor. Raw complex
//! electric-field phasors are accepted and provenance-hashed, but are emitted
//! only when callers explicitly select [`QuantumRfOutput::RawElectricField`].
//! Every input frame must pass the complete quality gate before construction
//! succeeds; the adapter never repairs, normalizes, or partially emits a bad
//! recording.

use rufield_core::{
    AdapterCapabilities, CalibrationReceipt, FieldAdapter, FieldAxis, FieldEvent, FieldTensor,
    Modality, Observation, PrivacyClass, ProvenanceRef, SensorDescriptor,
};
use rufield_provenance::{sha256_hex, Signer};
use serde::Deserialize;

pub use crate::quantum_rf_quality::{RydbergGateFailure, RydbergQualityThresholds};
use crate::quantum_rf_support::{
    canonical_calibration_bytes, canonical_frame_bytes, emitted_bearing_noise_f32,
    insert_attributes, insert_features, same_calibration_contract, validate_config,
};

/// Deterministic replay signing key. It identifies replay, not trusted hardware.
pub const QUANTUM_RF_REPLAY_SIGNER_SEED: [u8; 32] = [0x51; 32];

/// Maximum frames accepted by one adapter instance.
pub const MAX_QUANTUM_RF_FRAMES: usize = 100_000;
/// Maximum UTF-8 bytes accepted in one JSONL record.
pub const MAX_QUANTUM_RF_LINE_BYTES: usize = 65_536;
/// Maximum UTF-8 bytes accepted in identifiers and placement strings.
pub const MAX_ID_BYTES: usize = 256;

/// Selects whether an event exposes a derived bearing or raw electric field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuantumRfOutput {
    /// P1 tensor `[+k, -k]`, shape `[2, 3]`. This is the safe default.
    DerivedBearing,
    /// P0 complex phasor tensor `[Ex, Ey, Ez] x [real, imaginary]`.
    RawElectricField,
}

/// Declares whether replayed measurements are synthetic or captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaySource {
    /// Generated or simulated data. This is the fail-safe default.
    Synthetic,
    /// Captured data asserted by the caller. The replay signature attests only
    /// deterministic packaging and does not authenticate capture hardware.
    Captured,
}

/// Construction and output policy for [`RydbergReplayAdapter`].
#[derive(Debug, Clone, PartialEq)]
pub struct RydbergReplayConfig {
    /// Stable device identifier.
    pub device_id: String,
    /// Sensor placement description.
    pub placement: String,
    /// Logical observation zone.
    pub zone_id: String,
    /// Output privacy mode.
    pub output: QuantumRfOutput,
    /// Replay source declaration.
    pub source: ReplaySource,
    /// Quality gate thresholds.
    pub thresholds: RydbergQualityThresholds,
    /// Deterministic Ed25519 signing seed.
    pub signer_seed: [u8; 32],
}

impl Default for RydbergReplayConfig {
    fn default() -> Self {
        Self {
            device_id: "quantum_rf_replay_01".into(),
            placement: "replay".into(),
            zone_id: "quantum_rf_replay_zone".into(),
            output: QuantumRfOutput::DerivedBearing,
            source: ReplaySource::Synthetic,
            thresholds: RydbergQualityThresholds::default(),
            signer_seed: QUANTUM_RF_REPLAY_SIGNER_SEED,
        }
    }
}

/// One strict JSONL frame from a three-axis Rydberg vector receiver.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RydbergFrame {
    /// Midpoint of the coherent integration interval, nanoseconds since epoch.
    pub timestamp_ns: u64,
    /// World-frame sensor position `[x, y, z]` in metres.
    pub sensor_position_m: [f64; 3],
    /// Sensor-to-world unit quaternion `[x, y, z, w]`.
    pub sensor_orientation_xyzw: [f64; 4],
    /// Calibration-bound world coordinate-frame identifier.
    pub coordinate_frame: String,
    /// Exact emitter or tracked-signal identifier used for fusion association.
    pub signal_id: String,
    /// RF carrier frequency in hertz.
    pub carrier_hz: f64,
    /// Sensor-local complex `[Ex, Ey, Ez]`, encoded `[real, imaginary]`, V/m.
    pub e_field_sensor_vpm: [[f64; 2]; 3],
    /// One sensor-local unit bearing; its negation is the second candidate.
    pub k_hat_sensor: [f64; 3],
    /// Must be true. Current measurements cannot resolve the antipodal sign.
    pub sign_ambiguous: bool,
    /// Signed normalized axial ellipticity on the phasor `q_axis` scale in
    /// `-1..=1`; near zero is linearly polarized and rejected.
    pub ellipticity: f64,
    /// Receiver-reported signal-to-noise ratio in dB.
    pub snr_db: f64,
    /// Coherent integration interval in milliseconds.
    pub integration_ms: f64,
    /// Covariance in a deterministic orthonormal tangent-plane basis, rad².
    pub angular_covariance_rad2: [[f64; 2]; 2],
    /// Nonempty calibration receipt identifier.
    pub calibration_id: String,
    /// Calibration validity window start.
    pub calibration_created_ns: u64,
    /// Calibration validity window end, exclusive.
    pub calibration_expires_ns: u64,
    /// Calibration quality in `0..=1`.
    pub calibration_quality: f64,
    /// Optical lock quality in `0..=1`.
    pub lock_quality: f64,
}

/// Errors raised while constructing or replaying quantum RF frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RydbergReplayError {
    /// JSON parsing failed on a one-based line number.
    Parse { line: usize, message: String },
    /// The recording is empty.
    Empty,
    /// A JSONL line exceeded [`MAX_QUANTUM_RF_LINE_BYTES`].
    LineTooLong { line: usize, bytes: usize },
    /// A recording exceeded [`MAX_QUANTUM_RF_FRAMES`].
    TooManyFrames,
    /// Adapter configuration is invalid.
    InvalidConfig(String),
    /// A one-based frame failed the quality gate.
    QualityGate {
        frame: usize,
        reason: RydbergGateFailure,
    },
    /// Core tensor construction failed.
    Tensor(String),
    /// Event signing failed.
    Signing(String),
}

impl std::fmt::Display for RydbergReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse { line, message } => write!(f, "parse error on line {line}: {message}"),
            Self::Empty => f.write_str("recording contained no quantum RF frames"),
            Self::LineTooLong { line, bytes } => write!(
                f,
                "line {line} has {bytes} bytes; maximum is {MAX_QUANTUM_RF_LINE_BYTES}"
            ),
            Self::TooManyFrames => write!(
                f,
                "recording exceeds maximum of {MAX_QUANTUM_RF_FRAMES} frames"
            ),
            Self::InvalidConfig(message) => write!(f, "invalid configuration: {message}"),
            Self::QualityGate { frame, reason } => {
                write!(f, "frame {frame} failed quality gate: {reason}")
            }
            Self::Tensor(message) => write!(f, "tensor construction failed: {message}"),
            Self::Signing(message) => write!(f, "event signing failed: {message}"),
        }
    }
}

impl std::error::Error for RydbergReplayError {}

impl RydbergFrame {
    pub(crate) fn field_strength_vpm(&self) -> f64 {
        self.e_field_sensor_vpm
            .iter()
            .flatten()
            .map(|value| value * value)
            .sum::<f64>()
            .sqrt()
    }

    pub(crate) fn noise_floor_vpm(&self) -> f64 {
        self.field_strength_vpm() / 10.0_f64.powf(self.snr_db / 20.0)
    }
}

/// Strict, deterministic replay of quality-gated Rydberg vector frames.
pub struct RydbergReplayAdapter {
    frames: Vec<RydbergFrame>,
    config: RydbergReplayConfig,
    signer: Signer,
    calibration_data_hash: String,
    cursor: usize,
}

impl RydbergReplayAdapter {
    /// Parse strict JSONL using safe P1 synthetic-replay defaults.
    pub fn from_jsonl(text: &str) -> Result<Self, RydbergReplayError> {
        Self::from_jsonl_with_config(text, RydbergReplayConfig::default())
    }

    /// Parse strict JSONL with explicit source, privacy, identity, and gates.
    pub fn from_jsonl_with_config(
        text: &str,
        config: RydbergReplayConfig,
    ) -> Result<Self, RydbergReplayError> {
        let mut frames = Vec::new();
        for (index, raw) in text.lines().enumerate() {
            if index >= MAX_QUANTUM_RF_FRAMES {
                return Err(RydbergReplayError::TooManyFrames);
            }
            if raw.len() > MAX_QUANTUM_RF_LINE_BYTES {
                return Err(RydbergReplayError::LineTooLong {
                    line: index + 1,
                    bytes: raw.len(),
                });
            }
            if raw.trim().is_empty() {
                continue;
            }
            let frame = serde_json::from_str(raw).map_err(|error| RydbergReplayError::Parse {
                line: index + 1,
                message: error.to_string(),
            })?;
            frames.push(frame);
            if frames.len() > MAX_QUANTUM_RF_FRAMES {
                return Err(RydbergReplayError::TooManyFrames);
            }
        }
        Self::from_frames_with_config(frames, config)
    }

    /// Construct from already decoded frames. Useful for non-JSON transports.
    pub fn from_frames_with_config(
        frames: Vec<RydbergFrame>,
        config: RydbergReplayConfig,
    ) -> Result<Self, RydbergReplayError> {
        if frames.is_empty() {
            return Err(RydbergReplayError::Empty);
        }
        if frames.len() > MAX_QUANTUM_RF_FRAMES {
            return Err(RydbergReplayError::TooManyFrames);
        }
        validate_config(&config)?;
        config.thresholds.validate()?;
        let mut last_by_signal = std::collections::BTreeMap::new();
        for (index, frame) in frames.iter().enumerate() {
            frame.validate(config.thresholds).map_err(|reason| {
                RydbergReplayError::QualityGate {
                    frame: index + 1,
                    reason,
                }
            })?;
            if index > 0 && frame.timestamp_ns < frames[index - 1].timestamp_ns {
                return Err(RydbergReplayError::QualityGate {
                    frame: index + 1,
                    reason: RydbergGateFailure::NonMonotonicTimestamp,
                });
            }
            if last_by_signal
                .get(&frame.signal_id)
                .is_some_and(|previous| frame.timestamp_ns <= *previous)
            {
                return Err(RydbergReplayError::QualityGate {
                    frame: index + 1,
                    reason: RydbergGateFailure::NonMonotonicTimestamp,
                });
            }
            last_by_signal.insert(frame.signal_id.clone(), frame.timestamp_ns);
            if index > 0 && !same_calibration_contract(&frames[0], frame) {
                return Err(RydbergReplayError::QualityGate {
                    frame: index + 1,
                    reason: RydbergGateFailure::CalibrationContractChanged,
                });
            }
        }
        let signer = Signer::from_seed(&config.signer_seed);
        let calibration_data_hash = sha256_hex(&canonical_calibration_bytes(&frames[0], &config));
        Ok(Self {
            frames,
            config,
            signer,
            calibration_data_hash,
            cursor: 0,
        })
    }

    /// Number of validated frames.
    #[must_use]
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// Validated source frames.
    #[must_use]
    pub fn frames(&self) -> &[RydbergFrame] {
        &self.frames
    }

    /// Deterministic receipt for the calibration contract consumed by replay.
    /// It is content-addressed but does not claim hardware-side attestation.
    #[must_use]
    pub fn calibration_receipt(&self) -> CalibrationReceipt {
        let frame = &self.frames[0];
        CalibrationReceipt {
            calibration_id: frame.calibration_id.clone(),
            modality: "quantum_rf".into(),
            zone_id: self.config.zone_id.clone(),
            task: "rydberg_vector_calibration_replay".into(),
            created_ns: frame.calibration_created_ns,
            expires_ns: frame.calibration_expires_ns,
            data_hash: self.calibration_data_hash.clone(),
        }
    }

    /// Reset the replay cursor.
    pub fn reset(&mut self) {
        self.cursor = 0;
    }

    /// Build the complete deterministic stream without changing the cursor.
    pub fn collect_events(&self) -> Result<Vec<FieldEvent>, RydbergReplayError> {
        (0..self.frames.len())
            .map(|index| self.build_event(index))
            .collect()
    }

    fn build_event(&self, index: usize) -> Result<FieldEvent, RydbergReplayError> {
        let frame = &self.frames[index];
        let (axes, shape, values, tensor_privacy, noise_floor, model_id) = match self.config.output
        {
            QuantumRfOutput::DerivedBearing => (
                vec![FieldAxis::DirectionCandidate, FieldAxis::CartesianComponent],
                vec![2, 3],
                frame
                    .k_hat_sensor
                    .iter()
                    .copied()
                    .chain(frame.k_hat_sensor.iter().copied().map(|value| -value))
                    .map(|value| value as f32)
                    .collect(),
                PrivacyClass::P1,
                emitted_bearing_noise_f32(frame),
                "rydberg_vector_bearing_v0_1",
            ),
            QuantumRfOutput::RawElectricField => (
                vec![FieldAxis::CartesianComponent, FieldAxis::ComplexComponent],
                vec![3, 2],
                frame
                    .e_field_sensor_vpm
                    .iter()
                    .flatten()
                    .map(|value| *value as f32)
                    .collect(),
                PrivacyClass::P0,
                frame.noise_floor_vpm() as f32,
                "rydberg_complex_field_passthrough_v0_1",
            ),
        };
        let confidence = frame.calibration_quality.min(frame.lock_quality) as f32;
        let tensor = FieldTensor::new(
            frame.timestamp_ns,
            Modality::QuantumRf,
            axes,
            shape,
            values,
            confidence,
            noise_floor,
            Some(frame.calibration_id.clone()),
            tensor_privacy,
        )
        .map_err(|error| RydbergReplayError::Tensor(error.to_string()))?;
        let mut observation = Observation::occupancy(confidence, tensor_privacy);
        observation.zone_id = Some(self.config.zone_id.clone());
        observation.labels.push(match self.config.output {
            QuantumRfOutput::DerivedBearing => "quantum_rf_bearing_antipodal".into(),
            QuantumRfOutput::RawElectricField => "quantum_rf_complex_field".into(),
        });
        insert_attributes(
            &mut observation,
            frame,
            self.config.source,
            &self.calibration_data_hash,
        );
        insert_features(&mut observation, frame);
        let provenance = ProvenanceRef {
            raw_hash: sha256_hex(&canonical_frame_bytes(frame, &self.config.device_id)),
            firmware_hash: sha256_hex(b"rufield-quantum-rf-replay-adapter-v0.1"),
            model_id: model_id.into(),
            calibration_id: frame.calibration_id.clone(),
            synthetic: self.config.source == ReplaySource::Synthetic,
            signature_hex: None,
            signer_pubkey_hex: None,
        };
        let mut event = FieldEvent::new(
            format!("quantum-rf-{}-{index:06}", self.config.device_id),
            frame.timestamp_ns,
            SensorDescriptor {
                modality: "quantum_rf".into(),
                vendor: "rydberg_vector_replay".into(),
                device_id: self.config.device_id.clone(),
                placement: self.config.placement.clone(),
                coordinate_frame: Some(frame.coordinate_frame.clone()),
                position_m: Some(frame.sensor_position_m.map(|value| value as f32)),
                orientation_xyzw: Some(frame.sensor_orientation_xyzw.map(|value| value as f32)),
                clock_domain: "replay_file".into(),
            },
            tensor,
            observation,
            provenance,
        );
        self.signer
            .sign_event(&mut event)
            .map_err(|error| RydbergReplayError::Signing(error.to_string()))?;
        Ok(event)
    }

    fn estimated_rate_hz(&self) -> u32 {
        let Some(span) = self
            .frames
            .last()
            .zip(self.frames.first())
            .map(|(last, first)| last.timestamp_ns.saturating_sub(first.timestamp_ns))
        else {
            return 1;
        };
        let intervals = self.frames.len().saturating_sub(1) as u64;
        if span == 0 || intervals == 0 {
            return 1;
        }
        let rate = 1_000_000_000_u128 * u128::from(intervals) / u128::from(span);
        rate.clamp(1, u128::from(u32::MAX)) as u32
    }
}

impl FieldAdapter for RydbergReplayAdapter {
    type Error = RydbergReplayError;

    fn modality(&self) -> Modality {
        Modality::QuantumRf
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            modality: "quantum_rf".into(),
            sample_rate_hz: self.estimated_rate_hz(),
            can_calibrate: false,
            max_privacy_class: match self.config.output {
                QuantumRfOutput::DerivedBearing => PrivacyClass::P1,
                QuantumRfOutput::RawElectricField => PrivacyClass::P0,
            },
        }
    }

    fn next_event(&mut self) -> Result<Option<FieldEvent>, Self::Error> {
        if self.cursor >= self.frames.len() {
            return Ok(None);
        }
        let event = self.build_event(self.cursor)?;
        self.cursor += 1;
        Ok(Some(event))
    }
}
