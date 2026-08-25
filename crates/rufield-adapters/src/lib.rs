//! # rufield-adapters
//!
//! Adapters that emit RuField [`FieldEvent`](rufield_core::FieldEvent)s.
//!
//! The v0.1 reference stack includes [`SyntheticSim`], a
//! **deterministic seeded simulator** that produces the ADR-260 §19 camera-free
//! room-intelligence demo sequence — enter → sit → breathing → sleep → scratch
//! → bed-exit → leave — across 3 modalities (WiFi CSI, mmWave radar, thermal
//! IR). Every event carries a real `FieldTensor`, a P2 occupancy observation,
//! ground-truth labels, and a synthetic-signed provenance receipt.
//!
//! **Honesty note:** the [`SyntheticSim`] signals are synthetic. No hardware is
//! involved in the simulator.
//!
//! The crate also ships [`CsiReplayAdapter`] — the **first real (non-synthetic)
//! adapter**: it replays *real captured WiFi CSI* from a `.csi.jsonl` recording.
//! Real signal, but be explicit: it is **replay from file, not live hardware**,
//! the recordings are **unlabeled**, and its motion/presence output is a
//! **physically-grounded CSI-variance proxy, NOT validated accuracy.** Live
//! streaming + labeled-accuracy validation remain roadmap. See the
//! [`csi_replay`] module docs.
//!
//! BLE support is split deliberately: [`BleIdentityEvidenceAdapter`] consumes
//! authenticated RSSI telemetry and emits short-lived P5 pseudonymous evidence,
//! while [`BleChannelSoundingAdapter`] admits only complete, authenticated
//! procedures from an external Channel Sounding companion and emits P4
//! respiration features. An ESP32 may forward those records but is never
//! represented as their radio source. The deterministic crossing scenario
//! covers identity ambiguity, spoof abstention, expiry, and coherent procedure
//! grouping. It is not hardware or clinical validation.

#![doc(html_root_url = "https://docs.rs/rufield-adapters/0.1.0")]

pub mod ble;
pub mod ble_scenario;
pub mod csi_replay;
mod quantum_rf_quality;
pub mod quantum_rf_replay;
mod quantum_rf_support;
mod quantum_rf_wire;
pub mod rng;
pub mod scenario;
pub mod signals;
pub mod sim;
pub mod ultrasonic;

pub use ble::{
    derive_ble_pseudonym, BleAbstention, BleAbstentionReason, BleAdapterConfig, BleAdapterError,
    BleAnchorTrust, BleChannelSoundingAdapter, BleChannelSoundingSample,
    BleIdentityEvidenceAdapter, BleIdentitySample, BLE_PSEUDONYM_DOMAIN,
    MAX_ACTIVE_IDENTITY_BINDINGS, MAX_CHANNEL_SOUNDING_STEPS, MAX_IDENTITY_TTL_NS,
    MAX_PENDING_CHANNEL_SOUNDING_PROCEDURES, MIN_CHANNEL_SOUNDING_STEPS, MIN_IDENTITY_CONFIDENCE,
};
pub use ble_scenario::{
    two_person_ble_crossing_scenario, BleCrossingScenario, CROSSING_BASE_TS_NS, CROSSING_TICK_NS,
};
pub use csi_replay::{
    Baseline, CsiFrame, CsiReplayAdapter, CsiReplayError, DEFAULT_CALIBRATION_FRAMES,
    MAX_SUBCARRIERS, MOTION_THRESHOLD, PRESENCE_THRESHOLD, REPLAY_SIGNER_SEED,
};
pub use quantum_rf_replay::{
    QuantumRfOutput, ReplaySource, RydbergFrame, RydbergGateFailure, RydbergQualityThresholds,
    RydbergReplayAdapter, RydbergReplayConfig, RydbergReplayError, MAX_ID_BYTES,
    MAX_QUANTUM_RF_FRAMES, MAX_QUANTUM_RF_LINE_BYTES, QUANTUM_RF_REPLAY_SIGNER_SEED,
};
pub use scenario::{demo_timeline, ticks, Phase, PhaseSpan};
pub use signals::SignalFeatures;
pub use sim::{
    default_destination, run_demo, SimConfig, SimError, SimEvent, SyntheticSim, BASE_TS_NS,
    DEFAULT_SEED, TICK_NS,
};
pub use ultrasonic::{
    Baseline as UltrasonicBaseline, Echo, UltrasonicConfig, UltrasonicError, UltrasonicOutput,
    UltrasonicPing, UltrasonicReplayAdapter, UltrasonicSource, COARSE_BINS,
    DEFAULT_CALIBRATION_PINGS, MAX_DETECTIONS, MAX_LINE_BYTES, MAX_PINGS, MAX_PROFILE_BINS,
    MAX_RANGE_M, ULTRASONIC_SIGNER_SEED,
};
