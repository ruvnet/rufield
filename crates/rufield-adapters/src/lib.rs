//! # rufield-adapters
//!
//! Adapters that emit RuField [`FieldEvent`](rufield_core::FieldEvent)s.
//!
//! [`SyntheticSim`] is a **deterministic seeded simulator** that produces the
//! ADR-260 §19 camera-free
//! room-intelligence demo sequence — enter → sit → breathing → sleep → scratch
//! → bed-exit → leave — across 3 modalities (WiFi CSI, mmWave radar, thermal
//! IR). Every event carries a real `FieldTensor`, a P2 occupancy observation,
//! ground-truth labels, and a synthetic-signed provenance receipt.
//!
//! **Honesty note:** the [`SyntheticSim`] signals are synthetic. No hardware is
//! involved in the simulator.
//!
//! [`CsiReplayAdapter`] replays *real captured WiFi CSI* from a `.csi.jsonl`
//! recording.
//! Real signal, but be explicit: it is **replay from file, not live hardware**,
//! the recordings are **unlabeled**, and its motion/presence output is a
//! **physically-grounded CSI-variance proxy, NOT validated accuracy.** Live
//! streaming + labeled-accuracy validation remain roadmap. See the
//! [`csi_replay`] module docs.
//!
//! [`RydbergReplayAdapter`] strictly replays calibrated Rydberg quantum RF
//! vector frames. Its default P1 output preserves both antipodal bearing
//! candidates; raw complex electric fields require explicit P0 mode. The
//! bundled fixture is analytic synthetic evidence, not live quantum hardware.
//! A replay signature proves deterministic packaging and integrity, not sensor
//! authenticity, laboratory accuracy, indoor multipath performance, or field
//! readiness. See [`quantum_rf_replay`] for the fail-closed quality contract.

#![doc(html_root_url = "https://docs.rs/rufield-adapters/0.2.0")]

pub mod csi_replay;
mod quantum_rf_quality;
pub mod quantum_rf_replay;
mod quantum_rf_support;
mod quantum_rf_wire;
pub mod rng;
pub mod scenario;
pub mod signals;
pub mod sim;

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
