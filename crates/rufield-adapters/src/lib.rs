//! # rufield-adapters
//!
//! Adapters that emit RuField [`FieldEvent`](rufield_core::FieldEvent)s.
//!
//! The v0.1 reference stack ships exactly one adapter: [`SyntheticSim`], a
//! **deterministic seeded simulator** that produces the ADR-260 §19 camera-free
//! room-intelligence demo sequence — enter → sit → breathing → sleep → scratch
//! → bed-exit → leave — across 3 modalities (WiFi CSI, mmWave radar, thermal
//! IR). Every event carries a real `FieldTensor`, a P2 occupancy observation,
//! ground-truth labels, and a synthetic-signed provenance receipt.
//!
//! **Honesty note:** all signals are synthetic. No hardware is involved. The
//! real-firmware adapters (ESP32 CSI, mmWave, thermal IR) are a documented
//! follow-up — see the repository README "Firmware" section.

#![doc(html_root_url = "https://docs.rs/rufield-adapters/0.1.0")]

pub mod rng;
pub mod scenario;
pub mod signals;
pub mod sim;

pub use scenario::{demo_timeline, ticks, Phase, PhaseSpan};
pub use signals::SignalFeatures;
pub use sim::{
    default_destination, run_demo, SimConfig, SimError, SimEvent, SyntheticSim, BASE_TS_NS,
    DEFAULT_SEED, TICK_NS,
};
