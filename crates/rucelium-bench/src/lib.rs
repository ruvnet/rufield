//! # rucelium-bench
//!
//! Deterministic **SYNTHETIC** biome benchmark for RuCelium — the ADR-264
//! §14 acceptance test. A 64-node biome runs 30 simulated days through the
//! real production pipeline (ABI → ingest → calibration → WorldGraph + RF
//! context → biome federation → SensorThings → governed control path) while
//! the simulator injects drift, a flood anomaly, a 7-day uplink outage,
//! tamper/replay/forged-key attacks, and a mid-run device compromise.
//!
//! Same seed ⇒ identical deterministic report (wall-clock latencies aside).
//! These numbers prove the fabric's mechanics against known ground truth;
//! they are NOT a field deployment.

pub mod report;
pub mod runner;
pub mod sim;

pub use report::{BiomeReport, Criterion};
pub use runner::run;
pub use sim::{BiomeSim, Emission, EmissionKind, SimConfig, DEFAULT_SEED};
