//! # rucelium-core
//!
//! Core data model for **RuCelium** — the federated environmental
//! intelligence fabric (ADR-264). Defines the domain types every layer above
//! the C sensor boundary shares: [`EnvSample`], [`EnvFrame`],
//! [`CalibrationRecord`], [`EnvironmentalEvent`], the [`SensorModality`]
//! registry, [`GeoPoint`] geospatial references, and the three-tier
//! [`DataClass`] residency model.
//!
//! Nothing in this crate touches hardware or the network. All numbers in the
//! v0.1 reference stack come from a deterministic **synthetic** biome
//! simulator (`rucelium-bench`) — nothing here claims field-validated
//! accuracy.

#![doc(html_root_url = "https://docs.rs/rucelium-core/0.1.0")]

pub mod calibration;
pub mod error;
pub mod event;
pub mod geo;
pub mod modality;
pub mod sample;

pub use calibration::CalibrationRecord;
pub use error::EnvError;
pub use event::{evidence_digest, EnvironmentalEvent, EventKind, EvidenceRef, Severity};
pub use geo::GeoPoint;
pub use modality::{DataClass, Residency, SensorModality};
pub use sample::{EnvFrame, EnvSample, SampleProvenance, Uncertainty};

/// Wire spec version for the RuCelium fabric (ADR-264).
pub const SPEC_VERSION: &str = "rucelium.fabric.v0.1";
