//! # rufield-fusion
//!
//! The RuField MFS fusion graph + engine (ADR-260 §12 / §13 / §16 / §24).
//!
//! [`RuFieldFusion`] ingests [`FieldEvent`](rufield_core::FieldEvent)s, applies
//! a TOML [`RuleSet`] (weighted-Bayes and temporal-window methods) over a short
//! per-track, per-modality temporal window, and produces
//! [`FieldInference`](rufield_core::FieldInference)s with
//! supporting/contradicting events, privacy class, calibration/model id, and an
//! expiry time. Every event passes through an explicit stateful trust policy
//! before it reaches the fusion graph: events failing the §11 fusability
//! invariant are rejected at ingest, and BLE additionally fails closed unless it
//! satisfies the explicit device/signer [`BleTrustPolicy`].
//! [`RuFieldFusion::new`] is scoped to backwards-compatible simulation; live
//! ingestion must supply a production [`rufield_provenance::TrustVerifier`].

#![doc(html_root_url = "https://docs.rs/rufield-fusion/0.1.0")]

pub mod bearing;
mod bearing_math;
mod bearing_trust;
pub mod engine;
pub mod graph;
pub mod rules;

pub use bearing::{
    BearingEstimate, BearingFusionConfig, BearingFusionError, BearingObservation,
    QuantumBearingFusion, DEFAULT_MAX_TIME_SKEW_NS, MAX_BEARINGS, MIN_FUSABLE_CALIBRATION_QUALITY,
    MIN_FUSABLE_ELLIPTICITY, MIN_FUSABLE_LOCK_QUALITY, MIN_GEOMETRY_ANGLE_RAD,
};
pub use bearing_trust::{BearingTrustPolicy, LiveTrustWindow, TrustedSensorBinding};
pub use engine::{BleTrustPolicy, FusionError, RuFieldFusion};
pub use graph::{Edge, EdgeKind, FusionGraph, Node, NodeKind};
pub use rules::{Method, Rule, RuleSet};
