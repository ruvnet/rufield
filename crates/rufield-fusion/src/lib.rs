//! # rufield-fusion
//!
//! The RuField MFS fusion graph + engine (ADR-260 §12 / §13 / §16 / §24).
//!
//! [`RuFieldFusion`] ingests [`FieldEvent`](rufield_core::FieldEvent)s, applies
//! a TOML [`RuleSet`] (weighted-Bayes and temporal-window methods) over a short
//! per-modality temporal window, and produces [`FieldInference`](rufield_core::FieldInference)s
//! with supporting/contradicting events, privacy class, calibration/model id,
//! and an expiry time. Events that fail the §11 fusability invariant (no
//! verified receipt and not synthetic) are rejected at ingest.

#![doc(html_root_url = "https://docs.rs/rufield-fusion/0.2.0")]

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
pub use engine::{FusionError, RuFieldFusion};
pub use graph::{Edge, EdgeKind, FusionGraph, Node, NodeKind};
pub use rules::{Method, Rule, RuleSet};
