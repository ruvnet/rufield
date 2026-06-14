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

#![doc(html_root_url = "https://docs.rs/rufield-fusion/0.1.0")]

pub mod engine;
pub mod graph;
pub mod rules;

pub use engine::{FusionError, RuFieldFusion};
pub use graph::{Edge, EdgeKind, FusionGraph, Node, NodeKind};
pub use rules::{Method, Rule, RuleSet};
