//! # rufield-fusion
//!
//! The RuField MFS fusion graph + engine (ADR-260 §12 / §13 / §16 / §24).
//!
//! [`RuFieldFusion`] ingests [`FieldEvent`](rufield_core::FieldEvent)s, applies
//! a TOML [`RuleSet`] (weighted-Bayes and temporal-window methods) over a short
//! per-modality temporal window, and produces [`FieldInference`](rufield_core::FieldInference)s
//! with supporting/contradicting events, privacy class, calibration/model id,
//! and an expiry time. Every event passes through an explicit stateful trust
//! policy before it reaches the fusion graph. [`RuFieldFusion::new`] is scoped
//! to backwards-compatible simulation; live ingestion must supply a production
//! [`rufield_provenance::TrustVerifier`].

#![doc(html_root_url = "https://docs.rs/rufield-fusion/0.1.0")]

pub mod engine;
pub mod graph;
pub mod rules;

pub use engine::{FusionError, RuFieldFusion};
pub use graph::{Edge, EdgeKind, FusionGraph, Node, NodeKind};
pub use rules::{Method, Rule, RuleSet};
