//! Core RuField MFS traits (ADR-260 §16).

use crate::event::FieldEvent;
use crate::inference::{FieldEmbedding, FieldInference, InferenceQuery};
use crate::modality::Modality;
use crate::privacy::PrivacyClass;
use crate::tensor::FieldTensor;

/// Capabilities a [`FieldAdapter`] advertises (used by firmware integrators
/// to negotiate features). v0.1 is intentionally small.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterCapabilities {
    /// Modality string code.
    pub modality: String,
    /// Approximate sample rate in Hz.
    pub sample_rate_hz: u32,
    /// Whether the adapter can produce its own calibration receipt.
    pub can_calibrate: bool,
    /// Maximum privacy class this adapter ever emits.
    pub max_privacy_class: PrivacyClass,
}

/// A source of [`FieldEvent`]s. Real firmware integrations (ESP32 CSI, mmWave,
/// thermal IR) implement this trait; the v0.1 reference stack ships only the
/// synthetic simulator (`rufield-adapters::SyntheticSim`).
pub trait FieldAdapter {
    /// Adapter error type.
    type Error: std::error::Error;

    /// Modality this adapter produces.
    fn modality(&self) -> Modality;

    /// Advertised capabilities.
    fn capabilities(&self) -> AdapterCapabilities;

    /// Produce the next event, or `None` when the stream is exhausted.
    fn next_event(&mut self) -> Result<Option<FieldEvent>, Self::Error>;
}

/// Turns a [`FieldTensor`] into a [`FieldEmbedding`] (ADR-260 §16, Layer 3).
pub trait FieldEncoder {
    /// Encoder error type.
    type Error: std::error::Error;

    /// Encode a tensor from the given source event into an embedding.
    fn encode(
        &self,
        tensor: &FieldTensor,
        source_event_id: &str,
    ) -> Result<FieldEmbedding, Self::Error>;
}

/// Ingests events and produces fused inferences (ADR-260 §16, Layer 4).
pub trait FusionEngine {
    /// Fusion error type.
    type Error: std::error::Error;

    /// Ingest a single event into the fusion graph.
    fn ingest(&mut self, event: FieldEvent) -> Result<(), Self::Error>;

    /// Run inference over the current graph state.
    fn infer(&self, query: &InferenceQuery) -> Result<Vec<FieldInference>, Self::Error>;
}

/// Decision returned by a [`PrivacyGuard`] (ADR-260 §10 / §16, Layer 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivacyDecision {
    /// The action is permitted.
    Allow,
    /// The action is denied by policy.
    Deny(String),
    /// The action requires explicit consent before it can proceed.
    RequiresConsent(String),
}

/// Where an event/inference is headed — guards differ for edge vs network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    /// Stays on the device (edge storage / local fusion).
    EdgeLocal,
    /// Crosses the network boundary.
    Network,
}

/// Enforces privacy policy on transmission / storage (ADR-260 §16, Layer 5).
pub trait PrivacyGuard {
    /// Authorize sending data of `class` to `destination`. `consent` is true
    /// when explicit consent for the subject has been recorded; `identity_bound`
    /// is true when an identity binding + audit log exists (required for P5).
    fn authorize(
        &self,
        class: PrivacyClass,
        destination: Destination,
        consent: bool,
        identity_bound: bool,
    ) -> PrivacyDecision;
}
