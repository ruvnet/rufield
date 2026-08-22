//! Live-ingest mode (ADR-260 §27.9 and ADR-261 trust policy).
//!
//! In `--source live` the viewer no longer replays the built-in `SyntheticSim`.
//! Instead it consumes **real** `rufield_core::FieldEvent`s streamed from an
//! external upstream — RuView's `wifi-densepose-sensing-server`, which exposes
//! (ADR-262 P3):
//!
//! - `GET <upstream>/api/field` — JSON `{ events: [FieldEvent..], signer_pubkey,
//!   dev_signing_key }` over a bounded ring (poll source).
//! - `GET <upstream>/ws/field`  — an SSE/WS stream of one `FieldEvent` per cycle.
//!
//! Those events are the **same** `rufield_core::FieldEvent` the viewer already
//! deserializes for the synthetic path, so they are wire-compatible by
//! construction.
//!
//! ## Honesty & provenance (non-negotiable)
//!
//! Every ingested event is authorized by a persistent production or captured
//! replay [`rufield_provenance::TrustVerifier`]. Live ingestion never calls the
//! legacy stateless fusability helper and never creates a simulation fusion
//! engine. A rejected event is surfaced as a redacted diagnostic with a stable
//! reason code but cannot mutate replay, graph or inference-window state.
//! Raw upstream events never enter the broadcast channel: a default network
//! privacy guard creates a public projection that omits event, device and zone
//! identifiers, observation labels, hashes, signer keys and signatures.
//!
//! This module deliberately splits **pure** ingest/render logic (no I/O — fully
//! unit-testable by injecting a JSON payload) from the small HTTP client used at
//! runtime. The pure path is [`frame_from_api_payload`] / [`frame_from_events`].

use crate::runtime::PrivacyBadge;
use rufield_core::{
    Destination, FieldEvent, FieldInference, FusionEngine, InferenceQuery, PrivacyDecision,
    PrivacyGuard,
};
use rufield_fusion::{FusionError, RuFieldFusion};
use rufield_privacy::DefaultPrivacyGuard;
use rufield_provenance::{
    ProvenanceError, ReplayState, TrustError, TrustMode, TrustPolicy, TrustVerifier,
    TrustedKeyRegistry,
};
use serde::{Deserialize, Serialize};

/// Explicit trust configuration injected at the live source boundary.
#[derive(Debug, Clone)]
pub struct LiveTrustConfig {
    /// Production or captured-replay policy. Simulation is forbidden here.
    pub policy: TrustPolicy,
    /// Independently provisioned sensor-to-key bindings and revocations.
    pub registry: TrustedKeyRegistry,
    /// Optional replay watermark restored before ingest opens.
    pub replay_state: Option<ReplayState>,
}

impl LiveTrustConfig {
    /// Default live production trust configuration.
    #[must_use]
    pub fn production(registry: TrustedKeyRegistry) -> Self {
        Self {
            policy: TrustPolicy::production(),
            registry,
            replay_state: None,
        }
    }

    /// Historical captured-replay trust configuration.
    #[must_use]
    pub fn captured_replay(registry: TrustedKeyRegistry) -> Self {
        Self {
            policy: TrustPolicy::captured_replay(),
            registry,
            replay_state: None,
        }
    }

    /// Attach validated persisted replay state for restart protection.
    #[must_use]
    pub fn with_replay_state(mut self, replay_state: ReplayState) -> Self {
        self.replay_state = Some(replay_state);
        self
    }

    /// Build the stateful live processor. Simulation fails closed.
    pub fn into_processor(self) -> Result<LiveProcessor, TrustError> {
        LiveProcessor::new(self)
    }
}

/// Stateful live authorization and fusion boundary.
///
/// One processor must be retained for the lifetime of a live source so replay
/// watermarks and the temporal fusion window survive across batches.
pub struct LiveProcessor {
    engine: RuFieldFusion,
    privacy_guard: DefaultPrivacyGuard,
}

impl LiveProcessor {
    /// Build from explicit trust configuration.
    pub fn new(config: LiveTrustConfig) -> Result<Self, TrustError> {
        if config.policy.mode == TrustMode::Simulation {
            return Err(TrustError::InvalidRegistry(
                "simulation trust mode is forbidden for live ingestion".into(),
            ));
        }
        if config.registry.is_empty() {
            return Err(TrustError::InvalidRegistry(
                "live ingestion requires at least one enrolled sensor key".into(),
            ));
        }
        let mut verifier = TrustVerifier::new(config.policy, config.registry);
        if let Some(state) = config.replay_state {
            verifier.restore_replay_state(state)?;
        }
        Ok(Self {
            engine: RuFieldFusion::with_trust_verifier(verifier),
            privacy_guard: DefaultPrivacyGuard::default(),
        })
    }

    /// Read-only fusion state for governance and tests.
    #[must_use]
    pub const fn fusion(&self) -> &RuFieldFusion {
        &self.engine
    }

    fn process_events_at(&mut self, tick: usize, events: &[FieldEvent], now_ns: u64) -> LiveFrame {
        let mut event_views = Vec::with_capacity(events.len());
        let mut verified_count = 0usize;
        let mut unverified_count = 0usize;
        let mut privacy_redacted_count = 0usize;

        for (sequence, event) in events.iter().enumerate() {
            let trust = match self.engine.ingest_at(event.clone(), now_ns) {
                Ok(()) => LiveTrustDecisionView {
                    accepted: true,
                    rejection_code: None,
                },
                Err(error) => LiveTrustDecisionView {
                    accepted: false,
                    rejection_code: Some(trust_rejection_code(&error)),
                },
            };
            if trust.accepted {
                verified_count += 1;
            } else {
                unverified_count += 1;
            }
            let event_view = public_event_view(event, sequence, trust, &self.privacy_guard);
            if event_view.details.is_none() {
                privacy_redacted_count += 1;
            }
            event_views.push(event_view);
        }

        let produced = self
            .engine
            .infer(&InferenceQuery::all())
            .unwrap_or_default();
        let mut privacy_redacted_inference_count = 0usize;
        let inferences = produced
            .iter()
            .filter_map(|inference| {
                if network_allowed(&self.privacy_guard, inference.privacy_class) {
                    Some(LiveInferenceView::from(inference))
                } else {
                    privacy_redacted_inference_count += 1;
                    None
                }
            })
            .collect();

        LiveFrame {
            frame: LiveTickFrame {
                tick,
                events: event_views,
                inferences,
            },
            verified_count,
            unverified_count,
            privacy_redacted_count,
            privacy_redacted_inference_count,
        }
    }
}

/// Shape of the upstream `GET /api/field` response (ADR-262 P3).
///
/// The viewer only needs `events`; `signer_pubkey` / `dev_signing_key` are
/// accepted for compatibility but are informational only. Trust comes from the
/// independently injected [`TrustedKeyRegistry`], never this payload.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiFieldPayload {
    /// The bounded ring of field events the upstream is currently serving.
    pub events: Vec<FieldEvent>,
    /// The upstream's advertised signer public key (hex), if any. Informational.
    #[serde(default)]
    pub signer_pubkey: Option<String>,
    /// The upstream's advertised dev signing key id, if any. Informational.
    #[serde(default)]
    pub dev_signing_key: Option<String>,
}

/// Stable, non-identifying rejection categories exposed by the live viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveTrustRejectionCode {
    /// A compatibility-only simulation error reached the live boundary.
    TrustPolicyRejected,
    /// Event or sensor identity was empty.
    MalformedIdentity,
    /// Synthetic evidence was presented to a live policy.
    SyntheticRejected,
    /// No signer key was present.
    MissingPublicKey,
    /// The signer key was not independently enrolled.
    UnknownKey,
    /// The sensor was not independently enrolled.
    UnknownSensor,
    /// The sensor was bound to a different key.
    SensorKeyMismatch,
    /// The enrolled key was revoked.
    RevokedKey,
    /// The event fell outside the maximum age.
    StaleTimestamp,
    /// The event exceeded future clock tolerance.
    FutureTimestamp,
    /// The exact prior event was replayed.
    DuplicateEvent,
    /// The event did not advance its sensor watermark.
    NonmonotonicReplay,
    /// No detached signature was present.
    MissingSignature,
    /// Signature or key encoding was malformed.
    MalformedSignature,
    /// Detached signature verification failed.
    SignatureVerificationFailed,
    /// Canonical event encoding failed.
    EventEncodingError,
    /// Internal trust configuration or replay state failed closed.
    TrustPolicyError,
}

/// A public trust decision that carries no attacker-controlled error text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveTrustDecisionView {
    /// Whether the event passed the configured live trust policy.
    pub accepted: bool,
    /// Stable diagnostic code for a rejection, absent on acceptance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_code: Option<LiveTrustRejectionCode>,
}

/// The disposition of event details under the default network privacy policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LivePrivacyDisposition {
    /// P1 or P2 metadata allowed by the default network policy.
    Allowed,
    /// Event details denied by the default network ceiling.
    Redacted,
    /// P4 details withheld because no consent was supplied to the viewer.
    ConsentRequired,
}

/// Non-identifying event details permitted by the default network policy.
#[derive(Debug, Clone, Serialize)]
pub struct LiveEventDetails {
    /// A whitelisted modality code. Unknown upstream strings become `other`.
    pub modality: &'static str,
    /// Human-readable form of the whitelisted modality.
    pub modality_label: &'static str,
    /// Observation confidence, which contains no direct identifier.
    pub confidence: f32,
}

/// Fail-closed public projection for one live event.
///
/// This type deliberately has no event, device or zone id, timestamp, raw
/// label, receipt hash, signer key, signature, model id or calibration id.
#[derive(Debug, Clone, Serialize)]
pub struct LiveEventView {
    /// Batch-local ordinal used only for display ordering.
    pub sequence: usize,
    /// Privacy classification without the protected event contents.
    pub privacy: PrivacyBadge,
    /// Safe trust outcome and stable rejection code.
    pub trust: LiveTrustDecisionView,
    /// Why optional details are present or withheld.
    pub privacy_disposition: LivePrivacyDisposition,
    /// Details that passed the default network privacy guard.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<LiveEventDetails>,
}

/// Fail-closed public projection for a fused live inference.
///
/// Supporting event ids, contradicting event ids and model ids remain inside
/// the process. P4 and P5 inferences are omitted without consent or binding.
#[derive(Debug, Clone, Serialize)]
pub struct LiveInferenceView {
    /// Policy-owned inference label.
    pub label: String,
    /// Confidence of the inference.
    pub confidence: f32,
    /// Privacy classification.
    pub privacy: PrivacyBadge,
}

impl From<&FieldInference> for LiveInferenceView {
    fn from(inference: &FieldInference) -> Self {
        Self {
            label: inference.label.clone(),
            confidence: inference.confidence,
            privacy: inference.privacy_class.into(),
        }
    }
}

/// Public live frame containing only privacy-filtered projections.
#[derive(Debug, Clone, Serialize)]
pub struct LiveTickFrame {
    /// Batch sequence assigned by the viewer.
    pub tick: usize,
    /// Redacted per-event diagnostics.
    pub events: Vec<LiveEventView>,
    /// Inferences permitted by the default network privacy policy.
    pub inferences: Vec<LiveInferenceView>,
}

/// The result of ingesting one batch of upstream events: a public redacted
/// projection plus trust and privacy counters used by the LIVE integrity panel.
/// Only trust-accepted events are fused, and only privacy-allowed projections
/// reach the broadcast channel.
#[derive(Debug, Clone, Serialize)]
pub struct LiveFrame {
    /// The renderable, non-identifying public frame for this batch.
    pub frame: LiveTickFrame,
    /// How many ingested events passed the configured live trust policy.
    pub verified_count: usize,
    /// How many ingested events were rejected and not fused.
    pub unverified_count: usize,
    /// Event details withheld by the default network privacy guard.
    pub privacy_redacted_count: usize,
    /// Fused inferences omitted by the default network privacy guard.
    pub privacy_redacted_inference_count: usize,
}

/// Human-readable label for a modality string code (mirrors `runtime`).
fn public_modality(code: &str) -> (&'static str, &'static str) {
    match code {
        "wifi_csi" => ("wifi_csi", "WiFi CSI"),
        "mmwave_radar" => ("mmwave_radar", "mmWave Radar"),
        "infrared_thermal" => ("infrared_thermal", "Infrared Thermal"),
        _ => ("other", "Other camera-free sensor"),
    }
}

fn public_event_view(
    event: &FieldEvent,
    sequence: usize,
    trust: LiveTrustDecisionView,
    guard: &DefaultPrivacyGuard,
) -> LiveEventView {
    let decision = guard.authorize(
        event.observation.privacy_class,
        Destination::Network,
        false,
        false,
    );
    let (privacy_disposition, details) = match decision {
        PrivacyDecision::Allow => {
            let (modality, modality_label) = public_modality(&event.sensor.modality);
            (
                LivePrivacyDisposition::Allowed,
                Some(LiveEventDetails {
                    modality,
                    modality_label,
                    confidence: event.observation.confidence,
                }),
            )
        }
        PrivacyDecision::RequiresConsent(_) => (LivePrivacyDisposition::ConsentRequired, None),
        PrivacyDecision::Deny(_) => (LivePrivacyDisposition::Redacted, None),
    };

    LiveEventView {
        sequence,
        privacy: event.observation.privacy_class.into(),
        trust,
        privacy_disposition,
        details,
    }
}

fn network_allowed(guard: &DefaultPrivacyGuard, privacy_class: rufield_core::PrivacyClass) -> bool {
    matches!(
        guard.authorize(privacy_class, Destination::Network, false, false),
        PrivacyDecision::Allow
    )
}

fn trust_rejection_code(error: &FusionError) -> LiveTrustRejectionCode {
    let FusionError::TrustRejected { reason, .. } = error else {
        return LiveTrustRejectionCode::TrustPolicyRejected;
    };
    match reason {
        TrustError::MalformedIdentity(_) => LiveTrustRejectionCode::MalformedIdentity,
        TrustError::SyntheticRejected => LiveTrustRejectionCode::SyntheticRejected,
        TrustError::MissingPublicKey => LiveTrustRejectionCode::MissingPublicKey,
        TrustError::UnknownKey => LiveTrustRejectionCode::UnknownKey,
        TrustError::UnknownSensor(_) => LiveTrustRejectionCode::UnknownSensor,
        TrustError::SensorKeyMismatch(_) => LiveTrustRejectionCode::SensorKeyMismatch,
        TrustError::RevokedKey => LiveTrustRejectionCode::RevokedKey,
        TrustError::StaleTimestamp => LiveTrustRejectionCode::StaleTimestamp,
        TrustError::FutureTimestamp => LiveTrustRejectionCode::FutureTimestamp,
        TrustError::DuplicateEvent(_) => LiveTrustRejectionCode::DuplicateEvent,
        TrustError::NonMonotonicReplay { .. } => LiveTrustRejectionCode::NonmonotonicReplay,
        TrustError::Provenance(ProvenanceError::MissingSignature) => {
            LiveTrustRejectionCode::MissingSignature
        }
        TrustError::Provenance(ProvenanceError::BadEncoding(_)) => {
            LiveTrustRejectionCode::MalformedSignature
        }
        TrustError::Provenance(ProvenanceError::VerifyFailed) => {
            LiveTrustRejectionCode::SignatureVerificationFailed
        }
        TrustError::Provenance(ProvenanceError::Serialize(_)) => {
            LiveTrustRejectionCode::EventEncodingError
        }
        TrustError::InvalidRegistry(_) | TrustError::ReplayState(_) => {
            LiveTrustRejectionCode::TrustPolicyError
        }
    }
}

/// Turn a batch of freshly-ingested upstream [`FieldEvent`]s into a renderable
/// [`LiveFrame`].
///
/// The caller must inject and retain a [`LiveProcessor`]. Its production or
/// captured-replay verifier authorizes each event before graph and window
/// mutation. Rejected events remain visible with a ✗ badge but cannot support
/// an inference.
#[must_use]
pub fn frame_from_events(
    processor: &mut LiveProcessor,
    tick: usize,
    events: &[FieldEvent],
    now_ns: u64,
) -> LiveFrame {
    processor.process_events_at(tick, events, now_ns)
}

/// Parse an upstream `/api/field` JSON payload and build a renderable
/// [`LiveFrame`] from its event ring. Pure (no I/O) — this is the unit-testable
/// core of the live ingest path.
///
/// # Errors
/// Returns the serde error string if the payload is not a valid
/// [`ApiFieldPayload`] (e.g. malformed or not a `FieldEvent` ring).
pub fn frame_from_api_payload(
    processor: &mut LiveProcessor,
    tick: usize,
    json: &str,
    now_ns: u64,
) -> Result<LiveFrame, String> {
    let payload: ApiFieldPayload =
        serde_json::from_str(json).map_err(|e| format!("decode /api/field: {e}"))?;
    Ok(frame_from_events(processor, tick, &payload.events, now_ns))
}

/// Parse a single upstream `/ws/field` SSE `data:` payload (one serialized
/// [`FieldEvent`]) and build a one-event [`LiveFrame`]. Pure (no I/O).
///
/// # Errors
/// Returns the serde error string if the line is not a valid `FieldEvent`.
pub fn frame_from_ws_event(
    processor: &mut LiveProcessor,
    tick: usize,
    json: &str,
    now_ns: u64,
) -> Result<LiveFrame, String> {
    let ev: FieldEvent =
        serde_json::from_str(json).map_err(|e| format!("decode /ws/field event: {e}"))?;
    Ok(frame_from_events(
        processor,
        tick,
        std::slice::from_ref(&ev),
        now_ns,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rufield_adapters::{run_demo, SimConfig};
    use rufield_provenance::Signer;

    const NOW_NS: u64 = 1_800_000_000_000_000_000;

    /// Use the adapter only as an event factory, then remove its synthetic
    /// classification and sign with the explicitly enrolled test sensor key.
    fn real_signed_events(n: usize, signer: &Signer) -> Vec<FieldEvent> {
        let mut events: Vec<FieldEvent> = run_demo(&SimConfig::default())
            .into_iter()
            .map(|se| se.event)
            .take(n)
            .collect();
        for (index, event) in events.iter_mut().enumerate() {
            event.timestamp_ns = NOW_NS + index as u64;
            event.tensor.timestamp_ns = event.timestamp_ns;
            event.provenance.synthetic = false;
            signer.sign_event(event).unwrap();
        }
        events
    }

    fn production_processor(events: &[FieldEvent], signer: &Signer) -> LiveProcessor {
        let mut registry = TrustedKeyRegistry::new();
        for event in events {
            registry
                .enroll_sensor_key(&event.sensor.device_id, signer.public_hex())
                .unwrap();
        }
        LiveTrustConfig::production(registry)
            .into_processor()
            .unwrap()
    }

    #[test]
    fn api_payload_deserializes_verifies_and_renders() {
        let signer = Signer::from_seed(&[31; 32]);
        let events = real_signed_events(3, &signer);
        let mut processor = production_processor(&events, &signer);
        let payload = serde_json::json!({
            "events": events,
            "signer_pubkey": "deadbeef",
            "dev_signing_key": "dev-key-1",
        })
        .to_string();

        let live = frame_from_api_payload(&mut processor, 0, &payload, NOW_NS + 10)
            .expect("payload decodes");
        assert_eq!(live.verified_count, 3);
        assert_eq!(live.unverified_count, 0);
        assert_eq!(live.frame.events.len(), 3);
        // Every public diagnostic reports acceptance without exposing a receipt.
        for ev in &live.frame.events {
            assert!(ev.trust.accepted, "trusted event must be accepted");
            assert!(ev.trust.rejection_code.is_none());
        }
        // Verified events produce renderable room-state inferences.
        assert!(
            !live.frame.inferences.is_empty(),
            "verified events should fuse into >=1 inference"
        );
    }

    #[test]
    fn tampered_event_is_flagged_unverified_and_not_fused() {
        let signer = Signer::from_seed(&[32; 32]);
        let mut events = real_signed_events(2, &signer);
        let mut processor = production_processor(&events, &signer);
        events[0].tensor.values[0] += 13.5;

        let live = frame_from_events(&mut processor, 0, &events, NOW_NS + 10);
        // Event 0: not synthetic + broken signature ⇒ rejected, not fused.
        assert!(!live.frame.events[0].trust.accepted);
        assert_eq!(
            live.frame.events[0].trust.rejection_code,
            Some(LiveTrustRejectionCode::SignatureVerificationFailed)
        );
        assert_eq!(live.unverified_count, 1, "one event flagged unverified");

        // It is still surfaced as a redacted diagnostic so forgery is visible.
        assert_eq!(live.frame.events.len(), 2);
        assert!(!serde_json::to_string(&live)
            .unwrap()
            .contains(&events[0].event_id));
    }

    #[test]
    fn ws_event_renders_single_frame() {
        let signer = Signer::from_seed(&[33; 32]);
        let ev = real_signed_events(1, &signer).remove(0);
        let mut processor = production_processor(std::slice::from_ref(&ev), &signer);
        let json = serde_json::to_string(&ev).unwrap();
        let live =
            frame_from_ws_event(&mut processor, 5, &json, NOW_NS + 10).expect("ws event decodes");
        assert_eq!(live.frame.tick, 5);
        assert_eq!(live.frame.events.len(), 1);
        assert_eq!(live.verified_count, 1);
    }

    #[test]
    fn malformed_payload_errors_not_panics() {
        let signer = Signer::from_seed(&[34; 32]);
        let events = real_signed_events(1, &signer);
        let mut processor = production_processor(&events, &signer);
        assert!(frame_from_api_payload(&mut processor, 0, "not json", NOW_NS).is_err());
        assert!(frame_from_ws_event(&mut processor, 0, "{\"nope\":1}", NOW_NS).is_err());
    }

    #[test]
    fn live_self_signed_event_cannot_mutate_fusion() {
        let enrolled = Signer::from_seed(&[35; 32]);
        let attacker = Signer::from_seed(&[36; 32]);
        let mut events = real_signed_events(1, &attacker);
        events[0].event_id = "SECRET_REJECTED_EVENT_ID_119".into();
        events[0].observation.zone_id = Some("SECRET_REJECTED_ZONE_ID_229".into());
        events[0].observation.labels = vec!["SECRET_REJECTED_RAW_LABEL_339".into()];
        events[0].provenance.raw_hash = "sha256:SECRET_REJECTED_RAW_HASH_449".into();
        attacker.sign_event(&mut events[0]).unwrap();
        let rejected_signature = events[0].provenance.signature_hex.clone().unwrap();
        let mut registry = TrustedKeyRegistry::new();
        registry
            .enroll_sensor_key(&events[0].sensor.device_id, enrolled.public_hex())
            .unwrap();
        let mut processor = LiveTrustConfig::production(registry)
            .into_processor()
            .unwrap();

        let live = frame_from_events(&mut processor, 0, &events, NOW_NS + 10);
        assert_eq!(live.verified_count, 0);
        assert_eq!(live.unverified_count, 1);
        assert!(!live.frame.events[0].trust.accepted);
        assert_eq!(
            live.frame.events[0].trust.rejection_code,
            Some(LiveTrustRejectionCode::UnknownKey)
        );
        let rendered = serde_json::to_string(&live).unwrap();
        for secret in [
            attacker.public_hex(),
            rejected_signature,
            "SECRET_REJECTED_EVENT_ID_119".into(),
            "SECRET_REJECTED_ZONE_ID_229".into(),
            "SECRET_REJECTED_RAW_LABEL_339".into(),
            "SECRET_REJECTED_RAW_HASH_449".into(),
        ] {
            assert!(
                !rendered.contains(&secret),
                "rejected event leaked {secret}"
            );
        }
        assert_eq!(processor.fusion().graph().node_count(), 0);
        assert!(processor
            .fusion()
            .trust_verifier()
            .export_replay_state()
            .watermarks
            .is_empty());
    }

    #[test]
    fn live_synthetic_event_cannot_mutate_fusion() {
        let signer = Signer::from_seed(&[37; 32]);
        let mut events = real_signed_events(1, &signer);
        events[0].provenance.synthetic = true;
        signer.sign_event(&mut events[0]).unwrap();
        let mut processor = production_processor(&events, &signer);

        let live = frame_from_events(&mut processor, 0, &events, NOW_NS + 10);
        assert_eq!(live.verified_count, 0);
        assert_eq!(live.unverified_count, 1);
        assert!(!live.frame.events[0].trust.accepted);
        assert_eq!(
            live.frame.events[0].trust.rejection_code,
            Some(LiveTrustRejectionCode::SyntheticRejected)
        );
        assert_eq!(processor.fusion().graph().node_count(), 0);
        assert!(processor
            .fusion()
            .trust_verifier()
            .export_replay_state()
            .watermarks
            .is_empty());
    }

    #[test]
    fn live_public_projection_never_contains_sensitive_event_fields() {
        let signer = Signer::from_seed(&[38; 32]);
        let mut events = real_signed_events(1, &signer);
        let event = &mut events[0];
        event.event_id = "SECRET_EVENT_ID_993".into();
        event.sensor.device_id = "SECRET_DEVICE_ID_773".into();
        event.sensor.vendor = "SECRET_VENDOR_221".into();
        event.sensor.placement = "SECRET_PLACEMENT_551".into();
        event.observation.zone_id = Some("SECRET_ZONE_ID_662".into());
        event.observation.labels = vec!["SECRET_RAW_LABEL_884".into()];
        event.provenance.raw_hash = "sha256:SECRET_RAW_HASH_123".into();
        event.provenance.firmware_hash = "sha256:SECRET_FIRMWARE_HASH_456".into();
        event.provenance.model_id = "SECRET_MODEL_ID_789".into();
        event.provenance.calibration_id = "SECRET_CALIBRATION_ID_147".into();
        signer.sign_event(event).unwrap();
        let signer_key = event.provenance.signer_pubkey_hex.clone().unwrap();
        let signature = event.provenance.signature_hex.clone().unwrap();

        let mut processor = production_processor(&events, &signer);
        let live = frame_from_events(&mut processor, 9, &events, NOW_NS + 10);
        assert!(live.frame.events[0].trust.accepted);

        let rendered = serde_json::to_string(&live).unwrap();
        for secret in [
            "SECRET_EVENT_ID_993",
            "SECRET_DEVICE_ID_773",
            "SECRET_VENDOR_221",
            "SECRET_PLACEMENT_551",
            "SECRET_ZONE_ID_662",
            "SECRET_RAW_LABEL_884",
            "SECRET_RAW_HASH_123",
            "SECRET_FIRMWARE_HASH_456",
            "SECRET_MODEL_ID_789",
            "SECRET_CALIBRATION_ID_147",
            &signer_key,
            &signature,
        ] {
            assert!(!rendered.contains(secret), "live output leaked {secret}");
        }
        for forbidden_key in [
            "event_id",
            "device_id",
            "zone_id",
            "truth_labels",
            "receipt",
            "raw_hash",
            "firmware_hash",
            "signer_pubkey_hex",
            "signature_hex",
            "supporting_events",
            "contradicting_events",
            "model_id",
            "calibration_id",
        ] {
            assert!(
                !rendered.contains(&format!("\"{forbidden_key}\"")),
                "live output exposed forbidden field {forbidden_key}"
            );
        }
    }

    #[test]
    fn default_live_privacy_guard_redacts_disallowed_event_details() {
        let signer = Signer::from_seed(&[39; 32]);
        let mut events = real_signed_events(1, &signer);
        events[0].observation.privacy_class = rufield_core::PrivacyClass::P4;
        events[0].tensor.privacy_class = rufield_core::PrivacyClass::P4;
        signer.sign_event(&mut events[0]).unwrap();
        let mut processor = production_processor(&events, &signer);

        let live = frame_from_events(&mut processor, 0, &events, NOW_NS + 10);
        assert!(live.frame.events[0].trust.accepted);
        assert_eq!(
            live.frame.events[0].privacy_disposition,
            LivePrivacyDisposition::ConsentRequired
        );
        assert!(live.frame.events[0].details.is_none());
        assert_eq!(live.privacy_redacted_count, 1);
    }

    #[test]
    fn live_processor_rejects_simulation_mode() {
        let config = LiveTrustConfig {
            policy: TrustPolicy::simulation(),
            registry: TrustedKeyRegistry::new(),
            replay_state: None,
        };
        assert!(matches!(
            config.into_processor(),
            Err(TrustError::InvalidRegistry(_))
        ));
    }

    #[test]
    fn live_processor_rejects_empty_production_registry() {
        let config = LiveTrustConfig::production(TrustedKeyRegistry::new());
        assert!(matches!(
            config.into_processor(),
            Err(TrustError::InvalidRegistry(_))
        ));
    }
}
