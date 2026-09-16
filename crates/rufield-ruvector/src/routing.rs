//! Trusted local handoff to RuVector PR 986's `RuFieldRouter::ingest_json`.
//!
//! Verify the full signed SDK event before projecting it. The projection is a
//! derived local message, not a signed FieldEvent and never a network credential.
//! No dependency on an unpublished RuVector release is introduced.
use crate::BackendError;
use rufield_core::{FieldEvent, PrivacyClass};
use rufield_provenance::{TrustMode, TrustVerifier};
use serde::Serialize;

/// Immutable, verified routing projection. Cannot be deserialized or constructed
/// by a caller. Keep it for retry if the local router rejects an unmapped zone.
/// Verification records replay state before delivery; retries must use this
/// object rather than verifying the original event a second time.
pub struct PreparedRoutingEvent {
    json: Vec<u8>,
    timestamp_ns: u64,
    max_age_ns: u64,
    future_skew_ns: u64,
}
impl PreparedRoutingEvent {
    /// Size of the compact local payload, excluding the original sensor tensor.
    pub fn payload_bytes(&self) -> usize {
        self.json.len()
    }

    /// Invoke a local routing backend, preserving integer nanosecond precision.
    /// For RuVector: `prepared.deliver(now, |json, verified, now| router.ingest_json(json, verified, now))`.
    /// Do not forward these bytes or the trust boolean across a network boundary.
    /// The router must still enforce its own mapping, TTL and dedup policy.
    pub fn deliver<T, E>(
        &self,
        now_ns: u64,
        sink: impl FnOnce(&[u8], bool, u64) -> Result<T, E>,
    ) -> Result<Result<T, E>, BackendError> {
        if self.timestamp_ns > now_ns.saturating_add(self.future_skew_ns)
            || now_ns.saturating_sub(self.timestamp_ns) > self.max_age_ns
        {
            return Err(BackendError::new("expired routing authorization"));
        }
        Ok(sink(&self.json, true, now_ns))
    }
}
#[derive(Serialize)]
struct Sensor<'a> {
    device_id: &'a str,
}
#[derive(Serialize)]
struct Features {
    presence: f32,
    motion_energy: f32,
    transient: f32,
}
#[derive(Serialize)]
struct Observation<'a> {
    zone_id: Option<&'a str>,
    space_cell: Option<[i32; 3]>,
    confidence: f32,
    features: Features,
    privacy_class: PrivacyClass,
}
#[derive(Serialize)]
struct Provenance {
    synthetic: bool,
}
#[derive(Serialize)]
struct Projection<'a> {
    event_id: &'a str,
    timestamp_ns: u64,
    sensor: Sensor<'a>,
    observation: Observation<'a>,
    provenance: Provenance,
}

/// Prepare a local handoff using the SDK's production trust registry and replay
/// defense. Privacy checks apply to both tensor and observation. Only P1/P2
/// evidence is accepted. Raw tensors, identity, labels and unrelated features
/// never reach the routing backend. Callers own and persist verifier replay state.
/// Projection validation failures do not consume replay state.
pub fn prepare_routing_event(
    event: &FieldEvent,
    verifier: &mut TrustVerifier,
    now_ns: u64,
) -> Result<PreparedRoutingEvent, BackendError> {
    if verifier.mode() != TrustMode::Production {
        return Err(BackendError::new(
            "routing requires production trust policy",
        ));
    }
    let safe = |p| matches!(p, PrivacyClass::P1 | PrivacyClass::P2);
    if !safe(event.tensor.privacy_class)
        || !safe(event.observation.privacy_class)
        || event.observation.identity_evidence.is_some()
    {
        return Err(BackendError::new("routing privacy denied"));
    }
    for id in [
        Some(event.event_id.as_str()),
        Some(event.sensor.device_id.as_str()),
        event.observation.zone_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if id.trim().is_empty() || id.len() > 256 {
            return Err(BackendError::new("invalid routing identity"));
        }
    }
    if event.observation.zone_id.is_none() && event.observation.space_cell.is_none() {
        return Err(BackendError::new("routing requires explicit zone or cell"));
    }
    event
        .tensor
        .validate()
        .map_err(|e| BackendError::new(e.to_string()))?;
    event
        .validate_evidence_at(now_ns)
        .map_err(|e| BackendError::new(e.to_string()))?;
    let feature = |key: &str| event.observation.features.get(key).copied().unwrap_or(0.0);
    let features = Features {
        presence: feature("presence"),
        motion_energy: feature("motion_energy"),
        transient: feature("transient"),
    };
    if [
        event.observation.confidence,
        features.presence,
        features.motion_energy,
        features.transient,
    ]
    .iter()
    .any(|v| !v.is_finite() || !(0.0..=1.0).contains(v))
    {
        return Err(BackendError::new(
            "routing signals must be finite unit values",
        ));
    }
    let json = serde_json::to_vec(&Projection {
        event_id: &event.event_id,
        timestamp_ns: event.timestamp_ns,
        sensor: Sensor {
            device_id: &event.sensor.device_id,
        },
        observation: Observation {
            zone_id: event.observation.zone_id.as_deref(),
            space_cell: event.observation.space_cell,
            confidence: event.observation.confidence,
            features,
            privacy_class: event.observation.privacy_class,
        },
        provenance: Provenance { synthetic: false },
    })
    .map_err(|e| BackendError::new(e.to_string()))?;
    verifier
        .verify_and_record_at(event, now_ns)
        .map_err(|e| BackendError::new(e.to_string()))?;
    Ok(PreparedRoutingEvent {
        json,
        timestamp_ns: event.timestamp_ns,
        max_age_ns: verifier.policy().max_event_age_ns,
        future_skew_ns: verifier.policy().max_future_skew_ns,
    })
}
