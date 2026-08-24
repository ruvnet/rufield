//! Policy verification above the detached-signature primitive.
//!
//! The event-carried public key is treated as an identifier only. Captured
//! replay and production modes authorize it against an independently
//! configured trust registry before accepting the event.

use super::{hex_decode, is_fusable, verify_event, ProvenanceError};
use ed25519_dalek::VerifyingKey;
use rufield_core::FieldEvent;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Current serialized replay-state schema.
pub const REPLAY_STATE_VERSION: u16 = 1;

/// Default production event age: five minutes.
pub const DEFAULT_MAX_EVENT_AGE_NS: u64 = 300_000_000_000;

/// Default production future-clock tolerance: five seconds.
pub const DEFAULT_MAX_FUTURE_SKEW_NS: u64 = 5_000_000_000;

/// Verification context. The modes deliberately have different trust rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustMode {
    /// Deterministic tests and simulators. This is the only mode that accepts
    /// unsigned synthetic evidence or event-carried self-signed keys.
    Simulation,
    /// Historical, real captured evidence. Requires enrolled keys, binding and
    /// replay checks, but intentionally skips wall-clock freshness.
    CapturedReplay,
    /// Live evidence. Requires enrolled keys, binding, freshness and replay
    /// checks and always rejects synthetic evidence.
    Production,
}

/// Serializable policy parameters for a verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicy {
    /// Operational verification context.
    pub mode: TrustMode,
    /// Maximum accepted age in production.
    pub max_event_age_ns: u64,
    /// Maximum accepted positive clock skew in production.
    pub max_future_skew_ns: u64,
}

impl TrustPolicy {
    /// Policy preserving the original deterministic simulation behavior.
    #[must_use]
    pub const fn simulation() -> Self {
        Self {
            mode: TrustMode::Simulation,
            max_event_age_ns: 0,
            max_future_skew_ns: 0,
        }
    }

    /// Policy for an authenticated historical capture.
    #[must_use]
    pub const fn captured_replay() -> Self {
        Self {
            mode: TrustMode::CapturedReplay,
            max_event_age_ns: 0,
            max_future_skew_ns: 0,
        }
    }

    /// Default live policy with a five-minute age limit and five-second future
    /// clock tolerance.
    #[must_use]
    pub const fn production() -> Self {
        Self::production_with_window(DEFAULT_MAX_EVENT_AGE_NS, DEFAULT_MAX_FUTURE_SKEW_NS)
    }

    /// Live policy with caller-selected freshness limits.
    #[must_use]
    pub const fn production_with_window(max_event_age_ns: u64, max_future_skew_ns: u64) -> Self {
        Self {
            mode: TrustMode::Production,
            max_event_age_ns,
            max_future_skew_ns,
        }
    }
}

/// Independently provisioned sensor identity bindings and revocations.
///
/// This object is configuration, not event input. Persist it in a protected
/// control-plane store in production.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TrustedKeyRegistry {
    sensor_keys: BTreeMap<String, String>,
    revoked_keys: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedKeyRegistryWire {
    sensor_keys: BTreeMap<String, String>,
    revoked_keys: BTreeSet<String>,
}

impl<'de> Deserialize<'de> for TrustedKeyRegistry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = TrustedKeyRegistryWire::deserialize(deserializer)?;
        let mut registry = Self::new();

        for (sensor_id, public_key_hex) in wire.sensor_keys {
            let sensor_id =
                normalize_sensor_id(&sensor_id).map_err(<D::Error as serde::de::Error>::custom)?;
            let public_key_hex = normalize_public_key(&public_key_hex)
                .map_err(<D::Error as serde::de::Error>::custom)?;
            if registry
                .sensor_keys
                .insert(sensor_id.clone(), public_key_hex)
                .is_some()
            {
                return Err(<D::Error as serde::de::Error>::custom(format!(
                    "duplicate sensor id after normalization: {sensor_id}"
                )));
            }
        }

        for public_key_hex in wire.revoked_keys {
            let public_key_hex = normalize_public_key(&public_key_hex)
                .map_err(<D::Error as serde::de::Error>::custom)?;
            registry.revoked_keys.insert(public_key_hex);
        }

        Ok(registry)
    }
}

impl TrustedKeyRegistry {
    /// Create an empty, fail-closed registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sensor_keys: BTreeMap::new(),
            revoked_keys: BTreeSet::new(),
        }
    }

    /// Enroll or explicitly rotate a sensor to a valid Ed25519 public key.
    pub fn enroll_sensor_key(
        &mut self,
        sensor_id: impl Into<String>,
        public_key_hex: impl AsRef<str>,
    ) -> Result<(), TrustError> {
        let sensor_id = normalize_sensor_id(&sensor_id.into())?;
        let public_key_hex = normalize_public_key(public_key_hex.as_ref())?;
        self.sensor_keys.insert(sensor_id, public_key_hex);
        Ok(())
    }

    /// Revoke a valid public key. Revocation wins over any existing binding.
    pub fn revoke_key(&mut self, public_key_hex: impl AsRef<str>) -> Result<(), TrustError> {
        let key = normalize_public_key(public_key_hex.as_ref())?;
        self.revoked_keys.insert(key);
        Ok(())
    }

    /// Remove a revocation after an explicit control-plane decision.
    pub fn unrevoke_key(&mut self, public_key_hex: impl AsRef<str>) -> Result<(), TrustError> {
        let key = normalize_public_key(public_key_hex.as_ref())?;
        self.revoked_keys.remove(&key);
        Ok(())
    }

    /// Return the enrolled key for a sensor.
    #[must_use]
    pub fn key_for_sensor(&self, sensor_id: &str) -> Option<&str> {
        self.sensor_keys.get(sensor_id).map(String::as_str)
    }

    /// True when this key appears in at least one independently enrolled
    /// sensor binding.
    #[must_use]
    pub fn contains_key(&self, public_key_hex: &str) -> bool {
        self.sensor_keys
            .values()
            .any(|enrolled| enrolled == public_key_hex)
    }

    /// True when the key is explicitly revoked.
    #[must_use]
    pub fn is_revoked(&self, public_key_hex: &str) -> bool {
        self.revoked_keys.contains(public_key_hex)
    }

    /// Number of independently enrolled sensor identities.
    #[must_use]
    pub fn sensor_count(&self) -> usize {
        self.sensor_keys.len()
    }

    /// True when no sensor identity is enrolled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sensor_keys.is_empty()
    }
}

/// Last accepted event for one sensor stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayWatermark {
    /// Strictly increasing capture timestamp.
    pub last_timestamp_ns: u64,
    /// Last accepted event id, used to classify exact duplicates.
    pub last_event_id: String,
    /// Trusted signer responsible for the last accepted event.
    pub signer_pubkey_hex: Option<String>,
}

/// Persistable replay defense state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayState {
    /// Schema version for safe restoration.
    pub version: u16,
    /// Per-sensor strictly monotonic watermark.
    pub watermarks: BTreeMap<String, ReplayWatermark>,
}

impl Default for ReplayState {
    fn default() -> Self {
        Self {
            version: REPLAY_STATE_VERSION,
            watermarks: BTreeMap::new(),
        }
    }
}

impl ReplayState {
    /// Serialize for durable, integrity-protected storage.
    pub fn to_json(&self) -> Result<String, TrustError> {
        validate_replay_state(self)?;
        serde_json::to_string(self).map_err(|error| TrustError::ReplayState(error.to_string()))
    }

    /// Deserialize and validate the replay-state schema.
    pub fn from_json(json: &str) -> Result<Self, TrustError> {
        let state: Self = serde_json::from_str(json)
            .map_err(|error| TrustError::ReplayState(error.to_string()))?;
        validate_replay_state(&state)?;
        Ok(state)
    }
}

/// Policy rejection reason. Callers can map these variants to metrics without
/// parsing display strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustError {
    /// An event or sensor identity was empty or otherwise malformed.
    MalformedIdentity(String),
    /// Synthetic evidence was presented outside simulation.
    SyntheticRejected,
    /// No public key was carried by an event that requires one.
    MissingPublicKey,
    /// The event-carried key has no independent enrollment.
    UnknownKey,
    /// No identity binding exists for the sensor id.
    UnknownSensor(String),
    /// The sensor is enrolled to a different key.
    SensorKeyMismatch(String),
    /// The independently known key is revoked.
    RevokedKey,
    /// The timestamp is older than the production freshness window.
    StaleTimestamp,
    /// The timestamp exceeds the allowed positive clock skew.
    FutureTimestamp,
    /// The exact last accepted event was submitted again.
    DuplicateEvent(String),
    /// The event timestamp did not strictly increase for its sensor.
    NonMonotonicReplay {
        /// Persisted last accepted timestamp.
        last_timestamp_ns: u64,
        /// Rejected timestamp.
        event_timestamp_ns: u64,
    },
    /// Detached-signature validation failed.
    Provenance(ProvenanceError),
    /// Trust registry material was invalid.
    InvalidRegistry(String),
    /// Replay state was malformed, incompatible or attempted a rollback.
    ReplayState(String),
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedIdentity(message) => write!(f, "malformed identity: {message}"),
            Self::SyntheticRejected => write!(f, "synthetic evidence rejected by trust mode"),
            Self::MissingPublicKey => write!(f, "event is missing signer public key"),
            Self::UnknownKey => write!(f, "signer key is not independently enrolled"),
            Self::UnknownSensor(sensor) => write!(f, "sensor {sensor} is not enrolled"),
            Self::SensorKeyMismatch(sensor) => {
                write!(f, "sensor {sensor} is enrolled to a different key")
            }
            Self::RevokedKey => write!(f, "signer key is revoked"),
            Self::StaleTimestamp => write!(f, "event timestamp is stale"),
            Self::FutureTimestamp => write!(f, "event timestamp is too far in the future"),
            Self::DuplicateEvent(id) => write!(f, "duplicate event {id}"),
            Self::NonMonotonicReplay {
                last_timestamp_ns,
                event_timestamp_ns,
            } => write!(
                f,
                "event timestamp {event_timestamp_ns} is not newer than watermark {last_timestamp_ns}"
            ),
            Self::Provenance(error) => write!(f, "provenance rejected: {error}"),
            Self::InvalidRegistry(message) => write!(f, "invalid trust registry: {message}"),
            Self::ReplayState(message) => write!(f, "invalid replay state: {message}"),
        }
    }
}

impl std::error::Error for TrustError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Provenance(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ProvenanceError> for TrustError {
    fn from(error: ProvenanceError) -> Self {
        Self::Provenance(error)
    }
}

/// Stateful policy verifier. A successful decision atomically advances the
/// in-memory replay watermark. Every rejection leaves replay state unchanged.
#[derive(Debug, Clone)]
pub struct TrustVerifier {
    policy: TrustPolicy,
    registry: TrustedKeyRegistry,
    replay: ReplayState,
}

impl TrustVerifier {
    /// Construct from explicit policy and independently provisioned keys.
    #[must_use]
    pub fn new(policy: TrustPolicy, registry: TrustedKeyRegistry) -> Self {
        Self {
            policy,
            registry,
            replay: ReplayState::default(),
        }
    }

    /// Compatibility verifier for deterministic simulator flows.
    #[must_use]
    pub fn simulation() -> Self {
        Self::new(TrustPolicy::simulation(), TrustedKeyRegistry::new())
    }

    /// Current operational mode.
    #[must_use]
    pub const fn mode(&self) -> TrustMode {
        self.policy.mode
    }

    /// Read policy parameters.
    #[must_use]
    pub const fn policy(&self) -> &TrustPolicy {
        &self.policy
    }

    /// Read the independently configured registry.
    #[must_use]
    pub const fn registry(&self) -> &TrustedKeyRegistry {
        &self.registry
    }

    /// Mutate enrollment or revocation through a protected control plane.
    #[must_use]
    pub fn registry_mut(&mut self) -> &mut TrustedKeyRegistry {
        &mut self.registry
    }

    /// Export replay watermarks for durable storage before shutdown.
    #[must_use]
    pub fn export_replay_state(&self) -> ReplayState {
        self.replay.clone()
    }

    /// Restore replay watermarks. Restoring may add or advance watermarks but
    /// cannot remove or roll back any state already held by this verifier.
    pub fn restore_replay_state(&mut self, state: ReplayState) -> Result<(), TrustError> {
        validate_replay_state(&state)?;
        for (sensor, current) in &self.replay.watermarks {
            let incoming = state.watermarks.get(sensor).ok_or_else(|| {
                TrustError::ReplayState(format!(
                    "restore would remove watermark for sensor {sensor}"
                ))
            })?;
            if incoming.last_timestamp_ns < current.last_timestamp_ns {
                return Err(TrustError::ReplayState(format!(
                    "restore would roll back sensor {sensor}"
                )));
            }
        }
        self.replay = state;
        Ok(())
    }

    /// Verify an event against policy at an explicit wall-clock time, then
    /// advance its sensor replay watermark.
    ///
    /// The watermark mutation is intentionally the final operation. Signature,
    /// trust anchor, binding, revocation, freshness and replay checks all run
    /// first, so malformed input cannot consume a valid sequence position.
    pub fn verify_and_record_at(
        &mut self,
        event: &FieldEvent,
        now_ns: u64,
    ) -> Result<(), TrustError> {
        validate_event_identity(event)?;
        let signer = self.verify_without_replay(event, now_ns)?;
        self.check_replay(event)?;

        self.replay.watermarks.insert(
            event.sensor.device_id.clone(),
            ReplayWatermark {
                last_timestamp_ns: event.timestamp_ns,
                last_event_id: event.event_id.clone(),
                signer_pubkey_hex: signer,
            },
        );
        Ok(())
    }

    fn verify_without_replay(
        &self,
        event: &FieldEvent,
        now_ns: u64,
    ) -> Result<Option<String>, TrustError> {
        if self.policy.mode == TrustMode::Simulation {
            return if is_fusable(event) {
                Ok(event
                    .provenance
                    .signer_pubkey_hex
                    .as_deref()
                    .map(str::to_ascii_lowercase))
            } else {
                Err(TrustError::Provenance(ProvenanceError::VerifyFailed))
            };
        }

        if event.provenance.synthetic {
            return Err(TrustError::SyntheticRejected);
        }

        let carried_key = event
            .provenance
            .signer_pubkey_hex
            .as_deref()
            .ok_or(TrustError::MissingPublicKey)?;
        let carried_key = normalize_public_key(carried_key)?;

        if self.registry.is_revoked(&carried_key) {
            return Err(TrustError::RevokedKey);
        }
        if !self.registry.contains_key(&carried_key) {
            return Err(TrustError::UnknownKey);
        }
        let enrolled_key = self
            .registry
            .key_for_sensor(&event.sensor.device_id)
            .ok_or_else(|| TrustError::UnknownSensor(event.sensor.device_id.clone()))?;
        if enrolled_key != carried_key {
            return Err(TrustError::SensorKeyMismatch(
                event.sensor.device_id.clone(),
            ));
        }

        verify_event(event)?;

        if self.policy.mode == TrustMode::Production {
            if event.timestamp_ns > now_ns.saturating_add(self.policy.max_future_skew_ns) {
                return Err(TrustError::FutureTimestamp);
            }
            if now_ns
                > event
                    .timestamp_ns
                    .saturating_add(self.policy.max_event_age_ns)
            {
                return Err(TrustError::StaleTimestamp);
            }
        }

        Ok(Some(carried_key))
    }

    fn check_replay(&self, event: &FieldEvent) -> Result<(), TrustError> {
        let Some(watermark) = self.replay.watermarks.get(&event.sensor.device_id) else {
            return Ok(());
        };
        if event.event_id == watermark.last_event_id {
            return Err(TrustError::DuplicateEvent(event.event_id.clone()));
        }
        if event.timestamp_ns <= watermark.last_timestamp_ns {
            return Err(TrustError::NonMonotonicReplay {
                last_timestamp_ns: watermark.last_timestamp_ns,
                event_timestamp_ns: event.timestamp_ns,
            });
        }
        Ok(())
    }
}

fn normalize_public_key(public_key_hex: &str) -> Result<String, TrustError> {
    let bytes = hex_decode(public_key_hex)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| TrustError::InvalidRegistry("Ed25519 public key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|error| TrustError::InvalidRegistry(error.to_string()))?;
    Ok(public_key_hex.to_ascii_lowercase())
}

fn normalize_sensor_id(sensor_id: &str) -> Result<String, TrustError> {
    let sensor_id = sensor_id.trim();
    if sensor_id.is_empty() {
        return Err(TrustError::InvalidRegistry(
            "sensor id must not be empty".into(),
        ));
    }
    if sensor_id.chars().any(char::is_control) {
        return Err(TrustError::InvalidRegistry(
            "sensor id must not contain control characters".into(),
        ));
    }
    Ok(sensor_id.to_owned())
}

fn validate_event_identity(event: &FieldEvent) -> Result<(), TrustError> {
    if event.event_id.trim().is_empty() {
        return Err(TrustError::MalformedIdentity(
            "event id must not be empty".into(),
        ));
    }
    if event.sensor.device_id.trim().is_empty() {
        return Err(TrustError::MalformedIdentity(
            "sensor id must not be empty".into(),
        ));
    }
    Ok(())
}

fn validate_replay_state(state: &ReplayState) -> Result<(), TrustError> {
    if state.version != REPLAY_STATE_VERSION {
        return Err(TrustError::ReplayState(format!(
            "unsupported version {}; expected {REPLAY_STATE_VERSION}",
            state.version
        )));
    }
    if state
        .watermarks
        .keys()
        .any(|sensor| sensor.trim().is_empty())
    {
        return Err(TrustError::ReplayState(
            "sensor ids in replay state must not be empty".into(),
        ));
    }
    for (sensor, watermark) in &state.watermarks {
        if watermark.last_event_id.trim().is_empty() {
            return Err(TrustError::ReplayState(format!(
                "last event id for sensor {sensor} must not be empty"
            )));
        }
        if let Some(key) = &watermark.signer_pubkey_hex {
            normalize_public_key(key).map_err(|error| {
                TrustError::ReplayState(format!(
                    "signer key for sensor {sensor} is malformed: {error}"
                ))
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sha256_hex, Signer};
    use rufield_core::{
        FieldAxis, FieldTensor, Modality, Observation, PrivacyClass, ProvenanceRef,
        SensorDescriptor,
    };

    const NOW_NS: u64 = 1_800_000_000_000_000_000;

    fn sample_event(id: &str, timestamp_ns: u64, sensor_id: &str) -> FieldEvent {
        let tensor = FieldTensor::new(
            timestamp_ns,
            Modality::WifiCsi,
            vec![FieldAxis::Frequency],
            vec![3],
            vec![1.0, 2.0, 3.0],
            0.9,
            0.01,
            Some("cal".into()),
            PrivacyClass::P2,
        )
        .unwrap();
        FieldEvent::new(
            id,
            timestamp_ns,
            SensorDescriptor {
                modality: "wifi_csi".into(),
                vendor: "esp32_c6".into(),
                device_id: sensor_id.into(),
                placement: "corner".into(),
                clock_domain: "ptp".into(),
            },
            tensor,
            Observation::occupancy(0.9, PrivacyClass::P2),
            ProvenanceRef {
                raw_hash: sha256_hex(b"raw"),
                firmware_hash: sha256_hex(b"fw"),
                model_id: "m1".into(),
                calibration_id: "cal".into(),
                synthetic: false,
                signature_hex: None,
                signer_pubkey_hex: None,
            },
        )
    }

    fn production_verifier(signer: &Signer, sensor_id: &str) -> TrustVerifier {
        let mut registry = TrustedKeyRegistry::new();
        registry
            .enroll_sensor_key(sensor_id, signer.public_hex())
            .unwrap();
        TrustVerifier::new(TrustPolicy::production(), registry)
    }

    #[test]
    fn production_accepts_trusted_bound_fresh_event() {
        let signer = Signer::from_seed(&[1; 32]);
        let mut event = sample_event("trusted", NOW_NS, "sensor-a");
        signer.sign_event(&mut event).unwrap();
        let mut verifier = production_verifier(&signer, "sensor-a");
        assert_eq!(verifier.verify_and_record_at(&event, NOW_NS), Ok(()));
    }

    #[test]
    fn production_rejects_synthetic_flag_flip() {
        let signer = Signer::from_seed(&[2; 32]);
        let mut event = sample_event("flag-flip", NOW_NS, "sensor-a");
        signer.sign_event(&mut event).unwrap();
        event.provenance.synthetic = true;
        let mut verifier = production_verifier(&signer, "sensor-a");
        assert_eq!(
            verifier.verify_and_record_at(&event, NOW_NS),
            Err(TrustError::SyntheticRejected)
        );
    }

    #[test]
    fn production_rejects_unknown_self_signed_key() {
        let enrolled = Signer::from_seed(&[3; 32]);
        let attacker = Signer::from_seed(&[4; 32]);
        let mut event = sample_event("self-signed", NOW_NS, "sensor-a");
        attacker.sign_event(&mut event).unwrap();
        let mut verifier = production_verifier(&enrolled, "sensor-a");
        assert_eq!(
            verifier.verify_and_record_at(&event, NOW_NS),
            Err(TrustError::UnknownKey)
        );
    }

    #[test]
    fn production_rejects_exact_duplicate() {
        let signer = Signer::from_seed(&[5; 32]);
        let mut event = sample_event("duplicate", NOW_NS, "sensor-a");
        signer.sign_event(&mut event).unwrap();
        let mut verifier = production_verifier(&signer, "sensor-a");
        verifier.verify_and_record_at(&event, NOW_NS).unwrap();
        assert_eq!(
            verifier.verify_and_record_at(&event, NOW_NS),
            Err(TrustError::DuplicateEvent("duplicate".into()))
        );
    }

    #[test]
    fn production_rejects_nonmonotonic_replay() {
        let signer = Signer::from_seed(&[6; 32]);
        let mut newest = sample_event("newest", NOW_NS, "sensor-a");
        let mut older = sample_event("older", NOW_NS - 1, "sensor-a");
        signer.sign_event(&mut newest).unwrap();
        signer.sign_event(&mut older).unwrap();
        let mut verifier = production_verifier(&signer, "sensor-a");
        verifier.verify_and_record_at(&newest, NOW_NS).unwrap();
        assert!(matches!(
            verifier.verify_and_record_at(&older, NOW_NS),
            Err(TrustError::NonMonotonicReplay { .. })
        ));
    }

    #[test]
    fn production_rejects_stale_event() {
        let signer = Signer::from_seed(&[7; 32]);
        let timestamp = NOW_NS - DEFAULT_MAX_EVENT_AGE_NS - 1;
        let mut event = sample_event("stale", timestamp, "sensor-a");
        signer.sign_event(&mut event).unwrap();
        let mut verifier = production_verifier(&signer, "sensor-a");
        assert_eq!(
            verifier.verify_and_record_at(&event, NOW_NS),
            Err(TrustError::StaleTimestamp)
        );
    }

    #[test]
    fn production_rejects_future_event() {
        let signer = Signer::from_seed(&[8; 32]);
        let timestamp = NOW_NS + DEFAULT_MAX_FUTURE_SKEW_NS + 1;
        let mut event = sample_event("future", timestamp, "sensor-a");
        signer.sign_event(&mut event).unwrap();
        let mut verifier = production_verifier(&signer, "sensor-a");
        assert_eq!(
            verifier.verify_and_record_at(&event, NOW_NS),
            Err(TrustError::FutureTimestamp)
        );
    }

    #[test]
    fn production_rejects_revoked_key() {
        let signer = Signer::from_seed(&[9; 32]);
        let mut event = sample_event("revoked", NOW_NS, "sensor-a");
        signer.sign_event(&mut event).unwrap();
        let mut verifier = production_verifier(&signer, "sensor-a");
        verifier
            .registry_mut()
            .revoke_key(signer.public_hex())
            .unwrap();
        assert_eq!(
            verifier.verify_and_record_at(&event, NOW_NS),
            Err(TrustError::RevokedKey)
        );
    }

    #[test]
    fn deserialized_uppercase_revocation_is_normalized_and_rejected() {
        let signer = Signer::from_seed(&[31; 32]);
        let public_key = signer.public_hex();
        let json = serde_json::json!({
            "sensor_keys": { " sensor-a ": public_key.clone() },
            "revoked_keys": [public_key.to_ascii_uppercase()]
        })
        .to_string();
        let registry: TrustedKeyRegistry = serde_json::from_str(&json).unwrap();

        assert_eq!(
            registry.key_for_sensor("sensor-a"),
            Some(public_key.as_str())
        );
        assert!(registry.is_revoked(&public_key));

        let mut event = sample_event("uppercase-revocation", NOW_NS, "sensor-a");
        signer.sign_event(&mut event).unwrap();
        let mut verifier = TrustVerifier::new(TrustPolicy::production(), registry);
        assert_eq!(
            verifier.verify_and_record_at(&event, NOW_NS),
            Err(TrustError::RevokedKey)
        );
        assert!(verifier.export_replay_state().watermarks.is_empty());
    }

    #[test]
    fn registry_deserialization_rejects_invalid_ids_and_keys() {
        let signer = Signer::from_seed(&[32; 32]);
        let valid_key = signer.public_hex();
        let invalid_registries = [
            serde_json::json!({
                "sensor_keys": { "   ": valid_key.clone() },
                "revoked_keys": []
            }),
            serde_json::json!({
                "sensor_keys": { "sensor-a": "not-hex" },
                "revoked_keys": []
            }),
            serde_json::json!({
                "sensor_keys": { "sensor-a": valid_key.clone() },
                "revoked_keys": ["not-hex"]
            }),
        ];

        for invalid in invalid_registries {
            assert!(serde_json::from_value::<TrustedKeyRegistry>(invalid).is_err());
        }
    }

    #[test]
    fn production_rejects_sensor_key_binding_mismatch() {
        let signer_a = Signer::from_seed(&[10; 32]);
        let signer_b = Signer::from_seed(&[11; 32]);
        let mut registry = TrustedKeyRegistry::new();
        registry
            .enroll_sensor_key("sensor-a", signer_a.public_hex())
            .unwrap();
        registry
            .enroll_sensor_key("sensor-b", signer_b.public_hex())
            .unwrap();
        let mut event = sample_event("mismatch", NOW_NS, "sensor-a");
        signer_b.sign_event(&mut event).unwrap();
        let mut verifier = TrustVerifier::new(TrustPolicy::production(), registry);
        assert_eq!(
            verifier.verify_and_record_at(&event, NOW_NS),
            Err(TrustError::SensorKeyMismatch("sensor-a".into()))
        );
    }

    #[test]
    fn malformed_signature_does_not_advance_watermark() {
        let signer = Signer::from_seed(&[12; 32]);
        let mut event = sample_event("malformed", NOW_NS, "sensor-a");
        signer.sign_event(&mut event).unwrap();
        event.provenance.signature_hex = Some("not-hex".into());
        let mut verifier = production_verifier(&signer, "sensor-a");
        let before = verifier.export_replay_state();
        assert!(matches!(
            verifier.verify_and_record_at(&event, NOW_NS),
            Err(TrustError::Provenance(ProvenanceError::BadEncoding(_)))
        ));
        assert_eq!(verifier.export_replay_state(), before);
    }

    #[test]
    fn empty_event_id_does_not_advance_watermark() {
        let signer = Signer::from_seed(&[33; 32]);
        let mut event = sample_event("", NOW_NS, "sensor-a");
        signer.sign_event(&mut event).unwrap();
        let mut verifier = production_verifier(&signer, "sensor-a");
        let before = verifier.export_replay_state();
        assert_eq!(
            verifier.verify_and_record_at(&event, NOW_NS),
            Err(TrustError::MalformedIdentity(
                "event id must not be empty".into()
            ))
        );
        assert_eq!(verifier.export_replay_state(), before);
    }

    #[test]
    fn replay_state_json_round_trip_rejects_replay_after_restart() {
        let signer = Signer::from_seed(&[13; 32]);
        let mut event = sample_event("before-restart", NOW_NS, "sensor-a");
        signer.sign_event(&mut event).unwrap();

        let mut first = production_verifier(&signer, "sensor-a");
        first.verify_and_record_at(&event, NOW_NS).unwrap();
        let json = first.export_replay_state().to_json().unwrap();
        let restored = ReplayState::from_json(&json).unwrap();
        assert_eq!(restored, first.export_replay_state());

        let mut restarted = production_verifier(&signer, "sensor-a");
        restarted.restore_replay_state(restored).unwrap();
        assert_eq!(
            restarted.verify_and_record_at(&event, NOW_NS),
            Err(TrustError::DuplicateEvent("before-restart".into()))
        );
    }

    #[test]
    fn replay_state_rejects_empty_last_event_id() {
        let mut state = ReplayState::default();
        state.watermarks.insert(
            "sensor-a".into(),
            ReplayWatermark {
                last_timestamp_ns: NOW_NS,
                last_event_id: "".into(),
                signer_pubkey_hex: None,
            },
        );
        assert!(matches!(state.to_json(), Err(TrustError::ReplayState(_))));
    }

    #[test]
    fn replay_state_rejects_malformed_signer_key() {
        let json = format!(
            r#"{{"version":{REPLAY_STATE_VERSION},"watermarks":{{"sensor-a":{{"last_timestamp_ns":{NOW_NS},"last_event_id":"event-a","signer_pubkey_hex":"not-hex"}}}}}}"#
        );
        assert!(matches!(
            ReplayState::from_json(&json),
            Err(TrustError::ReplayState(_))
        ));
    }

    #[test]
    fn captured_replay_accepts_old_trusted_event() {
        let signer = Signer::from_seed(&[14; 32]);
        let mut event = sample_event("capture", 1, "sensor-a");
        signer.sign_event(&mut event).unwrap();
        let mut registry = TrustedKeyRegistry::new();
        registry
            .enroll_sensor_key("sensor-a", signer.public_hex())
            .unwrap();
        let mut verifier = TrustVerifier::new(TrustPolicy::captured_replay(), registry);
        assert_eq!(verifier.verify_and_record_at(&event, NOW_NS), Ok(()));
    }

    #[test]
    fn simulation_is_only_unsigned_synthetic_escape_hatch() {
        let mut event = sample_event("simulation", 1, "sim-a");
        event.provenance.synthetic = true;
        let mut verifier = TrustVerifier::simulation();
        assert_eq!(verifier.verify_and_record_at(&event, NOW_NS), Ok(()));
    }
}
