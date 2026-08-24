//! Field event, sensor descriptor, observation, calibration receipt
//! (ADR-260 §7 / §20 / §23).

use crate::privacy::PrivacyClass;
use crate::tensor::{FieldTensor, SPEC_VERSION};
use serde::{Deserialize, Serialize};

/// Maximum permitted lifetime of short-lived identity evidence: five seconds.
pub const MAX_IDENTITY_EVIDENCE_TTL_NS: u64 = 5_000_000_000;

/// Minimum confidence accepted for identity evidence at the fusion boundary.
pub const MIN_IDENTITY_EVIDENCE_CONFIDENCE: f32 = 0.60;

/// Minimum number of unique frequency channels in one promoted Channel
/// Sounding procedure.
pub const MIN_CHANNEL_SOUNDING_CHANNELS: usize = 4;

/// Maximum number of unique frequency channels in one promoted Channel
/// Sounding procedure.
pub const MAX_CHANNEL_SOUNDING_CHANNELS: usize = 79;

/// Largest Bluetooth RF channel index. Channel Sounding uses channels
/// `0..=78`, for 79 possible unique channels.
pub const MAX_CHANNEL_SOUNDING_CHANNEL_INDEX: u16 = 78;

const MAX_CHANNEL_SOUNDING_PHASE_RAD: f32 = 3_142.0 / 1_000.0;

/// A linkable identifier derived by an enrollment boundary from a secret or
/// rotating application token. It is never a BLE device address.
///
/// The wire form is `blep:<64 lowercase hex characters>`. Deserialization is
/// intentionally followed by semantic validation at the fusion boundary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PseudonymousId(String);

impl PseudonymousId {
    /// Construct an identifier from a 32-byte privacy-preserving digest.
    #[must_use]
    pub fn from_digest(digest: [u8; 32]) -> Self {
        let mut value = String::with_capacity(69);
        value.push_str("blep:");
        for byte in digest {
            value.push_str(&format!("{byte:02x}"));
        }
        Self(value)
    }

    /// Return the stable wire representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate the fixed digest representation.
    pub fn validate(&self) -> Result<(), crate::CoreError> {
        let Some(hex) = self.0.strip_prefix("blep:") else {
            return Err(crate::CoreError::Invalid(
                "identity evidence is not a RuField BLE pseudonym".into(),
            ));
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(crate::CoreError::Invalid(
                "BLE pseudonym must contain a 32-byte lowercase hex digest".into(),
            ));
        }
        Ok(())
    }
}

/// The evidence mechanism used to associate a pseudonym with a spatial track.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityEvidenceKind {
    /// A provisioned BLE application advertisement observed through RSSI.
    /// RSSI is proximity evidence only and never coherent ranging.
    BleAdvertisementRssi,
}

/// Short-lived pseudonymous identity evidence attached to an observation.
///
/// This is evidence about a track association, not a durable person record.
/// Its P5 classification requires consent, an enrollment binding, and an audit
/// log before release outside the governed edge boundary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityEvidence {
    /// Rotating or deployment-scoped pseudonym. Never a raw BLE MAC address.
    pub pseudonym: PseudonymousId,
    /// Spatial tracker identifier this evidence currently supports.
    pub track_id: String,
    /// Confidence in this short-lived association, `0.0..=1.0`.
    pub confidence: f32,
    /// Capture time in nanoseconds since Unix epoch.
    pub observed_ns: u64,
    /// Hard expiry time in nanoseconds since Unix epoch.
    pub expires_ns: u64,
    /// Enrollment or binding receipt identifier held by the governance plane.
    pub binding_receipt_id: String,
    /// Component that issued the evidence.
    pub issuer: String,
    /// Monotonic source record sequence used for replay rejection.
    pub source_sequence: u32,
    /// Rotation epoch of the source application token.
    pub token_epoch: u64,
    /// Evidence mechanism.
    pub kind: IdentityEvidenceKind,
}

impl IdentityEvidence {
    /// Validate representation, confidence, provenance references, and expiry
    /// at the supplied stream watermark.
    pub fn validate_at(&self, as_of_ns: u64) -> Result<(), crate::CoreError> {
        self.pseudonym.validate()?;
        if self.track_id.trim().is_empty()
            || self.binding_receipt_id.trim().is_empty()
            || self.issuer.trim().is_empty()
        {
            return Err(crate::CoreError::Invalid(
                "identity evidence requires track, binding receipt, and issuer".into(),
            ));
        }
        if !self.confidence.is_finite()
            || !(MIN_IDENTITY_EVIDENCE_CONFIDENCE..=1.0).contains(&self.confidence)
        {
            return Err(crate::CoreError::Invalid(
                "identity evidence confidence must be finite and within 0.60..=1".into(),
            ));
        }
        if self.expires_ns <= self.observed_ns || as_of_ns >= self.expires_ns {
            return Err(crate::CoreError::Invalid(
                "identity evidence is expired or has an invalid expiry".into(),
            ));
        }
        if self.expires_ns.saturating_sub(self.observed_ns) > MAX_IDENTITY_EVIDENCE_TTL_NS {
            return Err(crate::CoreError::Invalid(
                "identity evidence lifetime exceeds five seconds".into(),
            ));
        }
        if self.source_sequence == 0 {
            return Err(crate::CoreError::Invalid(
                "identity evidence source sequence must be non-zero".into(),
            ));
        }
        Ok(())
    }
}

/// Authenticated outer gateway metadata for one forwarded companion step.
///
/// The gateway transports the measurement but is not the Channel Sounding
/// sensor. These fields preserve the independently verified forwarding path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayEnvelopeProvenance {
    /// Enrolled ESP32 gateway node identifier.
    pub node_id: u8,
    /// Gateway envelope key selector.
    pub key_id: u8,
    /// Random nonzero gateway boot nonce.
    pub boot_nonce: u64,
    /// Monotonic envelope sequence within the boot nonce.
    pub sequence: u32,
    /// Gateway receive time in its monotonic boot clock.
    pub received_at_boot_us: u64,
    /// Gateway timestamp uncertainty in microseconds.
    pub timing_uncertainty_us: u32,
}

/// Typed provenance for one authenticated step of a Channel Sounding
/// procedure. Tensor phase values use the same ascending `step_index` order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSoundingStepProvenance {
    /// Host capture time assigned after both authentication layers.
    pub observed_ns: u64,
    /// Declared procedure step index.
    pub step_index: u16,
    /// Bluetooth frequency channel index.
    pub channel_index: u16,
    /// Companion HMAC key selector.
    pub companion_key_id: u8,
    /// Companion sequence number within `source_session_id`.
    pub companion_sequence: u32,
    /// Companion-declared age when received by the gateway.
    pub sample_age_us: u32,
    /// Companion timing uncertainty in microseconds.
    pub companion_timing_uncertainty_us: u16,
    /// Companion quality score in per mille.
    pub quality_permille: u16,
    /// Calibrated round-trip timing primitive in picoseconds.
    pub rtt_picoseconds: i32,
    /// Calibrated carrier-frequency offset in hertz.
    pub frequency_offset_hz: i32,
    /// Independently authenticated gateway forwarding provenance.
    pub gateway: GatewayEnvelopeProvenance,
}

/// A complete authenticated Channel Sounding procedure from an external
/// companion radio.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSoundingProcedureProvenance {
    /// Enrolled nonzero companion source identifier.
    pub source_id: u32,
    /// Nonzero companion boot/session identifier used for replay partitioning.
    pub source_session_id: u32,
    /// Nonzero procedure identifier within the source session.
    pub procedure_id: u32,
    /// Step count declared by every authenticated procedure frame.
    pub declared_step_count: u16,
    /// Complete steps in ascending `step_index` order.
    pub steps: Vec<ChannelSoundingStepProvenance>,
}

impl ChannelSoundingProcedureProvenance {
    /// Stable sensor identity for the external companion, distinct from its
    /// ESP32 forwarding gateway.
    #[must_use]
    pub fn sensor_id(&self) -> String {
        channel_sounding_sensor_id(self.source_id)
    }

    /// Validate completeness, uniqueness, coherence, and gateway provenance.
    pub fn validate(&self, event_timestamp_ns: u64) -> Result<(), crate::CoreError> {
        use std::collections::BTreeSet;

        if self.source_id == 0 || self.source_session_id == 0 || self.procedure_id == 0 {
            return Err(crate::CoreError::Invalid(
                "Channel Sounding source, session, and procedure ids must be nonzero".into(),
            ));
        }
        let declared = usize::from(self.declared_step_count);
        if !(MIN_CHANNEL_SOUNDING_CHANNELS..=MAX_CHANNEL_SOUNDING_CHANNELS).contains(&declared)
            || self.steps.len() != declared
        {
            return Err(crate::CoreError::Invalid(
                "Channel Sounding requires one complete 4..=79-step procedure".into(),
            ));
        }

        let first = self
            .steps
            .first()
            .expect("declared complete procedure has steps");
        if first.gateway.boot_nonce == 0 || first.gateway.sequence == 0 {
            return Err(crate::CoreError::Invalid(
                "Channel Sounding gateway boot nonce and sequence must be nonzero".into(),
            ));
        }
        let mut step_indices = BTreeSet::new();
        let mut channels = BTreeSet::new();
        let mut companion_sequences = BTreeSet::new();
        let mut gateway_sequences = BTreeSet::new();
        let mut newest_observed_ns = 0;
        for (expected_index, step) in self.steps.iter().enumerate() {
            if step.channel_index > MAX_CHANNEL_SOUNDING_CHANNEL_INDEX {
                return Err(crate::CoreError::Invalid(
                    "Channel Sounding frequency channel must be within 0..=78".into(),
                ));
            }
            if usize::from(step.step_index) != expected_index
                || usize::from(step.step_index) >= declared
                || !step_indices.insert(step.step_index)
                || !channels.insert(step.channel_index)
                || !companion_sequences.insert(step.companion_sequence)
                || !gateway_sequences.insert(step.gateway.sequence)
            {
                return Err(crate::CoreError::Invalid(
                    "Channel Sounding step indices, channels, companion sequences, and gateway sequences must be unique".into(),
                ));
            }
            if step.companion_sequence == 0
                || step.quality_permille > 1000
                || step.companion_timing_uncertainty_us > 10_000
                || !(0..=250_000).contains(&step.rtt_picoseconds)
                || !(-500_000..=500_000).contains(&step.frequency_offset_hz)
            {
                return Err(crate::CoreError::Invalid(
                    "Channel Sounding companion sequence, quality, timing, RTT, or frequency primitive is out of range".into(),
                ));
            }
            if step.gateway.node_id != first.gateway.node_id
                || step.gateway.key_id != first.gateway.key_id
                || step.gateway.boot_nonce != first.gateway.boot_nonce
                || step.companion_key_id != first.companion_key_id
                || step.gateway.sequence == 0
            {
                return Err(crate::CoreError::Invalid(
                    "Channel Sounding procedure crossed a companion key or gateway boot context"
                        .into(),
                ));
            }
            newest_observed_ns = newest_observed_ns.max(step.observed_ns);
        }
        if channels.len() != declared || newest_observed_ns != event_timestamp_ns {
            return Err(crate::CoreError::Invalid(
                "Channel Sounding event timestamp or unique-channel count is inconsistent".into(),
            ));
        }
        Ok(())
    }
}

/// Format the stable external-companion sensor id used on Channel Sounding
/// events. The forwarding ESP32 node is retained separately as provenance.
#[must_use]
pub fn channel_sounding_sensor_id(source_id: u32) -> String {
    format!("ble-cs-companion:{source_id:08x}")
}

/// Describes the sensor that produced an event (ADR-260 §7 `sensor`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorDescriptor {
    /// Modality string code (e.g. `wifi_csi`).
    pub modality: String,
    /// Vendor / chip identifier (e.g. `esp32_c6`).
    pub vendor: String,
    /// Stable device id (e.g. `sensor_room_01`).
    pub device_id: String,
    /// Physical placement hint (e.g. `ceiling_corner`).
    pub placement: String,
    /// Clock domain for `timestamp_ns` (e.g. `local_ptp`).
    pub clock_domain: String,
}

/// The interpreted observation derived from a tensor (ADR-260 §20
/// `Observation`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    /// Logical zone id, if known.
    pub zone_id: Option<String>,
    /// Discrete spatial cell `[x, y, z]`.
    pub space_cell: Option<[i32; 3]>,
    /// Range estimate in metres.
    pub range_m: Option<f32>,
    /// Velocity estimate in m/s.
    pub velocity_mps: Option<f32>,
    /// Motion vector `[dx, dy, dz]`.
    pub motion_vector: Option<[f32; 3]>,
    /// Anonymous spatial tracker identifier. This is not a human identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_id: Option<String>,
    /// Confidence `0.0..=1.0`.
    pub confidence: f32,
    /// Derived non-identity feature scalars (the P1-level encoder output that
    /// the fusion engine reads — e.g. `motion_energy`, `breathing_band`,
    /// `posture_height`, `transient`). This is NOT ground-truth: it is what a
    /// `FieldEncoder` would compute from the tensor.
    #[serde(default)]
    pub features: std::collections::BTreeMap<String, f32>,
    /// Ground-truth or derived labels attached to this observation. In the
    /// synthetic simulator these are the **ground-truth** labels used only by
    /// the benchmark to score against; the fusion engine never reads them.
    pub labels: Vec<String>,
    /// Privacy class of this observation.
    pub privacy_class: PrivacyClass,
    /// Optional short-lived pseudonymous identity evidence. Presence of this
    /// field makes the observation P5 regardless of whether a real name is
    /// available elsewhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_evidence: Option<IdentityEvidence>,
    /// Complete typed provenance for an external Channel Sounding procedure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_sounding_provenance: Option<ChannelSoundingProcedureProvenance>,
}

impl Observation {
    /// Minimal occupancy observation at the given confidence/privacy class.
    #[must_use]
    pub fn occupancy(confidence: f32, privacy_class: PrivacyClass) -> Self {
        Observation {
            zone_id: None,
            space_cell: None,
            range_m: None,
            velocity_mps: None,
            motion_vector: None,
            track_id: None,
            confidence,
            features: std::collections::BTreeMap::new(),
            labels: Vec::new(),
            privacy_class,
            identity_evidence: None,
            channel_sounding_provenance: None,
        }
    }
}

/// Provenance block inline on the event (ADR-260 §7 `provenance`). The full
/// signed receipt lives in `rufield-provenance`; this is the on-wire summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceRef {
    /// Hash of the raw measurement (`sha256:...`).
    pub raw_hash: String,
    /// Hash of the producing firmware (`sha256:...`).
    pub firmware_hash: String,
    /// Model identifier that produced derived features.
    pub model_id: String,
    /// Calibration receipt id.
    pub calibration_id: String,
    /// If true, this event is a simulator/replay event and may be fused
    /// without a verified cryptographic receipt (ADR-260 §11 invariant).
    #[serde(default)]
    pub synthetic: bool,
    /// Detached ed25519 signature over the event, hex-encoded, if signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
    /// Hex-encoded ed25519 verifying (public) key, if signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_pubkey_hex: Option<String>,
}

/// A timestamped observation from any ambient field sensor (ADR-260 §7 / §20).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldEvent {
    /// Wire spec version.
    pub spec_version: String,
    /// Unique event id (ULID-style string; deterministic in the simulator).
    pub event_id: String,
    /// Capture time, nanoseconds since Unix epoch.
    pub timestamp_ns: u64,
    /// Producing sensor.
    pub sensor: SensorDescriptor,
    /// Normalized numeric tensor.
    pub tensor: FieldTensor,
    /// Interpreted observation.
    pub observation: Observation,
    /// Provenance summary.
    pub provenance: ProvenanceRef,
}

impl FieldEvent {
    /// Construct a field event with the current spec version.
    #[must_use]
    pub fn new(
        event_id: impl Into<String>,
        timestamp_ns: u64,
        sensor: SensorDescriptor,
        tensor: FieldTensor,
        observation: Observation,
        provenance: ProvenanceRef,
    ) -> Self {
        FieldEvent {
            spec_version: SPEC_VERSION.to_string(),
            event_id: event_id.into(),
            timestamp_ns,
            sensor,
            tensor,
            observation,
            provenance,
        }
    }

    /// Validate cross-field evidence invariants at a stream watermark.
    ///
    /// This does not verify the event signature. The provenance crate owns
    /// cryptographic verification; fusion applies both checks before ingest.
    pub fn validate_evidence_at(&self, as_of_ns: u64) -> Result<(), crate::CoreError> {
        self.tensor.validate()?;
        if self.tensor.timestamp_ns != self.timestamp_ns {
            return Err(crate::CoreError::Invalid(
                "event and tensor timestamps differ".into(),
            ));
        }
        if self.sensor.modality != self.tensor.modality.as_str() {
            return Err(crate::CoreError::Invalid(
                "sensor and tensor modalities differ".into(),
            ));
        }

        if matches!(
            self.tensor.modality,
            crate::Modality::BleAdvertisementRssi | crate::Modality::BleChannelSounding
        ) {
            if !valid_sha256_ref(&self.provenance.firmware_hash)
                || self.provenance.model_id.trim().is_empty()
                || self.provenance.calibration_id.trim().is_empty()
            {
                return Err(crate::CoreError::Invalid(
                    "BLE evidence requires attested firmware, model, and calibration provenance"
                        .into(),
                ));
            }
            if self.tensor.calibration_id.as_deref()
                != Some(self.provenance.calibration_id.as_str())
            {
                return Err(crate::CoreError::Invalid(
                    "BLE tensor and provenance calibration receipts differ".into(),
                ));
            }
        }

        if let Some(evidence) = &self.observation.identity_evidence {
            evidence.validate_at(as_of_ns)?;
            if evidence.observed_ns != self.timestamp_ns {
                return Err(crate::CoreError::Invalid(
                    "identity evidence and event timestamps differ".into(),
                ));
            }
            if self.tensor.modality != crate::Modality::BleAdvertisementRssi {
                return Err(crate::CoreError::Invalid(
                    "BLE identity evidence must use the advertisement RSSI modality".into(),
                ));
            }
            if self.observation.privacy_class != PrivacyClass::P5
                || self.tensor.privacy_class != PrivacyClass::P5
            {
                return Err(crate::CoreError::Invalid(
                    "identity evidence must be classified P5".into(),
                ));
            }
            if self.observation.track_id.as_deref() != Some(evidence.track_id.as_str()) {
                return Err(crate::CoreError::Invalid(
                    "identity evidence track does not match observation track".into(),
                ));
            }
            if (self.observation.confidence - evidence.confidence).abs() > f32::EPSILON {
                return Err(crate::CoreError::Invalid(
                    "identity evidence confidence does not match observation".into(),
                ));
            }
            if evidence.issuer != self.sensor.device_id {
                return Err(crate::CoreError::Invalid(
                    "identity evidence issuer does not match sensor device".into(),
                ));
            }
            if evidence.binding_receipt_id == self.provenance.calibration_id {
                return Err(crate::CoreError::Invalid(
                    "BLE enrollment and sensor calibration receipts must be distinct".into(),
                ));
            }
        }

        match (
            self.tensor.modality,
            &self.observation.channel_sounding_provenance,
        ) {
            (crate::Modality::BleChannelSounding, Some(procedure)) => {
                procedure.validate(self.timestamp_ns)?;
                if self.sensor.device_id != procedure.sensor_id() {
                    return Err(crate::CoreError::Invalid(
                        "Channel Sounding sensor identity must be the external companion source"
                            .into(),
                    ));
                }
                if self.tensor.values.len() != procedure.steps.len() {
                    return Err(crate::CoreError::Invalid(
                        "Channel Sounding tensor does not contain one phase value per step".into(),
                    ));
                }
                if self.tensor.axes.as_slice() != [crate::FieldAxis::Frequency]
                    || self.tensor.shape.as_slice() != [procedure.steps.len()]
                    || !self.tensor.values.iter().all(|phase| {
                        phase.is_finite()
                            && (-MAX_CHANNEL_SOUNDING_PHASE_RAD..=MAX_CHANNEL_SOUNDING_PHASE_RAD)
                                .contains(phase)
                    })
                {
                    return Err(crate::CoreError::Invalid(
                        "Channel Sounding tensor must be one finite ordered phase value per frequency step"
                            .into(),
                    ));
                }
            }
            (crate::Modality::BleChannelSounding, None) => {
                return Err(crate::CoreError::Invalid(
                    "Channel Sounding event lacks complete typed procedure provenance".into(),
                ));
            }
            (_, Some(_)) => {
                return Err(crate::CoreError::Invalid(
                    "Channel Sounding provenance is attached to another modality".into(),
                ));
            }
            (_, None) => {}
        }

        if self.tensor.modality == crate::Modality::BleChannelSounding
            && self.observation.features.contains_key("breathing_band")
            && self.observation.privacy_class < PrivacyClass::P4
        {
            return Err(crate::CoreError::Invalid(
                "channel-sounding respiration features require P4 classification".into(),
            ));
        }
        Ok(())
    }
}

fn valid_sha256_ref(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// First-class calibration receipt (ADR-260 §23).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibrationReceipt {
    /// Calibration id.
    pub calibration_id: String,
    /// Modality this calibration applies to.
    pub modality: String,
    /// Room / zone the calibration was taken in.
    pub zone_id: String,
    /// Calibration task performed (e.g. `empty_room_baseline`).
    pub task: String,
    /// Capture time, nanoseconds since Unix epoch.
    pub created_ns: u64,
    /// Expiry time, nanoseconds since Unix epoch.
    pub expires_ns: u64,
    /// Hash of the calibration data (`sha256:...`).
    pub data_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modality::{FieldAxis, Modality};

    fn sample_tensor() -> FieldTensor {
        FieldTensor::new(
            1,
            Modality::WifiCsi,
            vec![FieldAxis::Frequency],
            vec![3],
            vec![0.1, 0.2, 0.3],
            0.8,
            0.01,
            Some("room_cal_2026".into()),
            PrivacyClass::P2,
        )
        .unwrap()
    }

    #[test]
    fn event_round_trips() {
        let ev = FieldEvent::new(
            "01J00000000000000000000000",
            1,
            SensorDescriptor {
                modality: "wifi_csi".into(),
                vendor: "esp32_c6".into(),
                device_id: "sensor_room_01".into(),
                placement: "ceiling_corner".into(),
                clock_domain: "local_ptp".into(),
            },
            sample_tensor(),
            Observation::occupancy(0.87, PrivacyClass::P2),
            ProvenanceRef {
                raw_hash: "sha256:abc".into(),
                firmware_hash: "sha256:def".into(),
                model_id: "ruvector_field_encoder_v1".into(),
                calibration_id: "room_cal_2026".into(),
                synthetic: true,
                signature_hex: None,
                signer_pubkey_hex: None,
            },
        );
        let j = serde_json::to_string(&ev).unwrap();
        let back: FieldEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn raw_mac_cannot_validate_as_pseudonym() {
        let id: PseudonymousId = serde_json::from_str("\"aa:bb:cc:dd:ee:ff\"").unwrap();
        assert!(id.validate().is_err());
        assert!(PseudonymousId::from_digest([7; 32]).validate().is_ok());
    }

    #[test]
    fn low_confidence_identity_evidence_fails_closed() {
        let evidence = IdentityEvidence {
            pseudonym: PseudonymousId::from_digest([7; 32]),
            track_id: "track_a".into(),
            confidence: 0.59,
            observed_ns: 100,
            expires_ns: 200,
            binding_receipt_id: "enrollment_1".into(),
            issuer: "gateway_1".into(),
            source_sequence: 1,
            token_epoch: 1,
            kind: IdentityEvidenceKind::BleAdvertisementRssi,
        };
        assert!(evidence.validate_at(100).is_err());
    }
}
