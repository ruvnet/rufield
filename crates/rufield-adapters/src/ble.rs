//! BLE adapters for coherent Channel Sounding measurements and short-lived
//! pseudonymous identity evidence.
//!
//! The two adapters are intentionally separate. [`BleChannelSoundingAdapter`]
//! accepts authenticated steps from an external companion and emits P4
//! respiration features only after a complete coherent procedure. ESP32
//! gateway metadata is retained as forwarding provenance, never sensor
//! identity.
//! [`BleIdentityEvidenceAdapter`] accepts RSSI advertisements that have already
//! crossed an enrollment boundary and emits P5 track-association evidence.
//! RSSI is never treated as coherent phase or as proof of physical distance.

use rufield_core::{
    channel_sounding_sensor_id, AdapterCapabilities, ChannelSoundingProcedureProvenance,
    ChannelSoundingStepProvenance, FieldAdapter, FieldAxis, FieldEvent, FieldTensor,
    GatewayEnvelopeProvenance, IdentityEvidence, IdentityEvidenceKind, Modality, Observation,
    PrivacyClass, ProvenanceRef, PseudonymousId, SensorDescriptor, MAX_CHANNEL_SOUNDING_CHANNELS,
    MAX_CHANNEL_SOUNDING_CHANNEL_INDEX, MAX_IDENTITY_EVIDENCE_TTL_NS,
    MIN_CHANNEL_SOUNDING_CHANNELS, MIN_IDENTITY_EVIDENCE_CONFIDENCE,
};
use rufield_provenance::{sha256_hex, Signer};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Identity evidence below this confidence is discarded.
pub const MIN_IDENTITY_CONFIDENCE: f32 = MIN_IDENTITY_EVIDENCE_CONFIDENCE;

/// Maximum lifetime accepted for BLE identity evidence: five seconds.
pub const MAX_IDENTITY_TTL_NS: u64 = MAX_IDENTITY_EVIDENCE_TTL_NS;

/// Minimum number of calibrated frequency steps required for a coherent
/// Channel Sounding event.
pub const MIN_CHANNEL_SOUNDING_STEPS: usize = MIN_CHANNEL_SOUNDING_CHANNELS;

/// Maximum number of authenticated frequency steps promoted as one coherent
/// Channel Sounding procedure.
pub const MAX_CHANNEL_SOUNDING_STEPS: usize = MAX_CHANNEL_SOUNDING_CHANNELS;

/// Maximum number of incomplete interleaved procedures retained at once.
pub const MAX_PENDING_CHANNEL_SOUNDING_PROCEDURES: usize = 128;

/// Domain separator for host-side BLE pseudonym derivation.
pub const BLE_PSEUDONYM_DOMAIN: &[u8] = b"rufield.ble.identity.v1\0";

/// Domain separator for the keyed digest retained as raw-record provenance.
const BLE_RAW_DIGEST_DOMAIN: &[u8] = b"rufield.ble.raw.v1\0";

const FIXTURE_SIGNER_SEED: [u8; 32] = [0x42; 32];
const FIXTURE_PSEUDONYM_KEY: [u8; 32] = [0x91; 32];
const FIXTURE_FIRMWARE_HASH: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const FIXTURE_IDENTITY_MODEL_ID: &str = "fixture.ble_identity_model.v1";
const FIXTURE_CHANNEL_MODEL_ID: &str = "fixture.ble_channel_model.v1";
const FIXTURE_IDENTITY_CALIBRATION_ID: &str = "fixture.ble_rssi_calibration.v1";

/// Maximum simultaneously live pseudonymous bindings retained by one adapter.
/// The cap bounds valid-token floods; expired bindings are removed first.
pub const MAX_ACTIVE_IDENTITY_BINDINGS: usize = 1024;

/// Common sensor and signing configuration for the BLE adapters.
#[derive(Clone, PartialEq, Eq)]
pub struct BleAdapterConfig {
    /// Stable gateway identifier used by BLE advertisement evidence. Channel
    /// Sounding events identify their external companion source instead.
    pub device_id: String,
    /// BLE advertisement gateway vendor and chipset description. Channel
    /// Sounding uses an explicit external-companion descriptor.
    pub vendor: String,
    /// Governed capture placement shared by the gateway and enrolled
    /// companion mapping.
    pub placement: String,
    /// Clock domain used by sample timestamps.
    pub clock_domain: String,
    /// Deterministic signing seed for provenance receipts.
    pub signer_seed: [u8; 32],
    /// Deployment-specific key used only at the host boundary to derive a
    /// pseudonym from the firmware's eight-byte ephemeral identifier.
    pub pseudonym_key: [u8; 32],
    /// Attested gateway firmware hash used by BLE advertisement telemetry.
    /// Channel Sounding samples carry their companion firmware hash.
    pub attested_firmware_hash: String,
    /// Identity evidence model identifier or immutable model digest.
    pub identity_model_id: String,
    /// Channel Sounding model identifier or immutable model digest.
    pub channel_sounding_model_id: String,
    /// RSSI calibration receipt, distinct from subject enrollment.
    pub identity_calibration_id: String,
    /// True only for simulation or generated fixtures.
    pub synthetic: bool,
}

impl BleAdapterConfig {
    /// Explicit deterministic configuration for simulation and tests only.
    #[must_use]
    pub fn synthetic_fixture() -> Self {
        Self {
            device_id: "ble_gateway_01".into(),
            vendor: "normalized_ble_source".into(),
            placement: "room_edge".into(),
            clock_domain: "local_ptp".into(),
            signer_seed: FIXTURE_SIGNER_SEED,
            pseudonym_key: FIXTURE_PSEUDONYM_KEY,
            attested_firmware_hash: FIXTURE_FIRMWARE_HASH.into(),
            identity_model_id: FIXTURE_IDENTITY_MODEL_ID.into(),
            channel_sounding_model_id: FIXTURE_CHANNEL_MODEL_ID.into(),
            identity_calibration_id: FIXTURE_IDENTITY_CALIBRATION_ID.into(),
            synthetic: true,
        }
    }

    /// Validate secrets and provenance metadata before constructing an adapter.
    pub fn validate(&self) -> Result<(), BleAdapterError> {
        for (name, value) in [
            ("device_id", self.device_id.as_str()),
            ("vendor", self.vendor.as_str()),
            ("placement", self.placement.as_str()),
            ("clock_domain", self.clock_domain.as_str()),
            ("identity_model_id", self.identity_model_id.as_str()),
            (
                "channel_sounding_model_id",
                self.channel_sounding_model_id.as_str(),
            ),
            (
                "identity_calibration_id",
                self.identity_calibration_id.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(BleAdapterError::UnsafeConfiguration(format!(
                    "{name} must not be empty"
                )));
            }
        }
        if !valid_sha256_ref(&self.attested_firmware_hash) {
            return Err(BleAdapterError::UnsafeConfiguration(
                "attested firmware hash must be sha256 followed by 64 lowercase hex digits".into(),
            ));
        }
        if self.signer_seed == [0; 32] || self.pseudonym_key == [0; 32] {
            return Err(BleAdapterError::UnsafeConfiguration(
                "zero signing or pseudonym keys are forbidden".into(),
            ));
        }
        if self.signer_seed == self.pseudonym_key {
            return Err(BleAdapterError::UnsafeConfiguration(
                "signing and pseudonym derivation require distinct keys".into(),
            ));
        }
        if !self.synthetic
            && (self.signer_seed == FIXTURE_SIGNER_SEED
                || self.pseudonym_key == FIXTURE_PSEUDONYM_KEY
                || self.attested_firmware_hash == FIXTURE_FIRMWARE_HASH
                || self.identity_model_id == FIXTURE_IDENTITY_MODEL_ID
                || self.channel_sounding_model_id == FIXTURE_CHANNEL_MODEL_ID
                || self.identity_calibration_id == FIXTURE_IDENTITY_CALIBRATION_ID)
        {
            return Err(BleAdapterError::UnsafeConfiguration(
                "production BLE configuration contains deterministic fixture material".into(),
            ));
        }
        Ok(())
    }
}

/// One authenticated frequency step from an external Bluetooth Channel
/// Sounding companion.
///
/// The adapter groups these records by typed source/session/procedure ids. A
/// single step is never promoted to a vital-sign feature.
#[derive(Debug, Clone, PartialEq)]
pub struct BleChannelSoundingSample {
    /// Host capture time assigned after companion and gateway authentication.
    pub timestamp_ns: u64,
    /// Enrolled nonzero external companion source identifier.
    pub source_id: u32,
    /// Nonzero companion boot/session identifier.
    pub source_session_id: u32,
    /// Nonzero Channel Sounding procedure identifier.
    pub procedure_id: u32,
    /// Step count declared by the authenticated companion frame.
    pub declared_step_count: u16,
    /// Step index declared by the authenticated companion frame.
    pub step_index: u16,
    /// Bluetooth frequency channel index.
    pub channel_index: u16,
    /// Companion HMAC key selector.
    pub companion_key_id: u8,
    /// Companion sequence within the source session.
    pub companion_sequence: u32,
    /// Companion-declared sample age when received by the gateway.
    pub sample_age_us: u32,
    /// Companion timing uncertainty in microseconds.
    pub companion_timing_uncertainty_us: u16,
    /// Authenticated ESP32 forwarding metadata. The gateway is transport, not
    /// the Channel Sounding sensor.
    pub gateway: GatewayEnvelopeProvenance,
    /// Logical zone.
    pub zone_id: String,
    /// Anonymous spatial track, if one was resolved upstream.
    pub track_id: Option<String>,
    /// Discrete spatial cell.
    pub space_cell: Option<[i32; 3]>,
    /// Calibrated phase primitive in milliradians.
    pub phase_millirad: i32,
    /// Calibrated round-trip timing primitive in picoseconds.
    pub rtt_picoseconds: i32,
    /// Calibrated frequency-offset primitive in hertz.
    pub frequency_offset_hz: i32,
    /// Companion quality score in per mille.
    pub quality_permille: u16,
    /// Host-extracted respiration-band strength in `0.0..=1.0`. The value is
    /// aggregated only after the complete procedure is admitted.
    pub breathing_band: f32,
    /// Attested firmware hash of the external companion, not the ESP32
    /// forwarding gateway.
    pub companion_firmware_hash: String,
    /// Calibration receipt identifier.
    pub calibration_id: String,
}

/// BLE adapter failures that indicate malformed source data or event signing
/// failure. Identity policy abstentions are recorded separately and skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BleAdapterError {
    /// Adapter configuration is unsafe or lacks distinct provenance metadata.
    UnsafeConfiguration(String),
    /// Input data violated a structural or semantic invariant.
    InvalidSample(String),
    /// The normalized event could not be signed.
    Signing(String),
}

impl std::fmt::Display for BleAdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsafeConfiguration(message) => {
                write!(f, "unsafe BLE adapter configuration: {message}")
            }
            Self::InvalidSample(message) => write!(f, "invalid BLE sample: {message}"),
            Self::Signing(message) => write!(f, "BLE event signing failed: {message}"),
        }
    }
}

impl std::error::Error for BleAdapterError {}

/// Normalizes coherent Channel Sounding samples into [`FieldEvent`]s.
pub struct BleChannelSoundingAdapter {
    config: BleAdapterConfig,
    samples: VecDeque<BleChannelSoundingSample>,
    pending: BTreeMap<ChannelSoundingProcedureKey, PendingChannelSoundingProcedure>,
    signer: Signer,
    ordinal: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ChannelSoundingProcedureKey {
    source_id: u32,
    source_session_id: u32,
    procedure_id: u32,
}

impl From<&BleChannelSoundingSample> for ChannelSoundingProcedureKey {
    fn from(sample: &BleChannelSoundingSample) -> Self {
        Self {
            source_id: sample.source_id,
            source_session_id: sample.source_session_id,
            procedure_id: sample.procedure_id,
        }
    }
}

#[derive(Debug, Clone)]
struct PendingChannelSoundingProcedure {
    declared_step_count: u16,
    zone_id: String,
    track_id: Option<String>,
    space_cell: Option<[i32; 3]>,
    companion_key_id: u8,
    gateway_node_id: u8,
    gateway_key_id: u8,
    gateway_boot_nonce: u64,
    companion_firmware_hash: String,
    calibration_id: String,
    steps: BTreeMap<u16, BleChannelSoundingSample>,
    channels: BTreeSet<u16>,
    companion_sequences: BTreeSet<u32>,
    gateway_sequences: BTreeSet<u32>,
}

impl PendingChannelSoundingProcedure {
    fn from_first(sample: &BleChannelSoundingSample) -> Self {
        Self {
            declared_step_count: sample.declared_step_count,
            zone_id: sample.zone_id.clone(),
            track_id: sample.track_id.clone(),
            space_cell: sample.space_cell,
            companion_key_id: sample.companion_key_id,
            gateway_node_id: sample.gateway.node_id,
            gateway_key_id: sample.gateway.key_id,
            gateway_boot_nonce: sample.gateway.boot_nonce,
            companion_firmware_hash: sample.companion_firmware_hash.clone(),
            calibration_id: sample.calibration_id.clone(),
            steps: BTreeMap::new(),
            channels: BTreeSet::new(),
            companion_sequences: BTreeSet::new(),
            gateway_sequences: BTreeSet::new(),
        }
    }

    fn insert(&mut self, sample: BleChannelSoundingSample) -> Result<bool, BleAdapterError> {
        if sample.declared_step_count != self.declared_step_count
            || sample.zone_id != self.zone_id
            || sample.track_id != self.track_id
            || sample.space_cell != self.space_cell
            || sample.companion_key_id != self.companion_key_id
            || sample.gateway.node_id != self.gateway_node_id
            || sample.gateway.key_id != self.gateway_key_id
            || sample.gateway.boot_nonce != self.gateway_boot_nonce
            || sample.companion_firmware_hash != self.companion_firmware_hash
            || sample.calibration_id != self.calibration_id
        {
            return Err(BleAdapterError::InvalidSample(
                "Channel Sounding procedure crossed a source, key, gateway boot, track, firmware, or calibration context"
                    .into(),
            ));
        }
        let step_entry = match self.steps.entry(sample.step_index) {
            std::collections::btree_map::Entry::Vacant(entry) => entry,
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err(BleAdapterError::InvalidSample(
                    "Channel Sounding procedure contains a duplicate step index".into(),
                ));
            }
        };
        if !self.channels.insert(sample.channel_index) {
            return Err(BleAdapterError::InvalidSample(
                "Channel Sounding procedure contains a duplicate frequency channel".into(),
            ));
        }
        if !self.companion_sequences.insert(sample.companion_sequence) {
            return Err(BleAdapterError::InvalidSample(
                "Channel Sounding procedure contains a duplicate companion sequence".into(),
            ));
        }
        if !self.gateway_sequences.insert(sample.gateway.sequence) {
            return Err(BleAdapterError::InvalidSample(
                "Channel Sounding procedure contains a duplicate gateway sequence".into(),
            ));
        }
        step_entry.insert(sample);
        Ok(self.steps.len() == usize::from(self.declared_step_count))
    }
}

impl BleChannelSoundingAdapter {
    /// Construct an adapter over a finite stream of normalized radio samples.
    pub fn new(
        config: BleAdapterConfig,
        samples: Vec<BleChannelSoundingSample>,
    ) -> Result<Self, BleAdapterError> {
        config.validate()?;
        let signer = Signer::from_seed(&config.signer_seed);
        Ok(Self {
            config,
            samples: samples.into(),
            pending: BTreeMap::new(),
            signer,
            ordinal: 0,
        })
    }

    fn ingest_step(
        &mut self,
        sample: BleChannelSoundingSample,
    ) -> Result<Option<FieldEvent>, BleAdapterError> {
        validate_channel_sounding_step(&sample)?;
        let key = ChannelSoundingProcedureKey::from(&sample);
        if self.pending.len() >= MAX_PENDING_CHANNEL_SOUNDING_PROCEDURES
            && !self.pending.contains_key(&key)
        {
            return Err(BleAdapterError::InvalidSample(format!(
                "more than {MAX_PENDING_CHANNEL_SOUNDING_PROCEDURES} incomplete Channel Sounding procedures"
            )));
        }
        self.pending
            .entry(key)
            .or_insert_with(|| PendingChannelSoundingProcedure::from_first(&sample));

        let insertion = self
            .pending
            .get_mut(&key)
            .expect("procedure was inserted above")
            .insert(sample);
        let complete = match insertion {
            Ok(complete) => complete,
            Err(error) => {
                self.pending.remove(&key);
                return Err(error);
            }
        };
        if !complete {
            return Ok(None);
        }
        let procedure = self
            .pending
            .remove(&key)
            .expect("completed procedure remains pending");
        self.build_event(key, procedure).map(Some)
    }

    fn build_event(
        &mut self,
        key: ChannelSoundingProcedureKey,
        procedure: PendingChannelSoundingProcedure,
    ) -> Result<FieldEvent, BleAdapterError> {
        let timestamp_ns = procedure
            .steps
            .values()
            .map(|sample| sample.timestamp_ns)
            .max()
            .ok_or_else(|| {
                BleAdapterError::InvalidSample("Channel Sounding procedure has no steps".into())
            })?;
        let step_count = procedure.steps.len();
        let phase_values: Vec<_> = procedure
            .steps
            .values()
            .map(|sample| sample.phase_millirad as f32 / 1_000.0)
            .collect();
        let phase_quality = procedure
            .steps
            .values()
            .map(|sample| f32::from(sample.quality_permille) / 1_000.0)
            .sum::<f32>()
            / step_count as f32;
        let breathing_band = procedure
            .steps
            .values()
            .map(|sample| sample.breathing_band)
            .sum::<f32>()
            / step_count as f32;
        let typed_provenance = ChannelSoundingProcedureProvenance {
            source_id: key.source_id,
            source_session_id: key.source_session_id,
            procedure_id: key.procedure_id,
            declared_step_count: procedure.declared_step_count,
            steps: procedure
                .steps
                .values()
                .map(|sample| ChannelSoundingStepProvenance {
                    observed_ns: sample.timestamp_ns,
                    step_index: sample.step_index,
                    channel_index: sample.channel_index,
                    companion_key_id: sample.companion_key_id,
                    companion_sequence: sample.companion_sequence,
                    sample_age_us: sample.sample_age_us,
                    companion_timing_uncertainty_us: sample.companion_timing_uncertainty_us,
                    quality_permille: sample.quality_permille,
                    rtt_picoseconds: sample.rtt_picoseconds,
                    frequency_offset_hz: sample.frequency_offset_hz,
                    gateway: sample.gateway.clone(),
                })
                .collect(),
        };
        typed_provenance
            .validate(timestamp_ns)
            .map_err(|error| BleAdapterError::InvalidSample(error.to_string()))?;

        let mut raw_bytes = serde_json::to_vec(&typed_provenance)
            .map_err(|error| BleAdapterError::InvalidSample(error.to_string()))?;
        for sample in procedure.steps.values() {
            raw_bytes.extend_from_slice(&sample.phase_millirad.to_le_bytes());
            raw_bytes.extend_from_slice(&sample.breathing_band.to_le_bytes());
        }
        let tensor = FieldTensor::new(
            timestamp_ns,
            Modality::BleChannelSounding,
            vec![FieldAxis::Frequency],
            vec![phase_values.len()],
            phase_values,
            phase_quality,
            1.0 - phase_quality,
            Some(procedure.calibration_id.clone()),
            PrivacyClass::P0,
        )
        .map_err(|error| BleAdapterError::InvalidSample(error.to_string()))?;

        let mut observation = Observation::occupancy(phase_quality, PrivacyClass::P4);
        observation.zone_id = Some(procedure.zone_id);
        observation.track_id = procedure.track_id;
        observation.space_cell = procedure.space_cell;
        observation
            .features
            .insert("breathing_band".into(), breathing_band);
        observation
            .features
            .insert("coherent_phase_quality".into(), phase_quality);
        observation.channel_sounding_provenance = Some(typed_provenance);

        let event_id = format!(
            "ble-cs-{:08x}-{}-{}-{:06}",
            key.source_id, key.source_session_id, key.procedure_id, self.ordinal
        );
        self.ordinal += 1;
        let mut event = FieldEvent::new(
            event_id,
            timestamp_ns,
            channel_sounding_descriptor(&self.config, key.source_id),
            tensor,
            observation,
            ProvenanceRef {
                raw_hash: sha256_hex(&raw_bytes),
                firmware_hash: procedure.companion_firmware_hash,
                model_id: self.config.channel_sounding_model_id.clone(),
                calibration_id: procedure.calibration_id,
                synthetic: self.config.synthetic,
                signature_hex: None,
                signer_pubkey_hex: None,
            },
        );
        self.signer
            .sign_event(&mut event)
            .map_err(|error| BleAdapterError::Signing(error.to_string()))?;
        event
            .validate_evidence_at(timestamp_ns)
            .map_err(|error| BleAdapterError::InvalidSample(error.to_string()))?;
        Ok(event)
    }
}

impl FieldAdapter for BleChannelSoundingAdapter {
    type Error = BleAdapterError;

    fn modality(&self) -> Modality {
        Modality::BleChannelSounding
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            modality: Modality::BleChannelSounding.as_str().into(),
            sample_rate_hz: approximate_sample_rate_hz(
                complete_channel_sounding_timestamps(self.samples.iter()).into_iter(),
            ),
            can_calibrate: false,
            max_privacy_class: PrivacyClass::P4,
        }
    }

    fn next_event(&mut self) -> Result<Option<FieldEvent>, Self::Error> {
        while let Some(sample) = self.samples.pop_front() {
            if let Some(event) = self.ingest_step(sample)? {
                return Ok(Some(event));
            }
        }
        if self.pending.is_empty() {
            Ok(None)
        } else {
            let incomplete = self.pending.len();
            self.pending.clear();
            Err(BleAdapterError::InvalidSample(format!(
                "input ended with {incomplete} incomplete Channel Sounding procedure(s)"
            )))
        }
    }
}

/// Enrollment state supplied by the governed identity boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BleAnchorTrust {
    /// The application token has a current enrollment receipt.
    Enrolled {
        /// Opaque binding receipt held by the governance plane.
        binding_receipt_id: String,
    },
    /// A normal background advertisement with no verifiable enrollment.
    Unverified,
    /// A formerly enrolled credential that has been revoked.
    Revoked,
}

/// One RSSI advertisement observation associated with a candidate CSI track.
///
/// The input accepts the authenticated eight-byte ephemeral firmware token.
/// The host derives a deployment-scoped pseudonym before building an event.
/// There is no raw Bluetooth device-address field by design.
#[derive(Clone, PartialEq)]
pub struct BleIdentitySample {
    /// Capture time in nanoseconds since Unix epoch.
    pub timestamp_ns: u64,
    /// Authenticated eight-byte ephemeral identifier from the firmware record.
    /// It is consumed in memory and never copied into a [`FieldEvent`].
    pub ephemeral_id: [u8; 8],
    /// Firmware token epoch used in pseudonym rotation.
    pub token_epoch: u64,
    /// Monotonic firmware record sequence within the token epoch.
    pub sequence: u32,
    /// Candidate spatial track from the anonymous tracker.
    pub track_id: String,
    /// Logical zone.
    pub zone_id: String,
    /// Discrete spatial cell.
    pub space_cell: Option<[i32; 3]>,
    /// Received signal strength in dBm.
    pub rssi_dbm: i16,
    /// Confidence in the RSSI-to-track association.
    pub confidence: f32,
    /// Requested evidence lifetime.
    pub ttl_ns: u64,
    /// Enrollment decision made by the governed boundary.
    pub trust: BleAnchorTrust,
}

/// Why an identity sample was not promoted to evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BleAbstentionReason {
    /// The advertisement had no governed enrollment binding.
    Unverified,
    /// The enrollment binding was revoked.
    Revoked,
    /// Confidence did not meet the minimum threshold.
    LowConfidence,
    /// Lifetime was zero, too long, or already expired at the stream watermark.
    Expired,
    /// The same pseudonym simultaneously claimed another live track.
    ConflictingTrack,
    /// A sequence was repeated or moved backwards within the token epoch.
    Replay,
    /// Another live pseudonym already occupied the candidate track.
    TrackOccupied,
    /// The bounded live-binding table was full.
    Capacity,
    /// Required identifiers were missing or malformed.
    Malformed,
}

/// Auditable record that a BLE identity sample was intentionally not emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BleAbstention {
    /// Capture time of the rejected sample.
    pub timestamp_ns: u64,
    /// Pseudonym involved in the decision.
    pub pseudonym: PseudonymousId,
    /// Candidate track involved in the decision.
    pub track_id: String,
    /// Fail-closed reason.
    pub reason: BleAbstentionReason,
}

#[derive(Debug, Clone)]
struct ActiveBinding {
    track_id: String,
    expires_ns: u64,
    binding_receipt_id: String,
}

/// Promotes only current, enrolled, unambiguous advertisement observations to
/// short-lived P5 identity evidence. Invalid inputs are skipped and recorded
/// as abstentions rather than becoming fusion events.
pub struct BleIdentityEvidenceAdapter {
    config: BleAdapterConfig,
    samples: VecDeque<BleIdentitySample>,
    signer: Signer,
    ordinal: u64,
    watermark_ns: u64,
    active: BTreeMap<PseudonymousId, ActiveBinding>,
    last_sequence: BTreeMap<PseudonymousId, u32>,
    abstentions: Vec<BleAbstention>,
}

impl BleIdentityEvidenceAdapter {
    /// Construct an adapter over a finite stream of advertisement samples.
    pub fn new(
        config: BleAdapterConfig,
        samples: Vec<BleIdentitySample>,
    ) -> Result<Self, BleAdapterError> {
        config.validate()?;
        let signer = Signer::from_seed(&config.signer_seed);
        Ok(Self {
            config,
            samples: samples.into(),
            signer,
            ordinal: 0,
            watermark_ns: 0,
            active: BTreeMap::new(),
            last_sequence: BTreeMap::new(),
            abstentions: Vec::new(),
        })
    }

    /// Policy abstentions accumulated while draining the adapter.
    #[must_use]
    pub fn abstentions(&self) -> &[BleAbstention] {
        &self.abstentions
    }

    fn abstain(
        &mut self,
        sample: BleIdentitySample,
        pseudonym: PseudonymousId,
        reason: BleAbstentionReason,
    ) {
        self.abstentions.push(BleAbstention {
            timestamp_ns: sample.timestamp_ns,
            pseudonym,
            track_id: sample.track_id,
            reason,
        });
    }

    fn promote(
        &mut self,
        sample: BleIdentitySample,
    ) -> Result<Option<FieldEvent>, BleAdapterError> {
        let pseudonym = derive_ble_pseudonym(
            &self.config.pseudonym_key,
            &sample.ephemeral_id,
            sample.token_epoch,
        );
        let enrolled_receipt = match &sample.trust {
            BleAnchorTrust::Enrolled { binding_receipt_id } => Some(binding_receipt_id.as_str()),
            BleAnchorTrust::Unverified | BleAnchorTrust::Revoked => None,
        };

        // Phase 1 -- everything decidable from the sample alone, evaluated
        // BEFORE the stream clock moves.
        //
        // The watermark used to advance unconditionally at the top of this
        // function, which meant an `Unverified` or `Revoked` advertisement
        // carrying a far-future `timestamp_ns` evicted every active binding and
        // pinned the clock before its own trust was ever examined. The packet
        // was refused, but every subsequent legitimate sample then abstained as
        // `Expired`. Untrusted input must not be able to move time, so trust and
        // shape are settled first and only a surviving sample advances the
        // watermark.
        let untrusted_reason = if sample.track_id.trim().is_empty()
            || sample.zone_id.trim().is_empty()
            || !sample.confidence.is_finite()
        {
            Some(BleAbstentionReason::Malformed)
        } else if matches!(&sample.trust, BleAnchorTrust::Unverified) {
            Some(BleAbstentionReason::Unverified)
        } else if matches!(&sample.trust, BleAnchorTrust::Revoked) {
            Some(BleAbstentionReason::Revoked)
        } else if sample.confidence < MIN_IDENTITY_CONFIDENCE || sample.confidence > 1.0 {
            Some(BleAbstentionReason::LowConfidence)
        } else if sample.ttl_ns == 0 || sample.ttl_ns > MAX_IDENTITY_TTL_NS {
            // The self-contained half of the expiry rule. The watermark
            // comparison stays in phase 2, keeping `Expired` at its original
            // position in the precedence order.
            Some(BleAbstentionReason::Expired)
        } else {
            None
        };

        if let Some(reason) = untrusted_reason {
            self.abstain(sample, pseudonym, reason);
            return Ok(None);
        }

        // Phase 2 -- the sample is well-formed and carries enrolled trust, so it
        // is now allowed to advance the stream clock and retire stale bindings.
        self.watermark_ns = self.watermark_ns.max(sample.timestamp_ns);
        self.active
            .retain(|_, binding| binding.expires_ns > self.watermark_ns);
        self.last_sequence
            .retain(|pseudonym, _| self.active.contains_key(pseudonym));

        let reason = if sample.timestamp_ns.saturating_add(sample.ttl_ns) <= self.watermark_ns {
            Some(BleAbstentionReason::Expired)
        } else if !self.active.contains_key(&pseudonym)
            && self.active.len() >= MAX_ACTIVE_IDENTITY_BINDINGS
        {
            Some(BleAbstentionReason::Capacity)
        } else if self
            .last_sequence
            .get(&pseudonym)
            .is_some_and(|last| sample.sequence <= *last)
        {
            Some(BleAbstentionReason::Replay)
        } else if self
            .active
            .get(&pseudonym)
            .is_some_and(|binding| binding.track_id != sample.track_id)
        {
            Some(BleAbstentionReason::ConflictingTrack)
        } else if self.active.iter().any(|(active_pseudonym, binding)| {
            active_pseudonym != &pseudonym
                && binding.track_id == sample.track_id
                && Some(binding.binding_receipt_id.as_str()) != enrolled_receipt
        }) {
            Some(BleAbstentionReason::TrackOccupied)
        } else {
            None
        };

        if let Some(reason) = reason {
            self.abstain(sample, pseudonym, reason);
            return Ok(None);
        }

        // Phase 1 abstains on every non-enrolled variant, so this is currently
        // total. It is written as a fallible match rather than `unreachable!`
        // because that totality is an invariant of the chain above, not
        // something the compiler checks: adding a `BleAnchorTrust` variant would
        // compile cleanly and turn a panic into the failure mode. Abstaining is
        // the fail-closed answer either way.
        let Some(binding_receipt_id) = (match &sample.trust {
            BleAnchorTrust::Enrolled { binding_receipt_id } => Some(binding_receipt_id.clone()),
            _ => None,
        }) else {
            self.abstain(sample, pseudonym, BleAbstentionReason::Unverified);
            return Ok(None);
        };
        if binding_receipt_id.trim().is_empty() {
            self.abstain(sample, pseudonym, BleAbstentionReason::Malformed);
            return Ok(None);
        }

        let expires_ns = sample.timestamp_ns.saturating_add(sample.ttl_ns);
        let normalized_rssi = ((f32::from(sample.rssi_dbm) + 100.0) / 70.0).clamp(0.0, 1.0);
        let tensor = FieldTensor::new(
            sample.timestamp_ns,
            Modality::BleAdvertisementRssi,
            vec![FieldAxis::Amplitude],
            vec![1],
            vec![f32::from(sample.rssi_dbm)],
            sample.confidence,
            1.0 - sample.confidence,
            Some(self.config.identity_calibration_id.clone()),
            PrivacyClass::P5,
        )
        .map_err(|error| BleAdapterError::InvalidSample(error.to_string()))?;

        let mut observation = Observation::occupancy(sample.confidence, PrivacyClass::P5);
        observation.zone_id = Some(sample.zone_id);
        observation.space_cell = sample.space_cell;
        observation.track_id = Some(sample.track_id.clone());
        observation
            .features
            .insert("identity_anchor_confidence".into(), sample.confidence);
        observation
            .features
            .insert("rssi_proximity".into(), normalized_rssi);
        observation.identity_evidence = Some(IdentityEvidence {
            pseudonym: pseudonym.clone(),
            track_id: sample.track_id.clone(),
            confidence: sample.confidence,
            observed_ns: sample.timestamp_ns,
            expires_ns,
            binding_receipt_id: binding_receipt_id.clone(),
            issuer: self.config.device_id.clone(),
            source_sequence: sample.sequence,
            token_epoch: sample.token_epoch,
            kind: IdentityEvidenceKind::BleAdvertisementRssi,
        });

        let mut raw_record = Vec::with_capacity(30);
        raw_record.extend_from_slice(&sample.ephemeral_id);
        raw_record.extend_from_slice(&sample.token_epoch.to_le_bytes());
        raw_record.extend_from_slice(&sample.sequence.to_le_bytes());
        raw_record.extend_from_slice(&sample.rssi_dbm.to_le_bytes());
        raw_record.extend_from_slice(&sample.ttl_ns.to_le_bytes());
        // A keyed digest prevents the 64-bit ephemeral token from becoming an
        // offline enumerable durable identifier through the provenance hash.
        let mut protected_record =
            Vec::with_capacity(BLE_RAW_DIGEST_DOMAIN.len() + raw_record.len());
        protected_record.extend_from_slice(BLE_RAW_DIGEST_DOMAIN);
        protected_record.extend_from_slice(&raw_record);
        let protected_raw_digest = hmac_sha256(&self.config.pseudonym_key, &protected_record);
        let event_id = format!(
            "ble-id-{}-{}-{:06}",
            self.config.device_id, sample.timestamp_ns, self.ordinal
        );
        self.ordinal += 1;
        let mut event = FieldEvent::new(
            event_id,
            sample.timestamp_ns,
            descriptor(&self.config, Modality::BleAdvertisementRssi),
            tensor,
            observation,
            ProvenanceRef {
                raw_hash: sha256_hex(&protected_raw_digest),
                firmware_hash: self.config.attested_firmware_hash.clone(),
                model_id: self.config.identity_model_id.clone(),
                calibration_id: self.config.identity_calibration_id.clone(),
                synthetic: self.config.synthetic,
                signature_hex: None,
                signer_pubkey_hex: None,
            },
        );
        self.signer
            .sign_event(&mut event)
            .map_err(|error| BleAdapterError::Signing(error.to_string()))?;
        event
            .validate_evidence_at(self.watermark_ns)
            .map_err(|error| BleAdapterError::InvalidSample(error.to_string()))?;

        // A legitimate token-epoch rotation retains the governed enrollment
        // receipt and track but changes the wire pseudonym. Retire the previous
        // epoch binding atomically so it cannot look like a second subject.
        self.active.retain(|active_pseudonym, binding| {
            active_pseudonym == &pseudonym
                || binding.track_id != sample.track_id
                || binding.binding_receipt_id != binding_receipt_id
        });
        self.active.insert(
            pseudonym.clone(),
            ActiveBinding {
                track_id: sample.track_id,
                expires_ns,
                binding_receipt_id,
            },
        );
        self.last_sequence.insert(pseudonym, sample.sequence);
        Ok(Some(event))
    }
}

impl FieldAdapter for BleIdentityEvidenceAdapter {
    type Error = BleAdapterError;

    fn modality(&self) -> Modality {
        Modality::BleAdvertisementRssi
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            modality: Modality::BleAdvertisementRssi.as_str().into(),
            sample_rate_hz: approximate_sample_rate_hz(
                self.samples.iter().map(|sample| sample.timestamp_ns),
            ),
            can_calibrate: false,
            max_privacy_class: PrivacyClass::P5,
        }
    }

    fn next_event(&mut self) -> Result<Option<FieldEvent>, Self::Error> {
        while let Some(sample) = self.samples.pop_front() {
            if let Some(event) = self.promote(sample)? {
                return Ok(Some(event));
            }
        }
        Ok(None)
    }
}

fn validate_channel_sounding_step(
    sample: &BleChannelSoundingSample,
) -> Result<(), BleAdapterError> {
    if sample.source_id == 0 || sample.source_session_id == 0 || sample.procedure_id == 0 {
        return Err(BleAdapterError::InvalidSample(
            "Channel Sounding source, session, and procedure ids must be nonzero".into(),
        ));
    }
    let declared = usize::from(sample.declared_step_count);
    if !(MIN_CHANNEL_SOUNDING_STEPS..=MAX_CHANNEL_SOUNDING_STEPS).contains(&declared) {
        return Err(BleAdapterError::InvalidSample(format!(
            "Channel Sounding declared step count must be within {MIN_CHANNEL_SOUNDING_STEPS}..={MAX_CHANNEL_SOUNDING_STEPS}"
        )));
    }
    if usize::from(sample.step_index) >= declared {
        return Err(BleAdapterError::InvalidSample(
            "Channel Sounding step index exceeds the declared procedure size".into(),
        ));
    }
    if sample.channel_index > MAX_CHANNEL_SOUNDING_CHANNEL_INDEX {
        return Err(BleAdapterError::InvalidSample(
            "Channel Sounding frequency channel must be within 0..=78".into(),
        ));
    }
    if sample.companion_sequence == 0
        || sample.gateway.boot_nonce == 0
        || sample.gateway.sequence == 0
    {
        return Err(BleAdapterError::InvalidSample(
            "Channel Sounding companion sequence, gateway boot nonce, and gateway sequence must be nonzero"
                .into(),
        ));
    }
    if !(-3_142..=3_142).contains(&sample.phase_millirad) {
        return Err(BleAdapterError::InvalidSample(
            "Channel Sounding phase primitive is outside -3142..=3142 milliradians".into(),
        ));
    }
    if !(0..=250_000).contains(&sample.rtt_picoseconds) {
        return Err(BleAdapterError::InvalidSample(
            "Channel Sounding RTT primitive is outside 0..=250000 picoseconds".into(),
        ));
    }
    if !(-500_000..=500_000).contains(&sample.frequency_offset_hz) {
        return Err(BleAdapterError::InvalidSample(
            "Channel Sounding frequency offset is outside -500000..=500000 hertz".into(),
        ));
    }
    if sample.quality_permille > 1_000 || sample.companion_timing_uncertainty_us > 10_000 {
        return Err(BleAdapterError::InvalidSample(
            "Channel Sounding quality or companion timing uncertainty is out of range".into(),
        ));
    }
    if !sample.breathing_band.is_finite() || !(0.0..=1.0).contains(&sample.breathing_band) {
        return Err(BleAdapterError::InvalidSample(
            "Channel Sounding breathing feature must be finite and within 0..=1".into(),
        ));
    }
    if sample.zone_id.trim().is_empty()
        || sample
            .track_id
            .as_ref()
            .is_some_and(|track_id| track_id.trim().is_empty())
        || sample.calibration_id.trim().is_empty()
    {
        return Err(BleAdapterError::InvalidSample(
            "Channel Sounding requires a zone, nonempty optional track, and calibration receipt"
                .into(),
        ));
    }
    if !valid_sha256_ref(&sample.companion_firmware_hash) {
        return Err(BleAdapterError::InvalidSample(
            "Channel Sounding companion firmware must be an attested SHA-256 reference".into(),
        ));
    }
    Ok(())
}

fn complete_channel_sounding_timestamps<'a>(
    samples: impl Iterator<Item = &'a BleChannelSoundingSample>,
) -> Vec<u64> {
    let mut procedures = BTreeMap::new();
    let mut invalid = BTreeSet::new();
    for sample in samples {
        let key = ChannelSoundingProcedureKey::from(sample);
        if invalid.contains(&key) {
            continue;
        }
        if validate_channel_sounding_step(sample).is_err() {
            procedures.remove(&key);
            invalid.insert(key);
            continue;
        }
        let insertion = procedures
            .entry(key)
            .or_insert_with(|| PendingChannelSoundingProcedure::from_first(sample))
            .insert(sample.clone());
        if insertion.is_err() {
            procedures.remove(&key);
            invalid.insert(key);
        }
    }
    procedures
        .into_values()
        .filter(|procedure| procedure.steps.len() == usize::from(procedure.declared_step_count))
        .filter_map(|procedure| {
            procedure
                .steps
                .into_values()
                .map(|sample| sample.timestamp_ns)
                .max()
        })
        .collect()
}

fn descriptor(config: &BleAdapterConfig, modality: Modality) -> SensorDescriptor {
    SensorDescriptor {
        modality: modality.as_str().into(),
        vendor: config.vendor.clone(),
        device_id: config.device_id.clone(),
        placement: config.placement.clone(),
        coordinate_frame: None,
        position_m: None,
        orientation_xyzw: None,
        clock_domain: config.clock_domain.clone(),
    }
}

fn channel_sounding_descriptor(config: &BleAdapterConfig, source_id: u32) -> SensorDescriptor {
    SensorDescriptor {
        modality: Modality::BleChannelSounding.as_str().into(),
        vendor: "external_ble_channel_sounding_companion".into(),
        device_id: channel_sounding_sensor_id(source_id),
        placement: config.placement.clone(),
        coordinate_frame: None,
        position_m: None,
        orientation_xyzw: None,
        clock_domain: config.clock_domain.clone(),
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

fn approximate_sample_rate_hz(timestamps: impl Iterator<Item = u64>) -> u32 {
    let mut timestamps: Vec<_> = timestamps.collect();
    timestamps.sort_unstable();
    timestamps.dedup();
    let mut deltas: Vec<_> = timestamps
        .windows(2)
        .filter_map(|pair| pair[1].checked_sub(pair[0]).filter(|delta| *delta > 0))
        .collect();
    if deltas.is_empty() {
        return 0;
    }
    deltas.sort_unstable();
    let median_ns = deltas[deltas.len() / 2];
    u32::try_from(1_000_000_000u64.saturating_add(median_ns / 2) / median_ns).unwrap_or(u32::MAX)
}

/// Derive the only identifier permitted on the RuField wire from the
/// firmware's authenticated ephemeral identifier. HMAC-SHA-256 is used as a
/// keyed, domain-separated one-way derivation at this trust boundary. The
/// ephemeral identifier is not retained in the returned value.
#[must_use]
pub fn derive_ble_pseudonym(
    deployment_key: &[u8; 32],
    ephemeral_id: &[u8; 8],
    token_epoch: u64,
) -> PseudonymousId {
    let mut message = Vec::with_capacity(BLE_PSEUDONYM_DOMAIN.len() + 16);
    message.extend_from_slice(BLE_PSEUDONYM_DOMAIN);
    message.extend_from_slice(ephemeral_id);
    message.extend_from_slice(&token_epoch.to_le_bytes());
    PseudonymousId::from_digest(hmac_sha256(deployment_key, &message))
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_BYTES: usize = 64;
    let mut normalized_key = [0u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        let digest = Sha256::digest(key);
        normalized_key[..32].copy_from_slice(&digest);
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK_BYTES];
    let mut outer_pad = [0x5cu8; BLOCK_BYTES];
    for index in 0..BLOCK_BYTES {
        inner_pad[index] ^= normalized_key[index];
        outer_pad[index] ^= normalized_key[index];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rufield_provenance::verify_event;

    fn config() -> BleAdapterConfig {
        BleAdapterConfig::synthetic_fixture()
    }

    fn coherent_samples(timestamp_ns: u64, procedure_id: u32) -> Vec<BleChannelSoundingSample> {
        (0..4u16)
            .map(|step_index| {
                let sequence = procedure_id
                    .saturating_mul(4)
                    .saturating_add(u32::from(step_index))
                    .saturating_add(1);
                BleChannelSoundingSample {
                    timestamp_ns,
                    source_id: 0x0102_0304,
                    source_session_id: 17,
                    procedure_id,
                    declared_step_count: 4,
                    step_index,
                    channel_index: 5 + step_index * 2,
                    companion_key_id: 3,
                    companion_sequence: sequence,
                    sample_age_us: 120 + u32::from(step_index),
                    companion_timing_uncertainty_us: 14,
                    gateway: GatewayEnvelopeProvenance {
                        node_id: 9,
                        key_id: 4,
                        boot_nonce: 0x0102_0304_0506_0708,
                        sequence: 1_000u32.saturating_add(sequence),
                        received_at_boot_us: 1_000 + u64::from(step_index) * 20,
                        timing_uncertainty_us: 27,
                    },
                    zone_id: "room".into(),
                    track_id: Some("track_a".into()),
                    space_cell: Some([0, 0, 1]),
                    phase_millirad: 100 + i32::from(step_index) * 100,
                    rtt_picoseconds: 80_000 + i32::from(step_index) * 100,
                    frequency_offset_hz: -30 + i32::from(step_index) * 20,
                    quality_permille: 900,
                    breathing_band: 0.7,
                    companion_firmware_hash: sha256_hex(b"companion_firmware_test_v1"),
                    calibration_id: "ble_cs_cal_1".into(),
                }
            })
            .collect()
    }

    #[test]
    fn channel_sounding_is_coherent_and_p4() {
        let expected_firmware_hash = sha256_hex(b"companion_firmware_test_v1");
        let mut adapter =
            BleChannelSoundingAdapter::new(config(), coherent_samples(100, 23)).unwrap();
        let event = adapter.next_event().unwrap().unwrap();
        assert_eq!(event.tensor.modality, Modality::BleChannelSounding);
        assert_eq!(event.tensor.privacy_class, PrivacyClass::P0);
        assert_eq!(event.observation.privacy_class, PrivacyClass::P4);
        assert!(event.observation.identity_evidence.is_none());
        assert_eq!(
            event.sensor.device_id,
            channel_sounding_sensor_id(0x0102_0304)
        );
        assert_ne!(event.sensor.device_id, config().device_id);
        assert_eq!(
            event.sensor.vendor,
            "external_ble_channel_sounding_companion"
        );
        assert_eq!(event.provenance.firmware_hash, expected_firmware_hash);
        assert_eq!(event.provenance.model_id, FIXTURE_CHANNEL_MODEL_ID);
        assert_eq!(event.provenance.calibration_id, "ble_cs_cal_1");
        assert!(!event.observation.features.contains_key("range_m"));
        assert!(event.observation.range_m.is_none());
        let procedure = event
            .observation
            .channel_sounding_provenance
            .as_ref()
            .unwrap();
        assert_eq!(procedure.source_id, 0x0102_0304);
        assert_eq!(procedure.source_session_id, 17);
        assert_eq!(procedure.procedure_id, 23);
        assert_eq!(procedure.declared_step_count, 4);
        assert_eq!(procedure.steps.len(), 4);
        assert_eq!(procedure.steps[2].observed_ns, 100);
        assert_eq!(procedure.steps[2].step_index, 2);
        assert_eq!(procedure.steps[2].channel_index, 9);
        assert_eq!(procedure.steps[2].companion_key_id, 3);
        assert_eq!(procedure.steps[2].companion_sequence, 95);
        assert_eq!(procedure.steps[2].sample_age_us, 122);
        assert_ne!(
            procedure.steps[2].companion_sequence,
            procedure.steps[2].gateway.sequence
        );
        assert_eq!(procedure.steps[2].companion_timing_uncertainty_us, 14);
        assert_eq!(procedure.steps[2].quality_permille, 900);
        assert_eq!(procedure.steps[2].rtt_picoseconds, 80_200);
        assert_eq!(procedure.steps[2].frequency_offset_hz, 10);
        assert_eq!(procedure.steps[2].gateway.node_id, 9);
        assert_eq!(procedure.steps[2].gateway.key_id, 4);
        assert_eq!(procedure.steps[2].gateway.boot_nonce, 0x0102_0304_0506_0708);
        assert_eq!(procedure.steps[2].gateway.sequence, 1_095);
        assert_eq!(procedure.steps[2].gateway.received_at_boot_us, 1_040);
        assert_eq!(procedure.steps[2].gateway.timing_uncertainty_us, 27);
        assert!((event.tensor.values[2] - 0.3).abs() < f32::EPSILON);
        assert!(verify_event(&event).is_ok());
        assert!(adapter.next_event().unwrap().is_none());
    }

    #[test]
    fn incomplete_channel_sounding_procedure_never_promotes() {
        let mut samples = coherent_samples(100, 23);
        samples.pop();
        let mut adapter = BleChannelSoundingAdapter::new(config(), samples).unwrap();
        assert!(matches!(
            adapter.next_event(),
            Err(BleAdapterError::InvalidSample(message)) if message.contains("incomplete")
        ));
    }

    #[test]
    fn duplicate_step_or_channel_never_promotes() {
        let mut duplicate_step = coherent_samples(100, 23);
        duplicate_step[3].step_index = 2;
        let mut step_adapter = BleChannelSoundingAdapter::new(config(), duplicate_step).unwrap();
        assert!(matches!(
            step_adapter.next_event(),
            Err(BleAdapterError::InvalidSample(message)) if message.contains("duplicate step")
        ));

        let mut duplicate_channel = coherent_samples(100, 23);
        let repeated_channel = duplicate_channel[2].channel_index;
        duplicate_channel[3].channel_index = repeated_channel;
        let mut channel_adapter =
            BleChannelSoundingAdapter::new(config(), duplicate_channel).unwrap();
        assert!(matches!(
            channel_adapter.next_event(),
            Err(BleAdapterError::InvalidSample(message)) if message.contains("duplicate frequency")
        ));
    }

    #[test]
    fn channel_sounding_step_count_is_bounded() {
        let mut too_many = coherent_samples(100, 23);
        too_many[0].declared_step_count = 80;
        let mut adapter = BleChannelSoundingAdapter::new(config(), too_many).unwrap();
        assert!(matches!(
            adapter.next_event(),
            Err(BleAdapterError::InvalidSample(message)) if message.contains("4..=79")
        ));

        let mut invalid_channel = coherent_samples(100, 23);
        invalid_channel[0].channel_index = 79;
        let mut adapter = BleChannelSoundingAdapter::new(config(), invalid_channel).unwrap();
        assert!(matches!(
            adapter.next_event(),
            Err(BleAdapterError::InvalidSample(message)) if message.contains("0..=78")
        ));
    }

    #[test]
    fn mixed_gateway_boot_context_never_promotes() {
        let mut mixed = coherent_samples(100, 23);
        mixed[3].gateway.boot_nonce = 99;
        let mut adapter = BleChannelSoundingAdapter::new(config(), mixed).unwrap();
        assert!(matches!(
            adapter.next_event(),
            Err(BleAdapterError::InvalidSample(message)) if message.contains("gateway boot")
        ));
    }

    #[test]
    fn raw_rssi_never_becomes_phase() {
        let sample = BleIdentitySample {
            timestamp_ns: 100,
            ephemeral_id: [1; 8],
            token_epoch: 7,
            sequence: 1,
            track_id: "track_a".into(),
            zone_id: "room".into(),
            space_cell: Some([0, 0, 1]),
            rssi_dbm: -55,
            confidence: 0.8,
            ttl_ns: 1_000,
            trust: BleAnchorTrust::Enrolled {
                binding_receipt_id: "enrollment_1".into(),
            },
        };
        let mut adapter = BleIdentityEvidenceAdapter::new(config(), vec![sample]).unwrap();
        let event = adapter.next_event().unwrap().unwrap();
        assert_eq!(event.tensor.modality, Modality::BleAdvertisementRssi);
        assert!(event.observation.features.contains_key("rssi_proximity"));
        assert!(!event.observation.features.contains_key("breathing_band"));
        assert_eq!(event.observation.privacy_class, PrivacyClass::P5);
        let evidence = event.observation.identity_evidence.as_ref().unwrap();
        assert_eq!(event.provenance.firmware_hash, FIXTURE_FIRMWARE_HASH);
        assert_eq!(event.provenance.model_id, FIXTURE_IDENTITY_MODEL_ID);
        assert_eq!(
            event.provenance.calibration_id,
            FIXTURE_IDENTITY_CALIBRATION_ID
        );
        assert_ne!(event.provenance.calibration_id, evidence.binding_receipt_id);
    }

    #[test]
    fn unverified_advertisement_abstains() {
        let sample = BleIdentitySample {
            timestamp_ns: 100,
            ephemeral_id: [2; 8],
            token_epoch: 7,
            sequence: 1,
            track_id: "track_a".into(),
            zone_id: "room".into(),
            space_cell: None,
            rssi_dbm: -60,
            confidence: 0.9,
            ttl_ns: 1_000,
            trust: BleAnchorTrust::Unverified,
        };
        let mut adapter = BleIdentityEvidenceAdapter::new(config(), vec![sample]).unwrap();
        assert!(adapter.next_event().unwrap().is_none());
        assert_eq!(
            adapter.abstentions()[0].reason,
            BleAbstentionReason::Unverified
        );
    }

    #[test]
    fn ephemeral_identifier_is_not_serialized() {
        let sample = BleIdentitySample {
            timestamp_ns: 100,
            ephemeral_id: [0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xca, 0xfe],
            token_epoch: 8,
            sequence: 1,
            track_id: "track_a".into(),
            zone_id: "room".into(),
            space_cell: None,
            rssi_dbm: -50,
            confidence: 0.9,
            ttl_ns: 1_000,
            trust: BleAnchorTrust::Enrolled {
                binding_receipt_id: "enrollment_1".into(),
            },
        };
        let mut adapter = BleIdentityEvidenceAdapter::new(config(), vec![sample]).unwrap();
        let event = adapter.next_event().unwrap().unwrap();
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("deadbeeffacecafe"));
        assert!(!json.contains("[222,173,190,239,250,206,202,254]"));
        assert!(json.contains("blep:"));
    }

    #[test]
    fn pseudonym_derivation_is_keyed_and_epoch_scoped() {
        let ephemeral = [9; 8];
        let first = derive_ble_pseudonym(&[1; 32], &ephemeral, 4);
        assert_eq!(first, derive_ble_pseudonym(&[1; 32], &ephemeral, 4));
        assert_ne!(first, derive_ble_pseudonym(&[2; 32], &ephemeral, 4));
        assert_ne!(first, derive_ble_pseudonym(&[1; 32], &ephemeral, 5));
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_one() {
        assert_eq!(
            hmac_sha256(&[0x0b; 20], b"Hi There"),
            [
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7,
            ]
        );
    }

    #[test]
    fn production_rejects_fixture_credentials_and_metadata() {
        let mut production = BleAdapterConfig::synthetic_fixture();
        production.synthetic = false;
        production.signer_seed = [0x21; 32];
        production.pseudonym_key = [0x22; 32];
        production.attested_firmware_hash = format!("sha256:{}", "2".repeat(64));
        production.identity_model_id = "model.ble_identity.production.v1".into();
        production.channel_sounding_model_id = "model.ble_cs.production.v1".into();
        production.identity_calibration_id = "cal.ble_rssi.production.v1".into();

        let assert_rejected = |candidate: BleAdapterConfig| {
            assert!(matches!(
                candidate.validate(),
                Err(BleAdapterError::UnsafeConfiguration(_))
            ));
        };

        let mut fixture_signer = production.clone();
        fixture_signer.signer_seed = FIXTURE_SIGNER_SEED;
        assert_rejected(fixture_signer);

        let mut fixture_pseudonym = production.clone();
        fixture_pseudonym.pseudonym_key = FIXTURE_PSEUDONYM_KEY;
        assert_rejected(fixture_pseudonym);

        let mut fixture_firmware = production.clone();
        fixture_firmware.attested_firmware_hash = FIXTURE_FIRMWARE_HASH.into();
        assert_rejected(fixture_firmware);

        let mut fixture_identity_model = production.clone();
        fixture_identity_model.identity_model_id = FIXTURE_IDENTITY_MODEL_ID.into();
        assert_rejected(fixture_identity_model);

        let mut fixture_channel_model = production.clone();
        fixture_channel_model.channel_sounding_model_id = FIXTURE_CHANNEL_MODEL_ID.into();
        assert_rejected(fixture_channel_model);

        let mut fixture_calibration = production;
        fixture_calibration.identity_calibration_id = FIXTURE_IDENTITY_CALIBRATION_ID.into();
        assert_rejected(fixture_calibration);
    }

    #[test]
    fn production_accepts_distinct_non_fixture_provenance() {
        let mut production = BleAdapterConfig::synthetic_fixture();
        production.synthetic = false;
        production.signer_seed = [0x21; 32];
        production.pseudonym_key = [0x22; 32];
        production.attested_firmware_hash = format!("sha256:{}", "2".repeat(64));
        production.identity_model_id = "model.ble_identity.production.v1".into();
        production.channel_sounding_model_id = "model.ble_cs.production.v1".into();
        production.identity_calibration_id = "cal.ble_rssi.production.v1".into();
        assert!(production.validate().is_ok());
    }

    #[test]
    fn capability_rate_is_measured_not_assumed() {
        assert_eq!(
            approximate_sample_rate_hz([0, 100_000_000, 200_000_000].into_iter()),
            10
        );
        assert_eq!(approximate_sample_rate_hz([42].into_iter()), 0);

        let mut complete = coherent_samples(100_000_000, 1);
        complete.extend(coherent_samples(200_000_000, 2));
        complete.extend(coherent_samples(300_000_000, 3));
        let adapter = BleChannelSoundingAdapter::new(config(), complete).unwrap();
        assert_eq!(adapter.capabilities().sample_rate_hz, 10);

        let incomplete = coherent_samples(100_000_000, 1)
            .into_iter()
            .take(3)
            .collect();
        let adapter = BleChannelSoundingAdapter::new(config(), incomplete).unwrap();
        assert_eq!(adapter.capabilities().sample_rate_hz, 0);
    }

    #[test]
    fn live_binding_capacity_fails_closed() {
        let mut adapter = BleIdentityEvidenceAdapter::new(config(), Vec::new()).unwrap();
        for index in 0..MAX_ACTIVE_IDENTITY_BINDINGS {
            let mut digest = [0u8; 32];
            digest[..8].copy_from_slice(&(index as u64).to_le_bytes());
            adapter.active.insert(
                PseudonymousId::from_digest(digest),
                ActiveBinding {
                    track_id: format!("track_{index}"),
                    expires_ns: 10_000,
                    binding_receipt_id: format!("enrollment_{index}"),
                },
            );
        }

        let sample = BleIdentitySample {
            timestamp_ns: 100,
            ephemeral_id: [0xfe; 8],
            token_epoch: 7,
            sequence: 1,
            track_id: "new_track".into(),
            zone_id: "room".into(),
            space_cell: None,
            rssi_dbm: -55,
            confidence: 0.9,
            ttl_ns: 1_000,
            trust: BleAnchorTrust::Enrolled {
                binding_receipt_id: "new_enrollment".into(),
            },
        };
        assert!(adapter.promote(sample).unwrap().is_none());
        assert_eq!(
            adapter.abstentions().last().unwrap().reason,
            BleAbstentionReason::Capacity
        );
    }
    fn identity_sample(timestamp_ns: u64, sequence: u32) -> BleIdentitySample {
        BleIdentitySample {
            timestamp_ns,
            ephemeral_id: [1; 8],
            token_epoch: 7,
            sequence,
            track_id: "track_a".into(),
            zone_id: "room".into(),
            space_cell: Some([0, 0, 1]),
            rssi_dbm: -55,
            confidence: 0.8,
            ttl_ns: 1_000,
            trust: BleAnchorTrust::Enrolled {
                binding_receipt_id: "enrollment_1".into(),
            },
        }
    }

    /// An advertisement is attacker-supplied: anyone can broadcast one with any
    /// `timestamp_ns`, with no key, enrollment, or signature. If an untrusted
    /// sample can advance the stream watermark before its trust is examined, one
    /// frame evicts every active binding and pins the clock, and every later
    /// legitimate sample abstains as `Expired` -- the packet is refused and the
    /// honest traffic dies with it. Trust is therefore settled before time moves.
    #[test]
    fn an_untrusted_far_future_sample_cannot_expire_legitimate_bindings() {
        let mut hostile = identity_sample(u64::MAX / 2, 1);
        hostile.ephemeral_id = [9; 8];
        hostile.track_id = "track_z".into();
        hostile.trust = BleAnchorTrust::Unverified;

        let mut adapter = BleIdentityEvidenceAdapter::new(
            config(),
            vec![identity_sample(100, 1), hostile, identity_sample(200, 2)],
        )
        .unwrap();

        assert!(
            adapter.next_event().unwrap().is_some(),
            "the first enrolled sample must promote"
        );
        assert!(
            adapter.next_event().unwrap().is_some(),
            "an unverified far-future advertisement must not expire later honest \
             samples; abstentions={:?}",
            adapter
                .abstentions()
                .iter()
                .map(|a| a.reason.clone())
                .collect::<Vec<_>>()
        );

        // The hostile frame is still refused, and refused for the right reason.
        let reasons: Vec<_> = adapter
            .abstentions()
            .iter()
            .map(|a| a.reason.clone())
            .collect();
        assert_eq!(reasons, vec![BleAbstentionReason::Unverified]);
    }

    /// A `Revoked` anchor is equally untrusted and must not move the clock either.
    #[test]
    fn a_revoked_far_future_sample_cannot_expire_legitimate_bindings() {
        let mut hostile = identity_sample(u64::MAX / 2, 1);
        hostile.ephemeral_id = [8; 8];
        hostile.trust = BleAnchorTrust::Revoked;

        let mut adapter = BleIdentityEvidenceAdapter::new(
            config(),
            vec![identity_sample(100, 1), hostile, identity_sample(200, 2)],
        )
        .unwrap();

        assert!(adapter.next_event().unwrap().is_some());
        assert!(
            adapter.next_event().unwrap().is_some(),
            "a revoked far-future advertisement must not expire later honest samples"
        );
    }
}
