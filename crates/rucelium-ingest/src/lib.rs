//! # rucelium-ingest
//!
//! The rhizome-gateway ingest pipeline (ADR-264 §5, responsibilities 1–3):
//! **decode** the signed wire envelope, **verify** signatures and sequence
//! numbers against the device registry and a per-device anti-replay window,
//! and **normalize** the payload into a [`rucelium_core::EnvSample`].
//!
//! Trust posture (ADR-264 §12): every failure is a *rejection* — the gateway
//! never repairs, guesses, or forwards unverified data. Samples that reach
//! the domain model always carry `provenance.verified = true`; anything else
//! never leaves the gateway. Revocation is biome-local first: revoking a
//! device in the [`DeviceRegistry`] invalidates its key at this gateway
//! immediately while the audit record is kept.
//!
//! Everything here is deterministic — no RNG, no clocks. Callers pass the
//! reception timestamp (`received_ns`) explicitly, so the same envelope bytes
//! plus the same timestamp always produce the same result.

#![doc(html_root_url = "https://docs.rs/rucelium-ingest/0.1.0")]

use rucelium_abi::{verify_record, RvEnvSampleV1, SignedEnvRecordV1};
use rucelium_core::EnvSample;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Device registry
// ---------------------------------------------------------------------------

/// A registered spore-node device: its provisioned ed25519 verifying key,
/// the firmware measurement implementation it attested at provisioning time,
/// and its revocation state (ADR-264 §12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    /// The device's ed25519 verifying key, as handed out at provisioning.
    pub pubkey: [u8; 32],
    /// `sha256:` hash of the firmware measurement implementation
    /// (requirement 10 of ADR-264 §7.1); stamped into every accepted
    /// sample's provenance.
    pub firmware_hash: String,
    /// Whether the device has been revoked. Revoked devices keep their
    /// record for audit, but ingest rejects everything they send.
    pub revoked: bool,
}

/// The gateway's registry of provisioned spore-node devices, keyed by
/// `node_id`. Backed by a `BTreeMap` so iteration and behavior are fully
/// deterministic (no hasher randomness anywhere in the pipeline).
///
/// Revocation follows ADR-264 §12: "revoking a device invalidates its key at
/// the biome's gateways immediately" — the record is retained for audit, but
/// [`IngestPipeline::ingest`] rejects revoked devices.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceRegistry {
    devices: BTreeMap<u64, DeviceRecord>,
}

impl DeviceRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or re-provision) a device. Re-registering an existing
    /// `node_id` replaces its record entirely — including clearing any
    /// revocation — modelling a fresh provisioning ceremony.
    pub fn register(&mut self, node_id: u64, pubkey: [u8; 32], firmware_hash: String) {
        self.devices.insert(
            node_id,
            DeviceRecord {
                pubkey,
                firmware_hash,
                revoked: false,
            },
        );
    }

    /// Revoke a device's key. Returns `true` if the device was registered
    /// and not already revoked. The record is kept for audit; ingest rejects
    /// the device from this call onward.
    pub fn revoke(&mut self, node_id: u64) -> bool {
        match self.devices.get_mut(&node_id) {
            Some(d) if !d.revoked => {
                d.revoked = true;
                true
            }
            _ => false,
        }
    }

    /// Whether the device is registered *and* revoked.
    #[must_use]
    pub fn is_revoked(&self, node_id: u64) -> bool {
        self.devices.get(&node_id).is_some_and(|d| d.revoked)
    }

    /// The device's record, if registered (revoked records are retained).
    #[must_use]
    pub fn get(&self, node_id: u64) -> Option<&DeviceRecord> {
        self.devices.get(&node_id)
    }
}

// ---------------------------------------------------------------------------
// Anti-replay window
// ---------------------------------------------------------------------------

/// Outcome of a failed [`ReplayWindow`] check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayCheck {
    /// The sequence number was already accepted (exact duplicate).
    Replay,
    /// The sequence number fell below the sliding window
    /// (`sequence < highest - 63`) and can no longer be deduplicated.
    TooOld,
}

impl fmt::Display for ReplayCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplayCheck::Replay => write!(f, "duplicate sequence (replay)"),
            ReplayCheck::TooOld => write!(f, "sequence below replay window"),
        }
    }
}

impl std::error::Error for ReplayCheck {}

/// Per-device anti-replay window in the DTLS/IPsec style (ADR-264 §5
/// responsibility 2): the highest sequence number accepted so far plus a
/// 64-bit bitmap of the 64 sequence numbers below it. Accepts each sequence
/// exactly once, tolerates out-of-order delivery within the window, and
/// rejects anything below it as [`ReplayCheck::TooOld`].
///
/// The `RV_ENV_FLAG_RETRANSMIT` flag marks store-and-forward ring-buffer
/// replay after an outage — it distinguishes honest retransmission from a
/// replay *attack*, but it **never** bypasses deduplication: a retransmit of
/// an already-accepted sequence is still dropped as [`ReplayCheck::Replay`]
/// (ADR-264 §11.2: "the sequence window still deduplicates").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplayWindow {
    /// Highest sequence number accepted so far; `None` until the first
    /// sequence from the device arrives (which is always accepted).
    highest: Option<u32>,
    /// Bit `i` set means sequence `highest - 1 - i` was accepted.
    bitmap: u64,
}

impl ReplayWindow {
    /// A fresh window that will accept whatever sequence arrives first.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The highest sequence accepted so far, if any.
    #[must_use]
    pub fn highest(&self) -> Option<u32> {
        self.highest
    }

    /// Check `sequence` against the window and, if acceptable, record it.
    ///
    /// - First sequence from the device: always accepted.
    /// - `sequence` already seen (highest or a set bitmap bit):
    ///   [`ReplayCheck::Replay`].
    /// - `sequence < highest - 63`: [`ReplayCheck::TooOld`].
    /// - Otherwise: accepted and recorded (advancing the window if
    ///   `sequence > highest`).
    ///
    /// Callers must only invoke this **after** all cryptographic checks pass
    /// — otherwise an attacker could burn sequence numbers with forged
    /// packets ([`IngestPipeline::ingest`] enforces this ordering).
    pub fn check_and_update(&mut self, sequence: u32) -> Result<(), ReplayCheck> {
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            self.bitmap = 0;
            return Ok(());
        };
        if sequence > highest {
            // Advance: previous `highest` moves to bit `shift - 1`, old
            // bitmap entries shift with it (falling off past 64).
            let shift = sequence - highest;
            self.bitmap = match shift {
                1..=63 => (self.bitmap << shift) | (1u64 << (shift - 1)),
                64 => 1u64 << 63,
                _ => 0,
            };
            self.highest = Some(sequence);
            return Ok(());
        }
        if sequence == highest {
            return Err(ReplayCheck::Replay);
        }
        let diff = highest - sequence; // >= 1
        if diff > 63 {
            return Err(ReplayCheck::TooOld);
        }
        let bit = 1u64 << (diff - 1);
        if self.bitmap & bit != 0 {
            return Err(ReplayCheck::Replay);
        }
        self.bitmap |= bit;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Reject reasons
// ---------------------------------------------------------------------------

/// Why an envelope was rejected at ingest. Every variant is a hard rejection
/// — the boundary never repairs or forwards unverified data (ADR-264 §12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// The CBOR envelope failed to decode (truncated, non-canonical, wrong
    /// field lengths, trailing bytes).
    BadEnvelope(String),
    /// The 48-byte packed payload failed ABI parse or field validation
    /// (ADR-264 §11.1).
    BadPayload(String),
    /// The payload's `node_id` is not in the [`DeviceRegistry`].
    UnknownDevice(u64),
    /// The device is registered but revoked (ADR-264 §12).
    RevokedDevice(u64),
    /// The envelope's embedded public key differs from the key registered
    /// for this `node_id`.
    KeyMismatch(u64),
    /// The ed25519 signature did not verify over the payload bytes.
    BadSignature(u64),
    /// The `(node_id, sequence)` pair was already accepted — an exact
    /// duplicate, whether a replay attack or a store-and-forward retransmit.
    Replay {
        /// Producing device identity.
        node_id: u64,
        /// The duplicated sequence number.
        sequence: u32,
    },
    /// The sequence number fell below the device's replay window and can no
    /// longer be deduplicated.
    TooOld {
        /// Producing device identity.
        node_id: u64,
        /// The stale sequence number.
        sequence: u32,
    },
    /// Domain conversion or `EnvSample` validation failed after all
    /// cryptographic checks passed (ADR-264 §7.1: invalid samples are
    /// rejected, never repaired).
    Domain(String),
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RejectReason::BadEnvelope(m) => write!(f, "envelope decode failed: {m}"),
            RejectReason::BadPayload(m) => write!(f, "payload parse/validate failed: {m}"),
            RejectReason::UnknownDevice(id) => write!(f, "unknown device {id}"),
            RejectReason::RevokedDevice(id) => write!(f, "revoked device {id}"),
            RejectReason::KeyMismatch(id) => {
                write!(
                    f,
                    "envelope key does not match registered key for device {id}"
                )
            }
            RejectReason::BadSignature(id) => {
                write!(f, "signature verification failed for device {id}")
            }
            RejectReason::Replay { node_id, sequence } => {
                write!(f, "replayed sequence {sequence} from device {node_id}")
            }
            RejectReason::TooOld { node_id, sequence } => {
                write!(
                    f,
                    "sequence {sequence} from device {node_id} below replay window"
                )
            }
            RejectReason::Domain(m) => write!(f, "domain conversion failed: {m}"),
        }
    }
}

impl std::error::Error for RejectReason {}

// ---------------------------------------------------------------------------
// Ingest statistics
// ---------------------------------------------------------------------------

/// Monotonic ingest counters: one for acceptance, one per reject category.
/// Serializable so gateways can publish them alongside signed regional
/// summaries (ADR-264 §5 responsibility 8, §12 public quality scores).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct IngestStats {
    /// Envelopes fully accepted into the domain model.
    pub accepted: u64,
    /// Rejections: CBOR envelope decode failed.
    pub bad_envelope: u64,
    /// Rejections: ABI payload parse/validation failed.
    pub bad_payload: u64,
    /// Rejections: device not registered.
    pub unknown_device: u64,
    /// Rejections: device revoked.
    pub revoked_device: u64,
    /// Rejections: envelope key differed from the registered key.
    pub key_mismatch: u64,
    /// Rejections: signature verification failed.
    pub bad_signature: u64,
    /// Rejections: duplicate sequence number.
    pub replay: u64,
    /// Rejections: sequence below the replay window.
    pub too_old: u64,
    /// Rejections: domain conversion/validation failed.
    pub domain: u64,
    /// Stored envelopes successfully re-verified after restart/outage
    /// restore ([`IngestPipeline::reverify_stored`]); counted separately
    /// from `accepted` because they bypass the replay window by design.
    pub restored: u64,
}

impl IngestStats {
    /// Bump the counter matching a reject reason.
    fn note_reject(&mut self, reason: &RejectReason) {
        match reason {
            RejectReason::BadEnvelope(_) => self.bad_envelope += 1,
            RejectReason::BadPayload(_) => self.bad_payload += 1,
            RejectReason::UnknownDevice(_) => self.unknown_device += 1,
            RejectReason::RevokedDevice(_) => self.revoked_device += 1,
            RejectReason::KeyMismatch(_) => self.key_mismatch += 1,
            RejectReason::BadSignature(_) => self.bad_signature += 1,
            RejectReason::Replay { .. } => self.replay += 1,
            RejectReason::TooOld { .. } => self.too_old += 1,
            RejectReason::Domain(_) => self.domain += 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Ingest pipeline
// ---------------------------------------------------------------------------

/// Hex-encode bytes (lowercase), the form `SampleProvenance` carries.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A cryptographically verified environmental sample — the ONLY type the
/// biome layer accepts (`rucelium_federation::Biome::accept`).
///
/// This wrapper is the type-level fix for the "forgeable `verified` boolean"
/// problem: it is deliberately **not** `Serialize`/`Deserialize` and has no
/// public constructor, so it can only come out of [`IngestPipeline::ingest`]
/// or [`IngestPipeline::reverify_stored`] — both of which perform the full
/// registry + signature checks. A deserialized `EnvSample` with
/// `provenance.verified = true` cannot impersonate one.
///
/// Serializing (storage, network) goes through [`Self::into_inner`] /
/// [`Self::sample`] and **loses** the seal; restoring verification requires
/// the original signed envelope bytes (`reverify_stored`).
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedEnvSample(EnvSample);

impl VerifiedEnvSample {
    /// Read access to the verified sample.
    #[must_use]
    pub fn sample(&self) -> &EnvSample {
        &self.0
    }

    /// Unwrap for storage/serialization. The seal is lost — a round-trip
    /// through disk or the network must re-verify via
    /// [`IngestPipeline::reverify_stored`].
    #[must_use]
    pub fn into_inner(self) -> EnvSample {
        self.0
    }

    /// Apply a legitimate transformation (e.g. calibration) while keeping
    /// the seal. The closure runs on a copy; the change is committed only if
    /// the transformed sample still validates — so a buggy transformation
    /// cannot corrupt a sealed sample.
    pub fn modify<T>(
        &mut self,
        f: impl FnOnce(&mut EnvSample) -> T,
    ) -> Result<T, rucelium_core::EnvError> {
        let mut candidate = self.0.clone();
        let out = f(&mut candidate);
        candidate.validate()?;
        self.0 = candidate;
        Ok(out)
    }
}

/// The rhizome-gateway ingest pipeline: parse → verify → replay-window →
/// normalize (ADR-264 §5.1). Owns the [`DeviceRegistry`], one
/// [`ReplayWindow`] per device, and running [`IngestStats`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngestPipeline {
    registry: DeviceRegistry,
    windows: BTreeMap<u64, ReplayWindow>,
    stats: IngestStats,
}

impl IngestPipeline {
    /// Build a pipeline over an already-provisioned registry.
    #[must_use]
    pub fn new(registry: DeviceRegistry) -> Self {
        IngestPipeline {
            registry,
            windows: BTreeMap::new(),
            stats: IngestStats::default(),
        }
    }

    /// The device registry (read-only).
    #[must_use]
    pub fn registry(&self) -> &DeviceRegistry {
        &self.registry
    }

    /// Mutable registry access — e.g. to revoke a device mid-run. Revocation
    /// takes effect on the very next [`Self::ingest`] call (ADR-264 §12).
    pub fn registry_mut(&mut self) -> &mut DeviceRegistry {
        &mut self.registry
    }

    /// Running acceptance/rejection counters.
    #[must_use]
    pub fn stats(&self) -> &IngestStats {
        &self.stats
    }

    /// Record a rejection in the stats and hand the reason back.
    fn reject(&mut self, reason: RejectReason) -> RejectReason {
        self.stats.note_reject(&reason);
        reason
    }

    /// Ingest one signed wire envelope received at `received_ns`
    /// (nanoseconds since Unix epoch, supplied by the caller — the pipeline
    /// holds no clock).
    ///
    /// Checks run strictly in this order:
    ///
    /// 1. CBOR envelope decode → [`RejectReason::BadEnvelope`]
    /// 2. ABI payload parse + validation → [`RejectReason::BadPayload`]
    /// 3. Registry lookup by payload `node_id` →
    ///    [`RejectReason::UnknownDevice`]
    /// 4. Revocation check → [`RejectReason::RevokedDevice`]
    /// 5. Envelope key vs registered key → [`RejectReason::KeyMismatch`]
    /// 6. ed25519 signature verification → [`RejectReason::BadSignature`]
    /// 7. Replay-window check → [`RejectReason::Replay`] /
    ///    [`RejectReason::TooOld`]
    /// 8. Domain conversion + validation → [`RejectReason::Domain`]
    ///
    /// The replay window is only consulted (and updated) **after** all
    /// cryptographic checks pass, so forged packets cannot burn sequence
    /// numbers for a genuine device. Accepted samples carry
    /// `provenance.verified = true` and the *registry's* firmware hash —
    /// never anything self-reported over the wire.
    pub fn ingest(
        &mut self,
        envelope_bytes: &[u8],
        received_ns: u64,
    ) -> Result<VerifiedEnvSample, RejectReason> {
        // (1)–(6): decode + full cryptographic verification.
        let (record, wire, firmware_hash) = match self.verify_envelope(envelope_bytes) {
            Ok(v) => v,
            Err(e) => return Err(self.reject(e)),
        };
        let node_id = wire.node_id;

        // (7) Anti-replay — only now, after every cryptographic check, may
        // the window advance. RV_ENV_FLAG_RETRANSMIT never bypasses dedup.
        if let Err(check) = self
            .windows
            .entry(node_id)
            .or_default()
            .check_and_update(wire.sequence)
        {
            let reason = match check {
                ReplayCheck::Replay => RejectReason::Replay {
                    node_id,
                    sequence: wire.sequence,
                },
                ReplayCheck::TooOld => RejectReason::TooOld {
                    node_id,
                    sequence: wire.sequence,
                },
            };
            return Err(self.reject(reason));
        }

        // (8) Normalize into the domain model. Identity comes from the
        // verified envelope + registry, never from unverified wire fields.
        match wire.to_env_sample(
            received_ns,
            &firmware_hash,
            &hex_encode(&record.pubkey),
            true,
        ) {
            Ok(sample) => {
                self.stats.accepted += 1;
                Ok(VerifiedEnvSample(sample))
            }
            Err(e) => Err(self.reject(RejectReason::Domain(e.to_string()))),
        }
    }

    /// Re-verify a **stored** signed envelope (e.g. drained from an outage
    /// buffer or restored after a crash) without touching the anti-replay
    /// window: its sequence was already consumed when it was first accepted,
    /// so a second window check would wrongly report `Replay`. All
    /// cryptographic checks — registry, revocation, key match, signature,
    /// payload validation — run in full; duplicate suppression is the biome
    /// dedup index's job on this path.
    pub fn reverify_stored(
        &mut self,
        envelope_bytes: &[u8],
        received_ns: u64,
    ) -> Result<VerifiedEnvSample, RejectReason> {
        let (record, wire, firmware_hash) = match self.verify_envelope(envelope_bytes) {
            Ok(v) => v,
            Err(e) => return Err(self.reject(e)),
        };
        match wire.to_env_sample(
            received_ns,
            &firmware_hash,
            &hex_encode(&record.pubkey),
            true,
        ) {
            Ok(sample) => {
                self.stats.restored += 1;
                Ok(VerifiedEnvSample(sample))
            }
            Err(e) => Err(self.reject(RejectReason::Domain(e.to_string()))),
        }
    }

    /// Rebuild the anti-replay windows from a durable dedup index after a
    /// process restart (ADR-265: the store's persistent `(node_id, sequence)`
    /// index is the replay memory — without this call, a restarted gateway
    /// would re-accept previously ingested signed packets).
    ///
    /// `keys` may arrive in any order; for each device the window is set to
    /// the highest sequence seen with the in-window history bits populated.
    pub fn prime_from_dedup(&mut self, keys: impl IntoIterator<Item = (u64, u32)>) {
        let mut per_node: BTreeMap<u64, Vec<u32>> = BTreeMap::new();
        for (node, seq) in keys {
            per_node.entry(node).or_default().push(seq);
        }
        for (node, mut seqs) in per_node {
            seqs.sort_unstable();
            let window = self.windows.entry(node).or_default();
            for seq in seqs {
                // Errors here mean "already recorded" — harmless during
                // priming.
                let _ = window.check_and_update(seq);
            }
        }
    }

    /// Steps (1)–(6) of the ingest contract, shared by [`Self::ingest`] and
    /// [`Self::reverify_stored`]: envelope decode, payload validation,
    /// registry + revocation lookup, key match, and signature verification.
    fn verify_envelope(
        &self,
        envelope_bytes: &[u8],
    ) -> Result<(SignedEnvRecordV1, RvEnvSampleV1, String), RejectReason> {
        let record = SignedEnvRecordV1::decode(envelope_bytes)
            .map_err(|e| RejectReason::BadEnvelope(e.to_string()))?;
        let wire = RvEnvSampleV1::parse_validated(&record.payload)
            .map_err(|e| RejectReason::BadPayload(e.to_string()))?;
        let node_id = wire.node_id;
        let (registered_pubkey, firmware_hash) = match self.registry.get(node_id) {
            None => return Err(RejectReason::UnknownDevice(node_id)),
            Some(d) if d.revoked => return Err(RejectReason::RevokedDevice(node_id)),
            Some(d) => (d.pubkey, d.firmware_hash.clone()),
        };
        if record.pubkey != registered_pubkey {
            return Err(RejectReason::KeyMismatch(node_id));
        }
        if verify_record(&record).is_err() {
            return Err(RejectReason::BadSignature(node_id));
        }
        Ok((record, wire, firmware_hash))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rucelium_abi::{NodeSigner, RV_ENV_FLAG_RETRANSMIT, RV_ENV_SCHEMA_V1};
    use rucelium_core::SensorModality;

    const SEED: &[u8; 32] = b"rucelium-provision-seed-32-byte!";
    const NODE_A: u64 = 0xDEAD_BEEF_0000_0007;
    const NODE_B: u64 = 0xDEAD_BEEF_0000_0008;
    const TS: u64 = 1_754_000_000_000_000_000;
    const RECV: u64 = TS + 1_000_000;
    const FW_A: &str = "sha256:firmware-a";
    const FW_B: &str = "sha256:firmware-b";

    fn wire(node_id: u64, sequence: u32, flags: u16) -> RvEnvSampleV1 {
        RvEnvSampleV1 {
            schema_version: RV_ENV_SCHEMA_V1,
            sensor_type: SensorModality::SoilMoisture.code(),
            flags,
            node_id,
            timestamp_ns: TS,
            sequence,
            latitude_e7: 514_778_216,
            longitude_e7: -14_767,
            altitude_mm: 46_000,
            value_q16: 27 * 65_536 + 32_768,
            quality_q15: 0x7000,
            battery_mv: 3_612,
            calibration_id: 3,
        }
    }

    /// Envelope bytes for `node_id` signed by that node's provisioned key.
    fn signed_envelope(node_id: u64, sequence: u32, flags: u16) -> Vec<u8> {
        NodeSigner::for_node(SEED, node_id)
            .sign_sample(&wire(node_id, sequence, flags))
            .encode()
    }

    /// A pipeline with NODE_A and NODE_B registered under their real keys.
    fn pipeline() -> IngestPipeline {
        let mut reg = DeviceRegistry::new();
        reg.register(
            NODE_A,
            NodeSigner::for_node(SEED, NODE_A).public_key(),
            FW_A.to_string(),
        );
        reg.register(
            NODE_B,
            NodeSigner::for_node(SEED, NODE_B).public_key(),
            FW_B.to_string(),
        );
        IngestPipeline::new(reg)
    }

    #[test]
    fn happy_path_ingests_verified_sample_with_registry_firmware() {
        let mut p = pipeline();
        let sealed = p.ingest(&signed_envelope(NODE_A, 1, 0), RECV).unwrap();
        let sample = sealed.sample();
        sample.validate().unwrap();
        assert_eq!(sample.node_id, NODE_A);
        assert_eq!(sample.sequence, 1);
        assert_eq!(sample.received_ns, RECV);
        assert!(sample.provenance.verified);
        assert_eq!(sample.provenance.firmware_hash, FW_A);
        assert_eq!(
            sample.provenance.signer_pubkey_hex,
            NodeSigner::for_node(SEED, NODE_A).public_key_hex()
        );
        assert_eq!(p.stats().accepted, 1);
    }

    #[test]
    fn any_tampered_envelope_byte_is_rejected() {
        let env = signed_envelope(NODE_A, 1, 0);
        for i in 0..env.len() {
            let mut p = pipeline();
            let mut tampered = env.clone();
            tampered[i] ^= 0x01;
            assert!(
                p.ingest(&tampered, RECV).is_err(),
                "tampered byte {i} must be rejected"
            );
            assert_eq!(p.stats().accepted, 0, "tampered byte {i} was accepted");
        }
        // The pristine envelope still ingests fine.
        assert!(pipeline().ingest(&env, RECV).is_ok());
    }

    #[test]
    fn exact_replay_rejected_and_counted() {
        let mut p = pipeline();
        let env = signed_envelope(NODE_A, 7, 0);
        p.ingest(&env, RECV).unwrap();
        assert_eq!(
            p.ingest(&env, RECV),
            Err(RejectReason::Replay {
                node_id: NODE_A,
                sequence: 7
            })
        );
        assert_eq!(p.stats().accepted, 1);
        assert_eq!(p.stats().replay, 1);
    }

    #[test]
    fn retransmit_flag_never_bypasses_dedup() {
        let mut p = pipeline();
        let env = signed_envelope(NODE_A, 9, RV_ENV_FLAG_RETRANSMIT);
        p.ingest(&env, RECV).unwrap();
        // Store-and-forward retransmit of an already-accepted sequence is
        // still dropped as a replay.
        assert!(matches!(
            p.ingest(&env, RECV),
            Err(RejectReason::Replay { sequence: 9, .. })
        ));
        assert_eq!(p.stats().replay, 1);
    }

    #[test]
    fn out_of_order_within_window_accepted_exactly_once_each() {
        let mut p = pipeline();
        p.ingest(&signed_envelope(NODE_A, 5, 0), RECV).unwrap();
        p.ingest(&signed_envelope(NODE_A, 3, 0), RECV).unwrap();
        p.ingest(&signed_envelope(NODE_A, 4, 0), RECV).unwrap();
        assert_eq!(
            p.ingest(&signed_envelope(NODE_A, 3, 0), RECV),
            Err(RejectReason::Replay {
                node_id: NODE_A,
                sequence: 3
            })
        );
        assert_eq!(p.stats().accepted, 3);
        assert_eq!(p.stats().replay, 1);
    }

    #[test]
    fn very_old_sequence_below_window_is_too_old() {
        let mut p = pipeline();
        p.ingest(&signed_envelope(NODE_A, 100, 0), RECV).unwrap();
        assert_eq!(
            p.ingest(&signed_envelope(NODE_A, 10, 0), RECV),
            Err(RejectReason::TooOld {
                node_id: NODE_A,
                sequence: 10
            })
        );
        assert_eq!(p.stats().too_old, 1);
    }

    #[test]
    fn unknown_device_rejected() {
        let mut p = pipeline();
        let unknown: u64 = 0x9999;
        assert_eq!(
            p.ingest(&signed_envelope(unknown, 1, 0), RECV),
            Err(RejectReason::UnknownDevice(unknown))
        );
        assert_eq!(p.stats().unknown_device, 1);
    }

    #[test]
    fn revoked_device_rejected_while_others_continue() {
        let mut p = pipeline();
        p.ingest(&signed_envelope(NODE_A, 1, 0), RECV).unwrap();
        assert!(p.registry_mut().revoke(NODE_A));
        assert!(p.registry().is_revoked(NODE_A));
        // Audit record is kept.
        assert!(p.registry().get(NODE_A).is_some());
        assert_eq!(
            p.ingest(&signed_envelope(NODE_A, 2, 0), RECV),
            Err(RejectReason::RevokedDevice(NODE_A))
        );
        // The second registered device is unaffected.
        let s = p.ingest(&signed_envelope(NODE_B, 1, 0), RECV).unwrap();
        assert_eq!(s.sample().provenance.firmware_hash, FW_B);
        assert_eq!(p.stats().accepted, 2);
        assert_eq!(p.stats().revoked_device, 1);
    }

    #[test]
    fn revoke_is_true_once_then_false() {
        let mut reg = DeviceRegistry::new();
        assert!(!reg.revoke(NODE_A), "unregistered device cannot be revoked");
        reg.register(NODE_A, [0xAA; 32], FW_A.to_string());
        assert!(!reg.is_revoked(NODE_A));
        assert!(reg.revoke(NODE_A));
        assert!(!reg.revoke(NODE_A), "second revoke must report false");
        assert!(reg.is_revoked(NODE_A));
        assert_eq!(reg.get(NODE_A).unwrap().firmware_hash, FW_A);
    }

    #[test]
    fn wrong_signer_claiming_node_a_is_rejected() {
        let mut p = pipeline();
        // Node B's key signs a payload that claims to be from node A: the
        // envelope carries B's pubkey, which differs from A's registration.
        let env = NodeSigner::for_node(SEED, NODE_B)
            .sign_sample(&wire(NODE_A, 1, 0))
            .encode();
        assert_eq!(p.ingest(&env, RECV), Err(RejectReason::KeyMismatch(NODE_A)));
        assert_eq!(p.stats().key_mismatch, 1);
    }

    #[test]
    fn forged_packets_do_not_advance_the_replay_window() {
        let mut p = pipeline();
        p.ingest(&signed_envelope(NODE_A, 1, 0), RECV).unwrap();
        // Forgery: node A's real registered pubkey, garbage signature,
        // sequence 50. Passes the key-match check, fails verification.
        let forged = SignedEnvRecordV1 {
            payload: wire(NODE_A, 50, 0).encode(),
            pubkey: NodeSigner::for_node(SEED, NODE_A).public_key(),
            signature: [0u8; 64],
        }
        .encode();
        assert_eq!(
            p.ingest(&forged, RECV),
            Err(RejectReason::BadSignature(NODE_A))
        );
        // The genuine sequence 50 must still be accepted: the forgery did
        // not burn the sequence number.
        p.ingest(&signed_envelope(NODE_A, 50, 0), RECV).unwrap();
        assert_eq!(p.stats().accepted, 2);
        assert_eq!(p.stats().bad_signature, 1);
        assert_eq!(p.stats().replay, 0);
    }

    #[test]
    fn garbage_and_bad_payload_counted_in_stats() {
        let mut p = pipeline();
        assert!(matches!(
            p.ingest(b"not cbor at all", RECV),
            Err(RejectReason::BadEnvelope(_))
        ));
        // Structurally valid envelope, invalid payload (bad schema version),
        // correctly signed — rejected at step 2 before any registry work.
        let mut bad = wire(NODE_A, 1, 0);
        bad.schema_version = 9;
        let env = NodeSigner::for_node(SEED, NODE_A)
            .sign_sample(&bad)
            .encode();
        assert!(matches!(
            p.ingest(&env, RECV),
            Err(RejectReason::BadPayload(_))
        ));
        assert_eq!(p.stats().bad_envelope, 1);
        assert_eq!(p.stats().bad_payload, 1);
        assert_eq!(p.stats().accepted, 0);
    }

    #[test]
    fn domain_failure_after_crypto_is_rejected_as_domain() {
        let mut p = pipeline();
        // received_ns before measured_ns: passes every wire check, fails
        // EnvSample::validate (TimeInverted) during conversion.
        assert!(matches!(
            p.ingest(&signed_envelope(NODE_A, 1, 0), TS - 1),
            Err(RejectReason::Domain(_))
        ));
        assert_eq!(p.stats().domain, 1);
        assert_eq!(p.stats().accepted, 0);
    }

    #[test]
    fn replay_window_first_sequence_always_accepted() {
        let mut w = ReplayWindow::new();
        w.check_and_update(0).unwrap();
        assert_eq!(w.highest(), Some(0));
        assert_eq!(w.check_and_update(0), Err(ReplayCheck::Replay));

        let mut w = ReplayWindow::new();
        w.check_and_update(u32::MAX).unwrap();
        assert_eq!(w.check_and_update(u32::MAX), Err(ReplayCheck::Replay));
    }

    #[test]
    fn replay_window_edges() {
        let mut w = ReplayWindow::new();
        w.check_and_update(100).unwrap();
        // Exactly highest - 63 is still inside the window.
        w.check_and_update(37).unwrap();
        assert_eq!(w.check_and_update(37), Err(ReplayCheck::Replay));
        // highest - 64 is below it.
        assert_eq!(w.check_and_update(36), Err(ReplayCheck::TooOld));
    }

    #[test]
    fn replay_window_large_jumps_shift_out_old_state() {
        let mut w = ReplayWindow::new();
        w.check_and_update(1).unwrap();
        // Jump far ahead: 1 falls out of the window entirely.
        w.check_and_update(1_000).unwrap();
        assert_eq!(w.check_and_update(1), Err(ReplayCheck::TooOld));
        assert_eq!(w.check_and_update(1_000), Err(ReplayCheck::Replay));
        // Advance by exactly 64: old highest lands on the last bitmap bit
        // but is out of the acceptance window (diff 64 > 63).
        let mut w = ReplayWindow::new();
        w.check_and_update(10).unwrap();
        w.check_and_update(74).unwrap();
        assert_eq!(w.check_and_update(10), Err(ReplayCheck::TooOld));
    }

    #[test]
    fn windows_are_per_device() {
        let mut p = pipeline();
        p.ingest(&signed_envelope(NODE_A, 5, 0), RECV).unwrap();
        // Node B reusing the same sequence number is not a replay.
        p.ingest(&signed_envelope(NODE_B, 5, 0), RECV).unwrap();
        assert_eq!(p.stats().accepted, 2);
    }

    #[test]
    fn stats_serialize_to_json() {
        let mut p = pipeline();
        p.ingest(&signed_envelope(NODE_A, 1, 0), RECV).unwrap();
        let env = signed_envelope(NODE_A, 1, 0);
        let _ = p.ingest(&env, RECV);
        let json = serde_json::to_value(p.stats()).unwrap();
        assert_eq!(json["accepted"], 1);
        assert_eq!(json["replay"], 1);
        assert_eq!(json["bad_signature"], 0);
    }

    #[test]
    fn reject_reasons_display() {
        assert_eq!(
            RejectReason::UnknownDevice(7).to_string(),
            "unknown device 7"
        );
        assert!(RejectReason::Replay {
            node_id: 7,
            sequence: 42
        }
        .to_string()
        .contains("42"));
        // Error trait is implemented.
        let e: Box<dyn std::error::Error> = Box::new(RejectReason::BadSignature(7));
        assert!(e.to_string().contains("7"));
    }
}
