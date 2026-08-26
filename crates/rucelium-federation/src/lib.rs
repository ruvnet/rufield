//! # rucelium-federation
//!
//! Biome sovereignty for the RuCelium fabric (ADR-264 §6, §7, §10, §12):
//!
//! - [`OutageBuffer`] — gateway store-and-forward log of **original signed
//!   envelopes** with duplicate-free replay across restarts (§14 criteria
//!   2–3); drained envelopes must pass
//!   `rucelium_ingest::IngestPipeline::reverify_stored` (full cryptographic
//!   re-verification) before they can enter a biome,
//! - [`Biome`] — the sovereign regional aggregate: admission requires a
//!   [`rucelium_ingest::VerifiedEnvSample`] (a sealed type only the ingest
//!   pipeline can produce, so unverified data is unrepresentable at this
//!   layer), global dedup spanning live ingest and buffer replay, device
//!   revocation as signed events, and delayed / coarsened disclosure,
//! - [`RegionalSummary`] + [`FederationBus`] — signed statistical summaries
//!   are what federate between biomes instead of raw data (§6), with
//!   biome-identity binding, key rotation by epoch, and replay-protected
//!   publication,
//! - [`sensorthings`] — a SensorThings-*inspired* entity projection so every
//!   accepted observation is externally consumable (§7, §14 criterion 6).
//!
//! Everything is deterministic: ed25519 signing is RFC 8032 deterministic,
//! keys derive from caller-supplied 32-byte seeds, and all timestamps are
//! passed in — no clocks, no RNG.

#![doc(html_root_url = "https://docs.rs/rucelium-federation/0.1.0")]

pub mod biome;
pub mod buffer;
pub mod sensorthings;
pub mod summary;

pub use biome::{verify_event, AcceptOutcome, Biome, BiomeConfig, DisclosurePolicy};
pub use buffer::OutageBuffer;
pub use sensorthings::{
    project_sample, rfc3339_from_ns, Datastream, FeatureOfInterest, GeoJsonPoint, Location,
    Observation, ObservedProperty, Sensor, SensorThingsBundle, Thing, UnitOfMeasurement,
};
pub use summary::{
    canonical_succession_bytes, sign_succession, verify_summary, FederationBus, FederationError,
    KeySuccession, ModalityStats, RegionalSummary,
};

/// Does this artifact survive its own wire format?
///
/// Serialize it, parse it back, and require the result to be *equal*. This is
/// the invariant every signature in the fabric silently depends on: a peer
/// verifies by re-serializing what it parsed, so an artifact that cannot
/// round-trip is signable but undeliverable — it verifies in-process and dies
/// at the far end.
///
/// The concrete hazard is non-finite floats. JSON has no NaN and no Infinity,
/// so `serde_json` writes both as `null` — indistinguishably — and parsing
/// `null` back into an `f32`/`f64` field fails outright. A signature over
/// such a payload is worse than no signature: it looks valid locally and is
/// unusable everywhere else.
///
/// Used by the signing paths to **refuse to sign** rather than mint an
/// artifact that cannot be verified by the peer it is meant for.
pub fn round_trips<T>(value: &T) -> bool
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq,
{
    match serde_json::to_vec(value) {
        Ok(bytes) => serde_json::from_slice::<T>(&bytes)
            .map(|parsed| &parsed == value)
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Shared hex + detached-signature helpers (same house style as
/// `rufield-provenance`).
pub(crate) mod sig {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

    /// Lowercase hex encoding.
    pub(crate) fn hex_encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// Hex decoding; `None` on odd length or non-hex characters.
    pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
        if !s.len().is_multiple_of(2) {
            return None;
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect()
    }

    /// Verify a detached hex ed25519 signature over `msg` with a hex public
    /// key. Any malformed input simply fails verification.
    pub(crate) fn verify_detached(pubkey_hex: &str, sig_hex: &str, msg: &[u8]) -> bool {
        let Some(pk_bytes) = hex_decode(pubkey_hex) else {
            return false;
        };
        let Ok(pk_arr) = <[u8; 32]>::try_from(pk_bytes) else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else {
            return false;
        };
        let Some(sig_bytes) = hex_decode(sig_hex) else {
            return false;
        };
        let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes) else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_arr);
        vk.verify(msg, &sig).is_ok()
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use rucelium_abi::{NodeSigner, RvEnvSampleV1, RV_ENV_SCHEMA_V1};
    use rucelium_core::{EnvSample, GeoPoint, SampleProvenance, SensorModality, Uncertainty};
    use rucelium_ingest::{DeviceRegistry, IngestPipeline, VerifiedEnvSample};

    /// A deterministic 32-byte biome signer seed for tests.
    pub(crate) const SEED: &[u8; 32] = b"rucelium-test-seed-32-bytes-ok!!";

    /// The device-provisioning seed all test node keys derive from.
    pub(crate) const PROVISION_SEED: &[u8; 32] = b"rucelium-provision-seed-32-byte!";

    /// Firmware hash registered for every test device.
    pub(crate) const FW: &str = "sha256:fw-test";

    /// A bare (unsealed) sample for projection tests — [`crate::sensorthings`]
    /// operates on plain [`EnvSample`]s, so this never needs the seal.
    pub(crate) fn sample(node_id: u64, sequence: u32, measured_ns: u64, value: f64) -> EnvSample {
        EnvSample {
            node_id,
            sequence,
            measured_ns,
            received_ns: measured_ns + 1_000_000,
            geo: GeoPoint::new(514_778_216, -14_767, 46_000).unwrap(),
            modality: SensorModality::Weather,
            observed_property: "air_temperature".into(),
            unit: "Cel".into(),
            value,
            quality: 0.9,
            uncertainty: Uncertainty::symmetric(value, 0.5),
            calibration_id: 1,
            flags: 0,
            battery_mv: 3300,
            provenance: SampleProvenance {
                firmware_hash: FW.into(),
                signer_pubkey_hex: "aa".into(),
                verified: true,
                lineage: vec!["cal:1".into()],
            },
        }
    }

    /// The wire record a test node emits.
    pub(crate) fn wire(node_id: u64, sequence: u32, measured_ns: u64, value: f64) -> RvEnvSampleV1 {
        RvEnvSampleV1 {
            schema_version: RV_ENV_SCHEMA_V1,
            sensor_type: SensorModality::Weather.code(),
            flags: 0,
            node_id,
            timestamp_ns: measured_ns,
            sequence,
            latitude_e7: 514_778_216,
            longitude_e7: -14_767,
            altitude_mm: 46_000,
            value_q16: (value * 65_536.0) as i32,
            quality_q15: 0x7000, // 0.875
            battery_mv: 3300,
            calibration_id: 1,
        }
    }

    /// A real signed wire envelope from `node_id`'s provisioned key.
    pub(crate) fn signed_envelope(
        node_id: u64,
        sequence: u32,
        measured_ns: u64,
        value: f64,
    ) -> Vec<u8> {
        NodeSigner::for_node(PROVISION_SEED, node_id)
            .sign_sample(&wire(node_id, sequence, measured_ns, value))
            .encode()
    }

    /// An ingest pipeline with the given devices registered under their real
    /// provisioned keys.
    pub(crate) fn pipeline(node_ids: &[u64]) -> IngestPipeline {
        let mut reg = DeviceRegistry::new();
        for &id in node_ids {
            reg.register(
                id,
                NodeSigner::for_node(PROVISION_SEED, id).public_key(),
                FW.to_string(),
            );
        }
        IngestPipeline::new(reg)
    }

    /// A sealed sample, produced the only way possible: a real signed
    /// envelope ingested through a real pipeline.
    pub(crate) fn verified_sample(
        p: &mut IngestPipeline,
        node_id: u64,
        sequence: u32,
        measured_ns: u64,
        value: f64,
    ) -> VerifiedEnvSample {
        p.ingest(
            &signed_envelope(node_id, sequence, measured_ns, value),
            measured_ns + 1_000_000,
        )
        .expect("test envelope must ingest")
    }
}
