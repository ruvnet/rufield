//! # rucelium-examples
//!
//! Worked, runnable applications of the RuCelium fabric (ADR-266) — the
//! practical deployment wedges and the biological research track.
//!
//! Every example is a real end-to-end scenario: synthetic spore nodes sign
//! genuine 48-byte wire records, the gateway pipeline verifies them
//! cryptographically, calibration and drift logic run for real, and the
//! WorldGraph, biome, and governed control path behave exactly as they do in
//! the daemon. **The sensor data is simulated; the machinery is not.**
//!
//! Run them:
//!
//! ```bash
//! cargo run -p rucelium-examples --bin flood-watershed
//! cargo run -p rucelium-examples --bin sentinel-forest
//! cargo test -p rucelium-examples          # every scenario is asserted
//! ```
//!
//! This module holds the small amount of boilerplate every scenario shares:
//! deterministic node provisioning, envelope construction, and a one-call
//! ingest harness. Scenario logic lives in each `src/bin/*.rs`, so the
//! examples read top-to-bottom as the story they tell.

#![doc(html_root_url = "https://docs.rs/rucelium-examples/0.1.0")]

use rucelium_abi::{NodeSigner, RvEnvSampleV1, RV_ENV_SCHEMA_V1};
use rucelium_core::{GeoPoint, SensorModality};
use rucelium_ingest::{DeviceRegistry, IngestPipeline, RejectReason, VerifiedEnvSample};

/// Nanoseconds per second.
pub const NS_PER_S: u64 = 1_000_000_000;
/// Seconds per day.
pub const S_PER_DAY: u64 = 86_400;
/// A fixed simulated epoch so every example is byte-reproducible.
pub const EPOCH_NS: u64 = 1_750_000_000 * NS_PER_S;
/// Provisioning seed for example device keys (examples only — a real
/// deployment provisions keys in a ceremony, never from a constant).
pub const PROVISION_SEED: &[u8; 32] = b"rucelium-examples-provision-key!";

/// SplitMix64 — the deterministic PRNG every RuCelium simulator uses. Same
/// seed, same story, every run.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// Seed the generator.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }

    /// Next raw `u64`.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform `f64` in `[0, 1)`.
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Approximately normal noise scaled by `sd`.
    pub fn noise(&mut self, sd: f64) -> f64 {
        (self.unit() + self.unit() + self.unit() + self.unit() - 2.0) * sd
    }
}

/// A provisioned example sensor node: identity, key, modality, placement.
pub struct Node {
    /// Device identity.
    pub node_id: u64,
    /// What it measures.
    pub modality: SensorModality,
    /// Where it sits.
    pub geo: GeoPoint,
    /// Human-readable placement (appears in the WorldGraph).
    pub label: String,
    /// Firmware measurement implementation hash.
    pub firmware_hash: String,
    /// Per-device signer.
    pub signer: NodeSigner,
    /// Next sequence number to emit.
    pub sequence: u32,
}

impl Node {
    /// Provision a node deterministically.
    #[must_use]
    pub fn new(node_id: u64, modality: SensorModality, geo: GeoPoint, label: &str) -> Self {
        Node {
            node_id,
            modality,
            geo,
            label: label.to_string(),
            firmware_hash: format!("sha256:example-fw-{}", modality.as_str()),
            signer: NodeSigner::for_node(PROVISION_SEED, node_id),
            sequence: 0,
        }
    }

    /// Build and sign one observation, returning the CBOR envelope bytes
    /// exactly as they would leave the radio.
    pub fn emit(&mut self, value: f64, measured_ns: u64, calibration_id: u32) -> Vec<u8> {
        self.emit_with_quality(value, measured_ns, calibration_id, 0.98)
    }

    /// As [`Self::emit`], with an explicit quality score (`0.0..=1.0`).
    pub fn emit_with_quality(
        &mut self,
        value: f64,
        measured_ns: u64,
        calibration_id: u32,
        quality: f64,
    ) -> Vec<u8> {
        let seq = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        let wire = RvEnvSampleV1 {
            schema_version: RV_ENV_SCHEMA_V1,
            sensor_type: self.modality.code(),
            flags: 0,
            node_id: self.node_id,
            timestamp_ns: measured_ns,
            sequence: seq,
            latitude_e7: self.geo.latitude_e7,
            longitude_e7: self.geo.longitude_e7,
            altitude_mm: self.geo.altitude_mm,
            value_q16: (value * 65_536.0).clamp(f64::from(i32::MIN), f64::from(i32::MAX)) as i32,
            quality_q15: (quality.clamp(0.0, 1.0) * 32_768.0) as u16,
            battery_mv: 3_600,
            calibration_id,
        };
        self.signer.sign_sample(&wire).encode()
    }
}

/// A minimal gateway harness: a device registry plus the real ingest
/// pipeline. Scenarios provision nodes into it and feed it envelopes.
pub struct Gateway {
    /// The real ingest pipeline (signatures, revocation, anti-replay).
    pub ingest: IngestPipeline,
}

impl Gateway {
    /// Build a gateway with the given nodes provisioned.
    #[must_use]
    pub fn with_nodes(nodes: &[Node]) -> Self {
        let mut registry = DeviceRegistry::new();
        for n in nodes {
            registry.register(n.node_id, n.signer.public_key(), n.firmware_hash.clone());
        }
        Gateway {
            ingest: IngestPipeline::new(registry),
        }
    }

    /// Ingest one envelope. The returned sample is *sealed*: it can only
    /// exist because every cryptographic check passed.
    pub fn ingest(
        &mut self,
        envelope: &[u8],
        received_ns: u64,
    ) -> Result<VerifiedEnvSample, RejectReason> {
        self.ingest.ingest(envelope, received_ns)
    }
}

/// Render a labelled scenario banner (examples print a readable narrative,
/// not a wall of JSON).
pub fn banner(title: &str, subtitle: &str) {
    println!("\n{}", "=".repeat(78));
    println!("  {title}");
    println!("  {subtitle}");
    println!("{}\n", "=".repeat(78));
}

/// Print a `key: value` line in the examples' consistent column layout.
pub fn line(key: &str, value: impl std::fmt::Display) {
    println!("  {key:<44} {value}");
}

/// Print the SYNTHETIC honesty footer every example ends with.
pub fn synthetic_footer(extra: &str) {
    println!("\n  ---");
    println!("  SYNTHETIC: sensor values are simulated; the verification,");
    println!("  calibration, graph, and governance machinery is the real");
    println!("  production code. {extra}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> Node {
        Node::new(
            0x00E0_0000_0000_0001,
            SensorModality::WaterQuality,
            GeoPoint::new(515_000_000, -1_000_000, 25_000).unwrap(),
            "test gauge",
        )
    }

    #[test]
    fn emitted_envelope_ingests_and_is_sealed() {
        let mut n = node();
        let mut gw = Gateway::with_nodes(std::slice::from_ref(&n));
        let env = n.emit(1.25, EPOCH_NS, 0);
        let sealed = gw.ingest(&env, EPOCH_NS + 1_000_000).unwrap();
        let s = sealed.sample();
        s.validate().unwrap();
        assert_eq!(s.node_id, n.node_id);
        assert!((s.value - 1.25).abs() < 1e-4);
        assert!(s.provenance.verified);
    }

    #[test]
    fn sequences_advance_and_replays_are_rejected() {
        let mut n = node();
        let mut gw = Gateway::with_nodes(std::slice::from_ref(&n));
        let a = n.emit(1.0, EPOCH_NS, 0);
        let b = n.emit(1.1, EPOCH_NS + NS_PER_S, 0);
        // Reception always follows measurement (the domain model rejects an
        // inverted pair — a real property, not test scaffolding).
        assert!(gw.ingest(&a, EPOCH_NS + NS_PER_S).is_ok());
        assert!(gw.ingest(&b, EPOCH_NS + 2 * NS_PER_S).is_ok());
        // Exact replay of the first envelope.
        assert!(matches!(
            gw.ingest(&a, EPOCH_NS + 3 * NS_PER_S),
            Err(RejectReason::Replay { .. })
        ));
    }

    #[test]
    fn tampered_envelope_never_ingests() {
        let mut n = node();
        let mut gw = Gateway::with_nodes(std::slice::from_ref(&n));
        let mut env = n.emit(1.0, EPOCH_NS, 0);
        let mid = env.len() / 2;
        env[mid] ^= 0x01;
        assert!(gw.ingest(&env, EPOCH_NS + NS_PER_S).is_err());
    }

    #[test]
    fn rng_is_deterministic() {
        let mut a = Rng::new(7);
        let mut b = Rng::new(7);
        for _ in 0..64 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }
}
