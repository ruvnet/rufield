//! Shared gateway runtime state (ADR-265 §4).
//!
//! v0.1 concurrency model: **one big lock**. Every mutable component lives in
//! [`Inner`] behind a single `Arc<tokio::sync::Mutex<Inner>>`. The UDP loop,
//! HTTP handlers, federation poller, retention timer, and simulator all take
//! the same lock; per-datagram work is microseconds, so contention is
//! negligible at v0.1 scale and the simplicity buys obvious correctness.
//! Finer-grained locking is deliberate future work.

use crate::config::GatewayConfig;
use crate::journal;
use rucelium_calibration::{
    AuthorityRegistry as CalibrationAuthorities, CalibrationAuthority, CalibrationError,
    CalibrationSigner, CalibrationStore, Calibrator, DriftDetector,
};
use rucelium_core::CalibrationRecord;
use rucelium_federation::{Biome, BiomeConfig, RegionalSummary};
use rucelium_ingest::IngestPipeline;
use rucelium_policy::{
    AuditTrail, AuthorityRegistry, CommandSigner, ExecutionReceipt, GatewayValidator, PolicyConfig,
    PolicyEngine, SafetyConfig, SafetySimulator,
};
use rucelium_store::{EventStore, ObservationStore};
use rucelium_transport::Reassembler;
use rucelium_worldgraph::WorldGraph;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, Mutex};

/// Max records per observation segment file.
const OBS_SEGMENT_MAX_RECORDS: usize = 4096;
/// Max records per event segment file.
const EVT_SEGMENT_MAX_RECORDS: usize = 1024;
/// Max in-flight partially reassembled messages held by the gateway.
const REASSEMBLER_MAX_PENDING: usize = 256;
/// Agent identity the biome owner grants actuator authority to at startup.
pub const GRANTED_AGENT_ID: &str = "agent/flood";
/// Name of the gateway's own local calibration authority.
const LOCAL_CALIBRATION_AUTHORITY: &str = "gateway-local";

/// Nanoseconds since the Unix epoch, from the system clock. The library
/// crates are clock-free; the daemon is where wall time enters the system.
#[must_use]
pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Datagram-level counters for the UDP front door (one bump per received
/// datagram, distinct from the envelope-level `IngestStats`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct DatagramStats {
    /// Datagrams that led to a fully accepted sample.
    pub accepted: u64,
    /// Datagrams rejected at any stage (transport, registry, ingest, store).
    pub rejected: u64,
    /// Fragment datagrams absorbed while awaiting the rest of their message.
    pub fragments: u64,
}

/// A verified regional summary fetched from a federation peer.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PeerSummary {
    /// Peer base URL the summary was fetched from.
    pub peer: String,
    /// The verified signed summary.
    pub summary: RegionalSummary,
    /// When this gateway fetched it (ns since Unix epoch).
    pub fetched_ns: u64,
}

/// Push-federation counters (ADR-269 §3): how well the push path and its
/// mandatory polling backstop are actually doing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct PushStats {
    /// Artifacts this gateway pushed to a peer and the peer accepted.
    pub pushes_sent: u64,
    /// Artifacts a peer pushed to this gateway that **verified** and were
    /// accepted (`POST /api/federation/announce`, or a QUIC stream).
    pub pushes_received: u64,
    /// Push attempts that failed — unreachable peer, protocol refusal, or a
    /// refused transport identity. Never fatal: the backstop converges.
    pub push_failures: u64,
    /// Completed `sync_since` backfill passes (the ADR-269 §3 backstop).
    pub backfills: u64,
}

/// A peer's federation identity as learned on first contact, and the address
/// it was learned from. This is the `biome_id → key` binding every received
/// artifact is checked against (ADR-269 §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KnownPeer {
    /// Peer biome identity (the map key).
    pub biome_id: String,
    /// The peer's published ed25519 federation key, hex.
    pub pubkey_hex: String,
    /// Where the identity was learned from.
    pub url: String,
}

/// Counters for the governed control path (ADR-264 §9).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ControlStats {
    /// Commands the gateway validated and executed, producing a receipt.
    pub commands_executed: u64,
    /// Proposals stopped at any stage of the governed path.
    pub proposals_rejected: u64,
    /// Signed execution receipts retained in memory.
    pub receipts: u64,
}

/// Everything mutable in the gateway, guarded by one lock (module docs).
pub struct Inner {
    /// Wire ingest: registry, signatures, anti-replay (ADR-264 §5).
    pub ingest: IngestPipeline,
    /// Calibration records with anchor-rooted lineage, in **strict** mode:
    /// every record must be signed by a registered calibration authority
    /// (ADR-264 §12 items 1–3).
    pub calibration: CalibrationStore,
    /// The gateway's own calibration authority key. The daemon's synthetic
    /// calibration records are signed with it before insertion; a record it
    /// did not sign is rejected by the strict store.
    pub cal_signer: CalibrationSigner,
    /// Applies calibration; never repairs (ADR-264 §12).
    pub calibrator: Calibrator,
    /// EWMA drift monitor with sticky quarantine.
    pub drift: DriftDetector,
    /// Environmental WorldGraph (ADR-264 §5.2).
    pub graph: WorldGraph,
    /// The sovereign biome aggregate + signing identity.
    pub biome: Biome,
    /// Durable observation log (disk).
    pub obs: ObservationStore,
    /// Durable event log (disk).
    pub events: EventStore,
    /// Fragment reassembly for MTU-constrained links.
    pub reassembler: Reassembler,
    /// Latest verified summary per federation peer.
    pub peer_summaries: Vec<PeerSummary>,
    /// `event_id`s of peer revocation events already applied locally.
    pub applied_revocation_ids: BTreeSet<String>,
    /// How many verified peer `DeviceRevoked` events were applied.
    pub applied_peer_revocations: u64,
    /// Federation identities learned on first contact, keyed by `biome_id`
    /// (ADR-269 §4: the identity binding every artifact is checked against).
    pub known_peers: BTreeMap<String, KnownPeer>,
    /// Push-federation counters (ADR-269 §3).
    pub push: PushStats,
    /// Local alert events raised (flood / anomaly rule).
    pub alerts: u64,
    /// Calibration application errors (sample kept raw, never repaired).
    pub calibration_errors: u64,
    /// Datagram-level UDP counters.
    pub datagrams: DatagramStats,

    // --- Governed control path (ADR-264 §9). Stage order is enforced by the
    // policy crate's type privacy; the daemon just owns the components. ---
    /// Stage 1: deterministic policy evaluation.
    pub policy: PolicyEngine,
    /// Stage 2: safety envelope. Budgets are checked here and charged by
    /// `record_execution` only after the gateway confirms execution.
    pub safety: SafetySimulator,
    /// Stage 3: per-biome actuator authority (never leaves the biome owner).
    pub authority: AuthorityRegistry,
    /// Stage 4: the biome owner's deterministic command-signing key.
    pub command_signer: CommandSigner,
    /// Stages 5–6: gateway validation + two-phase local execution, with the
    /// command phase table restored from [`Inner::command_journal`].
    pub gateway: GatewayValidator,
    /// Append-only audit trail across every control-path stage.
    pub audit: AuditTrail,
    /// Signed receipts of executed commands, in execution order.
    pub receipts: Vec<ExecutionReceipt>,
    /// Control-path counters.
    pub control: ControlStats,
    /// Path of the durable command-phase journal (`commands.jsonl`).
    pub command_journal: PathBuf,
}

impl Inner {
    /// Build the full component stack, opening the durable stores under
    /// `config.data_dir` (`obs/` and `events/` subdirectories) in the
    /// durability mode `config.fsync` selects.
    ///
    /// Two pieces of state are **restored from disk here**, and both are
    /// security-relevant (ADR-265):
    ///
    /// 1. The anti-replay windows are primed from the observation store's
    ///    durable dedup index ([`ObservationStore::dedup_keys`]). Without
    ///    this, a restarted gateway would happily re-accept signed packets it
    ///    had already ingested — replay protection would last only as long as
    ///    the process.
    /// 2. The command phase table is restored from the `commands.jsonl`
    ///    journal, so a command id that was executed (or was mid-execution
    ///    when the process died) is never executed a second time.
    pub fn open(config: &GatewayConfig) -> Result<Self, String> {
        let obs = ObservationStore::open(
            &config.data_dir.join("obs"),
            OBS_SEGMENT_MAX_RECORDS,
            config.fsync,
        )
        .map_err(|e| format!("open observation store: {e}"))?;
        let events = EventStore::open(
            &config.data_dir.join("events"),
            EVT_SEGMENT_MAX_RECORDS,
            config.fsync,
        )
        .map_err(|e| format!("open event store: {e}"))?;

        // (1) Replay protection must survive restart: the durable dedup index
        // is the replay memory.
        let mut ingest = IngestPipeline::default();
        ingest.prime_from_dedup(obs.dedup_keys());

        // Strict calibration: the daemon trusts exactly one authority — its
        // own deterministic key — and the store verifies every record's
        // signature against it. `CalibrationStore::new()` (permissive) would
        // let anyone who can insert a record declare an anchor.
        let cal_signer = CalibrationSigner::from_seed(&derive_seed(
            "calibration",
            &config.biome_id,
            config.seed,
        ));
        let mut authorities = CalibrationAuthorities::new();
        authorities.add(CalibrationAuthority {
            name: LOCAL_CALIBRATION_AUTHORITY.to_string(),
            pubkey_hex: cal_signer.public_hex(),
            modalities: BTreeSet::new(), // trusted for every modality
        });

        // Governed control path. The biome owner's command key and the
        // gateway's receipt identity are both deterministic in
        // `(biome_id, seed)`, so they are stable across restarts — which is
        // what lets a replayed command still verify and *then* be rejected as
        // a duplicate rather than as an untrusted key.
        let command_signer =
            CommandSigner::from_seed(&derive_seed("command", &config.biome_id, config.seed));
        let mut policy_config = PolicyConfig::default();
        policy_config
            .allowed_actuators
            .insert(config.actuator_id.clone());
        let mut authority = AuthorityRegistry::new();
        authority.grant(&config.biome_id, GRANTED_AGENT_ID, &config.actuator_id);

        // (2) Restore the journaled command phases.
        let command_journal = journal::journal_path(&config.data_dir);
        let mut gateway = GatewayValidator::new(
            vec![command_signer.public_hex()],
            &derive_seed("gateway-identity", &config.biome_id, config.seed),
        );
        gateway.restore_phases(journal::load(&command_journal)?);

        let seed = biome_seed(&config.biome_id, config.seed);
        Ok(Inner {
            ingest,
            calibration: CalibrationStore::with_authorities(authorities),
            cal_signer,
            calibrator: Calibrator::default(),
            drift: DriftDetector::default(),
            graph: WorldGraph::new(),
            biome: Biome::new(BiomeConfig::new(config.biome_id.clone()), &seed),
            obs,
            events,
            reassembler: Reassembler::new(REASSEMBLER_MAX_PENDING),
            peer_summaries: Vec::new(),
            applied_revocation_ids: BTreeSet::new(),
            applied_peer_revocations: 0,
            known_peers: BTreeMap::new(),
            push: PushStats::default(),
            alerts: 0,
            calibration_errors: 0,
            datagrams: DatagramStats::default(),
            policy: PolicyEngine::new(policy_config),
            safety: SafetySimulator::new(SafetyConfig::default()),
            authority,
            command_signer,
            gateway,
            audit: AuditTrail::new(),
            receipts: Vec::new(),
            control: ControlStats::default(),
            command_journal,
        })
    }

    /// Sign a calibration record with the gateway's calibration authority key
    /// and insert it into the strict store.
    ///
    /// This is the *only* way records enter the daemon's store: strict mode
    /// rejects unsigned records, so an attacker who can reach the store still
    /// cannot mint an "anchor_reference" root.
    pub fn insert_signed_calibration(
        &mut self,
        mut record: CalibrationRecord,
    ) -> Result<(), CalibrationError> {
        self.cal_signer.sign_record(&mut record)?;
        self.calibration.insert(record)
    }

    /// Persist the gateway validator's command phase table to the journal.
    /// Called after **every** execution attempt so a crash can never leave a
    /// command that ran on disk-less state.
    pub fn journal_command_phases(&self) -> Result<(), String> {
        journal::store(&self.command_journal, &self.gateway.export_phases())
    }
}

/// Depth of the push queue between the code that mints an artifact (e.g. the
/// admin revoke handler) and the federation task that announces it. A
/// `broadcast` channel is deliberate: a send with no federation task running
/// is a no-op instead of an unbounded leak, and an overrun drops the
/// *oldest* artifact rather than blocking the caller. Either way the ADR-269
/// §3 backstop converges the peer, which is exactly why push is allowed to
/// be best-effort.
const PUSH_QUEUE_DEPTH: usize = 256;

/// Handle shared by every task and HTTP handler. Cheap to clone.
#[derive(Clone)]
pub struct GatewayState {
    /// Biome identity (mirrors the config; readable without the lock).
    pub biome_id: String,
    /// The single mutable state lock (module docs).
    pub inner: Arc<Mutex<Inner>>,
    /// Daemon start time, for `uptime_s`.
    pub started: Instant,
    /// Outbound push queue (ADR-269 §3). Anything that mints a locally
    /// signed artifact publishes it here; the federation task announces it
    /// to every peer immediately.
    pub push_tx: broadcast::Sender<crate::transport::FederationArtifact>,
}

impl GatewayState {
    /// Open the durable stores and assemble the gateway state.
    pub fn open(config: &GatewayConfig) -> Result<Self, String> {
        let (push_tx, _) = broadcast::channel(PUSH_QUEUE_DEPTH);
        Ok(GatewayState {
            biome_id: config.biome_id.clone(),
            inner: Arc::new(Mutex::new(Inner::open(config)?)),
            started: Instant::now(),
            push_tx,
        })
    }

    /// Queue one locally signed artifact for immediate push to every peer
    /// (ADR-269 §3: a revoked device must not stay valid at peer gateways
    /// for a polling interval).
    ///
    /// Returns how many federation tasks were listening — `0` means nothing
    /// is federating right now, which is not an error: the receiving side's
    /// `sync_since` backstop is what makes push safe to drop.
    pub fn announce_local(&self, artifact: crate::transport::FederationArtifact) -> usize {
        self.push_tx.send(artifact).unwrap_or(0)
    }
}

/// Derive the biome's 32-byte ed25519 signing seed from the biome id and the
/// numeric config seed: id bytes repeated/truncated, XORed with the seed
/// bytes and an index whitener.
///
/// **Deliberately not cryptographically strong** (v0.1): what matters is
/// that the same `(biome_id, seed)` always yields the same biome identity —
/// determinism, restart-stable keys, distinct keys for distinct biomes. A
/// production deployment provisions the biome key from a real ceremony.
#[must_use]
pub fn biome_seed(biome_id: &str, seed: u64) -> [u8; 32] {
    let id = biome_id.as_bytes();
    let sb = seed.to_le_bytes();
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        let idb = if id.is_empty() {
            0x7A
        } else {
            id[i % id.len()]
        };
        *b = idb ^ sb[i % 8] ^ (i as u8).wrapping_mul(0x9E);
    }
    out
}

/// Derive a **domain-separated** 32-byte seed from the biome identity and the
/// numeric config seed, so the biome key, the command-signing key, the
/// gateway's receipt identity, and the calibration authority key are all
/// distinct while each stays deterministic and restart-stable.
///
/// Carries the same v0.1 caveat as [`biome_seed`]: this is **not** a
/// cryptographic KDF. It exists so a given `(domain, biome_id, seed)` always
/// yields the same identity; production provisions these from a real ceremony.
#[must_use]
pub fn derive_seed(domain: &str, biome_id: &str, seed: u64) -> [u8; 32] {
    let base = biome_seed(biome_id, seed);
    let d = domain.as_bytes();
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        let db = if d.is_empty() { 0x5E } else { d[i % d.len()] };
        *b = base[i] ^ db ^ (i as u8).wrapping_mul(0x1B);
    }
    out
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Unique per-test temp data dir (name uniqueness only, never store
    /// logic).
    pub(crate) fn temp_dir(tag: &str) -> PathBuf {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rucelium-gateway-{tag}-{}-{n}-{t}",
            std::process::id()
        ))
    }

    /// A fresh [`Inner`] over a unique temp data dir.
    pub(crate) fn test_inner(tag: &str) -> Inner {
        let config = GatewayConfig {
            data_dir: temp_dir(tag),
            ..GatewayConfig::default()
        };
        Inner::open(&config).expect("test inner opens")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn biome_seed_is_deterministic_and_id_sensitive() {
        assert_eq!(biome_seed("biome/a", 1), biome_seed("biome/a", 1));
        assert_ne!(biome_seed("biome/a", 1), biome_seed("biome/b", 1));
        assert_ne!(biome_seed("biome/a", 1), biome_seed("biome/a", 2));
        // Empty id still yields a stable, non-degenerate seed.
        let empty = biome_seed("", 7);
        assert_eq!(empty, biome_seed("", 7));
        assert!(empty.iter().any(|&b| b != 0));
    }

    #[test]
    fn same_config_reproduces_the_biome_identity() {
        let config = GatewayConfig {
            data_dir: testutil::temp_dir("identity"),
            ..GatewayConfig::default()
        };
        let a = Inner::open(&config).unwrap();
        let b = Inner::open(&config).unwrap();
        assert_eq!(a.biome.public_key_hex(), b.biome.public_key_hex());
        std::fs::remove_dir_all(&config.data_dir).ok();
    }

    #[test]
    fn derived_seeds_are_domain_separated_and_stable() {
        let a = derive_seed("command", "biome/a", 1);
        assert_eq!(a, derive_seed("command", "biome/a", 1));
        assert_ne!(a, derive_seed("gateway-identity", "biome/a", 1));
        assert_ne!(a, derive_seed("calibration", "biome/a", 1));
        assert_ne!(a, derive_seed("command", "biome/b", 1));
        assert_ne!(a, derive_seed("command", "biome/a", 2));
        assert_ne!(a, biome_seed("biome/a", 1));
        // Degenerate domain still produces a stable, non-zero seed.
        let empty = derive_seed("", "biome/a", 1);
        assert_eq!(empty, derive_seed("", "biome/a", 1));
        assert!(empty.iter().any(|&b| b != 0));
    }

    #[test]
    fn strict_calibration_rejects_records_the_gateway_did_not_sign() {
        use rucelium_core::SensorModality;
        let mut inner = testutil::test_inner("strict-cal");
        let record = |id: u32| rucelium_core::CalibrationRecord {
            calibration_id: id,
            node_id: 0,
            modality: SensorModality::Weather,
            method: "anchor_reference".into(),
            reference_station: Some("anchor/weather".into()),
            parent_id: None,
            created_ns: 1_000,
            expires_ns: u64::MAX / 2,
            scale_q16: 65_536,
            offset_q16: 0,
            uncertainty_q16: 6_554,
            data_hash: "sha256:anchor".into(),
            signature_hex: None,
            signer_pubkey_hex: None,
        };
        // Unsigned insertion is refused outright...
        assert!(matches!(
            inner.calibration.insert(record(1)),
            Err(CalibrationError::MissingSignature(1))
        ));
        // ...a record signed by a key the registry does not know is refused...
        let mut foreign = record(2);
        CalibrationSigner::from_seed(b"some-other-calibration-lab-key!!")
            .sign_record(&mut foreign)
            .unwrap();
        assert!(matches!(
            inner.calibration.insert(foreign),
            Err(CalibrationError::UntrustedSigner { id: 2, .. })
        ));
        // ...and only the gateway's own authority gets in.
        inner.insert_signed_calibration(record(3)).unwrap();
        assert_eq!(inner.calibration.verify_lineage(3).unwrap(), vec![3]);
    }

    #[test]
    fn now_ns_is_monotonic_enough_and_after_2020() {
        let a = now_ns();
        let b = now_ns();
        assert!(b >= a);
        assert!(a > 1_577_836_800_000_000_000, "clock reads before 2020");
    }
}
