//! The gateway-side [`Notary`], the third-party [`EvidenceBundle`], and
//! forward chaining by [`renotarize`] (ADR-267 §3, shipped items 3 and 4).
//!
//! # The shape of the argument (ADR-267 §2)
//!
//! ```text
//! spore node ──ed25519(48-byte record)──► gateway
//!                                           │  accepted observations
//!                                           ▼
//!                                    Merkle accumulator   (Notary)
//!                                           │ every N records / T seconds
//!                                           ▼
//!                                   signed NotaryRoot  ──► biome ──► federation
//!
//! verification in 2040:  observation  +  inclusion proof  +  signed root
//!                        └── recompute the root, check ONE signature ──┘
//! ```
//!
//! The gateway keeps the tree; the auditor needs none of it. An
//! [`EvidenceBundle`] is self-contained, and [`verify_bundle`] is the function
//! a regulator, insurer or reanalyst runs decades later with nothing but the
//! bundle and the public key they trust.
//!
//! # Batching latency is stated, not hidden (ADR-267 §4)
//!
//! A record is authentic the instant the node's ed25519 signature verifies, but
//! it is *notarized* only when its batch is sealed. Every bundle carries both
//! times ([`NotaryRoot::notarized_ns`] and the observation's `received_ns`), so
//! the gap is visible rather than implied; see
//! [`EvidenceBundle::notarization_lag_ns`].

use crate::root::{
    canonical_root_bytes, sign_root, verify_root, NotaryAlgorithm, NotaryRoot, RootSigner,
    RootVerifier,
};
use crate::tree::{leaf_hash, verify_inclusion, InclusionProof, MerkleTree};
use crate::{canonical_json, hex_decode32, hex_encode};
use rucelium_core::{EnvSample, EnvironmentalEvent, SPEC_VERSION};
use serde::{Deserialize, Serialize};

/// Why a piece of long-term evidence failed to verify (ADR-267 §3).
///
/// Every variant is a distinct, reportable failure: an auditor needs to say
/// *which* link of the chain broke, not merely that something did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotaryError {
    /// The observation in the bundle does not hash to the bundle's `leaf_hex`:
    /// the data was altered after notarization.
    LeafMismatch,
    /// The inclusion path does not carry the leaf to the signed root: the leaf
    /// was not in this batch, or the path was tampered with.
    ProofInvalid,
    /// The root's signature does not verify under its declared algorithm and
    /// key.
    RootSignatureInvalid,
    /// The signature is valid, but the signing key is not the key the auditor
    /// trusts.
    UntrustedSigner,
    /// The root declares an algorithm the supplied verifier does not implement.
    /// Never verify a root under an algorithm other than the one it claims.
    AlgorithmMismatch,
    /// The root carries no signature (or no signer key) at all.
    MissingSignature,
    /// Hex or JSON in the archived bundle was malformed.
    Encoding(String),
}

impl std::fmt::Display for NotaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotaryError::LeafMismatch => {
                write!(f, "observation does not hash to the bundle's leaf")
            }
            NotaryError::ProofInvalid => write!(f, "merkle inclusion proof does not verify"),
            NotaryError::RootSignatureInvalid => write!(f, "notary root signature is invalid"),
            NotaryError::UntrustedSigner => write!(f, "root was signed by an untrusted key"),
            NotaryError::AlgorithmMismatch => {
                write!(f, "root algorithm differs from the verifier's algorithm")
            }
            NotaryError::MissingSignature => write!(f, "notary root carries no signature"),
            NotaryError::Encoding(m) => write!(f, "bad encoding: {m}"),
        }
    }
}

impl std::error::Error for NotaryError {}

/// A sealed batch: the signed [`NotaryRoot`] that federates, plus the
/// [`MerkleTree`] the gateway keeps so it can serve inclusion proofs on demand
/// (ADR-267 §2 — proofs are served, not transmitted by default).
///
/// The tree is *derived* state: ADR-267 §4 makes the durable store the source
/// of truth, so a gateway that loses its tree rebuilds it from stored
/// observations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SealedBatch {
    /// The signed root — small, data-free, federable.
    pub root: NotaryRoot,
    /// The tree over this batch's leaves, retained to answer proof requests.
    pub tree: MerkleTree,
}

impl SealedBatch {
    /// Build the self-contained [`EvidenceBundle`] for one observation, or
    /// `None` if this batch does not contain it.
    ///
    /// The observation is located by its leaf hash — the hash of its canonical
    /// JSON — so a bundle can only be produced for bytes byte-identical to what
    /// was notarized. (`EnvSample::dedup_key` identifies a sample in the
    /// gateway's store; the leaf hash identifies it in the batch.)
    #[must_use]
    pub fn bundle_for(&self, sample: &EnvSample) -> Option<EvidenceBundle> {
        let leaf = leaf_hash(&canonical_json(sample));
        let index = self.tree.index_of(&leaf)?;
        let proof = self.tree.prove(index)?;
        Some(EvidenceBundle {
            observation: sample.clone(),
            leaf_hex: hex_encode(&leaf),
            proof,
            root: self.root.clone(),
        })
    }
}

/// The gateway-side Merkle accumulator (ADR-267 §2).
///
/// Accepted observations and events are hashed into leaves as they arrive; the
/// caller seals a batch when its own policy says so — after `batch_size`
/// records, or after an interval elapses. The notary itself reads no clock:
/// every timestamp is passed in by the caller, keeping the whole crate
/// deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notary {
    biome_id: String,
    batch_size: usize,
    pending: Vec<[u8; 32]>,
    next_batch_id: u64,
    prev_root_hex: Option<String>,
}

impl Notary {
    /// Create a notary for `biome_id` with a target `batch_size`.
    ///
    /// `batch_size` is advisory: it drives [`Notary::is_full`] so a caller can
    /// implement the "every N records" half of ADR-267 §2's sealing policy.
    /// Sealing is never automatic — [`Notary::seal`] is always explicit.
    #[must_use]
    pub fn new(biome_id: impl Into<String>, batch_size: usize) -> Self {
        Notary {
            biome_id: biome_id.into(),
            batch_size,
            pending: Vec::new(),
            next_batch_id: 0,
            prev_root_hex: None,
        }
    }

    /// The biome this notary seals for.
    #[must_use]
    pub fn biome_id(&self) -> &str {
        &self.biome_id
    }

    /// The configured target batch size.
    #[must_use]
    pub fn batch_size(&self) -> usize {
        self.batch_size
    }

    /// The batch id the next [`Notary::seal`] will use.
    #[must_use]
    pub fn next_batch_id(&self) -> u64 {
        self.next_batch_id
    }

    /// Root hash of the most recently sealed batch, hex-encoded, which the next
    /// batch will chain to via `prev_root_hex`.
    #[must_use]
    pub fn prev_root_hex(&self) -> Option<&str> {
        self.prev_root_hex.as_deref()
    }

    /// Number of leaves accumulated since the last seal.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Whether the target batch size has been reached (advisory sealing hint).
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.pending.len() >= self.batch_size
    }

    /// Accumulate an accepted observation; returns its leaf hash.
    ///
    /// The leaf is `sha256(0x00 || canonical_json(sample))`, so it commits to
    /// every one of ADR-264 §7.1's twelve mandatory attributes — value, units,
    /// uncertainty, geo, calibration id, node signature provenance, lineage.
    /// Change any byte of the sample and the leaf changes.
    pub fn accept_observation(&mut self, sample: &EnvSample) -> [u8; 32] {
        let leaf = leaf_hash(&canonical_json(sample));
        self.pending.push(leaf);
        leaf
    }

    /// Accumulate an accepted environmental event; returns its leaf hash.
    ///
    /// Events are `DataClass::FederatedEvent` (ADR-264 §10) and are notarized
    /// exactly like observations, so a federated alert is as provable in 2040
    /// as the readings behind it.
    pub fn accept_event(&mut self, event: &EnvironmentalEvent) -> [u8; 32] {
        let leaf = leaf_hash(&canonical_json(event));
        self.pending.push(leaf);
        leaf
    }

    /// Seal the pending leaves into a signed batch (ADR-267 §2).
    ///
    /// Builds the Merkle tree over everything accumulated since the last seal,
    /// chains `prev_root_hex` to the previous batch's root, signs the root with
    /// `signer`, increments the batch id and clears the pending set.
    ///
    /// Sealing **zero** pending leaves is allowed and produces the documented
    /// empty-batch sentinel root ([`crate::empty_root`]): a quiet interval must
    /// still leave a signed, chained artifact, otherwise a gap in the chain is
    /// indistinguishable from a deleted batch.
    ///
    /// All three timestamps are caller-supplied — the notary never reads a
    /// clock.
    pub fn seal(
        &mut self,
        signer: &dyn RootSigner,
        window_start_ns: u64,
        window_end_ns: u64,
        notarized_ns: u64,
    ) -> SealedBatch {
        let tree = MerkleTree::build(std::mem::take(&mut self.pending));
        let root_hex = hex_encode(&tree.root());
        let mut root = NotaryRoot {
            spec_version: SPEC_VERSION.to_string(),
            biome_id: self.biome_id.clone(),
            batch_id: self.next_batch_id,
            root_hex: root_hex.clone(),
            leaf_count: tree.len(),
            window_start_ns,
            window_end_ns,
            notarized_ns,
            prev_root_hex: self.prev_root_hex.clone(),
            algorithm: signer.algorithm(),
            signature_hex: None,
            signer_pubkey_hex: None,
        };
        sign_root(&mut root, signer);
        self.prev_root_hex = Some(root_hex);
        self.next_batch_id += 1;
        SealedBatch { root, tree }
    }
}

/// Everything a third party needs to prove one observation existed, unaltered,
/// inside a signed batch — and nothing else (ADR-267 §2, §3 shipped item 3).
///
/// This is the artifact handed to a regulator, an insurer or a court. It is
/// self-contained: [`verify_bundle`] needs no gateway, no database and no
/// network, only the bundle and the public key the auditor already trusts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    /// The observation being proven, exactly as notarized.
    pub observation: EnvSample,
    /// Hex-encoded leaf hash of `observation`.
    pub leaf_hex: String,
    /// Inclusion path from the leaf to the batch root.
    pub proof: InclusionProof,
    /// The signed root of the batch containing the leaf.
    pub root: NotaryRoot,
}

impl EvidenceBundle {
    /// Batching latency: nanoseconds between the gateway receiving the
    /// observation and the batch being notarized.
    ///
    /// ADR-267 §4 requires this distinction to be stated in any evidence
    /// bundle: the record was *authentic* on receipt and *notarized* only at
    /// seal time. Saturates at zero for a root sealed before reception (a clock
    /// domain mismatch, itself worth reporting).
    #[must_use]
    pub fn notarization_lag_ns(&self) -> u64 {
        self.root
            .notarized_ns
            .saturating_sub(self.observation.received_ns)
    }
}

/// **The 2040 auditor function** (ADR-267 §2, §3 shipped item 3).
///
/// Given only a bundle, a verifier for the root's algorithm, and the public key
/// the auditor trusts, decide whether this observation provably existed,
/// unaltered, in the signed batch. In order:
///
/// 1. recompute the leaf from the observation's canonical bytes and check it
///    against `leaf_hex` → [`NotaryError::LeafMismatch`];
/// 2. verify the inclusion proof against the root's `root_hex`, requiring the
///    proof's `leaf_count` to equal the root's signed `leaf_count` — otherwise
///    a forger could re-declare the batch size to fit a path they invented
///    → [`NotaryError::ProofInvalid`];
/// 3. check the root declares the verifier's algorithm
///    → [`NotaryError::AlgorithmMismatch`], and carries a signature
///    → [`NotaryError::MissingSignature`];
/// 4. check the signer is the trusted key → [`NotaryError::UntrustedSigner`];
/// 5. verify the root signature → [`NotaryError::RootSignatureInvalid`].
///
/// Exactly **one** signature check, for a whole batch — the asymmetry that
/// makes a 2,420-byte post-quantum signature affordable (ADR-267 §2).
pub fn verify_bundle(
    bundle: &EvidenceBundle,
    verifier: &dyn RootVerifier,
    trusted_pubkey_hex: &str,
) -> Result<(), NotaryError> {
    let claimed_leaf = hex_decode32(&bundle.leaf_hex)
        .ok_or_else(|| NotaryError::Encoding(format!("leaf_hex {:?}", bundle.leaf_hex)))?;
    let recomputed = leaf_hash(&canonical_json(&bundle.observation));
    if recomputed != claimed_leaf {
        return Err(NotaryError::LeafMismatch);
    }

    let root_hash = hex_decode32(&bundle.root.root_hex)
        .ok_or_else(|| NotaryError::Encoding(format!("root_hex {:?}", bundle.root.root_hex)))?;
    if bundle.proof.leaf_count != bundle.root.leaf_count
        || !verify_inclusion(&recomputed, &bundle.proof, &root_hash)
    {
        return Err(NotaryError::ProofInvalid);
    }

    if bundle.root.algorithm != verifier.algorithm() {
        return Err(NotaryError::AlgorithmMismatch);
    }
    let signer_hex = match (
        bundle.root.signature_hex.as_ref(),
        bundle.root.signer_pubkey_hex.as_ref(),
    ) {
        (Some(_), Some(pk)) => pk,
        _ => return Err(NotaryError::MissingSignature),
    };
    if signer_hex != trusted_pubkey_hex {
        return Err(NotaryError::UntrustedSigner);
    }
    if !verify_root(&bundle.root, verifier) {
        return Err(NotaryError::RootSignatureInvalid);
    }
    Ok(())
}

/// Re-notarization: chain existing roots forward under a new signer
/// (ADR-267 §3, shipped item 4).
///
/// Each old root's [`canonical_root_bytes`] becomes a **leaf** of a new tree,
/// and only the new root is signed — potentially by a stronger algorithm. Data
/// already notarized under ed25519 therefore gains the new guarantee **without
/// re-signing a single observation**: an old inclusion proof still verifies
/// against its old root, and the old root now has its own inclusion proof in
/// the new, stronger tree.
///
/// The synthesized root's window spans the earliest start and latest end of the
/// inputs, its `prev_root_hex` chains to the last input root, and `now_ns` is
/// supplied by the caller (no clock). Re-notarizing an empty slice yields the
/// documented empty-batch sentinel.
pub fn renotarize(
    old_roots: &[NotaryRoot],
    biome_id: impl Into<String>,
    batch_id: u64,
    signer: &dyn RootSigner,
    now_ns: u64,
) -> SealedBatch {
    let leaves: Vec<[u8; 32]> = old_roots
        .iter()
        .map(|r| leaf_hash(&canonical_root_bytes(r)))
        .collect();
    let tree = MerkleTree::build(leaves);
    let window_start_ns = old_roots
        .iter()
        .map(|r| r.window_start_ns)
        .min()
        .unwrap_or(0);
    let window_end_ns = old_roots.iter().map(|r| r.window_end_ns).max().unwrap_or(0);
    let mut root = NotaryRoot {
        spec_version: SPEC_VERSION.to_string(),
        biome_id: biome_id.into(),
        batch_id,
        root_hex: hex_encode(&tree.root()),
        leaf_count: tree.len(),
        window_start_ns,
        window_end_ns,
        notarized_ns: now_ns,
        prev_root_hex: old_roots.last().map(|r| r.root_hex.clone()),
        algorithm: signer.algorithm(),
        signature_hex: None,
        signer_pubkey_hex: None,
    };
    sign_root(&mut root, signer);
    SealedBatch { root, tree }
}

/// The leaf a re-notarized old root occupies in the new tree: the hash of its
/// canonical bytes (ADR-267 §3 item 4). Exposed so an auditor holding only an
/// old root can locate and check its own inclusion in the newer tree.
#[must_use]
pub fn renotarized_leaf(old_root: &NotaryRoot) -> [u8; 32] {
    leaf_hash(&canonical_root_bytes(old_root))
}

/// Algorithm tag helper for callers assembling a hybrid transition: the tag a
/// dual ed25519 + ML-DSA-44 signer must declare (ADR-267 §3).
#[must_use]
pub fn hybrid_algorithm() -> NotaryAlgorithm {
    NotaryAlgorithm::HybridEd25519MlDsa44
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::{Ed25519RootSigner, Ed25519RootVerifier, ML_DSA_44_SIGNATURE_BYTES};
    use crate::{empty_root, hex_decode, leaf_hash as lh};
    use rucelium_core::{
        EventKind, EvidenceRef, GeoPoint, SampleProvenance, SensorModality, Severity, Uncertainty,
    };

    const SEED: &[u8; 32] = b"rucelium-notary-test-seed-32byte";
    const ROGUE_SEED: &[u8; 32] = b"rucelium-notary-rogue-seed-32byt";

    fn sample(i: u32) -> EnvSample {
        let value = 20.0 + f64::from(i) * 0.01;
        EnvSample {
            node_id: 7,
            sequence: i,
            measured_ns: 1_000 + u64::from(i),
            received_ns: 2_000 + u64::from(i),
            geo: GeoPoint::new(514_778_216, -14_767, 46_000).unwrap(),
            modality: SensorModality::Weather,
            observed_property: "air_temperature".into(),
            unit: "Cel".into(),
            value,
            quality: 0.98,
            uncertainty: Uncertainty::symmetric(value, 0.3),
            calibration_id: 3,
            flags: 0,
            battery_mv: 3600,
            provenance: SampleProvenance {
                firmware_hash: "sha256:abc".into(),
                signer_pubkey_hex: "00ff".into(),
                verified: true,
                lineage: vec!["cal:3".into()],
            },
        }
    }

    fn event() -> EnvironmentalEvent {
        EnvironmentalEvent {
            evidence_digest: None,
            spec_version: SPEC_VERSION.into(),
            event_id: "evt-0001".into(),
            biome_id: "biome/thames-estuary".into(),
            kind: EventKind::FloodRisk,
            severity: Severity::Warning,
            modality: SensorModality::WaterQuality,
            geo: GeoPoint::new(514_000_000, 500_000, 0).unwrap(),
            window_start_ns: 1_000,
            window_end_ns: 5_000,
            detected_ns: 5_100,
            evidence: vec![EvidenceRef {
                node_id: 7,
                sequence: 42,
            }],
            confidence: 0.9,
            message: "water level rising across 3 nodes".into(),
            signature_hex: None,
            signer_pubkey_hex: None,
        }
    }

    #[test]
    fn accept_returns_the_leaf_and_tracks_pending() {
        let mut n = Notary::new("biome/thames-estuary", 4);
        assert_eq!(n.biome_id(), "biome/thames-estuary");
        assert_eq!(n.batch_size(), 4);
        assert_eq!(n.pending(), 0);
        assert_eq!(n.next_batch_id(), 0);
        assert_eq!(n.prev_root_hex(), None);
        assert!(!n.is_full());

        let s = sample(1);
        let leaf = n.accept_observation(&s);
        assert_eq!(leaf, lh(&serde_json::to_vec(&s).unwrap()));
        assert_eq!(n.pending(), 1);

        let e = event();
        let ev_leaf = n.accept_event(&e);
        assert_eq!(ev_leaf, lh(&serde_json::to_vec(&e).unwrap()));
        assert_ne!(ev_leaf, leaf);
        assert_eq!(n.pending(), 2);

        n.accept_observation(&sample(2));
        n.accept_observation(&sample(3));
        assert!(n.is_full());
    }

    #[test]
    fn seal_signs_chains_and_clears() {
        let signer = Ed25519RootSigner::from_seed(SEED);
        let mut n = Notary::new("biome/thames-estuary", 2);
        n.accept_observation(&sample(1));
        n.accept_observation(&sample(2));
        let b0 = n.seal(&signer, 1_000, 2_000, 2_100);
        assert_eq!(n.pending(), 0);
        assert_eq!(b0.root.batch_id, 0);
        assert_eq!(b0.root.leaf_count, 2);
        assert_eq!(b0.root.prev_root_hex, None);
        assert_eq!(b0.root.spec_version, SPEC_VERSION);
        assert_eq!(b0.root.algorithm, NotaryAlgorithm::Ed25519);
        assert!(verify_root(&b0.root, &Ed25519RootVerifier::new()));

        n.accept_observation(&sample(3));
        let b1 = n.seal(&signer, 2_000, 3_000, 3_100);
        assert_eq!(b1.root.batch_id, 1);
        // Chaining: batch N+1's prev_root_hex is batch N's root_hex.
        assert_eq!(b1.root.prev_root_hex.as_deref(), Some(&*b0.root.root_hex));
        assert!(verify_root(&b1.root, &Ed25519RootVerifier::new()));

        let b2 = n.seal(&signer, 3_000, 4_000, 4_100);
        assert_eq!(b2.root.batch_id, 2);
        assert_eq!(b2.root.prev_root_hex.as_deref(), Some(&*b1.root.root_hex));
    }

    #[test]
    fn empty_batch_seals_to_the_sentinel_and_still_verifies() {
        let signer = Ed25519RootSigner::from_seed(SEED);
        let mut n = Notary::new("biome/quiet", 64);
        let b = n.seal(&signer, 1_000, 2_000, 2_100);
        assert_eq!(b.root.leaf_count, 0);
        assert_eq!(b.root.root_hex, hex_encode(&empty_root()));
        assert!(b.tree.is_empty());
        assert!(verify_root(&b.root, &Ed25519RootVerifier::new()));
        assert!(b.bundle_for(&sample(1)).is_none());
        // The chain continues across the quiet interval.
        n.accept_observation(&sample(1));
        let b1 = n.seal(&signer, 2_000, 3_000, 3_100);
        assert_eq!(b1.root.prev_root_hex.as_deref(), Some(&*b.root.root_hex));
    }

    #[test]
    fn sealing_is_deterministic() {
        let build = || {
            let signer = Ed25519RootSigner::from_seed(SEED);
            let mut n = Notary::new("biome/thames-estuary", 8);
            for i in 0..8 {
                n.accept_observation(&sample(i));
            }
            n.seal(&signer, 1_000, 2_000, 2_100)
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn bundle_for_unknown_observation_is_none() {
        let signer = Ed25519RootSigner::from_seed(SEED);
        let mut n = Notary::new("biome/thames-estuary", 4);
        for i in 0..4 {
            n.accept_observation(&sample(i));
        }
        let b = n.seal(&signer, 1_000, 2_000, 2_100);
        assert!(b.bundle_for(&sample(0)).is_some());
        assert!(b.bundle_for(&sample(99)).is_none());
    }

    /// The headline: a stranger verifies one 2026 observation in 2040 holding
    /// nothing but the bundle and the public key they trust — no Notary, no
    /// tree, no gateway (ADR-267 §2).
    #[test]
    fn third_party_verifies_one_observation_from_the_bundle_alone() {
        let signer = Ed25519RootSigner::from_seed(SEED);
        let trusted = signer.public_hex();
        let mut n = Notary::new("biome/thames-estuary", 512);
        for i in 0..500 {
            n.accept_observation(&sample(i));
        }
        assert_eq!(n.pending(), 500);
        let batch = n.seal(&signer, 1_000, 500_000, 500_100);
        assert_eq!(batch.root.leaf_count, 500);

        let target = sample(317);
        let bundle = batch.bundle_for(&target).expect("observation is in batch");
        assert_eq!(bundle.proof.leaf_index, 317);
        assert_eq!(bundle.proof.leaf_count, 500);
        assert_eq!(bundle.notarization_lag_ns(), 500_100 - (2_000 + 317));

        // Everything the auditor gets travels as bytes.
        let wire = serde_json::to_string(&bundle).unwrap();
        let bundle: EvidenceBundle = serde_json::from_str(&wire).unwrap();
        let verifier = Ed25519RootVerifier::new();
        // The archived bundle carries no tree and no gateway state.
        verify_bundle(&bundle, &verifier, &trusted).expect("honest bundle verifies");

        // (a) the observation's value is altered
        let mut tampered = bundle.clone();
        tampered.observation.value += 0.5;
        assert_eq!(
            verify_bundle(&tampered, &verifier, &trusted),
            Err(NotaryError::LeafMismatch)
        );

        // (b) a sibling in the proof is altered
        let mut tampered = bundle.clone();
        tampered.proof.siblings[0].0[0] ^= 0x01;
        assert_eq!(
            verify_bundle(&tampered, &verifier, &trusted),
            Err(NotaryError::ProofInvalid)
        );

        // (c) the root signature is altered
        let mut tampered = bundle.clone();
        let mut sig = hex_decode(tampered.root.signature_hex.as_ref().unwrap()).unwrap();
        sig[0] ^= 0x01;
        tampered.root.signature_hex = Some(hex_encode(&sig));
        assert_eq!(
            verify_bundle(&tampered, &verifier, &trusted),
            Err(NotaryError::RootSignatureInvalid)
        );

        // (d) an untrusted key is supplied
        let rogue = Ed25519RootSigner::from_seed(ROGUE_SEED);
        assert_eq!(
            verify_bundle(&bundle, &verifier, &rogue.public_hex()),
            Err(NotaryError::UntrustedSigner)
        );

        // Bonus: a rogue notary re-signing the same tree is still untrusted.
        let mut forged = bundle;
        sign_root(&mut forged.root, &rogue);
        assert!(verify_root(&forged.root, &verifier));
        assert_eq!(
            verify_bundle(&forged, &verifier, &trusted),
            Err(NotaryError::UntrustedSigner)
        );
    }

    #[test]
    fn verify_bundle_rejects_structural_forgeries() {
        let signer = Ed25519RootSigner::from_seed(SEED);
        let trusted = signer.public_hex();
        let verifier = Ed25519RootVerifier::new();
        let mut n = Notary::new("biome/thames-estuary", 16);
        for i in 0..16 {
            n.accept_observation(&sample(i));
        }
        let batch = n.seal(&signer, 1_000, 2_000, 2_100);
        let bundle = batch.bundle_for(&sample(9)).unwrap();
        verify_bundle(&bundle, &verifier, &trusted).unwrap();

        // Unsigned root.
        let mut t = bundle.clone();
        t.root.signature_hex = None;
        assert_eq!(
            verify_bundle(&t, &verifier, &trusted),
            Err(NotaryError::MissingSignature)
        );

        // Root claiming another algorithm than the verifier implements.
        let mut t = bundle.clone();
        t.root.algorithm = NotaryAlgorithm::MlDsa44;
        assert_eq!(
            verify_bundle(&t, &verifier, &trusted),
            Err(NotaryError::AlgorithmMismatch)
        );

        // Malformed archived hex.
        let mut t = bundle.clone();
        t.leaf_hex = "not-hex".into();
        assert!(matches!(
            verify_bundle(&t, &verifier, &trusted),
            Err(NotaryError::Encoding(_))
        ));
        let mut t = bundle.clone();
        t.root.root_hex = "abc".into();
        assert!(matches!(
            verify_bundle(&t, &verifier, &trusted),
            Err(NotaryError::Encoding(_))
        ));

        // A proof re-pointed at another index.
        let mut t = bundle.clone();
        t.proof.leaf_index = 8;
        assert_eq!(
            verify_bundle(&t, &verifier, &trusted),
            Err(NotaryError::ProofInvalid)
        );

        // A proof that re-declares the batch size. `verify_inclusion` alone
        // accepts a same-shape count (15 vs 16 at index 9); the bundle check
        // rejects it because leaf_count is covered by the root signature.
        let mut t = bundle.clone();
        t.proof.leaf_count = 15;
        assert!(verify_inclusion(
            &hex_decode32(&t.leaf_hex).unwrap(),
            &t.proof,
            &hex_decode32(&t.root.root_hex).unwrap()
        ));
        assert_eq!(
            verify_bundle(&t, &verifier, &trusted),
            Err(NotaryError::ProofInvalid)
        );

        // A leaf_hex that matches nothing.
        let mut t = bundle;
        t.leaf_hex = hex_encode(&[0u8; 32]);
        assert_eq!(
            verify_bundle(&t, &verifier, &trusted),
            Err(NotaryError::LeafMismatch)
        );
    }

    /// ADR-267 §2's economic claim, encoded so it cannot silently rot: one
    /// signature per batch amortizes to a fraction of a byte per observation
    /// even at ML-DSA-44 size.
    #[test]
    fn batch_signature_amortizes_below_one_byte_per_observation() {
        let signer = Ed25519RootSigner::from_seed(SEED);
        let mut n = Notary::new("biome/thames-estuary", 4096);
        for i in 0..4096 {
            n.accept_observation(&sample(i));
        }
        assert!(n.is_full());
        let batch = n.seal(&signer, 1_000, 4_096_000, 4_096_100);
        let leaf_count = batch.root.leaf_count;
        assert_eq!(leaf_count, 4096);

        // 2,420 bytes is the NIST FIPS 204 ML-DSA-44 signature size (ADR-267
        // §1). v0.1 signs with ed25519, but the batch geometry is what makes
        // the PQ swap affordable, so the assertion is written against the PQ
        // number.
        let bytes_per_observation = ML_DSA_44_SIGNATURE_BYTES as f64 / leaf_count as f64;
        assert!(
            bytes_per_observation < 1.0,
            "ML-DSA-44 amortization regressed: {bytes_per_observation} B/observation"
        );
        assert!((bytes_per_observation - 0.590_820_312_5).abs() < 1e-12);

        // Per-observation ML-DSA would instead cost 2,420 B each — ~38x
        // ed25519 and ~49 LoRaWAN DR0 datagrams (ADR-267 §1).
        assert!(bytes_per_observation < ML_DSA_44_SIGNATURE_BYTES as f64 / 100.0);

        // The proof an observation actually needs stays small: a 4,096-leaf
        // batch gives a 12-hash (384-byte) path (ADR-267 §2).
        let bundle = batch.bundle_for(&sample(4_095)).unwrap();
        assert_eq!(bundle.proof.siblings.len(), 12);
        assert_eq!(bundle.proof.siblings.len() * 32, 384);
        verify_bundle(&bundle, &Ed25519RootVerifier::new(), &signer.public_hex()).unwrap();
    }

    #[test]
    fn renotarization_chains_history_forward_without_resigning_observations() {
        let old_signer = Ed25519RootSigner::from_seed(SEED);
        let verifier = Ed25519RootVerifier::new();
        let mut n = Notary::new("biome/thames-estuary", 4);

        let mut batches = Vec::new();
        for b in 0..3u32 {
            for i in 0..4 {
                n.accept_observation(&sample(b * 4 + i));
            }
            let start = 1_000 + u64::from(b) * 1_000;
            batches.push(n.seal(&old_signer, start, start + 999, start + 1_000));
        }
        let old_roots: Vec<NotaryRoot> = batches.iter().map(|b| b.root.clone()).collect();

        // The "stronger" signer of the future. v0.1 has only ed25519, so this
        // stands in for the ML-DSA key the same code path will carry.
        let new_signer = Ed25519RootSigner::from_seed(ROGUE_SEED);
        let renotarized = renotarize(&old_roots, "biome/thames-estuary", 100, &new_signer, 9_000);

        assert_eq!(renotarized.root.leaf_count, 3);
        assert_eq!(renotarized.root.batch_id, 100);
        assert_eq!(renotarized.root.window_start_ns, 1_000);
        assert_eq!(renotarized.root.window_end_ns, 3_999);
        assert_eq!(renotarized.root.notarized_ns, 9_000);
        assert_eq!(
            renotarized.root.prev_root_hex.as_deref(),
            Some(&*old_roots[2].root_hex)
        );
        assert!(verify_root(&renotarized.root, &verifier));

        // An OLD root's inclusion in the NEW tree, proven and verified.
        let old_leaf = renotarized_leaf(&old_roots[1]);
        let idx = renotarized
            .tree
            .index_of(&old_leaf)
            .expect("old root is a leaf");
        assert_eq!(idx, 1);
        let proof = renotarized.tree.prove(idx).unwrap();
        let new_root_hash = hex_decode32(&renotarized.root.root_hex).unwrap();
        assert!(verify_inclusion(&old_leaf, &proof, &new_root_hash));

        // Tampering with the old root changes its leaf, so it no longer proves.
        let mut tampered = old_roots[1].clone();
        tampered.leaf_count += 1;
        assert!(!verify_inclusion(
            &renotarized_leaf(&tampered),
            &proof,
            &new_root_hash
        ));

        // No observation was re-signed: the original bundles still verify
        // against their original roots and the original key.
        let bundle = batches[1].bundle_for(&sample(5)).unwrap();
        verify_bundle(&bundle, &verifier, &old_signer.public_hex()).unwrap();

        // Re-notarizing nothing yields the documented sentinel.
        let empty = renotarize(&[], "biome/quiet", 0, &new_signer, 9_000);
        assert_eq!(empty.root.root_hex, hex_encode(&empty_root()));
        assert_eq!(empty.root.prev_root_hex, None);
        assert!(verify_root(&empty.root, &verifier));
    }

    #[test]
    fn errors_display_distinctly_and_hybrid_tag_is_available() {
        let all = [
            NotaryError::LeafMismatch,
            NotaryError::ProofInvalid,
            NotaryError::RootSignatureInvalid,
            NotaryError::UntrustedSigner,
            NotaryError::AlgorithmMismatch,
            NotaryError::MissingSignature,
            NotaryError::Encoding("leaf_hex".into()),
        ];
        let mut seen: Vec<String> = all.iter().map(ToString::to_string).collect();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), all.len());
        let as_err: &dyn std::error::Error = &NotaryError::ProofInvalid;
        assert!(!as_err.to_string().is_empty());
        assert_eq!(hybrid_algorithm().as_str(), "hybrid-ed25519+ml-dsa-44");
    }

    /// Archival stability regression. A leaf commits to the canonical JSON of
    /// an observation, so an archived bundle must rehash to its own leaf after
    /// being parsed back out of storage. `serde_json`'s default float parser
    /// lands one ULP away from the value that printed it (e.g. the decimal
    /// `23.470000000000002` parses back as `23.47`), which would silently break
    /// every float-bearing bundle on the way out of the archive; this crate
    /// therefore enables serde_json's `float_roundtrip` feature. If that
    /// feature is ever dropped, this test fails rather than the year-2040
    /// auditor.
    #[test]
    fn archived_observations_rehash_exactly_after_a_json_round_trip() {
        for i in [0u32, 1, 7, 317, 4_095] {
            let original = sample(i);
            let leaf = lh(&serde_json::to_vec(&original).unwrap());
            let text = serde_json::to_string(&original).unwrap();
            let parsed: EnvSample = serde_json::from_str(&text).unwrap();
            assert_eq!(parsed, original, "sample {i} lost precision");
            assert_eq!(
                lh(&serde_json::to_vec(&parsed).unwrap()),
                leaf,
                "sample {i} rehashed differently after archival"
            );
        }
    }

    #[test]
    fn sealed_batch_round_trips_as_json() {
        let signer = Ed25519RootSigner::from_seed(SEED);
        let mut n = Notary::new("biome/thames-estuary", 5);
        for i in 0..5 {
            n.accept_observation(&sample(i));
        }
        let b = n.seal(&signer, 1_000, 2_000, 2_100);
        let json = serde_json::to_string(&b).unwrap();
        let back: SealedBatch = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
        let bundle = back.bundle_for(&sample(3)).unwrap();
        verify_bundle(&bundle, &Ed25519RootVerifier::new(), &signer.public_hex()).unwrap();
    }
}
