//! Algorithm-agile signed notary roots (ADR-267 §3, shipped items 2 and 3).
//!
//! ADR-267's shipped feature is **algorithm agility, not ML-DSA itself**. The
//! root signature algorithm is reached only through the [`RootSigner`] /
//! [`RootVerifier`] trait pair, and the algorithm actually used is recorded
//! *inside* the signed structure as a [`NotaryAlgorithm`] tag. Two consequences
//! matter:
//!
//! - swapping ed25519 for ML-DSA-44 (or dual-signing during the hybrid
//!   transition) is an implementation swap, not a protocol break;
//! - a verifier **never has to guess** which algorithm a root was signed under,
//!   and a root minted in 2032 under ML-DSA is self-describing to a reader
//!   written today. Because the tag is part of the canonical bytes, it is
//!   covered by the signature and cannot be downgraded after the fact.
//!
//! **Honest label (ADR-267 §3):** only [`Ed25519RootSigner`] ships in v0.1.
//! Shipping a hand-rolled lattice implementation would be worse than shipping
//! none; the [`ML_DSA_44_SIGNATURE_BYTES`] constant records the size that
//! matters for the amortization argument until a vetted implementation exists.

use crate::{canonical_json, hex_decode, hex_encode};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Ed25519 detached signature size, bytes (RFC 8032) — what v0.1 actually
/// signs roots with (ADR-267 §1 table).
pub const ED25519_SIGNATURE_BYTES: usize = 64;

/// ML-DSA-44 signature size, bytes, per NIST FIPS 204 (ADR-267 §1 table).
///
/// This constant is the whole economic argument of ADR-267 §2 in one number:
/// ~38× an ed25519 signature, infeasible per observation on a LoRaWAN DR0 link
/// (~49 datagrams), but negligible once amortized across a batch — 2,420 bytes
/// over a 4,096-leaf batch is **0.6 bytes per observation**.
pub const ML_DSA_44_SIGNATURE_BYTES: usize = 2420;

/// ML-DSA-44 public key size, bytes, per NIST FIPS 204 (ADR-267 §1).
pub const ML_DSA_44_PUBLIC_KEY_BYTES: usize = 1312;

/// Signature algorithm of a notary root, recorded inside the root itself so a
/// verifier never has to guess (ADR-267 §3).
///
/// The serde names are the exact wire strings named in ADR-267 §3:
/// `"ed25519"`, `"ml-dsa-44"`, `"hybrid-ed25519+ml-dsa-44"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NotaryAlgorithm {
    /// Ed25519 (RFC 8032) — the v0.1 shipped algorithm.
    #[serde(rename = "ed25519")]
    Ed25519,
    /// ML-DSA-44 (NIST FIPS 204). Tag reserved; no implementation ships in
    /// v0.1 (ADR-267 §3 honest label).
    #[serde(rename = "ml-dsa-44")]
    MlDsa44,
    /// Concurrent ed25519 **and** ML-DSA-44 signing — the deliberately
    /// hybrid-first migration path of ADR-267 §3, where a root stays verifiable
    /// by old and new verifiers alike and no historical data is re-signed.
    #[serde(rename = "hybrid-ed25519+ml-dsa-44")]
    HybridEd25519MlDsa44,
}

impl NotaryAlgorithm {
    /// The canonical wire string for this algorithm (ADR-267 §3).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            NotaryAlgorithm::Ed25519 => "ed25519",
            NotaryAlgorithm::MlDsa44 => "ml-dsa-44",
            NotaryAlgorithm::HybridEd25519MlDsa44 => "hybrid-ed25519+ml-dsa-44",
        }
    }
}

impl std::fmt::Display for NotaryAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A signed commitment to one batch of observations — the small, data-free
/// artifact that leaves the biome and travels to the federation (ADR-267 §2,
/// §4).
///
/// It carries no raw observations: exactly what ADR-264 §6 permits to cross a
/// biome boundary. Everything in it is covered by the signature except the
/// signature fields themselves (see [`canonical_root_bytes`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotaryRoot {
    /// Wire spec version (`rucelium_core::SPEC_VERSION`).
    pub spec_version: String,
    /// Owning biome.
    pub biome_id: String,
    /// Monotonic batch number within this notary, starting at 0.
    pub batch_id: u64,
    /// Hex-encoded Merkle root of the batch (the empty-batch sentinel when
    /// `leaf_count == 0`).
    pub root_hex: String,
    /// Number of leaves committed to by `root_hex`.
    pub leaf_count: usize,
    /// Start of the observation window this batch covers, ns since Unix epoch.
    pub window_start_ns: u64,
    /// End of the observation window this batch covers, ns since Unix epoch.
    pub window_end_ns: u64,
    /// When the batch was sealed and signed, ns since Unix epoch. The gap
    /// between an observation's reception and this instant is the batching
    /// latency ADR-267 §4 requires evidence to state honestly.
    pub notarized_ns: u64,
    /// Root hash of the previous batch, hex-encoded, or `None` for the first
    /// batch.
    ///
    /// Two jobs: it **chains** consecutive batches into an append-only history
    /// (a gap or a rewrite is detectable), and it is the hook for ADR-267 §3
    /// **re-notarization** — an old root becomes a leaf of a new, possibly
    /// PQ-signed tree, carrying history forward without re-signing a single
    /// observation.
    pub prev_root_hex: Option<String>,
    /// Which algorithm signed this root — self-describing, and covered by the
    /// signature so it cannot be downgraded after the fact.
    pub algorithm: NotaryAlgorithm,
    /// Hex-encoded signature over [`canonical_root_bytes`], if signed.
    pub signature_hex: Option<String>,
    /// Hex-encoded public key of the signer, if signed.
    pub signer_pubkey_hex: Option<String>,
}

/// Produces a signature over a root's canonical bytes. The indirection *is* the
/// shipped feature of ADR-267 §3: adding ML-DSA means adding an implementation
/// of this trait, not changing the notary or the wire format.
pub trait RootSigner {
    /// Which algorithm this signer implements; written into the root's
    /// `algorithm` tag by [`sign_root`].
    fn algorithm(&self) -> NotaryAlgorithm;
    /// Hex-encoded public key, recorded in the root so a verifier can bind the
    /// signature to a key it trusts.
    fn public_hex(&self) -> String;
    /// Sign canonical root bytes, returning a hex-encoded signature.
    fn sign(&self, canonical: &[u8]) -> String;
}

/// Checks a signature over a root's canonical bytes. The counterpart of
/// [`RootSigner`]; a 2040 auditor holds only this half (ADR-267 §3).
pub trait RootVerifier {
    /// Which algorithm this verifier understands. [`verify_root`] refuses to
    /// check a root that declares a different one.
    fn algorithm(&self) -> NotaryAlgorithm;
    /// Verify `sig_hex` over `canonical` under `pubkey_hex`. Malformed hex,
    /// wrong lengths and bad keys all return `false` — a verifier reading
    /// decades-old archived bytes must never panic.
    fn verify(&self, canonical: &[u8], sig_hex: &str, pubkey_hex: &str) -> bool;
}

/// Deterministic ed25519 root signer derived from a 32-byte seed — the v0.1
/// implementation of [`RootSigner`] (ADR-267 §3, shipped item 3).
///
/// Mirrors `rufield-provenance::Signer`: same seed ⇒ same key ⇒ same
/// signatures. No RNG is used anywhere.
pub struct Ed25519RootSigner {
    key: SigningKey,
}

impl Ed25519RootSigner {
    /// Construct from a fixed 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Ed25519RootSigner {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// Hex-encoded ed25519 public key of this signer.
    #[must_use]
    pub fn public_hex(&self) -> String {
        hex_encode(self.key.verifying_key().as_bytes())
    }
}

impl RootSigner for Ed25519RootSigner {
    fn algorithm(&self) -> NotaryAlgorithm {
        NotaryAlgorithm::Ed25519
    }

    fn public_hex(&self) -> String {
        Ed25519RootSigner::public_hex(self)
    }

    fn sign(&self, canonical: &[u8]) -> String {
        let sig: Signature = self.key.sign(canonical);
        hex_encode(&sig.to_bytes())
    }
}

/// Stateless ed25519 [`RootVerifier`] — holds no key material; the trusted key
/// is supplied per verification (ADR-267 §3, shipped item 3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ed25519RootVerifier;

impl Ed25519RootVerifier {
    /// Construct the verifier.
    #[must_use]
    pub fn new() -> Self {
        Ed25519RootVerifier
    }
}

impl RootVerifier for Ed25519RootVerifier {
    fn algorithm(&self) -> NotaryAlgorithm {
        NotaryAlgorithm::Ed25519
    }

    fn verify(&self, canonical: &[u8], sig_hex: &str, pubkey_hex: &str) -> bool {
        let Some(pk_arr) = hex_decode(pubkey_hex).and_then(|b| <[u8; 32]>::try_from(b).ok()) else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else {
            return false;
        };
        let Some(sig_arr) =
            hex_decode(sig_hex).and_then(|b| <[u8; ED25519_SIGNATURE_BYTES]>::try_from(b).ok())
        else {
            return false;
        };
        vk.verify(canonical, &Signature::from_bytes(&sig_arr))
            .is_ok()
    }
}

/// The exact bytes a root signature covers: the root serialized as JSON with
/// `signature_hex` and `signer_pubkey_hex` cleared.
///
/// Every content field — including `algorithm`, `leaf_count`, the window, and
/// `prev_root_hex` — is therefore signed, but the signature never covers
/// itself. Same house rule as `rufield-provenance` and
/// `rucelium-calibration::authority`.
#[must_use]
pub fn canonical_root_bytes(root: &NotaryRoot) -> Vec<u8> {
    let mut r = root.clone();
    r.signature_hex = None;
    r.signer_pubkey_hex = None;
    canonical_json(&r)
}

/// Sign a root in place (ADR-267 §3).
///
/// Clears any existing signature, stamps `algorithm` from the signer — the
/// signer is authoritative for the tag, so a root can never advertise an
/// algorithm other than the one that actually signed it — then fills in
/// `signature_hex` and `signer_pubkey_hex`.
pub fn sign_root(root: &mut NotaryRoot, signer: &dyn RootSigner) {
    root.signature_hex = None;
    root.signer_pubkey_hex = None;
    root.algorithm = signer.algorithm();
    let canonical = canonical_root_bytes(root);
    root.signature_hex = Some(signer.sign(&canonical));
    root.signer_pubkey_hex = Some(signer.public_hex());
}

/// Verify a root's signature (ADR-267 §3).
///
/// Returns `false` unless **all** of:
///
/// - the root declares the same [`NotaryAlgorithm`] the verifier implements — a
///   root must never be checked under an algorithm other than the one it
///   claims, or a future ML-DSA root could be silently "verified" by a
///   downgraded ed25519 path;
/// - both `signature_hex` and `signer_pubkey_hex` are present;
/// - the signature verifies over [`canonical_root_bytes`].
///
/// Binding the signature to a *trusted* key is a separate decision, made by
/// [`crate::verify_bundle`].
#[must_use]
pub fn verify_root(root: &NotaryRoot, verifier: &dyn RootVerifier) -> bool {
    if root.algorithm != verifier.algorithm() {
        return false;
    }
    let (Some(sig), Some(pk)) = (root.signature_hex.as_ref(), root.signer_pubkey_hex.as_ref())
    else {
        return false;
    };
    verifier.verify(&canonical_root_bytes(root), sig, pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A named single-field tamper applied to a signed root.
    type Mutation = (&'static str, fn(&mut NotaryRoot));

    pub(crate) const SEED: &[u8; 32] = b"rucelium-notary-test-seed-32byte";
    pub(crate) const OTHER_SEED: &[u8; 32] = b"rucelium-notary-other-seed-32byt";

    /// A stub verifier that declares ML-DSA-44 and accepts everything. It
    /// exists solely to prove that [`verify_root`]'s algorithm check fires
    /// *before* any signature math: if the check were missing, this verifier
    /// would happily "verify" an ed25519 root.
    struct AlwaysOkMlDsaVerifier;
    impl RootVerifier for AlwaysOkMlDsaVerifier {
        fn algorithm(&self) -> NotaryAlgorithm {
            NotaryAlgorithm::MlDsa44
        }
        fn verify(&self, _canonical: &[u8], _sig_hex: &str, _pubkey_hex: &str) -> bool {
            true
        }
    }

    pub(crate) fn root() -> NotaryRoot {
        NotaryRoot {
            spec_version: rucelium_core::SPEC_VERSION.into(),
            biome_id: "biome/thames-estuary".into(),
            batch_id: 7,
            root_hex: crate::hex_encode(&crate::leaf_hash(b"batch")),
            leaf_count: 4096,
            window_start_ns: 1_000,
            window_end_ns: 2_000,
            notarized_ns: 2_100,
            prev_root_hex: Some(crate::hex_encode(&crate::leaf_hash(b"prev"))),
            algorithm: NotaryAlgorithm::Ed25519,
            signature_hex: None,
            signer_pubkey_hex: None,
        }
    }

    #[test]
    fn algorithm_wire_names_match_the_adr() {
        assert_eq!(NotaryAlgorithm::Ed25519.as_str(), "ed25519");
        assert_eq!(NotaryAlgorithm::MlDsa44.as_str(), "ml-dsa-44");
        assert_eq!(
            NotaryAlgorithm::HybridEd25519MlDsa44.as_str(),
            "hybrid-ed25519+ml-dsa-44"
        );
        for a in [
            NotaryAlgorithm::Ed25519,
            NotaryAlgorithm::MlDsa44,
            NotaryAlgorithm::HybridEd25519MlDsa44,
        ] {
            let json = serde_json::to_string(&a).unwrap();
            assert_eq!(json, format!("\"{}\"", a.as_str()));
            assert_eq!(serde_json::from_str::<NotaryAlgorithm>(&json).unwrap(), a);
            assert_eq!(a.to_string(), a.as_str());
        }
    }

    #[test]
    fn sign_verify_round_trip_and_serde() {
        let signer = Ed25519RootSigner::from_seed(SEED);
        let mut r = root();
        sign_root(&mut r, &signer);
        assert_eq!(r.algorithm, NotaryAlgorithm::Ed25519);
        assert_eq!(r.signer_pubkey_hex.as_deref(), Some(&*signer.public_hex()));
        assert_eq!(
            r.signature_hex.as_ref().map(String::len),
            Some(ED25519_SIGNATURE_BYTES * 2)
        );
        assert!(verify_root(&r, &Ed25519RootVerifier::new()));

        let json = serde_json::to_string(&r).unwrap();
        let back: NotaryRoot = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
        assert!(verify_root(&back, &Ed25519RootVerifier));
    }

    #[test]
    fn signing_is_deterministic() {
        let mut a = root();
        let mut b = root();
        sign_root(&mut a, &Ed25519RootSigner::from_seed(SEED));
        sign_root(&mut b, &Ed25519RootSigner::from_seed(SEED));
        assert_eq!(a, b);
        // Re-signing clears the old fields first, so it is idempotent.
        sign_root(&mut a, &Ed25519RootSigner::from_seed(SEED));
        assert_eq!(a, b);
    }

    #[test]
    fn every_content_field_is_covered_by_the_signature() {
        let signer = Ed25519RootSigner::from_seed(SEED);
        let v = Ed25519RootVerifier::new();
        let signed = {
            let mut r = root();
            sign_root(&mut r, &signer);
            r
        };
        assert!(verify_root(&signed, &v));

        let mutations: Vec<Mutation> = vec![
            ("root_hex", |r| r.root_hex = crate::hex_encode(&[9u8; 32])),
            ("leaf_count", |r| r.leaf_count += 1),
            ("biome_id", |r| r.biome_id = "biome/elsewhere".into()),
            ("window_start_ns", |r| r.window_start_ns += 1),
            ("window_end_ns", |r| r.window_end_ns += 1),
            ("notarized_ns", |r| r.notarized_ns += 1),
            ("batch_id", |r| r.batch_id += 1),
            ("prev_root_hex", |r| r.prev_root_hex = None),
            ("spec_version", |r| r.spec_version = "bogus.v9".into()),
            ("signature_hex", |r| {
                r.signature_hex = Some(crate::hex_encode(&[0u8; ED25519_SIGNATURE_BYTES]));
            }),
            ("signer_pubkey_hex", |r| {
                r.signer_pubkey_hex = Some(crate::hex_encode(&[0u8; 32]));
            }),
        ];
        for (name, mutate) in mutations {
            let mut tampered = signed.clone();
            mutate(&mut tampered);
            assert!(
                !verify_root(&tampered, &v),
                "{name} mutation still verified"
            );
        }

        // The algorithm tag is signed too: flipping it fails on the algorithm
        // check *and* would fail on the bytes.
        let mut tampered = signed;
        tampered.algorithm = NotaryAlgorithm::MlDsa44;
        assert!(!verify_root(&tampered, &v));
    }

    #[test]
    fn verify_rejects_an_algorithm_mismatch_before_checking_bytes() {
        let mut r = root();
        sign_root(&mut r, &Ed25519RootSigner::from_seed(SEED));
        // The stub verifier accepts any bytes, so only the algorithm check can
        // reject this ed25519 root.
        assert!(!verify_root(&r, &AlwaysOkMlDsaVerifier));
        // Same root, matching verifier: accepted.
        assert!(verify_root(&r, &Ed25519RootVerifier));
    }

    #[test]
    fn unsigned_or_half_signed_roots_do_not_verify() {
        let v = Ed25519RootVerifier::new();
        assert!(!verify_root(&root(), &v)); // no signature at all

        let mut r = root();
        sign_root(&mut r, &Ed25519RootSigner::from_seed(SEED));
        let mut half = r.clone();
        half.signature_hex = None;
        assert!(!verify_root(&half, &v));
        let mut half = r;
        half.signer_pubkey_hex = None;
        assert!(!verify_root(&half, &v));
    }

    #[test]
    fn malformed_encodings_return_false_and_never_panic() {
        let v = Ed25519RootVerifier::new();
        let mut r = root();
        sign_root(&mut r, &Ed25519RootSigner::from_seed(SEED));

        for bad_sig in ["", "zz", "abc", &crate::hex_encode(&[0u8; 10])] {
            let mut t = r.clone();
            t.signature_hex = Some(bad_sig.to_string());
            assert!(!verify_root(&t, &v));
        }
        for bad_pk in ["", "zz", "00ff", &crate::hex_encode(&[0xffu8; 32])] {
            let mut t = r.clone();
            t.signer_pubkey_hex = Some(bad_pk.to_string());
            assert!(!verify_root(&t, &v));
        }
    }

    #[test]
    fn a_different_key_does_not_verify() {
        let mut r = root();
        sign_root(&mut r, &Ed25519RootSigner::from_seed(SEED));
        let other = Ed25519RootSigner::from_seed(OTHER_SEED);
        assert_ne!(other.public_hex(), r.signer_pubkey_hex.clone().unwrap());
        let mut swapped = r;
        swapped.signer_pubkey_hex = Some(other.public_hex());
        assert!(!verify_root(&swapped, &Ed25519RootVerifier::new()));
    }

    #[test]
    fn canonical_bytes_exclude_the_signature_fields() {
        let signer = Ed25519RootSigner::from_seed(SEED);
        let unsigned = root();
        let before = canonical_root_bytes(&unsigned);
        let mut signed = unsigned;
        sign_root(&mut signed, &signer);
        assert_eq!(before, canonical_root_bytes(&signed));
        let text = String::from_utf8(before).unwrap();
        assert!(text.contains("\"algorithm\":\"ed25519\""));
        assert!(text.contains("\"signature_hex\":null"));
    }
}
