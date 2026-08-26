//! # rucelium-notary
//!
//! Long-term provenance for RuCelium: a gateway-side **Merkle notary** that
//! makes environmental evidence verifiable decades after it was collected
//! (ADR-267).
//!
//! ## Why this crate exists (ADR-267 §1–§2)
//!
//! A spore node signs every observation with ed25519 so the gateway can answer
//! *"is this packet from this device, unmodified?"* right now. That signature
//! is cheap enough for a duty-cycled sub-GHz radio (64 bytes, 3 LoRaWAN DR0
//! datagrams) but it is **not durable**: a cryptographically relevant quantum
//! computer breaks ECC, and a signature that cannot be trusted in 2040
//! retroactively destroys the evidentiary value of data collected in 2026.
//!
//! Signing each observation with ML-DSA-44 instead is infeasible at the sensor
//! boundary — 2,420-byte signatures plus a 1,312-byte public key would need
//! ~49 datagrams per reading (ADR-267 §1). So ADR-267 splits the two jobs a
//! signature does today:
//!
//! 1. **Authenticity now** stays ed25519, per observation, at the node.
//! 2. **Verifiability later** moves here: the gateway accumulates accepted
//!    observations into a domain-separated Merkle tree and signs only the
//!    **root**. One expensive signature amortizes across the whole batch —
//!    a 4,096-leaf batch under a 2,420-byte ML-DSA-44 signature costs
//!    **0.6 bytes per observation** (see the amortization test).
//!
//! ## What v0.1 ships (ADR-267 §3, implementation-status items 1–4)
//!
//! - [`tree`] — a binary Merkle tree over `sha256` with domain-separated leaf
//!   (`0x00`) and interior (`0x01`) hashing, deterministic batch construction,
//!   inclusion proofs, and a **stateless** [`verify_inclusion`] a third party
//!   can run with no access to the gateway.
//! - [`root`] — the [`RootSigner`] / [`RootVerifier`] trait pair plus the
//!   self-describing [`NotaryAlgorithm`] tag recorded *inside* the signed root,
//!   so swapping in ML-DSA is a configuration change, not a protocol break.
//! - [`bundle`] — the [`Notary`] accumulator, [`Ed25519RootSigner`]-signed
//!   batches, the third-party [`EvidenceBundle`] and its 2040 auditor function
//!   [`verify_bundle`], and [`renotarize`] for chaining old roots forward into
//!   a new (potentially stronger) tree.
//!
//! **Honest label (ADR-267 §3):** RuCelium is *post-quantum ready*, not
//! post-quantum. No ML-DSA implementation ships here — that needs a vetted,
//! ideally FIPS-validated implementation. What ships is the architecture that
//! makes the swap cheap, plus the amortization that makes it affordable.
//!
//! ## Determinism
//!
//! Nothing in this crate reads a clock or an RNG. Callers pass `now_ns` /
//! window bounds explicitly, and ed25519 (RFC 8032) is deterministic, so the
//! same inputs always produce byte-identical roots and signatures.

#![doc(html_root_url = "https://docs.rs/rucelium-notary/0.1.0")]
#![deny(missing_docs)]

pub mod bundle;
pub mod root;
pub mod tree;

pub use bundle::{renotarize, verify_bundle, EvidenceBundle, Notary, NotaryError, SealedBatch};
pub use root::{
    canonical_root_bytes, sign_root, verify_root, Ed25519RootSigner, Ed25519RootVerifier,
    NotaryAlgorithm, NotaryRoot, RootSigner, RootVerifier, ED25519_SIGNATURE_BYTES,
    ML_DSA_44_PUBLIC_KEY_BYTES, ML_DSA_44_SIGNATURE_BYTES,
};
pub use tree::{
    empty_root, leaf_hash, node_hash, verify_inclusion, InclusionProof, MerkleTree, EMPTY_DOMAIN,
    EMPTY_TREE_LABEL, LEAF_DOMAIN, NODE_DOMAIN,
};

/// Lowercase-hex encoding of arbitrary bytes — the encoding used by every
/// `*_hex` field in this crate (matching `rufield-provenance` house style).
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Decode hex into bytes. Returns `None` for an odd length or a non-hex digit —
/// callers map that to an encoding error rather than panicking, because an
/// evidence bundle read in 2040 may be arbitrarily corrupt (ADR-267 §3).
#[must_use]
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Decode exactly 32 hex-encoded bytes (a `sha256` digest: a leaf hash or a
/// Merkle root). Returns `None` unless the input is valid hex of exactly 64
/// characters.
#[must_use]
pub fn hex_decode32(s: &str) -> Option<[u8; 32]> {
    hex_decode(s).and_then(|b| b.try_into().ok())
}

/// Canonical JSON bytes of any serializable value — the byte string this crate
/// hashes into leaves and signs as roots (ADR-267 §3).
///
/// The domain types involved (`EnvSample`, `EnvironmentalEvent`, [`NotaryRoot`])
/// are plain data whose `serde_json` encoding cannot fail: `serde_json` encodes
/// a non-finite `f64` as `null` rather than erroring. Should an unrepresentable
/// value ever appear, this degrades to empty bytes — producing a leaf that
/// simply fails to verify — instead of panicking inside a notary that may be
/// running unattended on a gateway.
pub(crate) fn canonical_json<T: serde::Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_rejects_malformed() {
        let bytes = [0x00u8, 0x0f, 0xff, 0xa5];
        assert_eq!(hex_encode(&bytes), "000fffa5");
        assert_eq!(hex_decode("000fffa5").unwrap(), bytes);
        assert!(hex_decode("abc").is_none()); // odd length
        assert!(hex_decode("zz").is_none()); // not hex
        assert!(hex_decode32("00").is_none()); // wrong length
        assert_eq!(hex_decode32(&hex_encode(&[7u8; 32])).unwrap(), [7u8; 32]);
    }
}
