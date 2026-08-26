//! Compact signed envelope v2: pubkey **by reference** (ADR-265 §2).
//!
//! The v1 envelope carries the signer's 32-byte ed25519 public key on every
//! message. On a constrained uplink that is pure overhead: the gateway
//! already holds the device registry keyed by the `node_id` embedded in the
//! 48-byte payload, so it can look the key up. Dropping the pubkey — and
//! replacing CBOR framing with a packed 2-byte header — shrinks the envelope
//! from 151 encoded bytes to a fixed **114**:
//!
//! ```text
//! [0]        magic   = 0xC2
//! [1]        version = 2
//! [2..50]    payload   (48-byte packed rv_env_sample_v1 wire record)
//! [50..114]  signature (64-byte ed25519 detached signature over payload)
//! ```
//!
//! The signature is over the *exact same 48 payload bytes* as v1, so a
//! compact envelope rehydrated with the registry key ([`to_v1`]) verifies
//! under the unchanged v1 rules — the ingest pipeline downstream never
//! notices the wire format changed. Note 114 bytes still exceeds a single
//! LoRaWAN DR0 datagram (51 bytes); the [`crate::frag`] layer handles that.

use crate::TransportError;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use rucelium_abi::{sign_payload, NodeSigner, SignedEnvRecordV1, RV_ENV_SAMPLE_V1_WIRE_LEN};

/// Magic byte identifying a compact envelope v2.
pub const COMPACT_ENV_MAGIC: u8 = 0xC2;

/// Version byte of the compact envelope (2 — v1 is the CBOR envelope).
pub const COMPACT_ENV_VERSION: u8 = 2;

/// Exact serialized length of a compact envelope v2:
/// `2 (header) + 48 (payload) + 64 (signature) = 114`.
pub const COMPACT_ENV_V2_LEN: usize = 2 + RV_ENV_SAMPLE_V1_WIRE_LEN + 64;

/// Offset of the payload within the encoded envelope.
const PAYLOAD_OFF: usize = 2;
/// Offset of the signature within the encoded envelope.
const SIG_OFF: usize = PAYLOAD_OFF + RV_ENV_SAMPLE_V1_WIRE_LEN;

/// Compact signed envelope v2: the 48-byte wire payload and the ed25519
/// signature over exactly those bytes. The signer's public key is *not*
/// carried — verification requires the registry key for the payload's
/// `node_id` ([`verify_compact`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactEnvV2 {
    /// The 48-byte packed `rv_env_sample_v1` payload.
    pub payload: [u8; RV_ENV_SAMPLE_V1_WIRE_LEN],
    /// ed25519 detached signature over `payload` (64 bytes).
    pub signature: [u8; 64],
}

impl CompactEnvV2 {
    /// Encode to the packed 114-byte wire layout.
    #[must_use]
    pub fn encode(&self) -> [u8; COMPACT_ENV_V2_LEN] {
        let mut b = [0u8; COMPACT_ENV_V2_LEN];
        b[0] = COMPACT_ENV_MAGIC;
        b[1] = COMPACT_ENV_VERSION;
        b[PAYLOAD_OFF..SIG_OFF].copy_from_slice(&self.payload);
        b[SIG_OFF..COMPACT_ENV_V2_LEN].copy_from_slice(&self.signature);
        b
    }

    /// Parse a packed compact envelope. Exactly one bounds check (the
    /// length), then magic and version validation; never panics on any
    /// input. Parsing does **not** verify the signature — call
    /// [`verify_compact`] with the registry key before trusting the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() != COMPACT_ENV_V2_LEN {
            return Err(TransportError::WrongLength {
                expected: COMPACT_ENV_V2_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0] != COMPACT_ENV_MAGIC {
            return Err(TransportError::BadMagic(bytes[0]));
        }
        if bytes[1] != COMPACT_ENV_VERSION {
            return Err(TransportError::BadVersion(bytes[1]));
        }
        let mut payload = [0u8; RV_ENV_SAMPLE_V1_WIRE_LEN];
        payload.copy_from_slice(&bytes[PAYLOAD_OFF..SIG_OFF]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[SIG_OFF..COMPACT_ENV_V2_LEN]);
        Ok(CompactEnvV2 { payload, signature })
    }
}

/// Sign a 48-byte wire payload into a compact envelope. Reuses the v1
/// signing path ([`rucelium_abi::sign_payload`]) — same key, same bytes,
/// same deterministic RFC 8032 signature — and drops the pubkey from the
/// result.
#[must_use]
pub fn sign_compact(
    signer: &NodeSigner,
    payload: &[u8; RV_ENV_SAMPLE_V1_WIRE_LEN],
) -> CompactEnvV2 {
    let rec = sign_payload(signer, payload);
    CompactEnvV2 {
        payload: rec.payload,
        signature: rec.signature,
    }
}

/// Verify the envelope's ed25519 signature over its 48 payload bytes using
/// a key supplied *by reference* — the gateway's registry entry for the
/// payload's `node_id`. Proves the payload is intact and was signed by that
/// key; whether the device is registered and unrevoked stays the ingest
/// pipeline's job.
pub fn verify_compact(env: &CompactEnvV2, pubkey: &[u8; 32]) -> Result<(), TransportError> {
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| TransportError::BadKey)?;
    let sig = Signature::from_bytes(&env.signature);
    vk.verify(&env.payload, &sig)
        .map_err(|_| TransportError::BadSignature)
}

/// Rehydrate a compact envelope into a v1 [`SignedEnvRecordV1`] by
/// re-attaching the registry public key, so the existing ingest pipeline is
/// unchanged downstream. This performs no verification itself — ingest
/// re-verifies the record ([`rucelium_abi::verify_record`]), so a wrong key
/// supplied here is caught there.
#[must_use]
pub fn to_v1(env: &CompactEnvV2, pubkey: [u8; 32]) -> SignedEnvRecordV1 {
    SignedEnvRecordV1 {
        payload: env.payload,
        pubkey,
        signature: env.signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rucelium_abi::verify_record;

    const SEED: &[u8; 32] = b"rucelium-provision-seed-32-byte!";

    fn payload() -> [u8; RV_ENV_SAMPLE_V1_WIRE_LEN] {
        let mut p = [0u8; RV_ENV_SAMPLE_V1_WIRE_LEN];
        for (i, b) in p.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        p
    }

    #[test]
    fn sign_encode_parse_verify_round_trip() {
        let signer = NodeSigner::for_node(SEED, 7);
        let env = sign_compact(&signer, &payload());
        let bytes = env.encode();
        assert_eq!(bytes.len(), COMPACT_ENV_V2_LEN);
        assert_eq!(bytes[0], COMPACT_ENV_MAGIC);
        assert_eq!(bytes[1], COMPACT_ENV_VERSION);
        let back = CompactEnvV2::parse(&bytes).unwrap();
        assert_eq!(back, env);
        verify_compact(&back, &signer.public_key()).unwrap();
    }

    #[test]
    fn every_single_byte_tamper_breaks_parse_or_verify() {
        let signer = NodeSigner::for_node(SEED, 7);
        let env = sign_compact(&signer, &payload());
        let bytes = env.encode();
        let pk = signer.public_key();
        for i in 0..COMPACT_ENV_V2_LEN {
            let mut t = bytes;
            t[i] ^= 0x01;
            let broken = match CompactEnvV2::parse(&t) {
                Err(_) => true,
                Ok(parsed) => verify_compact(&parsed, &pk).is_err(),
            };
            assert!(broken, "tampered byte {i} must break parse or verify");
        }
    }

    #[test]
    fn wrong_length_magic_version_rejected() {
        let signer = NodeSigner::for_node(SEED, 7);
        let bytes = sign_compact(&signer, &payload()).encode();
        assert_eq!(
            CompactEnvV2::parse(&bytes[..COMPACT_ENV_V2_LEN - 1]),
            Err(TransportError::WrongLength {
                expected: COMPACT_ENV_V2_LEN,
                actual: COMPACT_ENV_V2_LEN - 1,
            })
        );
        assert!(CompactEnvV2::parse(&[]).is_err());
        let mut bad = bytes;
        bad[0] = 0xC3;
        assert_eq!(
            CompactEnvV2::parse(&bad),
            Err(TransportError::BadMagic(0xC3))
        );
        let mut bad = bytes;
        bad[1] = 1;
        assert_eq!(
            CompactEnvV2::parse(&bad),
            Err(TransportError::BadVersion(1))
        );
    }

    #[test]
    fn wrong_pubkey_is_bad_signature() {
        let a = NodeSigner::for_node(SEED, 7);
        let b = NodeSigner::for_node(SEED, 8);
        let env = sign_compact(&a, &payload());
        assert_eq!(
            verify_compact(&env, &b.public_key()),
            Err(TransportError::BadSignature)
        );
    }

    #[test]
    fn invalid_pubkey_bytes_are_bad_key() {
        // Roughly half of all 32-byte strings fail ed25519 point
        // decompression. Sweep a deterministic family and require that at
        // least one hits the BadKey path (probability of the sweep missing
        // is ~2^-256) and that no other error kind ever appears for the
        // remainder (a wrong-but-valid key must be BadSignature).
        let signer = NodeSigner::for_node(SEED, 7);
        let env = sign_compact(&signer, &payload());
        let mut bad_keys = 0u32;
        for first in 0u8..=255 {
            let mut key = [0x5Au8; 32];
            key[0] = first;
            match verify_compact(&env, &key) {
                Err(TransportError::BadKey) => bad_keys += 1,
                Err(TransportError::BadSignature) => {}
                other => panic!("unexpected result for key sweep: {other:?}"),
            }
        }
        assert!(bad_keys > 0, "sweep must hit at least one invalid point");
    }

    #[test]
    fn to_v1_rehydrates_a_record_the_v1_pipeline_verifies() {
        let signer = NodeSigner::for_node(SEED, 7);
        let env = sign_compact(&signer, &payload());
        let rec = to_v1(&env, signer.public_key());
        verify_record(&rec).unwrap();
        assert_eq!(rec.payload, env.payload);
        assert_eq!(rec.signature, env.signature);
        // And the size arithmetic that motivates v2:
        assert_eq!(rec.encode().len(), 151);
        assert_eq!(COMPACT_ENV_V2_LEN, 114);
    }

    #[test]
    fn to_v1_with_wrong_key_fails_downstream_verification() {
        let a = NodeSigner::for_node(SEED, 7);
        let b = NodeSigner::for_node(SEED, 8);
        let env = sign_compact(&a, &payload());
        assert!(verify_record(&to_v1(&env, b.public_key())).is_err());
    }

    #[test]
    fn parse_never_panics_on_arbitrary_bytes() {
        // Deterministic LCG pseudo-fuzz over lengths 0..=130 (covers the
        // exact 114-byte length too).
        let mut x: u64 = 0xC2C2_0002_DEAD_BEEF;
        for len in 0..=130usize {
            let mut buf = vec![0u8; len];
            for b in &mut buf {
                x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                *b = (x >> 56) as u8;
            }
            let _ = CompactEnvV2::parse(&buf); // must not panic
        }
    }
}
