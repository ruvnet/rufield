//! Device signing over the wire payload (ADR-264 §11.2 / §12).
//!
//! ed25519 detached signatures over the exact 48 payload bytes, carried in
//! the [`SignedEnvRecordV1`] envelope. Signing is deterministic (RFC 8032):
//! same key + payload ⇒ same signature — required by the deterministic
//! benchmark, and matching `rufield-provenance`'s posture.

use crate::cbor::SignedEnvRecordV1;
use crate::wire::{RvEnvSampleV1, RV_ENV_SAMPLE_V1_WIRE_LEN};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;

/// Signature-layer errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// The embedded public key bytes were not a valid ed25519 point.
    BadKey,
    /// The signature did not verify over the payload.
    VerifyFailed,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignError::BadKey => write!(f, "invalid ed25519 public key"),
            SignError::VerifyFailed => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for SignError {}

/// A deterministic per-device signer, as run by spore-node firmware (in v0.1,
/// by the synthetic node simulator).
pub struct NodeSigner {
    key: SigningKey,
}

impl NodeSigner {
    /// Construct from a fixed 32-byte seed. Same seed ⇒ same key.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        NodeSigner {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// Derive a device key deterministically from a provisioning seed and the
    /// device id: `sha256(provision_seed || node_id_le)`. This mirrors how a
    /// provisioning ceremony hands each spore node a unique key.
    #[must_use]
    pub fn for_node(provision_seed: &[u8; 32], node_id: u64) -> Self {
        let mut h = Sha256::new();
        h.update(provision_seed);
        h.update(node_id.to_le_bytes());
        let digest: [u8; 32] = h.finalize().into();
        Self::from_seed(&digest)
    }

    /// The verifying (public) key bytes, as registered with the gateway.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Hex-encoded public key (the form `SampleProvenance` carries).
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.public_key() {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// Sign a wire sample: encode to the packed 48-byte payload, sign those
    /// exact bytes, and wrap in the envelope.
    #[must_use]
    pub fn sign_sample(&self, sample: &RvEnvSampleV1) -> SignedEnvRecordV1 {
        sign_payload(self, &sample.encode())
    }
}

/// Sign an exact 48-byte payload.
#[must_use]
pub fn sign_payload(
    signer: &NodeSigner,
    payload: &[u8; RV_ENV_SAMPLE_V1_WIRE_LEN],
) -> SignedEnvRecordV1 {
    let sig: Signature = signer.key.sign(payload);
    SignedEnvRecordV1 {
        payload: *payload,
        pubkey: signer.public_key(),
        signature: sig.to_bytes(),
    }
}

/// Verify the ed25519 signature carried in an envelope over its payload.
/// This proves the payload is intact and was signed by the embedded key —
/// whether that key belongs to a *registered, unrevoked* device is the
/// ingest pipeline's job (`rucelium-ingest`).
pub fn verify_record(record: &SignedEnvRecordV1) -> Result<(), SignError> {
    let vk = VerifyingKey::from_bytes(&record.pubkey).map_err(|_| SignError::BadKey)?;
    let sig = Signature::from_bytes(&record.signature);
    vk.verify(&record.payload, &sig)
        .map_err(|_| SignError::VerifyFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::RV_ENV_SCHEMA_V1;

    fn sample() -> RvEnvSampleV1 {
        RvEnvSampleV1 {
            schema_version: RV_ENV_SCHEMA_V1,
            sensor_type: 5,
            flags: 0,
            node_id: 11,
            timestamp_ns: 1_000_000,
            sequence: 1,
            latitude_e7: 0,
            longitude_e7: 0,
            altitude_mm: 0,
            value_q16: 65_536,
            quality_q15: 0x8000,
            battery_mv: 3_300,
            calibration_id: 0,
        }
    }

    #[test]
    fn sign_verify_round_trip_through_cbor() {
        let signer = NodeSigner::for_node(b"rucelium-provision-seed-32-byte!", 11);
        let rec = signer.sign_sample(&sample());
        verify_record(&rec).unwrap();
        // Through the CBOR envelope and back.
        let enc = rec.encode();
        let back = SignedEnvRecordV1::decode(&enc).unwrap();
        verify_record(&back).unwrap();
    }

    #[test]
    fn any_payload_tamper_breaks_verification() {
        let signer = NodeSigner::for_node(b"rucelium-provision-seed-32-byte!", 11);
        let rec = signer.sign_sample(&sample());
        for i in 0..RV_ENV_SAMPLE_V1_WIRE_LEN {
            let mut t = rec.clone();
            t.payload[i] ^= 0x01;
            assert_eq!(
                verify_record(&t),
                Err(SignError::VerifyFailed),
                "tampered byte {i} must break the signature"
            );
        }
    }

    #[test]
    fn wrong_key_rejected() {
        let a = NodeSigner::for_node(b"rucelium-provision-seed-32-byte!", 11);
        let b = NodeSigner::for_node(b"rucelium-provision-seed-32-byte!", 12);
        let mut rec = a.sign_sample(&sample());
        rec.pubkey = b.public_key();
        assert!(verify_record(&rec).is_err());
    }

    #[test]
    fn node_key_derivation_is_deterministic_and_unique() {
        let seed = b"rucelium-provision-seed-32-byte!";
        assert_eq!(
            NodeSigner::for_node(seed, 1).public_key(),
            NodeSigner::for_node(seed, 1).public_key()
        );
        assert_ne!(
            NodeSigner::for_node(seed, 1).public_key(),
            NodeSigner::for_node(seed, 2).public_key()
        );
    }
}
