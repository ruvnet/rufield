//! # rufield-provenance
//!
//! Provenance receipts for RuField MFS (ADR-260 §11). Provides real
//! `sha256` hashing of feature / firmware / model / calibration material and
//! `ed25519` detached signatures over [`FieldEvent`]s, plus the §11
//! fusability invariant:
//!
//! > No fused inference is valid unless every contributing event has a
//! > provenance receipt **or** is explicitly marked synthetic.
//!
//! Signing is **deterministic**: ed25519 (RFC 8032) produces the same
//! signature for the same key + message, and [`Signer`] derives its key
//! deterministically from a 32-byte seed. No RNG is used anywhere, so the same
//! input always yields the same receipt — a requirement for the deterministic
//! benchmark.

#![doc(html_root_url = "https://docs.rs/rufield-provenance/0.1.0")]

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rufield_core::FieldEvent;
use sha2::{Digest, Sha256};

/// Compute a `sha256:<hex>` digest over arbitrary bytes (firmware image, raw
/// measurement, model weights, calibration data).
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut s = String::from("sha256:");
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A fully materialized provenance receipt: the four content hashes plus an
/// optional detached signature over the event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceReceipt {
    /// `sha256:` of the raw measurement / feature bytes.
    pub raw_hash: String,
    /// `sha256:` of the producing firmware image.
    pub firmware_hash: String,
    /// Model identifier (not hashed — an opaque id).
    pub model_id: String,
    /// `sha256:` of the calibration data.
    pub calibration_hash: String,
    /// Hex-encoded ed25519 signature over the canonical event bytes.
    pub signature_hex: Option<String>,
    /// Hex-encoded ed25519 public key of the signer.
    pub signer_pubkey_hex: Option<String>,
}

/// Errors raised while signing/verifying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceError {
    /// Event JSON could not be produced.
    Serialize(String),
    /// Signature or key bytes were malformed hex / wrong length.
    BadEncoding(String),
    /// The signature did not verify against the event + key.
    VerifyFailed,
    /// No signature was present where one was required.
    MissingSignature,
}

impl std::fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvenanceError::Serialize(m) => write!(f, "serialize failed: {m}"),
            ProvenanceError::BadEncoding(m) => write!(f, "bad encoding: {m}"),
            ProvenanceError::VerifyFailed => write!(f, "signature verification failed"),
            ProvenanceError::MissingSignature => write!(f, "missing signature"),
        }
    }
}

impl std::error::Error for ProvenanceError {}

/// Canonical bytes that get signed for an event: we sign the event with its
/// own signature fields cleared, so the signature covers the immutable content
/// (including the tensor values, observation, and hashes) but not itself.
fn canonical_event_bytes(event: &FieldEvent) -> Result<Vec<u8>, ProvenanceError> {
    let mut ev = event.clone();
    ev.provenance.signature_hex = None;
    ev.provenance.signer_pubkey_hex = None;
    serde_json::to_vec(&ev).map_err(|e| ProvenanceError::Serialize(e.to_string()))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ProvenanceError> {
    if !s.len().is_multiple_of(2) {
        return Err(ProvenanceError::BadEncoding("odd hex length".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| ProvenanceError::BadEncoding(e.to_string()))
        })
        .collect()
}

/// A deterministic ed25519 signer derived from a 32-byte seed.
pub struct Signer {
    key: SigningKey,
}

impl Signer {
    /// Construct a signer from a fixed 32-byte seed. Same seed ⇒ same key ⇒
    /// same signatures (deterministic).
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Signer {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// Hex-encoded public key.
    #[must_use]
    pub fn public_hex(&self) -> String {
        hex_encode(self.key.verifying_key().as_bytes())
    }

    /// Sign an event in place, populating its `signature_hex` and
    /// `signer_pubkey_hex` provenance fields.
    pub fn sign_event(&self, event: &mut FieldEvent) -> Result<(), ProvenanceError> {
        let bytes = canonical_event_bytes(event)?;
        let sig: Signature = self.key.sign(&bytes);
        event.provenance.signature_hex = Some(hex_encode(&sig.to_bytes()));
        event.provenance.signer_pubkey_hex = Some(self.public_hex());
        Ok(())
    }
}

/// Verify the ed25519 signature carried on an event. Returns `Ok(())` only if
/// a signature + pubkey are present and verify over the canonical bytes.
pub fn verify_event(event: &FieldEvent) -> Result<(), ProvenanceError> {
    let sig_hex = event
        .provenance
        .signature_hex
        .as_ref()
        .ok_or(ProvenanceError::MissingSignature)?;
    let pk_hex = event
        .provenance
        .signer_pubkey_hex
        .as_ref()
        .ok_or(ProvenanceError::MissingSignature)?;

    let pk_bytes = hex_decode(pk_hex)?;
    let pk_arr: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| ProvenanceError::BadEncoding("pubkey not 32 bytes".into()))?;
    let vk = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| ProvenanceError::BadEncoding(e.to_string()))?;

    let sig_bytes = hex_decode(sig_hex)?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| ProvenanceError::BadEncoding("signature not 64 bytes".into()))?;
    let sig = Signature::from_bytes(&sig_arr);

    let msg = canonical_event_bytes(event)?;
    vk.verify(&msg, &sig)
        .map_err(|_| ProvenanceError::VerifyFailed)
}

/// The §11 fusability invariant. An event may be fused into an inference iff it
/// is explicitly marked `synthetic` **or** it carries a signature that verifies.
#[must_use]
pub fn is_fusable(event: &FieldEvent) -> bool {
    if event.provenance.synthetic {
        return true;
    }
    verify_event(event).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rufield_core::{
        FieldAxis, FieldTensor, Modality, Observation, PrivacyClass, ProvenanceRef,
        SensorDescriptor,
    };

    fn sample_event() -> FieldEvent {
        let tensor = FieldTensor::new(
            42,
            Modality::WifiCsi,
            vec![FieldAxis::Frequency],
            vec![3],
            vec![1.0, 2.0, 3.0],
            0.9,
            0.01,
            Some("cal".into()),
            PrivacyClass::P2,
        )
        .unwrap();
        FieldEvent::new(
            "ev-1",
            42,
            SensorDescriptor {
                modality: "wifi_csi".into(),
                vendor: "esp32_c6".into(),
                device_id: "d1".into(),
                placement: "corner".into(),
                clock_domain: "local".into(),
            },
            tensor,
            Observation::occupancy(0.9, PrivacyClass::P2),
            ProvenanceRef {
                raw_hash: sha256_hex(b"raw"),
                firmware_hash: sha256_hex(b"fw"),
                model_id: "m1".into(),
                calibration_id: "cal".into(),
                synthetic: false,
                signature_hex: None,
                signer_pubkey_hex: None,
            },
        )
    }

    #[test]
    fn sha256_is_real_and_stable() {
        // Known vector: sha256("") = e3b0c442...
        assert_eq!(
            sha256_hex(b""),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(sha256_hex(b"abc"), sha256_hex(b"abc"));
        assert_ne!(sha256_hex(b"abc"), sha256_hex(b"abd"));
    }

    #[test]
    fn sign_then_verify_ok() {
        let signer = Signer::from_seed(b"rufield-test-seed-32-bytes-long!");
        let mut ev = sample_event();
        signer.sign_event(&mut ev).unwrap();
        assert!(verify_event(&ev).is_ok());
        assert!(is_fusable(&ev));
    }

    #[test]
    fn tamper_breaks_signature() {
        let signer = Signer::from_seed(b"rufield-test-seed-32-bytes-long!");
        let mut ev = sample_event();
        signer.sign_event(&mut ev).unwrap();
        // Tamper a tensor value after signing.
        ev.tensor.values[0] = 99.0;
        assert!(verify_event(&ev).is_err());
        assert!(!is_fusable(&ev)); // not synthetic, signature broken ⇒ not fusable
    }

    #[test]
    fn synthetic_event_is_fusable_without_signer() {
        let mut ev = sample_event();
        ev.provenance.synthetic = true;
        // No signature at all.
        assert!(ev.provenance.signature_hex.is_none());
        assert!(is_fusable(&ev));
    }

    #[test]
    fn unsigned_non_synthetic_is_not_fusable() {
        let ev = sample_event(); // synthetic=false, unsigned
        assert!(!is_fusable(&ev));
    }

    #[test]
    fn signing_is_deterministic() {
        let signer = Signer::from_seed(b"rufield-test-seed-32-bytes-long!");
        let mut a = sample_event();
        let mut b = sample_event();
        signer.sign_event(&mut a).unwrap();
        signer.sign_event(&mut b).unwrap();
        assert_eq!(a.provenance.signature_hex, b.provenance.signature_hex);
    }
}
