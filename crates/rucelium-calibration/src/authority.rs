//! Calibration authorities: ed25519-signed calibration records and the
//! registry of keys trusted to sign them (ADR-264 §12 items 1–3).
//!
//! Lineage structure alone is not enough — a record's *content* must be
//! attested by a key the operator actually trusts, otherwise anyone who can
//! insert a record can declare an "anchor" simply by writing the right method
//! string. This module provides:
//!
//! - [`CalibrationSigner`] — deterministic ed25519 signing of
//!   [`CalibrationRecord`]s from a 32-byte seed (mirrors
//!   `rufield-provenance::Signer`; no RNG anywhere).
//! - [`verify_record_signature`] — detached-signature verification over the
//!   record's canonical bytes.
//! - [`CalibrationAuthority`] / [`AuthorityRegistry`] — which public keys are
//!   trusted to sign calibrations, optionally scoped per sensor modality.
//!
//! The canonical bytes that get signed are the `serde_json` encoding of the
//! record with its own `signature_hex` / `signer_pubkey_hex` fields cleared,
//! so the signature covers every content field (coefficients, expiry, method,
//! lineage pointers, …) but never itself.

use crate::error::CalibrationError;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rucelium_core::{CalibrationRecord, SensorModality};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Compute a `sha256:<hex>` digest over calibration source material, suitable
/// for a record's `data_hash` field (same format as
/// `rufield-provenance::sha256_hex`).
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

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Canonical bytes that get signed for a calibration record: the record with
/// its own signature fields cleared, serialized as JSON. The signature
/// therefore covers all content fields but not itself.
fn canonical_record_bytes(record: &CalibrationRecord) -> Result<Vec<u8>, CalibrationError> {
    let mut r = record.clone();
    r.signature_hex = None;
    r.signer_pubkey_hex = None;
    serde_json::to_vec(&r).map_err(|e| {
        CalibrationError::Core(rucelium_core::EnvError::Invalid(format!(
            "calibration {} could not be canonicalized: {e}",
            record.calibration_id
        )))
    })
}

/// A calibration authority: a named ed25519 public key trusted to sign
/// calibration records.
///
/// `modalities` scopes the trust: an **empty** set means the authority is
/// trusted for **all** modalities; a non-empty set restricts it to exactly
/// those modalities (e.g. a weather-station operator that must not attest
/// soil-moisture calibrations).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalibrationAuthority {
    /// Human-readable authority name (operator, lab, vendor).
    pub name: String,
    /// Hex-encoded ed25519 public key.
    pub pubkey_hex: String,
    /// Modalities this authority may sign for; empty = all modalities.
    pub modalities: BTreeSet<SensorModality>,
}

/// Registry of [`CalibrationAuthority`]s, keyed by public key.
///
/// Adding an authority with an already-registered `pubkey_hex` replaces the
/// previous entry (last write wins).
#[derive(Debug, Clone, Default)]
pub struct AuthorityRegistry {
    authorities: std::collections::BTreeMap<String, CalibrationAuthority>,
}

impl AuthorityRegistry {
    /// Create an empty registry (trusts no one).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an authority. A repeated `pubkey_hex` replaces the earlier
    /// entry.
    pub fn add(&mut self, authority: CalibrationAuthority) {
        self.authorities
            .insert(authority.pubkey_hex.clone(), authority);
    }

    /// Whether `pubkey_hex` is trusted to sign calibrations for `modality`.
    /// An authority with an empty modality set is trusted for all modalities.
    #[must_use]
    pub fn trusted_for(&self, pubkey_hex: &str, modality: SensorModality) -> bool {
        self.authorities
            .get(pubkey_hex)
            .is_some_and(|a| a.modalities.is_empty() || a.modalities.contains(&modality))
    }

    /// Whether the registry holds no authorities.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.authorities.is_empty()
    }
}

/// A deterministic ed25519 signer for calibration records, derived from a
/// 32-byte seed (mirrors `rufield-provenance::Signer`). Same seed ⇒ same key
/// ⇒ same signatures — no RNG anywhere.
pub struct CalibrationSigner {
    key: SigningKey,
}

impl CalibrationSigner {
    /// Construct a signer from a fixed 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        CalibrationSigner {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// Hex-encoded public key.
    #[must_use]
    pub fn public_hex(&self) -> String {
        hex_encode(self.key.verifying_key().as_bytes())
    }

    /// Sign a record in place: clear its signature fields, sign the canonical
    /// bytes, then populate `signature_hex` and `signer_pubkey_hex`.
    pub fn sign_record(&self, record: &mut CalibrationRecord) -> Result<(), CalibrationError> {
        record.signature_hex = None;
        record.signer_pubkey_hex = None;
        let bytes = canonical_record_bytes(record)?;
        let sig: Signature = self.key.sign(&bytes);
        record.signature_hex = Some(hex_encode(&sig.to_bytes()));
        record.signer_pubkey_hex = Some(self.public_hex());
        Ok(())
    }
}

/// Verify the ed25519 signature carried on a calibration record.
///
/// Fails with [`CalibrationError::MissingSignature`] when either
/// `signature_hex` or `signer_pubkey_hex` is absent, and
/// [`CalibrationError::BadSignature`] when the encoding is malformed or the
/// signature does not verify over the record's canonical bytes.
pub fn verify_record_signature(record: &CalibrationRecord) -> Result<(), CalibrationError> {
    let id = record.calibration_id;
    let sig_hex = record
        .signature_hex
        .as_ref()
        .ok_or(CalibrationError::MissingSignature(id))?;
    let pk_hex = record
        .signer_pubkey_hex
        .as_ref()
        .ok_or(CalibrationError::MissingSignature(id))?;

    let pk_arr: [u8; 32] = hex_decode(pk_hex)
        .and_then(|b| b.try_into().ok())
        .ok_or(CalibrationError::BadSignature(id))?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| CalibrationError::BadSignature(id))?;

    let sig_arr: [u8; 64] = hex_decode(sig_hex)
        .and_then(|b| b.try_into().ok())
        .ok_or(CalibrationError::BadSignature(id))?;
    let sig = Signature::from_bytes(&sig_arr);

    let msg = canonical_record_bytes(record)?;
    vk.verify(&msg, &sig)
        .map_err(|_| CalibrationError::BadSignature(id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rucelium_core::calibration::Q16_ONE;

    const SEED: &[u8; 32] = b"rucelium-cal-test-seed-32-bytes!";

    fn record() -> CalibrationRecord {
        CalibrationRecord {
            calibration_id: 1,
            node_id: 7,
            modality: SensorModality::Weather,
            method: "anchor_reference".into(),
            reference_station: Some("anchor-01".into()),
            parent_id: None,
            created_ns: 1_000,
            expires_ns: 2_000_000,
            scale_q16: Q16_ONE,
            offset_q16: -32_768,
            uncertainty_q16: Q16_ONE / 10,
            data_hash: sha256_hex(b"cal-source-data"),
            signature_hex: None,
            signer_pubkey_hex: None,
        }
    }

    #[test]
    fn sha256_is_real_and_stable() {
        assert_eq!(
            sha256_hex(b""),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(sha256_hex(b"abc"), sha256_hex(b"abc"));
        assert_ne!(sha256_hex(b"abc"), sha256_hex(b"abd"));
    }

    #[test]
    fn sign_then_verify_ok() {
        let signer = CalibrationSigner::from_seed(SEED);
        let mut r = record();
        signer.sign_record(&mut r).unwrap();
        assert_eq!(r.signer_pubkey_hex.as_deref(), Some(&*signer.public_hex()));
        verify_record_signature(&r).unwrap();
    }

    #[test]
    fn unsigned_record_is_missing_signature() {
        let r = record();
        assert_eq!(
            verify_record_signature(&r).unwrap_err(),
            CalibrationError::MissingSignature(1)
        );
        // Half-signed records (only one field present) are also missing.
        let signer = CalibrationSigner::from_seed(SEED);
        let mut half = record();
        signer.sign_record(&mut half).unwrap();
        half.signer_pubkey_hex = None;
        assert_eq!(
            verify_record_signature(&half).unwrap_err(),
            CalibrationError::MissingSignature(1)
        );
        let mut half = record();
        signer.sign_record(&mut half).unwrap();
        half.signature_hex = None;
        assert_eq!(
            verify_record_signature(&half).unwrap_err(),
            CalibrationError::MissingSignature(1)
        );
    }

    #[test]
    fn changing_any_content_field_breaks_the_signature() {
        let signer = CalibrationSigner::from_seed(SEED);

        let mut r = record();
        signer.sign_record(&mut r).unwrap();
        r.scale_q16 += 1;
        assert_eq!(
            verify_record_signature(&r).unwrap_err(),
            CalibrationError::BadSignature(1)
        );

        let mut r = record();
        signer.sign_record(&mut r).unwrap();
        r.expires_ns += 1;
        assert_eq!(
            verify_record_signature(&r).unwrap_err(),
            CalibrationError::BadSignature(1)
        );

        let mut r = record();
        signer.sign_record(&mut r).unwrap();
        r.method = "factory".into();
        assert_eq!(
            verify_record_signature(&r).unwrap_err(),
            CalibrationError::BadSignature(1)
        );

        let mut r = record();
        signer.sign_record(&mut r).unwrap();
        r.offset_q16 = 0;
        assert_eq!(
            verify_record_signature(&r).unwrap_err(),
            CalibrationError::BadSignature(1)
        );
    }

    #[test]
    fn malformed_signature_or_key_is_bad_signature() {
        let signer = CalibrationSigner::from_seed(SEED);
        let mut r = record();
        signer.sign_record(&mut r).unwrap();

        let mut bad = r.clone();
        bad.signature_hex = Some("zz".into());
        assert_eq!(
            verify_record_signature(&bad).unwrap_err(),
            CalibrationError::BadSignature(1)
        );

        let mut bad = r.clone();
        bad.signer_pubkey_hex = Some("00ff".into()); // not 32 bytes
        assert_eq!(
            verify_record_signature(&bad).unwrap_err(),
            CalibrationError::BadSignature(1)
        );

        let mut bad = r;
        bad.signature_hex = Some("abc".into()); // odd hex length
        assert_eq!(
            verify_record_signature(&bad).unwrap_err(),
            CalibrationError::BadSignature(1)
        );
    }

    #[test]
    fn signing_is_deterministic() {
        let mut a = record();
        let mut b = record();
        CalibrationSigner::from_seed(SEED)
            .sign_record(&mut a)
            .unwrap();
        CalibrationSigner::from_seed(SEED)
            .sign_record(&mut b)
            .unwrap();
        assert_eq!(a.signature_hex, b.signature_hex);
        assert_eq!(a.signer_pubkey_hex, b.signer_pubkey_hex);
        // Re-signing an already-signed record clears the old fields first, so
        // the result is identical too.
        CalibrationSigner::from_seed(SEED)
            .sign_record(&mut a)
            .unwrap();
        assert_eq!(a.signature_hex, b.signature_hex);
    }

    #[test]
    fn registry_scopes_trust_by_modality() {
        let mut reg = AuthorityRegistry::new();
        assert!(reg.is_empty());
        assert!(!reg.trusted_for("00", SensorModality::Weather));

        // Empty modality set = trusted for everything.
        reg.add(CalibrationAuthority {
            name: "global-lab".into(),
            pubkey_hex: "aa".into(),
            modalities: BTreeSet::new(),
        });
        // Scoped authority: Weather only.
        reg.add(CalibrationAuthority {
            name: "weather-op".into(),
            pubkey_hex: "bb".into(),
            modalities: BTreeSet::from([SensorModality::Weather]),
        });
        assert!(!reg.is_empty());
        for m in SensorModality::ALL {
            assert!(reg.trusted_for("aa", m));
        }
        assert!(reg.trusted_for("bb", SensorModality::Weather));
        assert!(!reg.trusted_for("bb", SensorModality::SoilMoisture));
        assert!(!reg.trusted_for("cc", SensorModality::Weather));

        // Re-adding the same pubkey replaces the entry.
        reg.add(CalibrationAuthority {
            name: "weather-op-v2".into(),
            pubkey_hex: "bb".into(),
            modalities: BTreeSet::from([SensorModality::SoilMoisture]),
        });
        assert!(!reg.trusted_for("bb", SensorModality::Weather));
        assert!(reg.trusted_for("bb", SensorModality::SoilMoisture));
    }
}
