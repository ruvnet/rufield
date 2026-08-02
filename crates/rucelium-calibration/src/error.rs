//! Error type for calibration lineage, application, and drift handling
//! (ADR-264 §12).

use rucelium_core::EnvError;
use std::fmt;

/// Errors raised while validating calibration lineage or applying a
/// calibration record to a sample. Per ADR-264 §12, every failure is a
/// rejection — nothing is silently repaired.
#[derive(Debug, Clone, PartialEq)]
pub enum CalibrationError {
    /// The referenced calibration record is not in the store.
    UnknownRecord(u32),
    /// A record's `parent_id` points at a record that does not exist.
    BrokenLineage {
        /// The record whose parent link is broken.
        id: u32,
        /// The parent id that could not be resolved.
        missing_parent: u32,
    },
    /// The lineage chain revisited a record (a forged cycle never reaches an
    /// anchor and is rejected, §12 item 1).
    LineageCycle(u32),
    /// A lineage root (`parent_id: None`) whose method is neither `factory`
    /// nor `anchor_reference` — lineage must terminate at a reference-grade
    /// anchor (§12 items 1–3).
    UnanchoredRoot(u32),
    /// The record had expired at the caller-supplied `now_ns`.
    Expired {
        /// The expired record.
        id: u32,
        /// Expiry time, nanoseconds since Unix epoch.
        expires_ns: u64,
        /// The caller-supplied evaluation time.
        now_ns: u64,
    },
    /// The record calibrates a different device than the sample's producer.
    WrongDevice {
        /// The mismatched record.
        id: u32,
        /// Node the record calibrates.
        expected: u64,
        /// Node the sample actually came from.
        actual: u64,
    },
    /// The record applies to a different sensor modality than the sample's.
    WrongModality(u32),
    /// The record carries no signature (or no signer public key) where a
    /// cryptographically verified lineage requires one (§12 items 1–3).
    MissingSignature(u32),
    /// The record's signature (or its encoding) failed to verify over the
    /// record's canonical bytes — the content was tampered with or the
    /// signature is forged.
    BadSignature(u32),
    /// The record's signature verifies, but the signing key is not a
    /// registered authority for the record's modality.
    UntrustedSigner {
        /// The record with the untrusted signer.
        id: u32,
        /// Hex-encoded public key that signed the record.
        signer: String,
    },
    /// A core data-model validation failure (record or sample invariants).
    Core(EnvError),
}

impl fmt::Display for CalibrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CalibrationError::UnknownRecord(id) => {
                write!(f, "unknown calibration record {id}")
            }
            CalibrationError::BrokenLineage { id, missing_parent } => write!(
                f,
                "calibration {id} references missing parent {missing_parent}"
            ),
            CalibrationError::LineageCycle(id) => {
                write!(f, "calibration lineage cycle detected at record {id}")
            }
            CalibrationError::UnanchoredRoot(id) => write!(
                f,
                "calibration root {id} is not anchored \
                 (method must be `factory` or `anchor_reference`)"
            ),
            CalibrationError::Expired {
                id,
                expires_ns,
                now_ns,
            } => write!(f, "calibration {id} expired at {expires_ns} (now {now_ns})"),
            CalibrationError::WrongDevice {
                id,
                expected,
                actual,
            } => write!(
                f,
                "calibration {id} calibrates node {expected}, sample is from node {actual}"
            ),
            CalibrationError::WrongModality(id) => {
                write!(
                    f,
                    "calibration {id} does not apply to the sample's modality"
                )
            }
            CalibrationError::MissingSignature(id) => {
                write!(f, "calibration {id} is unsigned (signature required)")
            }
            CalibrationError::BadSignature(id) => {
                write!(f, "calibration {id} signature verification failed")
            }
            CalibrationError::UntrustedSigner { id, signer } => write!(
                f,
                "calibration {id} was signed by untrusted key {signer} \
                 (not a registered authority for this modality)"
            ),
            CalibrationError::Core(e) => write!(f, "core validation error: {e}"),
        }
    }
}

impl std::error::Error for CalibrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CalibrationError::Core(e) => Some(e),
            _ => None,
        }
    }
}

impl From<EnvError> for CalibrationError {
    fn from(e: EnvError) -> Self {
        CalibrationError::Core(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_informative() {
        let cases: Vec<(CalibrationError, &str)> = vec![
            (CalibrationError::UnknownRecord(9), "unknown"),
            (
                CalibrationError::BrokenLineage {
                    id: 3,
                    missing_parent: 2,
                },
                "missing parent 2",
            ),
            (CalibrationError::LineageCycle(4), "cycle"),
            (CalibrationError::UnanchoredRoot(5), "not anchored"),
            (
                CalibrationError::Expired {
                    id: 6,
                    expires_ns: 10,
                    now_ns: 20,
                },
                "expired",
            ),
            (
                CalibrationError::WrongDevice {
                    id: 7,
                    expected: 1,
                    actual: 2,
                },
                "node",
            ),
            (CalibrationError::WrongModality(8), "modality"),
            (CalibrationError::MissingSignature(9), "unsigned"),
            (CalibrationError::BadSignature(10), "verification failed"),
            (
                CalibrationError::UntrustedSigner {
                    id: 11,
                    signer: "aabb".into(),
                },
                "untrusted key aabb",
            ),
            (
                CalibrationError::Core(EnvError::MissingField("unit")),
                "unit",
            ),
        ];
        for (err, needle) in cases {
            assert!(
                err.to_string().contains(needle),
                "{err} should mention {needle}"
            );
        }
    }

    #[test]
    fn core_error_converts_and_sources() {
        let err: CalibrationError = EnvError::MissingField("method").into();
        assert!(matches!(err, CalibrationError::Core(_)));
        assert!(std::error::Error::source(&err).is_some());
        assert!(std::error::Error::source(&CalibrationError::UnknownRecord(1)).is_none());
    }
}
