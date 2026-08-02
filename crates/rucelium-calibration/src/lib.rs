//! # rucelium-calibration
//!
//! Calibration lineage, calibration application, EWMA drift detection, and
//! sensor quarantine for the RuCelium fabric (ADR-264 §12).
//!
//! This crate enforces the §12 countermeasures on the gateway side:
//!
//! 1. **Signed calibration lineage** — every [`rucelium_core::CalibrationRecord`]
//!    chains via `parent_id` up to a reference-grade anchor; broken chains are
//!    rejected ([`CalibrationStore::verify_lineage`], §12 items 1–3). In
//!    strict mode ([`CalibrationStore::with_authorities`]) every record must
//!    additionally carry an ed25519 signature from a registered
//!    [`CalibrationAuthority`] trusted for the record's modality — a method
//!    string alone can never declare an anchor.
//! 2. **Measurement uncertainty on every observation** — applying a
//!    calibration recentres and (only ever) widens the sample's uncertainty
//!    interval to at least the record's stated half-width
//!    ([`Calibrator::apply`], §12 item 4).
//! 3. **Automatic drift detection** — an EWMA residual monitor against
//!    co-located anchor stations ([`DriftDetector`], §12 item 5).
//! 4. **Sensor quarantine rather than silent correction** — drifted sensors
//!    are quarantined and stay quarantined until an explicit recalibration
//!    ([`DriftDetector::reinstate`], §12 item 6); values are never rewritten,
//!    and an uncalibrated sample is penalised, never "corrected".
//!
//! Everything here is fully deterministic: no clocks, no RNG — callers pass
//! `now_ns` explicitly, and identical inputs always produce identical
//! outputs.

#![doc(html_root_url = "https://docs.rs/rucelium-calibration/0.1.0")]

pub mod authority;
pub mod calibrator;
pub mod drift;
pub mod error;
pub mod store;

pub use authority::{
    sha256_hex, verify_record_signature, AuthorityRegistry, CalibrationAuthority, CalibrationSigner,
};
pub use calibrator::{CalibrationOutcome, Calibrator};
pub use drift::{DriftConfig, DriftDetector, QuarantineState};
pub use error::CalibrationError;
pub use store::CalibrationStore;
