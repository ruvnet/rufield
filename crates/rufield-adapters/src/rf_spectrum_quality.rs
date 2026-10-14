//! Advisory RF diagnostics, never CSI, occupancy, or calibrated power.
//! IQ is not accepted. Unknown fields fail closed. Local receipt time is
//! separate from the producer's monotonic clock; replay does not prove freshness.
use rufield_core::{
    FieldAxis, FieldEvent, FieldTensor, Modality, Observation, PrivacyClass, ProvenanceRef,
    SensorDescriptor,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, BufRead, Read};

/// Maximum JSONL record size including newline.
pub const MAX_RECORD_BYTES: usize = 4096;
/// Producer mode is a claim, not authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Synthetic,
    Live,
    CapturedReplay,
}
/// Exact bridge v1 wire record; no unknown fields or raw IQ.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RfDiagnostic {
    pub schema: String,
    pub source_kind: SourceKind,
    pub source_id: String,
    pub observed_monotonic_ns: u64,
    pub run: u64,
    pub slot_index: u64,
    pub sample_start: Option<u64>,
    pub sample_rate_hz: u64,
    pub center_frequency_hz: Option<u64>,
    pub config_verified: bool,
    pub valid: bool,
    pub invalid_reasons: Vec<String>,
    pub sample_count: u64,
    pub rms_dbfs: Option<f64>,
    pub rail_fraction: Option<f64>,
    pub missing_samples: u64,
    pub event_count: u64,
    pub overrun_slices: u64,
    pub ttl_ms: u64,
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
impl RfDiagnostic {
    /// Validate the diagnostic-only contract. No v1 record is promotable.
    pub fn validate(&self) -> io::Result<()> {
        let reasons = [
            "configuration_unverified",
            "lost",
            "event",
            "overrun",
            "stale",
            "tag_mismatch",
            "run_change",
        ];
        if self.schema != "ruview.rf_diagnostics.v1"
            || self.source_id != "w1700k"
            || self.config_verified
            || self.valid
            || self.ttl_ms != 1000
            || self.sample_start.is_some()
            || self.invalid_reasons.is_empty()
            || self.invalid_reasons.len() > reasons.len()
            || !self.invalid_reasons.iter().any(|s| s == reasons[0])
            || self
                .invalid_reasons
                .iter()
                .any(|s| !reasons.contains(&s.as_str()))
            || self
                .invalid_reasons
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.invalid_reasons.len()
        {
            return Err(invalid("unsupported or promotable RF diagnostic"));
        }
        if ![0, 40_000_000, 80_000_000, 160_000_000, 320_000_000].contains(&self.sample_rate_hz)
            || self
                .center_frequency_hz
                .is_some_and(|f| !(2_000_000_000..=8_000_000_000).contains(&f))
            || ![0, 2048].contains(&self.sample_count)
            || self.missing_samples % 2048 != 0
            || self
                .rms_dbfs
                .is_some_and(|v| !v.is_finite() || !(-200.0..=16.0).contains(&v))
            || self
                .rail_fraction
                .is_some_and(|v| !v.is_finite() || !(0.0..=1.0).contains(&v))
            || (self.rms_dbfs.is_some() && self.rail_fraction.is_none())
        {
            return Err(invalid("RF diagnostic range violation"));
        }
        Ok(())
    }
}

impl RfDiagnostic {
    /// Construct an unsigned P1 advisory event. Timestamp is local receipt time,
    /// not capture time. No receiver identity, firmware or calibration is attested.
    pub fn to_event(&self, receipt_ns: u64) -> io::Result<FieldEvent> {
        self.validate()?;
        let canonical = serde_json::to_vec(self).map_err(|_| invalid("serialization"))?;
        let digest = format!("{:x}", Sha256::digest(&canonical));
        let mut observation = Observation::occupancy(0.0, PrivacyClass::P1);
        observation
            .attributes
            .insert("kind".into(), "rf_spectrum_quality".into());
        observation
            .attributes
            .insert("trust".into(), "unverified_advisory".into());
        observation.attributes.insert(
            "timestamp_semantics".into(),
            "local_receipt_not_capture".into(),
        );
        observation.attributes.insert(
            "source_record".into(),
            String::from_utf8(canonical).map_err(|_| invalid("serialization"))?,
        );
        if let Some(v) = self.rms_dbfs {
            observation
                .features
                .insert("rf_quality_rms_dbfs".into(), v as f32);
        }
        if let Some(v) = self.rail_fraction {
            observation
                .features
                .insert("rf_quality_rail_fraction".into(), v as f32);
        }
        // Constant invalidity marker: absence of RMS is not represented as zero.
        let tensor = FieldTensor::new(
            receipt_ns,
            Modality::RfSpectrumQuality,
            vec![FieldAxis::Uncertainty],
            vec![1],
            vec![1.0],
            0.0,
            0.0,
            None,
            PrivacyClass::P1,
        )
        .map_err(|_| invalid("tensor"))?;
        Ok(FieldEvent::new(
            format!("rf-diagnostic-{digest}"),
            receipt_ns,
            SensorDescriptor {
                modality: "rf_spectrum_quality".into(),
                vendor: "unverified".into(),
                device_id: self.source_id.clone(),
                placement: "unknown".into(),
                coordinate_frame: None,
                position_m: None,
                orientation_xyzw: None,
                clock_domain: "adapter_receipt_unix_ns".into(),
            },
            tensor,
            observation,
            ProvenanceRef {
                raw_hash: format!("sha256:{digest}"),
                firmware_hash: "unverified".into(),
                model_id: "rf-diagnostics-advisory-v1".into(),
                calibration_id: "none".into(),
                synthetic: self.source_kind == SourceKind::Synthetic,
                signature_hex: None,
                signer_pubkey_hex: None,
            },
        ))
    }
}

/// Streaming bounded parser. A failed record permanently closes the reader.
/// Records already emitted remain advisory; callers must honor errors.
pub struct RfDiagnosticReader<R> {
    reader: R,
    failed: bool,
}
impl<R: BufRead> RfDiagnosticReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            failed: false,
        }
    }
    pub fn next_record(&mut self) -> io::Result<Option<RfDiagnostic>> {
        if self.failed {
            return Err(invalid("reader closed after invalid record"));
        }
        let result = self.read_one();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn read_one(&mut self) -> io::Result<Option<RfDiagnostic>> {
        let mut bytes = Vec::new();
        self.reader
            .by_ref()
            .take((MAX_RECORD_BYTES + 1) as u64)
            .read_until(b'\n', &mut bytes)?;
        if bytes.is_empty() {
            return Ok(None);
        }
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid("record too large"));
        }
        let record: RfDiagnostic =
            serde_json::from_slice(&bytes).map_err(|_| invalid("invalid RF diagnostic JSON"))?;
        record.validate()?;
        Ok(Some(record))
    }
}
