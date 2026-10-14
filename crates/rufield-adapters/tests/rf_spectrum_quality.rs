use rufield_adapters::rf_spectrum_quality::{
    RfDiagnostic, RfDiagnosticReader, SourceKind, MAX_RECORD_BYTES,
};
use rufield_core::{FusionEngine, Modality, PrivacyClass};
use rufield_fusion::{FusionError, RuFieldFusion};
use serde_json::{json, Value};
use std::io::Cursor;

fn fixture() -> Value {
    json!({"schema":"ruview.rf_diagnostics.v1","source_kind":"synthetic",
        "source_id":"w1700k","observed_monotonic_ns":123,"run":1,"slot_index":2,
        "sample_start":null,"sample_rate_hz":40000000,"center_frequency_hz":null,
        "config_verified":false,"valid":false,"invalid_reasons":["configuration_unverified"],
        "sample_count":2048,"rms_dbfs":-20.0,"rail_fraction":0.0,"missing_samples":0,
        "event_count":0,"overrun_slices":0,"ttl_ms":1000})
}
fn parse(v: &Value) -> std::io::Result<Option<RfDiagnostic>> {
    RfDiagnosticReader::new(Cursor::new(v.to_string())).next_record()
}
#[test]
fn emits_only_unsigned_advisory_features_and_exact_source_metadata() {
    let d = parse(&fixture()).unwrap().unwrap();
    let event = d.to_event(999).unwrap();
    assert_eq!(event.timestamp_ns, 999);
    assert_eq!(event.tensor.modality, Modality::RfSpectrumQuality);
    assert_eq!(event.tensor.modality.code(), 18);
    assert_eq!(event.tensor.privacy_class, PrivacyClass::P1);
    assert_eq!(event.observation.confidence, 0.0);
    assert!(event.observation.labels.is_empty());
    assert!(event.observation.zone_id.is_none());
    assert!(event.observation.identity_evidence.is_none());
    assert!(event.provenance.synthetic);
    assert!(event.provenance.signature_hex.is_none());
    assert!(event
        .observation
        .features
        .keys()
        .all(|k| k.starts_with("rf_quality_")));
    let raw: Value = serde_json::from_str(&event.observation.attributes["source_record"]).unwrap();
    assert_eq!(raw["observed_monotonic_ns"], 123);
    event.validate_evidence_at(999).unwrap();
}
#[test]
fn rejects_promotion_unknown_fields_and_invalid_ranges() {
    for (key, value) in [
        ("valid", json!(true)),
        ("config_verified", json!(true)),
        ("ttl_ms", json!(1001)),
        ("sample_start", json!(0)),
        ("sample_rate_hz", json!(1)),
        ("rail_fraction", json!(1.1)),
        ("rms_dbfs", json!(100)),
        ("center_frequency_hz", json!(1)),
        ("raw_iq", json!([1, 2])),
        ("source_kind", json!("authenticated")),
        ("invalid_reasons", json!([])),
        ("sample_count", json!(2049)),
        ("missing_samples", json!(1)),
        (
            "invalid_reasons",
            json!(["configuration_unverified", "configuration_unverified"]),
        ),
        ("source_id", json!("unknown")),
        ("schema", json!("v2")),
    ] {
        let mut f = fixture();
        f[key] = value;
        assert!(parse(&f).is_err(), "{key}");
    }
}
#[test]
fn bounded_reader_stays_closed_after_error() {
    let bytes = vec![b' '; MAX_RECORD_BYTES + 1];
    let mut reader = RfDiagnosticReader::new(Cursor::new(bytes));
    assert!(reader.next_record().is_err());
    assert!(reader.next_record().is_err());
    let mut reader =
        RfDiagnosticReader::new(Cursor::new(format!("{}\n{}\n", fixture(), fixture())));
    assert!(reader.next_record().unwrap().is_some());
    assert!(reader.next_record().unwrap().is_some());
    assert!(reader.next_record().unwrap().is_none());
}

#[test]
fn diagnostic_is_rejected_by_spatial_fusion_even_when_synthetic() {
    let mut record = parse(&fixture()).unwrap().unwrap();
    for source in [
        SourceKind::Synthetic,
        SourceKind::Live,
        SourceKind::CapturedReplay,
    ] {
        record.source_kind = source;
        let event = record.to_event(999).unwrap();
        let mut fusion = RuFieldFusion::new();
        assert!(matches!(
            fusion.ingest(event),
            Err(FusionError::InvalidEvidence { .. })
        ));
        assert_eq!(fusion.graph().node_count(), 0);
    }
}
#[test]
fn direct_constructor_rejects_nonfinite_metrics() {
    let mut record = parse(&fixture()).unwrap().unwrap();
    record.rms_dbfs = Some(f64::NAN);
    assert!(record.to_event(999).is_err());
    record.rms_dbfs = Some(f64::INFINITY);
    assert!(record.to_event(999).is_err());
}
#[test]
fn silent_signal_and_unknown_rate_are_advisory() {
    let mut record = parse(&fixture()).unwrap().unwrap();
    record.rms_dbfs = None;
    record.sample_rate_hz = 0;
    assert!(record
        .to_event(999)
        .unwrap()
        .observation
        .features
        .get("rf_quality_rms_dbfs")
        .is_none());
}
