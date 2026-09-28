use rufield_interop::{StandardsOrganization, StandardsReference, StandardsRole};

#[test]
fn three_gpp_ts_23_138_sa113_version_is_representable_without_compliance_claim() {
    let reference = StandardsReference::new(
        StandardsOrganization::ThreeGpp,
        "TS 23.138",
        "1.0.0",
        Some("Release 20 draft; SA#113".into()),
        "2026-09-08",
        StandardsRole::VerticalExposure,
    )
    .expect("TS 23.138 SA#113 reference should satisfy bounded metadata rules");

    assert_eq!(reference.version, "1.0.0");
    assert_eq!(reference.reference_date, "2026-09-08");
    assert!(!reference.compliance_claim);
}

#[test]
fn fresh_version_reference_does_not_relax_compliance_guard() {
    let mut reference = StandardsReference::new(
        StandardsOrganization::ThreeGpp,
        "TS 23.138",
        "1.0.0",
        Some("Release 20 draft; SA#113".into()),
        "2026-09-08",
        StandardsRole::VerticalExposure,
    )
    .unwrap();

    reference.compliance_claim = true;
    assert!(reference.validate().is_err());
}
