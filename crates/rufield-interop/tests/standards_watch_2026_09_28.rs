use rufield_interop::{StandardsOrganization, StandardsReference, StandardsRole};

#[test]
fn three_gpp_ts_23_137_controlled_release_is_representable_without_compliance_claim() {
    let reference = StandardsReference::new(
        StandardsOrganization::ThreeGpp,
        "TS 23.137",
        "20.0.0",
        Some("Release 20; Under change control".into()),
        "2026-09-24",
        StandardsRole::SensingService,
    )
    .expect("3GPP TS 23.137 controlled Release 20 reference should satisfy bounded metadata rules");

    assert_eq!(reference.version, "20.0.0");
    assert_eq!(reference.reference_date, "2026-09-24");
    assert_eq!(reference.role, StandardsRole::SensingService);
    assert!(!reference.compliance_claim);
}

#[test]
fn controlled_release_reference_does_not_relax_compliance_guard() {
    let mut reference = StandardsReference::new(
        StandardsOrganization::ThreeGpp,
        "TS 23.137",
        "20.0.0",
        Some("Release 20; Under change control".into()),
        "2026-09-24",
        StandardsRole::SensingService,
    )
    .unwrap();

    reference.compliance_claim = true;
    assert!(reference.validate().is_err());
}
