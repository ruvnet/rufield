use rufield_interop::{StandardsOrganization, StandardsReference, StandardsRole};

#[test]
fn etsi_gr_isc_005_stable_draft_is_representable_without_compliance_claim() {
    let reference = StandardsReference::new(
        StandardsOrganization::Etsi,
        "GR ISC 005",
        "0.1.0",
        Some("Stable draft".into()),
        "2026-09-17",
        StandardsRole::ComputePlacement,
    )
    .expect("ETSI GR ISC 005 stable draft reference should satisfy bounded metadata rules");

    assert_eq!(reference.version, "0.1.0");
    assert_eq!(reference.reference_date, "2026-09-17");
    assert_eq!(reference.role, StandardsRole::ComputePlacement);
    assert!(!reference.compliance_claim);
}

#[test]
fn stable_draft_reference_does_not_relax_compliance_guard() {
    let mut reference = StandardsReference::new(
        StandardsOrganization::Etsi,
        "GR ISC 005",
        "0.1.0",
        Some("Stable draft".into()),
        "2026-09-17",
        StandardsRole::ComputePlacement,
    )
    .unwrap();

    reference.compliance_claim = true;
    assert!(reference.validate().is_err());
}
