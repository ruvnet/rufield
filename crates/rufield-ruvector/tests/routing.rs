use rufield_core::{FieldEvent, PrivacyClass};
use rufield_provenance::{Signer, TrustPolicy, TrustVerifier, TrustedKeyRegistry};
use rufield_ruvector::routing::prepare_routing_event;
fn fixture() -> (FieldEvent, Signer, TrustVerifier) {
    let mut event: FieldEvent = serde_json::from_str(include_str!("fixtures/ruview.json")).unwrap();
    let signer = Signer::from_seed(&[17; 32]);
    signer.sign_event(&mut event).unwrap();
    let mut registry = TrustedKeyRegistry::new();
    registry
        .enroll_sensor_key(&event.sensor.device_id, signer.public_hex())
        .unwrap();
    let verifier = TrustVerifier::new(TrustPolicy::production_with_window(100, 0), registry);
    (event, signer, verifier)
}
#[test]
fn production_projection_replay_retry_and_expiry() {
    let (event, _, mut verifier) = fixture();
    let prepared = prepare_routing_event(&event, &mut verifier, 100).unwrap();
    assert!(prepared.payload_bytes() < serde_json::to_vec(&event).unwrap().len());
    prepared
        .deliver(100, |bytes, verified, now| {
            let v: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            assert!(verified);
            assert_eq!(now, 100);
            assert!(v.get("tensor").is_none());
            assert!(v["observation"].get("labels").is_none());
            assert_eq!(v["sensor"]["device_id"], event.sensor.device_id);
            assert_eq!(v["observation"]["features"]["presence"], 1.0);
            Ok::<_, ()>(())
        })
        .unwrap()
        .unwrap();
    assert!(prepare_routing_event(&event, &mut verifier, 100).is_err());
    assert_eq!(
        prepared
            .deliver(100, |_, _, _| Err::<(), _>("unmapped"))
            .unwrap(),
        Err("unmapped")
    );
    assert!(prepared.deliver(201, |_, _, _| Ok::<_, ()>(())).is_err());
}
#[test]
fn privacy_tampering_simulation_and_revocation_fail_closed() {
    let (event, signer, mut verifier) = fixture();
    let initial = verifier.export_replay_state();
    for class in [
        PrivacyClass::P0,
        PrivacyClass::P3,
        PrivacyClass::P4,
        PrivacyClass::P5,
    ] {
        let mut denied = event.clone();
        denied.tensor.privacy_class = class;
        signer.sign_event(&mut denied).unwrap();
        assert!(prepare_routing_event(&denied, &mut verifier, 100).is_err());
        assert_eq!(initial, verifier.export_replay_state());
    }
    let mut tampered = event.clone();
    tampered.observation.confidence = 0.1;
    assert!(prepare_routing_event(&tampered, &mut verifier, 100).is_err());
    assert!(prepare_routing_event(&event, &mut TrustVerifier::simulation(), 100).is_err());
    verifier
        .registry_mut()
        .revoke_key(signer.public_hex())
        .unwrap();
    assert!(prepare_routing_event(&event, &mut verifier, 100).is_err());
    assert_eq!(initial, verifier.export_replay_state());
}
#[test]
fn exact_epoch_nanoseconds_and_nonfinite_signals() {
    let (mut event, signer, mut verifier) = fixture();
    event.timestamp_ns = 1_789_516_800_000_000_123;
    event.tensor.timestamp_ns = event.timestamp_ns;
    signer.sign_event(&mut event).unwrap();
    let prepared = prepare_routing_event(&event, &mut verifier, event.timestamp_ns).unwrap();
    prepared
        .deliver(event.timestamp_ns, |bytes, _, now| {
            let v: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            assert_eq!(v["timestamp_ns"].as_u64(), Some(now));
            Ok::<_, ()>(())
        })
        .unwrap()
        .unwrap();
    event
        .observation
        .features
        .insert("presence".into(), f32::NAN);
    assert!(prepare_routing_event(&event, &mut verifier, event.timestamp_ns).is_err());
}
