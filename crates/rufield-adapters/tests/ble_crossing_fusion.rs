use rufield_adapters::{
    two_person_ble_crossing_scenario, BleAbstentionReason, CROSSING_BASE_TS_NS, CROSSING_TICK_NS,
};
use rufield_core::{FusionEngine, InferenceQuery, Modality, PrivacyClass};
use rufield_fusion::{BleTrustPolicy, FusionError, RuFieldFusion, RuleSet};
use rufield_provenance::Signer;
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn scenario_output_is_byte_deterministic() {
    let first = two_person_ble_crossing_scenario();
    let second = two_person_ble_crossing_scenario();
    assert_eq!(
        serde_json::to_vec(&first.events).unwrap(),
        serde_json::to_vec(&second.events).unwrap()
    );
    assert_eq!(first.identity_abstentions, second.identity_abstentions);
}

#[test]
fn privacy_and_signal_kinds_are_not_conflated() {
    let scenario = two_person_ble_crossing_scenario();
    let mut counts = [0usize; 3];
    for event in &scenario.events {
        match event.tensor.modality {
            Modality::WifiCsi => {
                counts[0] += 1;
                assert_eq!(event.observation.privacy_class, PrivacyClass::P2);
                assert!(event.observation.identity_evidence.is_none());
            }
            Modality::BleAdvertisementRssi => {
                counts[1] += 1;
                assert_eq!(event.tensor.privacy_class, PrivacyClass::P5);
                assert_eq!(event.observation.privacy_class, PrivacyClass::P5);
                assert!(event.observation.identity_evidence.is_some());
                assert!(!event.observation.features.contains_key("breathing_band"));
            }
            Modality::BleChannelSounding => {
                counts[2] += 1;
                assert_eq!(event.tensor.privacy_class, PrivacyClass::P0);
                assert_eq!(event.observation.privacy_class, PrivacyClass::P4);
                assert!(event.observation.identity_evidence.is_none());
                assert!(event.observation.features.contains_key("breathing_band"));
                assert!(!event.observation.features.contains_key("range_m"));
                let procedure = event
                    .observation
                    .channel_sounding_provenance
                    .as_ref()
                    .unwrap();
                assert_eq!(event.sensor.device_id, procedure.sensor_id());
                assert_eq!(procedure.steps.len(), 8);
                assert!(procedure.steps.iter().all(|step| step.gateway.node_id == 7
                    && step.gateway.key_id == 11
                    && step.gateway.boot_nonce == 0xaabb_ccdd_1020_3040
                    && step.companion_timing_uncertainty_us == 18
                    && step.gateway.timing_uncertainty_us == 30));
            }
            other => panic!("unexpected scenario modality: {other:?}"),
        }
    }
    assert_eq!(counts, [10, 10, 10]);
}

#[test]
fn spoof_and_expired_replay_abstain_without_identity_swap() {
    let scenario = two_person_ble_crossing_scenario();
    assert!(scenario
        .identity_abstentions
        .iter()
        .any(|item| item.reason == BleAbstentionReason::ConflictingTrack));
    assert!(scenario
        .identity_abstentions
        .iter()
        .any(|item| item.reason == BleAbstentionReason::Expired));

    let bindings: BTreeSet<_> = scenario
        .events
        .iter()
        .filter_map(|event| event.observation.identity_evidence.as_ref())
        .map(|evidence| (evidence.pseudonym.clone(), evidence.track_id.clone()))
        .collect();
    assert_eq!(bindings.len(), 2);
    assert!(bindings.contains(&(scenario.subject_a, "track_a".into())));
    assert!(bindings.contains(&(scenario.subject_b, "track_b".into())));
}

#[test]
fn expired_identity_event_never_enters_fusion_graph() {
    let scenario = two_person_ble_crossing_scenario();
    let stale_identity = scenario
        .events
        .iter()
        .find(|event| {
            event.tensor.modality == Modality::BleAdvertisementRssi
                && event.timestamp_ns == CROSSING_BASE_TS_NS
        })
        .unwrap()
        .clone();
    let watermark_event = scenario
        .events
        .iter()
        .find(|event| {
            event.tensor.modality == Modality::BleChannelSounding
                && event.timestamp_ns == CROSSING_BASE_TS_NS + 4 * CROSSING_TICK_NS
        })
        .unwrap()
        .clone();

    let mut fusion = RuFieldFusion::with_ble_trust(BleTrustPolicy::synthetic_test_only());
    fusion.ingest(watermark_event).unwrap();
    let nodes_before = fusion.graph().node_count();
    let error = fusion.ingest(stale_identity).unwrap_err();
    assert!(matches!(error, FusionError::InvalidEvidence { .. }));
    assert_eq!(fusion.graph().node_count(), nodes_before);
}

#[test]
fn channel_sounding_uses_the_existing_breathing_feature_contract() {
    let rules = RuleSet::from_toml(
        r#"
[rule.breathing]
inputs = ["ble_channel_sounding"]
method = "weighted_bayes"
feature = "breathing_band"
threshold = 0.60
privacy_max = "P4"
requires_consent = true
"#,
    )
    .unwrap();
    let event = two_person_ble_crossing_scenario()
        .events
        .into_iter()
        .find(|event| event.tensor.modality == Modality::BleChannelSounding)
        .unwrap();
    let mut fusion =
        RuFieldFusion::with_rules_and_ble_trust(rules, BleTrustPolicy::synthetic_test_only());
    fusion.ingest(event).unwrap();
    let inferences = fusion.infer(&InferenceQuery::all()).unwrap();
    assert_eq!(inferences.len(), 1);
    assert_eq!(inferences[0].label, "breathing");
    assert_eq!(inferences[0].privacy_class, PrivacyClass::P4);
}

#[test]
fn production_policy_rejects_synthetic_ble() {
    let events = two_person_ble_crossing_scenario().events;
    for modality in [Modality::BleAdvertisementRssi, Modality::BleChannelSounding] {
        let event = events
            .iter()
            .find(|event| event.tensor.modality == modality)
            .unwrap()
            .clone();
        let mut fusion = RuFieldFusion::new();
        let error = fusion.ingest(event).unwrap_err();
        assert!(matches!(error, FusionError::UntrustedBle { .. }));
        assert_eq!(fusion.graph().node_count(), 0);
    }
}

#[test]
fn production_ble_requires_exact_device_and_signer_allowlist_pair() {
    let mut event = two_person_ble_crossing_scenario()
        .events
        .into_iter()
        .find(|event| event.tensor.modality == Modality::BleChannelSounding)
        .unwrap();
    event.provenance.synthetic = false;
    event.sensor.vendor = "production_ble_radio".into();
    event.provenance.firmware_hash = format!("sha256:{}", "2".repeat(64));
    event.provenance.model_id = "model.ble_cs.production.v1".into();
    event.provenance.calibration_id = "cal.ble_cs.production.v1".into();
    event.tensor.calibration_id = Some(event.provenance.calibration_id.clone());
    event.provenance.signature_hex = None;
    event.provenance.signer_pubkey_hex = None;
    let signer = Signer::from_seed(&[0x73; 32]);
    signer.sign_event(&mut event).unwrap();

    let mut denied = RuFieldFusion::new();
    assert!(matches!(
        denied.ingest(event.clone()),
        Err(FusionError::UntrustedBle { .. })
    ));

    let wrong_device_policy =
        BleTrustPolicy::production().with_allowed_signer("different_device", signer.public_hex());
    let mut wrong_device = RuFieldFusion::with_ble_trust(wrong_device_policy);
    assert!(matches!(
        wrong_device.ingest(event.clone()),
        Err(FusionError::UntrustedBle { .. })
    ));

    let wrong_signer = Signer::from_seed(&[0x74; 32]);
    let wrong_signer_policy = BleTrustPolicy::production()
        .with_allowed_signer(event.sensor.device_id.clone(), wrong_signer.public_hex());
    let mut wrong_signer_fusion = RuFieldFusion::with_ble_trust(wrong_signer_policy);
    assert!(matches!(
        wrong_signer_fusion.ingest(event.clone()),
        Err(FusionError::UntrustedBle { .. })
    ));

    let policy = BleTrustPolicy::production()
        .with_allowed_signer(event.sensor.device_id.clone(), signer.public_hex());
    let mut allowed = RuFieldFusion::with_ble_trust(policy);
    allowed.ingest(event).unwrap();
}

#[test]
fn invalid_channel_sounding_group_never_enters_fusion() {
    let mut event = two_person_ble_crossing_scenario()
        .events
        .into_iter()
        .find(|event| event.tensor.modality == Modality::BleChannelSounding)
        .unwrap();
    let procedure = event
        .observation
        .channel_sounding_provenance
        .as_mut()
        .unwrap();
    let repeated_channel = procedure.steps[6].channel_index;
    procedure.steps[7].channel_index = repeated_channel;

    let mut fusion = RuFieldFusion::with_ble_trust(BleTrustPolicy::synthetic_test_only());
    assert!(matches!(
        fusion.ingest(event),
        Err(FusionError::InvalidEvidence { .. })
    ));
    assert_eq!(fusion.graph().node_count(), 0);
}

#[test]
fn gateway_identity_cannot_replace_channel_sounding_companion() {
    let mut event = two_person_ble_crossing_scenario()
        .events
        .into_iter()
        .find(|event| event.tensor.modality == Modality::BleChannelSounding)
        .unwrap();
    event.sensor.device_id = "esp32_gateway_7".into();

    let mut fusion = RuFieldFusion::with_ble_trust(BleTrustPolicy::synthetic_test_only());
    assert!(matches!(
        fusion.ingest(event),
        Err(FusionError::InvalidEvidence { .. })
    ));
    assert_eq!(fusion.graph().node_count(), 0);
}

#[test]
fn identity_issuer_mismatch_never_enters_fusion() {
    let mut event = two_person_ble_crossing_scenario()
        .events
        .into_iter()
        .find(|event| event.tensor.modality == Modality::BleAdvertisementRssi)
        .unwrap();
    event.observation.identity_evidence.as_mut().unwrap().issuer = "different_gateway".into();
    let mut fusion = RuFieldFusion::with_ble_trust(BleTrustPolicy::synthetic_test_only());
    assert!(matches!(
        fusion.ingest(event),
        Err(FusionError::InvalidEvidence { .. })
    ));
    assert_eq!(fusion.graph().node_count(), 0);
}

#[test]
fn crossing_breathing_inferences_never_mix_tracks() {
    let rules = RuleSet::from_toml(
        r#"
[rule.breathing]
inputs = ["ble_channel_sounding"]
method = "weighted_bayes"
feature = "breathing_band"
threshold = 0.60
privacy_max = "P4"
requires_consent = true
"#,
    )
    .unwrap();
    let scenario = two_person_ble_crossing_scenario();
    let event_tracks: BTreeMap<_, _> = scenario
        .events
        .iter()
        .map(|event| (event.event_id.clone(), event.observation.track_id.clone()))
        .collect();
    let mut fusion =
        RuFieldFusion::with_rules_and_ble_trust(rules, BleTrustPolicy::synthetic_test_only());
    for event in scenario
        .events
        .into_iter()
        .filter(|event| event.tensor.modality == Modality::BleChannelSounding)
    {
        fusion.ingest(event).unwrap();
    }

    let breathing = fusion.infer(&InferenceQuery::all()).unwrap();
    assert_eq!(breathing.len(), 2);
    for inference in breathing {
        let track_id = inference.track_id.as_deref().unwrap();
        let cited_tracks: BTreeSet<_> = inference
            .supporting_events
            .iter()
            .chain(inference.contradicting_events.iter())
            .map(|event_id| event_tracks[event_id].as_deref().unwrap())
            .collect();
        assert!(!cited_tracks.is_empty());
        assert_eq!(cited_tracks, BTreeSet::from([track_id]));
    }
}
