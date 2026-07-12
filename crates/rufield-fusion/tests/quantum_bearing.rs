use rufield_core::{
    FieldAxis, FieldEvent, FieldTensor, Modality, Observation, PrivacyClass, ProvenanceRef,
    SensorDescriptor,
};
use rufield_fusion::{
    BearingFusionConfig, BearingFusionError, BearingTrustPolicy, LiveTrustWindow,
    QuantumBearingFusion, TrustedSensorBinding, DEFAULT_MAX_TIME_SKEW_NS,
};
use rufield_provenance::Signer;
use std::collections::BTreeMap;

const CALIBRATION_HASH: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const CALIBRATION_CREATED_NS: u64 = 0;
const CALIBRATION_EXPIRES_NS: u64 = 120_000_000_000;

fn unit(vector: [f64; 3]) -> [f32; 3] {
    let norm = vector.iter().map(|x| x * x).sum::<f64>().sqrt();
    [
        (vector[0] / norm) as f32,
        (vector[1] / norm) as f32,
        (vector[2] / norm) as f32,
    ]
}

fn event(id: &str, sensor: &str, timestamp_ns: u64, position: [f32; 3], k: [f32; 3]) -> FieldEvent {
    let tensor = FieldTensor::new(
        timestamp_ns,
        Modality::QuantumRf,
        vec![FieldAxis::DirectionCandidate, FieldAxis::CartesianComponent],
        vec![2, 3],
        vec![k[0], k[1], k[2], -k[0], -k[1], -k[2]],
        0.95,
        0.001,
        Some("qrf-cal-1".into()),
        PrivacyClass::P1,
    )
    .unwrap();
    let mut features = BTreeMap::new();
    features.insert("sensor_x_m".into(), position[0]);
    features.insert("sensor_y_m".into(), position[1]);
    features.insert("sensor_z_m".into(), position[2]);
    features.insert("carrier_hz".into(), 6.64e9_f32);
    features.insert("ellipticity".into(), 0.9);
    features.insert("field_strength_vpm".into(), 0.06);
    features.insert("snr_db".into(), 30.0);
    let integration_ms = if timestamp_ns < 5_000_000 {
        0.000_001
    } else {
        10.0
    };
    features.insert("integration_ms".into(), integration_ms);
    features.insert("angle_cov_00_rad2".into(), 0.001_f32.powi(2));
    features.insert("angle_cov_01_rad2".into(), 0.0);
    features.insert("angle_cov_11_rad2".into(), 0.001_f32.powi(2));
    features.insert("sign_ambiguous".into(), 1.0);
    features.insert("quality_valid".into(), 1.0);
    features.insert("lock_quality".into(), 0.95);
    features.insert("calibration_quality".into(), 0.90);
    let integration_ns = (f64::from(integration_ms) * 1_000_000.0).round() as u64;
    let integration_end_ns = timestamp_ns.saturating_add(integration_ns - integration_ns / 2);
    features.insert(
        "calibration_remaining_s".into(),
        (CALIBRATION_EXPIRES_NS.saturating_sub(integration_end_ns) as f64 / 1_000_000_000.0) as f32,
    );
    let attributes = BTreeMap::from([
        ("signal_id".into(), "pilot-alpha".into()),
        ("tensor_frame".into(), "sensor_local".into()),
        ("evidence_kind".into(), "synthetic_replay".into()),
        ("calibration_data_hash".into(), CALIBRATION_HASH.into()),
        (
            "calibration_created_ns".into(),
            CALIBRATION_CREATED_NS.to_string(),
        ),
        (
            "calibration_expires_ns".into(),
            CALIBRATION_EXPIRES_NS.to_string(),
        ),
    ]);
    FieldEvent::new(
        id,
        timestamp_ns,
        SensorDescriptor {
            modality: "quantum_rf".into(),
            vendor: "replay_rydberg".into(),
            device_id: sensor.into(),
            placement: "surveyed".into(),
            coordinate_frame: Some("lab_enu".into()),
            position_m: Some(position),
            orientation_xyzw: Some([0.0, 0.0, 0.0, 1.0]),
            clock_domain: "ptp".into(),
        },
        tensor,
        Observation {
            zone_id: None,
            space_cell: None,
            range_m: None,
            velocity_mps: None,
            motion_vector: None,
            confidence: 0.95,
            features,
            attributes,
            labels: vec!["rf_bearing".into()],
            privacy_class: PrivacyClass::P1,
        },
        ProvenanceRef {
            raw_hash: "sha256:raw".into(),
            firmware_hash: "sha256:firmware".into(),
            model_id: "rydberg_k_vector_v1".into(),
            calibration_id: "qrf-cal-1".into(),
            synthetic: true,
            signature_hex: None,
            signer_pubkey_hex: None,
        },
    )
}

fn set_calibration_expiry(event: &mut FieldEvent, expires_ns: u64) {
    event
        .observation
        .attributes
        .insert("calibration_expires_ns".into(), expires_ns.to_string());
    refresh_calibration_remaining(event);
}

fn set_integration_ms(event: &mut FieldEvent, integration_ms: f32) {
    event
        .observation
        .features
        .insert("integration_ms".into(), integration_ms);
    refresh_calibration_remaining(event);
}

fn refresh_calibration_remaining(event: &mut FieldEvent) {
    let expires_ns = event.observation.attributes["calibration_expires_ns"]
        .parse::<u64>()
        .unwrap();
    let integration_ns =
        (f64::from(event.observation.features["integration_ms"]) * 1_000_000.0).round() as u64;
    let integration_end_ns = event
        .timestamp_ns
        .saturating_add(integration_ns - integration_ns / 2);
    event.observation.features.insert(
        "calibration_remaining_s".into(),
        (expires_ns.saturating_sub(integration_end_ns) as f64 / 1_000_000_000.0) as f32,
    );
}

fn sign_live(event: &mut FieldEvent, signer: &Signer) {
    event.provenance.synthetic = false;
    event
        .observation
        .attributes
        .insert("evidence_kind".into(), "live".into());
    signer.sign_event(event).unwrap();
}

fn binding_for(event: &FieldEvent, signer: &Signer) -> TrustedSensorBinding {
    TrustedSensorBinding {
        device_id: event.sensor.device_id.clone(),
        signer_pubkey_hex: signer.public_hex(),
        coordinate_frame: event.sensor.coordinate_frame.clone().unwrap(),
        position_m: event.sensor.position_m.unwrap(),
        orientation_xyzw: event.sensor.orientation_xyzw.unwrap(),
        calibration_id: event.provenance.calibration_id.clone(),
        calibration_data_hash: event.observation.attributes["calibration_data_hash"].clone(),
        calibration_created_ns: event.observation.attributes["calibration_created_ns"]
            .parse()
            .unwrap(),
        calibration_expires_ns: event.observation.attributes["calibration_expires_ns"]
            .parse()
            .unwrap(),
        revoked: false,
    }
}

fn live_window(evaluation_time_ns: u64) -> LiveTrustWindow {
    LiveTrustWindow {
        evaluation_time_ns,
        max_event_age_ns: 1_000_000_000,
        max_future_skew_ns: 10_000_000,
    }
}

fn assert_close(actual: [f64; 3], expected: [f64; 3], tolerance: f64) {
    for idx in 0..3 {
        assert!(
            (actual[idx] - expected[idx]).abs() <= tolerance,
            "axis {idx}: expected {}, got {}",
            expected[idx],
            actual[idx]
        );
    }
}

#[test]
fn two_viewpoints_recover_intersection() {
    let target = [5.0, 3.0, 2.0];
    let a = event("a", "sensor-a", 1, [0.0, 0.0, 0.0], unit(target));
    let b = event("b", "sensor-b", 1, [10.0, 0.0, 0.0], unit([-5.0, 3.0, 2.0]));
    let mut fusion = QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS);
    fusion.ingest(&a).unwrap();
    fusion.ingest(&b).unwrap();
    let estimate = fusion.estimate().unwrap();
    assert_close(estimate.position_m, target, 1.0e-5);
    assert!(estimate.residual_rmse_m < 1.0e-5);
    assert_eq!(estimate.coordinate_frame, "lab_enu");
    assert_eq!(estimate.signal_id, "pilot-alpha");
    assert_eq!(estimate.privacy_class, PrivacyClass::P1);
    assert!(estimate.sign_invariant);
    assert_eq!(estimate.produced_ns, 1);
    assert!(estimate.expires_ns > estimate.produced_ns);
    for axis_variance in [
        estimate.covariance_m2[0][0],
        estimate.covariance_m2[1][1],
        estimate.covariance_m2[2][2],
    ] {
        let standard_deviation = axis_variance.sqrt();
        assert!(
            (1.0e-3..0.1).contains(&standard_deviation),
            "absolute angular uncertainty must propagate to metres, got {standard_deviation}"
        );
    }
    assert_eq!(estimate.supporting_events, ["a", "b"]);
    assert_eq!(estimate.calibration_ids, ["qrf-cal-1", "qrf-cal-1"]);
}

#[test]
fn sensor_local_direction_is_rotated_once_into_world_frame() {
    let target = [5.0, 3.0, 2.0];
    let mut a = event("a", "sensor-a", 1, [0.0, 0.0, 0.0], unit([3.0, -5.0, 2.0]));
    let half = std::f32::consts::FRAC_1_SQRT_2;
    a.sensor.orientation_xyzw = Some([0.0, 0.0, half, half]);
    let b = event("b", "sensor-b", 1, [10.0, 0.0, 0.0], unit([-5.0, 3.0, 2.0]));
    let mut fusion = QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS);
    fusion.ingest(&a).unwrap();
    fusion.ingest(&b).unwrap();
    assert_close(fusion.estimate().unwrap().position_m, target, 1.0e-5);
}

#[test]
fn reversing_both_k_candidates_does_not_change_position() {
    let target = [4.0, 2.0, 1.0];
    let mut a = event("a", "sensor-a", 1, [0.0, 0.0, 0.0], unit(target));
    let b = event("b", "sensor-b", 1, [8.0, 0.0, 0.0], unit([-4.0, 2.0, 1.0]));
    a.tensor.values.rotate_left(3);
    let mut fusion = QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS);
    fusion.ingest(&a).unwrap();
    fusion.ingest(&b).unwrap();
    assert_close(fusion.estimate().unwrap().position_m, target, 1.0e-5);
}

#[test]
fn position_covariance_preserves_absolute_angular_noise_scale() {
    let target = [5.0, 3.0, 2.0];
    let estimate = |variance: f32| {
        let mut a = event("a", "sensor-a", 1, [0.0, 0.0, 0.0], unit(target));
        let mut b = event("b", "sensor-b", 1, [10.0, 0.0, 0.0], unit([-5.0, 3.0, 2.0]));
        for event in [&mut a, &mut b] {
            event
                .observation
                .features
                .insert("angle_cov_00_rad2".into(), variance);
            event
                .observation
                .features
                .insert("angle_cov_11_rad2".into(), variance);
            event.tensor.noise_floor = variance.sqrt();
        }
        let mut fusion = QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS);
        fusion.ingest(&a).unwrap();
        fusion.ingest(&b).unwrap();
        fusion.estimate().unwrap()
    };
    let low = estimate(1.0e-6);
    let high = estimate(4.0e-6);
    for axis in 0..3 {
        let ratio = high.covariance_m2[axis][axis] / low.covariance_m2[axis][axis];
        assert!((ratio - 4.0).abs() < 1.0e-4, "axis {axis}: ratio={ratio}");
    }
}

#[test]
fn parallel_axes_fail_closed() {
    let a = event("a", "sensor-a", 1, [0.0, 0.0, 0.0], [1.0, 0.0, 0.0]);
    let b = event("b", "sensor-b", 1, [0.0, 1.0, 0.0], [1.0, 0.0, 0.0]);
    let mut fusion = QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS);
    fusion.ingest(&a).unwrap();
    fusion.ingest(&b).unwrap();
    assert!(matches!(
        fusion.estimate(),
        Err(BearingFusionError::DegenerateGeometry { .. })
    ));
}

#[test]
fn malformed_vector_and_covariance_are_rejected() {
    let mut bad_vector = event("a", "sensor-a", 1, [0.0; 3], [1.0, 0.0, 0.0]);
    bad_vector.tensor.values[0] = 2.0;
    assert!(matches!(
        QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS).ingest(&bad_vector),
        Err(BearingFusionError::InvalidObservation(_))
    ));

    let mut bad_covariance = event("b", "sensor-b", 1, [0.0; 3], [1.0, 0.0, 0.0]);
    bad_covariance
        .observation
        .features
        .insert("angle_cov_01_rad2".into(), 1.0);
    assert!(matches!(
        QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS).ingest(&bad_covariance),
        Err(BearingFusionError::InvalidObservation(_))
    ));

    let mut subtly_indefinite = event("c", "sensor-c", 1, [0.0; 3], [1.0, 0.0, 0.0]);
    subtly_indefinite
        .observation
        .features
        .insert("angle_cov_00_rad2".into(), 1.0e-12);
    subtly_indefinite
        .observation
        .features
        .insert("angle_cov_01_rad2".into(), 5.0e-7);
    subtly_indefinite
        .observation
        .features
        .insert("angle_cov_11_rad2".into(), 1.0e-12);
    assert!(matches!(
        QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS).ingest(&subtly_indefinite),
        Err(BearingFusionError::InvalidObservation(_))
    ));
}

#[test]
fn fusion_rechecks_canonical_wire_quality_invariants() {
    let rejected = |candidate: &FieldEvent| {
        QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS)
            .ingest(candidate)
            .is_err()
    };

    let mut fractional_gate = event("gate", "sensor-a", 1, [0.0; 3], [1.0, 0.0, 0.0]);
    fractional_gate
        .observation
        .features
        .insert("quality_valid".into(), 0.5);
    assert!(rejected(&fractional_gate));

    let mut invalid_sign = event("sign", "sensor-a", 1, [0.0; 3], [1.0, 0.0, 0.0]);
    invalid_sign
        .observation
        .features
        .insert("sign_ambiguous".into(), 1.5);
    assert!(rejected(&invalid_sign));

    let mut invalid_quality = event("quality", "sensor-a", 1, [0.0; 3], [1.0, 0.0, 0.0]);
    invalid_quality
        .observation
        .features
        .insert("lock_quality".into(), 1.1);
    assert!(rejected(&invalid_quality));

    let mut invalid_carrier = event("carrier", "sensor-a", 1, [0.0; 3], [1.0, 0.0, 0.0]);
    invalid_carrier
        .observation
        .features
        .insert("carrier_hz".into(), f32::MAX);
    assert!(rejected(&invalid_carrier));

    let mut missing_pose_mirror = event("pose", "sensor-a", 1, [0.0; 3], [1.0, 0.0, 0.0]);
    missing_pose_mirror
        .observation
        .features
        .remove("sensor_x_m");
    assert!(rejected(&missing_pose_mirror));

    let mut inexact_pose_mirror = event("pose-bits", "sensor-a", 1, [0.0; 3], [1.0, 0.0, 0.0]);
    inexact_pose_mirror
        .observation
        .features
        .insert("sensor_x_m".into(), 0.000_5);
    assert!(rejected(&inexact_pose_mirror));

    let mut inconsistent_expiry = event("expiry", "sensor-a", 1, [0.0; 3], [1.0, 0.0, 0.0]);
    inconsistent_expiry
        .observation
        .features
        .insert("calibration_remaining_s".into(), 1.0);
    assert!(rejected(&inconsistent_expiry));

    let mut wrong_version = event("version", "sensor-a", 1, [0.0; 3], [1.0, 0.0, 0.0]);
    wrong_version.spec_version = "rufield.mfs.v999".into();
    assert!(rejected(&wrong_version));
}

#[test]
fn unsigned_live_event_and_closed_quality_gate_are_rejected() {
    let mut unsigned = event("a", "sensor-a", 1, [0.0; 3], [1.0, 0.0, 0.0]);
    unsigned.provenance.synthetic = false;
    assert!(matches!(
        QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS).ingest(&unsigned),
        Err(BearingFusionError::NotFusable(_))
    ));

    let mut gated = event("b", "sensor-b", 1, [0.0; 3], [1.0, 0.0, 0.0]);
    gated
        .observation
        .features
        .insert("quality_valid".into(), 0.0);
    assert!(matches!(
        QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS).ingest(&gated),
        Err(BearingFusionError::InvalidObservation(_))
    ));

    let mut linear = event("c", "sensor-c", 1, [0.0; 3], [1.0, 0.0, 0.0]);
    linear
        .observation
        .features
        .insert("ellipticity".into(), 0.0);
    assert!(matches!(
        QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS).ingest(&linear),
        Err(BearingFusionError::InvalidObservation(_))
    ));

    let mut raw = event("d", "sensor-d", 1, [0.0; 3], [1.0, 0.0, 0.0]);
    raw.tensor.privacy_class = PrivacyClass::P0;
    raw.observation.privacy_class = PrivacyClass::P0;
    assert!(matches!(
        QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS).ingest(&raw),
        Err(BearingFusionError::InvalidObservation(_))
    ));
}

#[test]
fn synchronization_and_unique_viewpoint_invariants_hold() {
    let mut a = event("a", "sensor-a", 1_100_000_000, [0.0; 3], [1.0, 0.0, 0.0]);
    let duplicate = event("b", "sensor-a", 1_100_000_001, [0.0; 3], [0.0, 1.0, 0.0]);
    let mut early = event(
        "early",
        "sensor-b",
        1_000_000_000,
        [1.0, 0.0, 0.0],
        [0.0, 1.0, 0.0],
    );
    let late = event(
        "late",
        "sensor-c",
        1_200_000_000,
        [2.0, 0.0, 0.0],
        [0.0, 0.0, 1.0],
    );
    set_integration_ms(&mut a, 200.0);
    set_integration_ms(&mut early, 200.0);
    let mut fusion = QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS);
    fusion.ingest(&a).unwrap();
    assert!(matches!(
        fusion.ingest(&duplicate),
        Err(BearingFusionError::DuplicateSensor(_))
    ));
    fusion.ingest(&early).unwrap();
    assert!(matches!(
        fusion.ingest(&late),
        Err(BearingFusionError::TimeSkew { .. })
    ));
    assert_eq!(fusion.len(), 2);
    fusion.clear();
    assert!(fusion.is_empty());
}

#[test]
fn integration_windows_and_tensor_frame_fail_closed() {
    let a = event("a", "sensor-a", 100_000_000, [0.0; 3], [1.0, 0.0, 0.0]);
    let b = event(
        "b",
        "sensor-b",
        115_000_000,
        [1.0, 0.0, 0.0],
        [0.0, 1.0, 0.0],
    );
    let mut fusion = QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS);
    fusion.ingest(&a).unwrap();
    assert!(matches!(
        fusion.ingest(&b),
        Err(BearingFusionError::IntegrationWindowMismatch {
            gap_ns: 5_000_000,
            ..
        })
    ));

    let mut missing_frame = event("c", "sensor-c", 100_000_000, [0.0; 3], [1.0, 0.0, 0.0]);
    missing_frame.observation.attributes.remove("tensor_frame");
    assert!(matches!(
        QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS).ingest(&missing_frame),
        Err(BearingFusionError::InvalidObservation(_))
    ));
}

#[test]
fn invalid_fusion_configuration_is_rejected() {
    let invalid = BearingFusionConfig {
        min_geometry_angle_rad: f64::NAN,
        ..BearingFusionConfig::default()
    };
    assert!(matches!(
        QuantumBearingFusion::with_config(invalid, BearingTrustPolicy::simulation()),
        Err(BearingFusionError::InvalidConfiguration(_))
    ));
}

#[test]
fn evidence_group_and_baseline_gates_fail_closed() {
    let a = event("a", "sensor-a", 1, [0.0; 3], [1.0, 0.0, 0.0]);
    let mut wrong_frame = event("b", "sensor-b", 1, [1.0, 0.0, 0.0], [0.0, 1.0, 0.0]);
    wrong_frame.sensor.coordinate_frame = Some("other_frame".into());
    let mut fusion = QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS);
    fusion.ingest(&a).unwrap();
    assert!(matches!(
        fusion.ingest(&wrong_frame),
        Err(BearingFusionError::CoordinateFrameMismatch { .. })
    ));

    let mut wrong_signal = event("c", "sensor-c", 1, [1.0, 0.0, 0.0], [0.0, 1.0, 0.0]);
    wrong_signal
        .observation
        .attributes
        .insert("signal_id".into(), "pilot-beta".into());
    assert!(matches!(
        fusion.ingest(&wrong_signal),
        Err(BearingFusionError::SignalMismatch { .. })
    ));

    let mut wrong_carrier = event("d", "sensor-d", 1, [1.0, 0.0, 0.0], [0.0, 1.0, 0.0]);
    wrong_carrier
        .observation
        .features
        .insert("carrier_hz".into(), 6.642e9_f32);
    assert!(matches!(
        fusion.ingest(&wrong_carrier),
        Err(BearingFusionError::CarrierMismatch { .. })
    ));

    let co_located = event("e", "sensor-e", 1, [0.0; 3], [0.0, 1.0, 0.0]);
    fusion.ingest(&co_located).unwrap();
    assert!(matches!(
        fusion.estimate(),
        Err(BearingFusionError::InsufficientBaseline { .. })
    ));
}

#[test]
fn production_policy_rejects_synthetic_and_unknown_signers() {
    let synthetic = event("synthetic", "sensor-a", 1, [0.0; 3], [1.0, 0.0, 0.0]);
    assert!(matches!(
        QuantumBearingFusion::default().ingest(&synthetic),
        Err(BearingFusionError::SyntheticRejected(_))
    ));

    let signer = Signer::from_seed(b"quantum-bearing-test-key-32byte!");
    let other_signer = Signer::from_seed(&[0x19; 32]);
    let mut live = event("live", "sensor-b", 1_000_000_000, [0.0; 3], [1.0, 0.0, 0.0]);
    sign_live(&mut live, &signer);
    let binding = binding_for(&live, &other_signer);
    let policy = BearingTrustPolicy::production([binding], live_window(1_000_000_000)).unwrap();
    let mut fusion = QuantumBearingFusion::new(DEFAULT_MAX_TIME_SKEW_NS, policy);
    assert!(matches!(
        fusion.ingest(&live),
        Err(BearingFusionError::UntrustedSigner(_))
    ));
}

#[test]
fn production_policy_accepts_an_allowlisted_verified_signer() {
    let signer = Signer::from_seed(b"quantum-bearing-test-key-32byte!");
    let mut live = event("live", "sensor-a", 1_000_000_000, [0.0; 3], [1.0, 0.0, 0.0]);
    sign_live(&mut live, &signer);
    let binding = binding_for(&live, &signer);
    let policy = BearingTrustPolicy::production([binding], live_window(1_000_000_000)).unwrap();
    let mut fusion = QuantumBearingFusion::new(DEFAULT_MAX_TIME_SKEW_NS, policy);
    fusion.ingest(&live).unwrap();
    assert_eq!(fusion.len(), 1);
}

#[test]
fn captured_replay_requires_a_distinct_trust_policy() {
    let signer = Signer::from_seed(&[0x52; 32]);
    let mut captured = event("captured", "sensor-a", 1, [0.0; 3], [1.0, 0.0, 0.0]);
    captured.provenance.synthetic = false;
    captured
        .observation
        .attributes
        .insert("evidence_kind".into(), "captured_replay".into());
    signer.sign_event(&mut captured).unwrap();

    let production = BearingTrustPolicy::production(
        [binding_for(&captured, &signer)],
        live_window(captured.timestamp_ns),
    )
    .unwrap();
    assert!(matches!(
        QuantumBearingFusion::new(DEFAULT_MAX_TIME_SKEW_NS, production).ingest(&captured),
        Err(BearingFusionError::EvidenceKindRejected { .. })
    ));

    let replay = BearingTrustPolicy::captured_replay([signer.public_hex()]).unwrap();
    let mut fusion = QuantumBearingFusion::new(DEFAULT_MAX_TIME_SKEW_NS, replay);
    fusion.ingest(&captured).unwrap();
    assert_eq!(fusion.len(), 1);
}

#[test]
fn production_binding_rejects_fabricated_devices_revocation_and_duplicate_keys() {
    let signer = Signer::from_seed(&[0x21; 32]);
    let enrolled = event(
        "enrolled",
        "sensor-a",
        1_000_000_000,
        [0.0; 3],
        [1.0, 0.0, 0.0],
    );
    let binding = binding_for(&enrolled, &signer);

    let mut fabricated = event(
        "fabricated",
        "sensor-b",
        1_000_000_000,
        [10.0, 0.0, 0.0],
        [0.0, 1.0, 0.0],
    );
    sign_live(&mut fabricated, &signer);
    let policy =
        BearingTrustPolicy::production([binding.clone()], live_window(1_000_000_000)).unwrap();
    assert!(matches!(
        QuantumBearingFusion::new(DEFAULT_MAX_TIME_SKEW_NS, policy).ingest(&fabricated),
        Err(BearingFusionError::UnknownTrustedSensor(id)) if id == "sensor-b"
    ));

    let mut revoked = binding.clone();
    revoked.revoked = true;
    let mut enrolled_event = enrolled.clone();
    sign_live(&mut enrolled_event, &signer);
    let policy = BearingTrustPolicy::production([revoked], live_window(1_000_000_000)).unwrap();
    assert!(matches!(
        QuantumBearingFusion::new(DEFAULT_MAX_TIME_SKEW_NS, policy).ingest(&enrolled_event),
        Err(BearingFusionError::RevokedTrustedSensor(id)) if id == "sensor-a"
    ));

    let other = event(
        "other",
        "sensor-b",
        1_000_000_000,
        [10.0, 0.0, 0.0],
        [0.0, 1.0, 0.0],
    );
    assert!(matches!(
        BearingTrustPolicy::production(
            [binding, binding_for(&other, &signer)],
            live_window(1_000_000_000)
        ),
        Err(BearingFusionError::InvalidTrustPolicy(_))
    ));
}

#[test]
fn production_binding_rejects_pose_and_calibration_hash_mismatch() {
    let signer = Signer::from_seed(&[0x22; 32]);
    let original = event(
        "original",
        "sensor-a",
        1_000_000_000,
        [0.0; 3],
        [1.0, 0.0, 0.0],
    );
    let binding = binding_for(&original, &signer);

    let mut moved = original.clone();
    moved.event_id = "moved".into();
    moved.sensor.position_m = Some([1.0, 0.0, 0.0]);
    sign_live(&mut moved, &signer);
    let policy =
        BearingTrustPolicy::production([binding.clone()], live_window(1_000_000_000)).unwrap();
    assert!(matches!(
        QuantumBearingFusion::new(DEFAULT_MAX_TIME_SKEW_NS, policy).ingest(&moved),
        Err(BearingFusionError::TrustedSensorBindingMismatch {
            field: "position_m",
            ..
        })
    ));

    let mut wrong_hash = original;
    wrong_hash.event_id = "wrong-hash".into();
    wrong_hash.observation.attributes.insert(
        "calibration_data_hash".into(),
        "sha256:2222222222222222222222222222222222222222222222222222222222222222".into(),
    );
    sign_live(&mut wrong_hash, &signer);
    let policy = BearingTrustPolicy::production([binding], live_window(1_000_000_000)).unwrap();
    assert!(matches!(
        QuantumBearingFusion::new(DEFAULT_MAX_TIME_SKEW_NS, policy).ingest(&wrong_hash),
        Err(BearingFusionError::TrustedSensorBindingMismatch {
            field: "calibration_data_hash",
            ..
        })
    ));

    let original = event(
        "original-created",
        "sensor-a",
        1_000_000_000,
        [0.0; 3],
        [1.0, 0.0, 0.0],
    );
    let binding = binding_for(&original, &signer);
    let mut wrong_created = original;
    wrong_created
        .observation
        .attributes
        .insert("calibration_created_ns".into(), "1".into());
    sign_live(&mut wrong_created, &signer);
    let policy = BearingTrustPolicy::production([binding], live_window(1_000_000_000)).unwrap();
    assert!(matches!(
        QuantumBearingFusion::new(DEFAULT_MAX_TIME_SKEW_NS, policy).ingest(&wrong_created),
        Err(BearingFusionError::TrustedSensorBindingMismatch {
            field: "calibration_created_ns",
            ..
        })
    ));
}

#[test]
fn malformed_signed_event_does_not_advance_live_replay_watermark() {
    let signer = Signer::from_seed(&[0x24; 32]);
    let timestamp_ns = 2_000_000_000;
    let original = event(
        "original",
        "sensor-a",
        timestamp_ns,
        [0.0; 3],
        [1.0, 0.0, 0.0],
    );
    let binding = binding_for(&original, &signer);
    let policy = BearingTrustPolicy::production([binding], live_window(timestamp_ns)).unwrap();
    let mut fusion = QuantumBearingFusion::new(DEFAULT_MAX_TIME_SKEW_NS, policy);

    let mut malformed = original.clone();
    malformed.event_id = "malformed".into();
    malformed.tensor.values[0] = 2.0;
    sign_live(&mut malformed, &signer);
    assert!(matches!(
        fusion.ingest(&malformed),
        Err(BearingFusionError::InvalidObservation(_))
    ));

    let mut valid = original;
    valid.event_id = "valid".into();
    sign_live(&mut valid, &signer);
    fusion.ingest(&valid).unwrap();
    assert_eq!(fusion.len(), 1);
}

#[test]
fn live_freshness_future_skew_and_replay_watermark_fail_closed() {
    let signer = Signer::from_seed(&[0x23; 32]);
    let evaluation_ns = 2_000_000_000;
    let window = LiveTrustWindow {
        evaluation_time_ns: evaluation_ns,
        max_event_age_ns: 100,
        max_future_skew_ns: 50,
    };

    let mut stale = event(
        "stale",
        "sensor-a",
        evaluation_ns - 101,
        [0.0; 3],
        [1.0, 0.0, 0.0],
    );
    sign_live(&mut stale, &signer);
    let policy = BearingTrustPolicy::production([binding_for(&stale, &signer)], window).unwrap();
    assert!(matches!(
        QuantumBearingFusion::new(DEFAULT_MAX_TIME_SKEW_NS, policy).ingest(&stale),
        Err(BearingFusionError::StaleLiveEvent { age_ns: 101, .. })
    ));

    let mut future = event(
        "future",
        "sensor-a",
        evaluation_ns + 51,
        [0.0; 3],
        [1.0, 0.0, 0.0],
    );
    sign_live(&mut future, &signer);
    let policy = BearingTrustPolicy::production([binding_for(&future, &signer)], window).unwrap();
    assert!(matches!(
        QuantumBearingFusion::new(DEFAULT_MAX_TIME_SKEW_NS, policy).ingest(&future),
        Err(BearingFusionError::FutureLiveEvent { skew_ns: 51, .. })
    ));

    let mut first = event(
        "first",
        "sensor-a",
        evaluation_ns,
        [0.0; 3],
        [1.0, 0.0, 0.0],
    );
    sign_live(&mut first, &signer);
    let policy = BearingTrustPolicy::production([binding_for(&first, &signer)], window).unwrap();
    let mut fusion = QuantumBearingFusion::new(DEFAULT_MAX_TIME_SKEW_NS, policy);
    fusion.ingest(&first).unwrap();
    fusion.clear();

    let mut replay = event(
        "replay",
        "sensor-a",
        evaluation_ns,
        [0.0; 3],
        [1.0, 0.0, 0.0],
    );
    sign_live(&mut replay, &signer);
    assert!(matches!(
        fusion.ingest(&replay),
        Err(BearingFusionError::LiveReplayDetected {
            timestamp_ns,
            ..
        }) if timestamp_ns == evaluation_ns
    ));
}

#[test]
fn trusted_time_advances_in_place_without_erasing_replay_watermarks() {
    let signer = Signer::from_seed(&[0x25; 32]);
    let first_timestamp_ns = 1_000_000_000;
    let second_timestamp_ns = 2_000_000_000;
    let mut first = event(
        "first-live",
        "sensor-a",
        first_timestamp_ns,
        [0.0; 3],
        [1.0, 0.0, 0.0],
    );
    sign_live(&mut first, &signer);
    let policy = BearingTrustPolicy::production(
        [binding_for(&first, &signer)],
        live_window(first_timestamp_ns),
    )
    .unwrap();
    let mut fusion = QuantumBearingFusion::new(DEFAULT_MAX_TIME_SKEW_NS, policy);
    fusion.ingest(&first).unwrap();
    assert!(matches!(
        fusion.advance_live_evaluation_time(second_timestamp_ns),
        Err(BearingFusionError::InvalidTrustPolicy(_))
    ));
    fusion.clear();

    assert!(matches!(
        fusion.advance_live_evaluation_time(first_timestamp_ns - 1),
        Err(BearingFusionError::InvalidTrustPolicy(_))
    ));
    fusion
        .advance_live_evaluation_time(second_timestamp_ns)
        .unwrap();

    let mut second = event(
        "second-live",
        "sensor-a",
        second_timestamp_ns,
        [0.0; 3],
        [1.0, 0.0, 0.0],
    );
    sign_live(&mut second, &signer);
    fusion.ingest(&second).unwrap();
    fusion.clear();

    let mut replay = second;
    replay.event_id = "second-live-replay".into();
    sign_live(&mut replay, &signer);
    assert!(matches!(
        fusion.ingest(&replay),
        Err(BearingFusionError::LiveReplayDetected {
            timestamp_ns,
            ..
        }) if timestamp_ns == second_timestamp_ns
    ));
}

#[test]
fn estimate_expiry_is_capped_by_earliest_calibration() {
    let target = [5.0, 3.0, 2.0];
    let timestamp_ns = 1_000_000_000;
    let calibration_expiry = 1_050_000_000;
    let mut a = event("a", "sensor-a", timestamp_ns, [0.0, 0.0, 0.0], unit(target));
    let mut b = event(
        "b",
        "sensor-b",
        timestamp_ns,
        [10.0, 0.0, 0.0],
        unit([-5.0, 3.0, 2.0]),
    );
    for event in [&mut a, &mut b] {
        set_calibration_expiry(event, calibration_expiry);
    }
    let mut fusion = QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS);
    fusion.ingest(&a).unwrap();
    fusion.ingest(&b).unwrap();
    assert_eq!(fusion.estimate().unwrap().expires_ns, calibration_expiry);
}

#[test]
fn estimate_expired_before_latest_capture_is_rejected() {
    let target = [5.0, 3.0, 2.0];
    let mut a = event(
        "a",
        "sensor-a",
        1_000_000_000,
        [0.0, 0.0, 0.0],
        unit(target),
    );
    let mut b = event(
        "b",
        "sensor-b",
        1_300_000_000,
        [10.0, 0.0, 0.0],
        unit([-5.0, 3.0, 2.0]),
    );
    set_integration_ms(&mut a, 500.0);
    set_integration_ms(&mut b, 500.0);
    set_calibration_expiry(&mut a, 1_260_000_000);

    let mut fusion = QuantumBearingFusion::for_simulation(400_000_000);
    fusion.ingest(&a).unwrap();
    fusion.ingest(&b).unwrap();
    assert!(matches!(
        fusion.estimate(),
        Err(BearingFusionError::EstimateExpired {
            produced_ns: 1_300_000_000,
            expires_ns: 1_260_000_000,
        })
    ));
}

#[test]
fn carrier_span_and_touching_half_open_intervals_are_rejected() {
    let timestamp_ns = 100_000_000;
    let first = event(
        "first",
        "sensor-a",
        timestamp_ns,
        [0.0, 0.0, 0.0],
        [1.0, 0.0, 0.0],
    );
    let mut low = event(
        "low",
        "sensor-b",
        timestamp_ns,
        [1.0, 0.0, 0.0],
        [0.0, 1.0, 0.0],
    );
    low.observation
        .features
        .insert("carrier_hz".into(), 6.6391e9_f32);
    let mut high = event(
        "high",
        "sensor-c",
        timestamp_ns,
        [2.0, 0.0, 0.0],
        [0.0, 0.0, 1.0],
    );
    high.observation
        .features
        .insert("carrier_hz".into(), 6.6409e9_f32);
    let mut fusion = QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS);
    fusion.ingest(&first).unwrap();
    fusion.ingest(&low).unwrap();
    assert!(matches!(
        fusion.ingest(&high),
        Err(BearingFusionError::CarrierMismatch { .. })
    ));

    let a = event(
        "a",
        "sensor-a",
        100_000_000,
        [0.0, 0.0, 0.0],
        [1.0, 0.0, 0.0],
    );
    let b = event(
        "b",
        "sensor-b",
        110_000_000,
        [1.0, 0.0, 0.0],
        [0.0, 1.0, 0.0],
    );
    let mut fusion = QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS);
    fusion.ingest(&a).unwrap();
    assert!(matches!(
        fusion.ingest(&b),
        Err(BearingFusionError::IntegrationWindowMismatch { gap_ns: 0, .. })
    ));
}
