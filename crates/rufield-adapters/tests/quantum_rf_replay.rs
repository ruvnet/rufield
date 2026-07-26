use rufield_adapters::{
    QuantumRfOutput, ReplaySource, RydbergFrame, RydbergGateFailure, RydbergQualityThresholds,
    RydbergReplayAdapter, RydbergReplayConfig, RydbergReplayError, MAX_ID_BYTES,
    MAX_QUANTUM_RF_LINE_BYTES,
};
use rufield_core::{FieldAdapter, FieldAxis, Modality, PrivacyClass};
use rufield_fusion::{QuantumBearingFusion, DEFAULT_MAX_TIME_SKEW_NS};
use rufield_provenance::{is_fusable, verify_event};

const FIXTURE: &str = include_str!("fixtures/synthetic_quantum_rf.jsonl");

fn valid_frame() -> RydbergFrame {
    RydbergFrame {
        timestamp_ns: 1_000_000_000,
        sensor_position_m: [1.0, 2.0, 3.0],
        sensor_orientation_xyzw: [0.0, 0.0, 0.0, 1.0],
        coordinate_frame: "lab_world_enu".into(),
        signal_id: "pilot-6g64-01".into(),
        carrier_hz: 6_640_000_000.0,
        e_field_sensor_vpm: [[0.04, 0.0], [0.0, 0.03], [0.0, 0.0]],
        k_hat_sensor: [0.0, 0.0, 1.0],
        sign_ambiguous: true,
        ellipticity: 0.96,
        snr_db: 30.0,
        integration_ms: 10.0,
        angular_covariance_rad2: [[0.001, 0.0002], [0.0002, 0.002]],
        calibration_id: "rydberg-cal-001".into(),
        calibration_created_ns: 900_000_000,
        calibration_expires_ns: 3_000_000_000,
        calibration_quality: 0.95,
        lock_quality: 0.98,
    }
}

fn adapter_from(frame: RydbergFrame) -> Result<RydbergReplayAdapter, RydbergReplayError> {
    RydbergReplayAdapter::from_frames_with_config(vec![frame], RydbergReplayConfig::default())
}

fn assert_gate(frame: RydbergFrame, expected: RydbergGateFailure) {
    match adapter_from(frame) {
        Err(RydbergReplayError::QualityGate { frame: 1, reason }) => {
            assert_eq!(reason, expected)
        }
        other => panic!(
            "expected quality gate {expected:?}, got {}",
            error_name(other)
        ),
    }
}

fn error_name(result: Result<RydbergReplayAdapter, RydbergReplayError>) -> String {
    match result {
        Ok(_) => "Ok(adapter)".into(),
        Err(error) => format!("Err({error})"),
    }
}

#[test]
fn default_emits_signed_p1_antipodal_bearings_with_typed_pose() {
    let adapter = RydbergReplayAdapter::from_jsonl(FIXTURE).expect("valid fixture");
    let receipt = adapter.calibration_receipt();
    assert_eq!(adapter.frame_count(), 2);
    assert_eq!(adapter.modality(), Modality::QuantumRf);
    assert_eq!(adapter.capabilities().sample_rate_hz, 10);
    assert_eq!(adapter.capabilities().max_privacy_class, PrivacyClass::P1);

    let events = adapter.collect_events().expect("events");
    for event in &events {
        assert_eq!(event.tensor.modality, Modality::QuantumRf);
        assert_eq!(
            event.tensor.axes,
            vec![FieldAxis::DirectionCandidate, FieldAxis::CartesianComponent]
        );
        assert_eq!(event.tensor.shape, vec![2, 3]);
        assert_eq!(event.tensor.values, vec![0.0, 0.0, 1.0, 0.0, 0.0, -1.0]);
        assert_eq!(event.tensor.privacy_class, PrivacyClass::P1);
        assert_eq!(event.observation.privacy_class, PrivacyClass::P1);
        assert_eq!(
            event.tensor.calibration_id.as_deref(),
            Some("rydberg-cal-001")
        );
        assert_eq!(event.provenance.calibration_id, "rydberg-cal-001");
        assert_eq!(
            event.sensor.coordinate_frame.as_deref(),
            Some("lab_world_enu")
        );
        assert_eq!(event.sensor.position_m, Some([1.0, 2.0, 3.0]));
        assert_eq!(event.sensor.orientation_xyzw, Some([0.0, 0.0, 0.0, 1.0]));
        assert_eq!(event.observation.attributes["signal_id"], "pilot-6g64-01");
        assert_eq!(event.observation.attributes["tensor_frame"], "sensor_local");
        assert_eq!(
            event.observation.attributes["evidence_kind"],
            "synthetic_replay"
        );
        assert_eq!(
            event.observation.attributes["calibration_data_hash"],
            receipt.data_hash
        );
        assert_eq!(
            event.observation.attributes["calibration_created_ns"],
            "900000000"
        );
        assert_eq!(
            event.observation.attributes["calibration_expires_ns"],
            "3000000000"
        );
        for index in 0..3 {
            assert_eq!(
                event.tensor.values[index + 3].to_bits(),
                (-event.tensor.values[index]).to_bits()
            );
        }
        assert_eq!(event.observation.features["quality_valid"], 1.0);
        assert_eq!(event.observation.features["sign_ambiguous"], 1.0);
        assert!(event.observation.features["calibration_remaining_s"] > 0.0);
        assert_eq!(
            event.observation.features["sensor_x_m"],
            event.sensor.position_m.unwrap()[0]
        );
        assert_eq!(
            event.observation.features["sensor_y_m"],
            event.sensor.position_m.unwrap()[1]
        );
        assert_eq!(
            event.observation.features["sensor_z_m"],
            event.sensor.position_m.unwrap()[2]
        );
        assert_eq!(event.observation.features.len(), 16);
        assert!(event.tensor.noise_floor > 0.002_f32.sqrt());
        assert!(event.tensor.values.iter().all(|value| value.is_finite()));
        assert!(event
            .observation
            .features
            .values()
            .all(|value| value.is_finite()));
        assert_eq!(event.observation.range_m, None);
        assert_eq!(event.observation.velocity_mps, None);
        assert_eq!(event.observation.motion_vector, None);
        assert!(event.provenance.synthetic);
        assert!(verify_event(event).is_ok());
        assert!(is_fusable(event));
        event.tensor.validate().expect("tensor invariant");
    }
}

#[test]
fn conversion_boundaries_fail_closed_without_repair() {
    let min_subnormal = f64::from(f32::from_bits(1));

    let mut frame = valid_frame();
    frame.e_field_sensor_vpm[2][0] = min_subnormal / 2.0;
    assert_gate(frame, RydbergGateFailure::RawPhasorUnderflow);

    let mut frame = valid_frame();
    frame.carrier_hz = min_subnormal / 2.0;
    assert_gate(
        frame,
        RydbergGateFailure::FeatureNotRepresentable("carrier_hz"),
    );

    let mut frame = valid_frame();
    frame.sensor_position_m[0] = min_subnormal / 2.0;
    assert_gate(
        frame,
        RydbergGateFailure::FeatureNotRepresentable("sensor_x_m"),
    );

    let mut frame = valid_frame();
    frame.angular_covariance_rad2 = [[1.0e-50, 0.0], [0.0, 1.0e-50]];
    assert_gate(frame, RydbergGateFailure::InvalidAngularCovariance);

    let mut frame = valid_frame();
    frame.k_hat_sensor[2] = 1.0 + 9.99e-6;
    assert_gate(frame, RydbergGateFailure::DirectionNotNormalized);

    let mut frame = valid_frame();
    frame.sensor_orientation_xyzw[3] = 1.0 + 9.99e-6;
    assert_gate(frame, RydbergGateFailure::OrientationNotNormalized);
}

#[test]
fn integration_interval_requires_positive_post_integration_calibration_headroom() {
    let mut exact = valid_frame();
    exact.calibration_created_ns = exact.timestamp_ns - 5_000_000;
    exact.calibration_expires_ns = exact.timestamp_ns + 5_000_001;
    assert!(adapter_from(exact.clone()).is_ok());

    let mut starts_too_early = exact.clone();
    starts_too_early.calibration_created_ns += 1;
    assert_gate(starts_too_early, RydbergGateFailure::StaleCalibration);

    let mut ends_at_exclusive_bound = exact;
    ends_at_exclusive_bound.calibration_expires_ns -= 1;
    assert_gate(
        ends_at_exclusive_bound,
        RydbergGateFailure::StaleCalibration,
    );

    let mut rounds_to_zero = valid_frame();
    rounds_to_zero.integration_ms = 0.000_000_4;
    assert_gate(
        rounds_to_zero,
        RydbergGateFailure::OutOfRange("integration_ms rounds to zero nanoseconds"),
    );
}

#[test]
fn tensor_stays_sensor_local_and_pose_carries_the_only_world_transform() {
    let half = std::f64::consts::FRAC_1_SQRT_2;
    let mut frame = valid_frame();
    frame.sensor_orientation_xyzw = [0.0, 0.0, half, half];
    frame.e_field_sensor_vpm = [[0.0, 0.0], [0.04, 0.0], [0.0, 0.03]];
    frame.k_hat_sensor = [1.0, 0.0, 0.0];
    let event = &adapter_from(frame).unwrap().collect_events().unwrap()[0];
    assert_eq!(event.tensor.values, vec![1.0, 0.0, 0.0, -1.0, 0.0, 0.0]);
    assert_eq!(
        event.sensor.orientation_xyzw,
        Some([0.0, 0.0, half as f32, half as f32])
    );
    assert_eq!(event.observation.attributes["tensor_frame"], "sensor_local");
}

#[test]
fn raw_mode_is_explicit_p0_and_never_mislabeled_as_bearing() {
    let config = RydbergReplayConfig {
        output: QuantumRfOutput::RawElectricField,
        ..RydbergReplayConfig::default()
    };
    let adapter = RydbergReplayAdapter::from_jsonl_with_config(FIXTURE, config).unwrap();
    assert_eq!(adapter.capabilities().max_privacy_class, PrivacyClass::P0);
    let event = &adapter.collect_events().unwrap()[0];
    assert_eq!(
        event.tensor.axes,
        vec![FieldAxis::CartesianComponent, FieldAxis::ComplexComponent]
    );
    assert_eq!(event.tensor.shape, vec![3, 2]);
    assert_eq!(event.tensor.values, vec![0.04, 0.0, 0.0, 0.03, 0.0, 0.0]);
    assert_eq!(event.tensor.privacy_class, PrivacyClass::P0);
    assert_eq!(event.observation.privacy_class, PrivacyClass::P0);
    assert_eq!(event.observation.labels, vec!["quantum_rf_complex_field"]);
}

#[test]
fn captured_replay_is_signed_without_claiming_synthetic_escape_hatch() {
    let config = RydbergReplayConfig {
        source: ReplaySource::Captured,
        signer_seed: [0x43; 32],
        ..RydbergReplayConfig::default()
    };
    let event = &RydbergReplayAdapter::from_jsonl_with_config(FIXTURE, config)
        .unwrap()
        .collect_events()
        .unwrap()[0];
    assert!(!event.provenance.synthetic);
    assert_eq!(
        event.observation.attributes["evidence_kind"],
        "captured_replay"
    );
    assert!(verify_event(event).is_ok());
    assert!(is_fusable(event));
}

#[test]
fn captured_replay_rejects_public_default_signing_key() {
    let config = RydbergReplayConfig {
        source: ReplaySource::Captured,
        ..RydbergReplayConfig::default()
    };
    assert!(matches!(
        RydbergReplayAdapter::from_jsonl_with_config(FIXTURE, config),
        Err(RydbergReplayError::InvalidConfig(_))
    ));
}

#[test]
fn stream_receipt_and_signatures_are_deterministic() {
    let a = RydbergReplayAdapter::from_jsonl(FIXTURE).unwrap();
    let b = RydbergReplayAdapter::from_jsonl(FIXTURE).unwrap();
    assert_eq!(a.collect_events().unwrap(), b.collect_events().unwrap());
    assert_eq!(a.calibration_receipt(), b.calibration_receipt());
    let receipt = a.calibration_receipt();
    assert_eq!(receipt.modality, "quantum_rf");
    assert_eq!(receipt.task, "rydberg_vector_calibration_replay");
    assert!(receipt.data_hash.starts_with("sha256:"));
}

#[test]
fn raw_hash_binds_measurement_to_device() {
    let a = adapter_from(valid_frame())
        .unwrap()
        .collect_events()
        .unwrap();
    let config = RydbergReplayConfig {
        device_id: "different-device".into(),
        ..RydbergReplayConfig::default()
    };
    let b = RydbergReplayAdapter::from_frames_with_config(vec![valid_frame()], config)
        .unwrap()
        .collect_events()
        .unwrap();
    assert_ne!(a[0].provenance.raw_hash, b[0].provenance.raw_hash);
    assert!(verify_event(&a[0]).is_ok());
    assert!(verify_event(&b[0]).is_ok());
}

#[test]
fn rejects_nonfinite_direction_sign_and_polarization_failures() {
    let mut frame = valid_frame();
    frame.sensor_position_m[0] = f64::NAN;
    assert_gate(frame, RydbergGateFailure::NonFinite("sensor_position_m"));

    let mut frame = valid_frame();
    frame.e_field_sensor_vpm = [[f32::MAX as f64, 0.0], [0.0, f32::MAX as f64], [0.0, 0.0]];
    assert_gate(frame, RydbergGateFailure::NonFinite("field_strength_vpm"));

    let mut frame = valid_frame();
    frame.k_hat_sensor = [0.0, 0.0, 2.0];
    assert_gate(frame, RydbergGateFailure::DirectionNotNormalized);

    let mut frame = valid_frame();
    frame.sign_ambiguous = false;
    assert_gate(frame, RydbergGateFailure::DirectionSignResolved);

    let mut frame = valid_frame();
    frame.e_field_sensor_vpm[1][1] = 1.0e-9;
    assert_gate(frame, RydbergGateFailure::EllipticityDegenerate);

    let mut frame = valid_frame();
    frame.ellipticity = 0.5;
    assert_gate(frame, RydbergGateFailure::EllipticityMismatch);

    let mut frame = valid_frame();
    frame.k_hat_sensor = [1.0, 0.0, 0.0];
    assert_gate(frame, RydbergGateFailure::FieldDirectionMismatch);
}

#[test]
fn rejects_bad_pose_covariance_calibration_and_lock() {
    let mut frame = valid_frame();
    frame.sensor_position_m[0] = 1.0e6 + 1.0;
    assert_gate(frame, RydbergGateFailure::OutOfRange("sensor_position_m"));

    let mut frame = valid_frame();
    frame.sensor_orientation_xyzw = [0.0, 0.0, 0.0, 2.0];
    assert_gate(frame, RydbergGateFailure::OrientationNotNormalized);

    let mut frame = valid_frame();
    frame.coordinate_frame.clear();
    assert_gate(frame, RydbergGateFailure::InvalidCoordinateFrame);

    let mut frame = valid_frame();
    frame.signal_id.clear();
    assert_gate(frame, RydbergGateFailure::InvalidSignalId);

    let mut frame = valid_frame();
    frame.angular_covariance_rad2 = [[0.001, 0.1], [0.0, 0.001]];
    assert_gate(frame, RydbergGateFailure::InvalidAngularCovariance);

    let mut frame = valid_frame();
    frame.angular_covariance_rad2 = [[1.0e-10, 1.0e-5], [1.0e-5, 1.0e-10]];
    assert_gate(frame, RydbergGateFailure::InvalidAngularCovariance);

    let mut frame = valid_frame();
    frame.angular_covariance_rad2 = [[0.1, 0.0], [0.0, 0.1]];
    assert_gate(frame, RydbergGateFailure::AngularUncertaintyTooHigh);

    let mut frame = valid_frame();
    frame.calibration_expires_ns = frame.timestamp_ns;
    assert_gate(frame, RydbergGateFailure::StaleCalibration);

    let mut frame = valid_frame();
    frame.calibration_expires_ns = frame.timestamp_ns + 1_000_000;
    assert_gate(frame, RydbergGateFailure::StaleCalibration);

    let mut frame = valid_frame();
    frame.calibration_id.clear();
    assert_gate(frame, RydbergGateFailure::InvalidCalibrationId);

    let mut frame = valid_frame();
    frame.calibration_created_ns = frame.calibration_expires_ns;
    assert_gate(frame, RydbergGateFailure::InvalidCalibrationWindow);

    let mut frame = valid_frame();
    frame.calibration_quality = 0.5;
    assert_gate(frame, RydbergGateFailure::CalibrationQualityTooLow);

    let mut frame = valid_frame();
    frame.lock_quality = 0.5;
    assert_gate(frame, RydbergGateFailure::OpticalLockQualityTooLow);

    let mut frame = valid_frame();
    frame.snr_db = 5.0;
    assert_gate(frame, RydbergGateFailure::SignalToNoiseTooLow);
}

#[test]
fn rejects_sequence_contract_config_and_parser_abuse() {
    let invalid_thresholds = RydbergQualityThresholds {
        min_lock_quality: f64::NAN,
        ..RydbergQualityThresholds::default()
    };
    assert_eq!(
        valid_frame().validate(invalid_thresholds),
        Err(RydbergGateFailure::InvalidThresholds)
    );

    let first = valid_frame();
    let mut second = valid_frame();
    second.timestamp_ns = first.timestamp_ns;
    match RydbergReplayAdapter::from_frames_with_config(
        vec![first.clone(), second],
        RydbergReplayConfig::default(),
    ) {
        Err(RydbergReplayError::QualityGate {
            frame: 2,
            reason: RydbergGateFailure::NonMonotonicTimestamp,
        }) => {}
        other => panic!("expected monotonic gate, got {}", error_name(other)),
    }

    let first = valid_frame();
    let mut simultaneous_other_signal = first.clone();
    simultaneous_other_signal.signal_id = "pilot-6g64-02".into();
    assert!(RydbergReplayAdapter::from_frames_with_config(
        vec![first.clone(), simultaneous_other_signal],
        RydbergReplayConfig::default(),
    )
    .is_ok());

    let mut second = first.clone();
    second.timestamp_ns += 1;
    second.sensor_position_m[0] += 1.0;
    match RydbergReplayAdapter::from_frames_with_config(
        vec![first, second],
        RydbergReplayConfig::default(),
    ) {
        Err(RydbergReplayError::QualityGate {
            frame: 2,
            reason: RydbergGateFailure::CalibrationContractChanged,
        }) => {}
        other => panic!("expected contract gate, got {}", error_name(other)),
    }

    let config = RydbergReplayConfig {
        device_id: "x".repeat(MAX_ID_BYTES + 1),
        ..RydbergReplayConfig::default()
    };
    assert!(matches!(
        RydbergReplayAdapter::from_frames_with_config(vec![valid_frame()], config),
        Err(RydbergReplayError::InvalidConfig(_))
    ));

    let oversized = " ".repeat(MAX_QUANTUM_RF_LINE_BYTES + 1);
    assert!(matches!(
        RydbergReplayAdapter::from_jsonl(&oversized),
        Err(RydbergReplayError::LineTooLong { line: 1, .. })
    ));

    let unknown = FIXTURE.lines().next().unwrap().replace(
        "\"lock_quality\":0.98",
        "\"lock_quality\":0.98,\"unknown\":1",
    );
    assert!(matches!(
        RydbergReplayAdapter::from_jsonl(&unknown),
        Err(RydbergReplayError::Parse { line: 1, .. })
    ));
}

#[test]
fn two_replay_adapters_feed_sign_invariant_fusion_end_to_end() {
    let diagonal = std::f64::consts::FRAC_1_SQRT_2;
    let make_frame = |position: [f64; 3], axis: [f64; 3]| {
        let mut frame = valid_frame();
        frame.sensor_position_m = position;
        frame.k_hat_sensor = axis;
        frame.e_field_sensor_vpm = [[0.0, axis[1] * 0.04], [0.0, -axis[0] * 0.04], [0.04, 0.0]];
        frame.ellipticity = 1.0;
        frame
    };
    let mut a = RydbergReplayAdapter::from_frames_with_config(
        vec![make_frame([0.0, 0.0, 0.0], [diagonal, diagonal, 0.0])],
        RydbergReplayConfig {
            device_id: "quantum-a".into(),
            ..RydbergReplayConfig::default()
        },
    )
    .unwrap()
    .collect_events()
    .unwrap();
    let mut b = RydbergReplayAdapter::from_frames_with_config(
        vec![make_frame([2.0, 0.0, 0.0], [-diagonal, diagonal, 0.0])],
        RydbergReplayConfig {
            device_id: "quantum-b".into(),
            ..RydbergReplayConfig::default()
        },
    )
    .unwrap()
    .collect_events()
    .unwrap();

    let mut fusion = QuantumBearingFusion::for_simulation(DEFAULT_MAX_TIME_SKEW_NS);
    fusion.ingest(&a.remove(0)).unwrap();
    fusion.ingest(&b.remove(0)).unwrap();
    let estimate = fusion.estimate().unwrap();
    for (actual, expected) in estimate.position_m.into_iter().zip([1.0, 1.0, 0.0]) {
        assert!((actual - expected).abs() < 1.0e-6, "{actual} != {expected}");
    }
}
