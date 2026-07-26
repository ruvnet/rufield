//! Canonical encoding and compatibility features for quantum RF replay.

use crate::quantum_rf_replay::{
    ReplaySource, RydbergFrame, RydbergReplayConfig, RydbergReplayError, MAX_ID_BYTES,
    QUANTUM_RF_REPLAY_SIGNER_SEED,
};
use rufield_core::Observation;

pub(crate) fn validate_config(config: &RydbergReplayConfig) -> Result<(), RydbergReplayError> {
    for (name, value) in [
        ("device_id", config.device_id.as_str()),
        ("placement", config.placement.as_str()),
        ("zone_id", config.zone_id.as_str()),
    ] {
        if !valid_id(value) {
            return Err(RydbergReplayError::InvalidConfig(format!(
                "{name} must be nonempty, control-free, and at most {MAX_ID_BYTES} bytes"
            )));
        }
    }
    if config.source == ReplaySource::Captured
        && (config.signer_seed == QUANTUM_RF_REPLAY_SIGNER_SEED
            || config.signer_seed.iter().all(|byte| *byte == 0))
    {
        return Err(RydbergReplayError::InvalidConfig(
            "captured replay requires an explicit nondefault signing seed".into(),
        ));
    }
    Ok(())
}

pub(crate) fn valid_id(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_ID_BYTES && !value.chars().any(char::is_control)
}

pub(crate) fn same_calibration_contract(a: &RydbergFrame, b: &RydbergFrame) -> bool {
    a.sensor_position_m == b.sensor_position_m
        && a.sensor_orientation_xyzw == b.sensor_orientation_xyzw
        && a.coordinate_frame == b.coordinate_frame
        && a.carrier_hz == b.carrier_hz
        && a.calibration_id == b.calibration_id
        && a.calibration_created_ns == b.calibration_created_ns
        && a.calibration_expires_ns == b.calibration_expires_ns
        && a.calibration_quality == b.calibration_quality
}

pub(crate) fn insert_features(observation: &mut Observation, frame: &RydbergFrame) {
    observation
        .features
        .extend(emitted_feature_values(frame).map(|(key, value)| (key.into(), value as f32)));
}

pub(crate) fn insert_attributes(
    observation: &mut Observation,
    frame: &RydbergFrame,
    source: ReplaySource,
    calibration_data_hash: &str,
) {
    let entries = [
        ("signal_id", frame.signal_id.clone()),
        ("tensor_frame", "sensor_local".into()),
        (
            "evidence_kind",
            match source {
                ReplaySource::Synthetic => "synthetic_replay".into(),
                ReplaySource::Captured => "captured_replay".into(),
            },
        ),
        ("calibration_data_hash", calibration_data_hash.into()),
        (
            "calibration_created_ns",
            frame.calibration_created_ns.to_string(),
        ),
        (
            "calibration_expires_ns",
            frame.calibration_expires_ns.to_string(),
        ),
    ];
    observation
        .attributes
        .extend(entries.map(|(key, value)| (key.into(), value)));
}

pub(crate) fn calibration_remaining_s(frame: &RydbergFrame) -> f64 {
    let integration_ns = (f64::from(frame.integration_ms as f32) * 1_000_000.0).round() as u64;
    let integration_end_ns = frame
        .timestamp_ns
        .saturating_add(integration_ns - integration_ns / 2);
    frame
        .calibration_expires_ns
        .saturating_sub(integration_end_ns) as f64
        / 1_000_000_000.0
}

pub(crate) fn emitted_feature_values(frame: &RydbergFrame) -> [(&'static str, f64); 16] {
    [
        ("sensor_x_m", frame.sensor_position_m[0]),
        ("sensor_y_m", frame.sensor_position_m[1]),
        ("sensor_z_m", frame.sensor_position_m[2]),
        ("carrier_hz", frame.carrier_hz),
        ("ellipticity", frame.ellipticity),
        ("field_strength_vpm", frame.field_strength_vpm()),
        ("snr_db", frame.snr_db),
        ("integration_ms", frame.integration_ms),
        ("angle_cov_00_rad2", frame.angular_covariance_rad2[0][0]),
        (
            "angle_cov_01_rad2",
            (frame.angular_covariance_rad2[0][1] + frame.angular_covariance_rad2[1][0]) / 2.0,
        ),
        ("angle_cov_11_rad2", frame.angular_covariance_rad2[1][1]),
        ("sign_ambiguous", 1.0),
        ("quality_valid", 1.0),
        ("lock_quality", frame.lock_quality),
        ("calibration_quality", frame.calibration_quality),
        ("calibration_remaining_s", calibration_remaining_s(frame)),
    ]
}

pub(crate) fn emitted_covariance_f32(frame: &RydbergFrame) -> [f32; 3] {
    let [[a, b], [c, d]] = frame.angular_covariance_rad2;
    [a as f32, ((b + c) / 2.0) as f32, d as f32]
}

pub(crate) fn emitted_bearing_noise_f32(frame: &RydbergFrame) -> f32 {
    let [a, b, d] = emitted_covariance_f32(frame);
    let (a, b, d) = (f64::from(a), f64::from(b), f64::from(d));
    ((a + d + ((a - d).powi(2) + 4.0 * b.powi(2)).sqrt()) / 2.0).sqrt() as f32
}

pub(crate) fn canonical_frame_bytes(frame: &RydbergFrame, device_id: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_string(&mut bytes, device_id);
    bytes.extend_from_slice(&frame.timestamp_ns.to_le_bytes());
    append_f64s(&mut bytes, frame.sensor_position_m);
    append_f64s(&mut bytes, frame.sensor_orientation_xyzw);
    append_string(&mut bytes, &frame.coordinate_frame);
    append_string(&mut bytes, &frame.signal_id);
    append_f64s(&mut bytes, [frame.carrier_hz]);
    append_f64s(
        &mut bytes,
        frame.e_field_sensor_vpm.iter().flatten().copied(),
    );
    append_f64s(&mut bytes, frame.k_hat_sensor);
    bytes.push(u8::from(frame.sign_ambiguous));
    append_f64s(
        &mut bytes,
        [frame.ellipticity, frame.snr_db, frame.integration_ms],
    );
    append_f64s(
        &mut bytes,
        frame.angular_covariance_rad2.iter().flatten().copied(),
    );
    append_string(&mut bytes, &frame.calibration_id);
    bytes.extend_from_slice(&frame.calibration_created_ns.to_le_bytes());
    bytes.extend_from_slice(&frame.calibration_expires_ns.to_le_bytes());
    append_f64s(&mut bytes, [frame.calibration_quality, frame.lock_quality]);
    bytes
}

pub(crate) fn canonical_calibration_bytes(
    frame: &RydbergFrame,
    config: &RydbergReplayConfig,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_string(&mut bytes, &config.device_id);
    append_string(&mut bytes, &config.placement);
    append_string(&mut bytes, &config.zone_id);
    append_string(&mut bytes, &frame.coordinate_frame);
    append_f64s(&mut bytes, frame.sensor_position_m);
    append_f64s(&mut bytes, frame.sensor_orientation_xyzw);
    append_f64s(&mut bytes, [frame.carrier_hz, frame.calibration_quality]);
    append_string(&mut bytes, &frame.calibration_id);
    bytes.extend_from_slice(&frame.calibration_created_ns.to_le_bytes());
    bytes.extend_from_slice(&frame.calibration_expires_ns.to_le_bytes());
    let q = config.thresholds;
    append_f64s(
        &mut bytes,
        [
            q.min_abs_ellipticity,
            q.min_calibration_quality,
            q.min_lock_quality,
            q.min_snr_db,
            q.max_angular_std_rad,
            q.k_norm_tolerance,
            q.covariance_tolerance,
            q.max_axis_misalignment_rad,
            q.ellipticity_consistency_tolerance,
            q.quaternion_norm_tolerance,
        ],
    );
    bytes
}

fn append_string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn append_f64s(bytes: &mut Vec<u8>, values: impl IntoIterator<Item = f64>) {
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
}
