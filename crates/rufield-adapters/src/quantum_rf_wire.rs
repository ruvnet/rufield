//! Validation of the canonical f32 values emitted on the RuField wire.

use crate::quantum_rf_quality::RydbergGateFailure;
use crate::quantum_rf_replay::{RydbergFrame, RydbergQualityThresholds};
use crate::quantum_rf_support::{
    emitted_bearing_noise_f32, emitted_covariance_f32, emitted_feature_values,
};

pub(crate) fn validate_emitted_f32(
    frame: &RydbergFrame,
    q: RydbergQualityThresholds,
) -> Result<(), RydbergGateFailure> {
    validate_direction(frame, q)?;
    validate_orientation(frame, q)?;
    validate_covariance(frame, q)?;

    for component in frame.e_field_sensor_vpm.iter().flatten() {
        let emitted = *component as f32;
        if *component != 0.0 && emitted == 0.0 {
            return Err(RydbergGateFailure::RawPhasorUnderflow);
        }
        if !emitted.is_finite() {
            return Err(RydbergGateFailure::FeatureNotRepresentable(
                "e_field_sensor_vpm",
            ));
        }
    }

    for (name, value) in emitted_feature_values(frame) {
        validate_scalar(name, value)?;
    }
    if frame.carrier_hz as f32 <= 0.0 {
        return Err(RydbergGateFailure::FeatureNotRepresentable("carrier_hz"));
    }

    let bearing_noise = f64::from(emitted_bearing_noise_f32(frame));
    validate_scalar("bearing_noise_floor", bearing_noise)?;
    validate_scalar("raw_noise_floor_vpm", frame.noise_floor_vpm())?;
    validate_scalar(
        "confidence",
        frame.calibration_quality.min(frame.lock_quality),
    )?;
    Ok(())
}

fn validate_direction(
    frame: &RydbergFrame,
    q: RydbergQualityThresholds,
) -> Result<(), RydbergGateFailure> {
    let positive = frame.k_hat_sensor.map(|value| value as f32);
    let negative = frame.k_hat_sensor.map(|value| (-value) as f32);
    if positive
        .iter()
        .zip(negative)
        .any(|(plus, minus)| minus.to_bits() != (-*plus).to_bits())
    {
        return Err(RydbergGateFailure::DirectionNotAntipodal);
    }
    if (norm3(positive) - 1.0).abs() > q.k_norm_tolerance
        || (norm3(negative) - 1.0).abs() > q.k_norm_tolerance
    {
        return Err(RydbergGateFailure::DirectionNotNormalized);
    }
    Ok(())
}

fn validate_orientation(
    frame: &RydbergFrame,
    q: RydbergQualityThresholds,
) -> Result<(), RydbergGateFailure> {
    let emitted = frame.sensor_orientation_xyzw.map(|value| value as f32);
    let norm = emitted
        .iter()
        .map(|value| f64::from(*value).powi(2))
        .sum::<f64>()
        .sqrt();
    if !norm.is_finite() || (norm - 1.0).abs() > q.quaternion_norm_tolerance {
        return Err(RydbergGateFailure::OrientationNotNormalized);
    }
    Ok(())
}

fn validate_covariance(
    frame: &RydbergFrame,
    q: RydbergQualityThresholds,
) -> Result<(), RydbergGateFailure> {
    let [a, b, d] = emitted_covariance_f32(frame);
    if !a.is_finite() || !b.is_finite() || !d.is_finite() || a <= 0.0 || d <= 0.0 {
        return Err(RydbergGateFailure::InvalidAngularCovariance);
    }
    let (a, b, d) = (f64::from(a), f64::from(b), f64::from(d));
    let discriminant = ((a - d).powi(2) + 4.0 * b.powi(2)).sqrt();
    let lambda_min = (a + d - discriminant) / 2.0;
    let lambda_max = (a + d + discriminant) / 2.0;
    let expected_noise = lambda_max.sqrt();
    let emitted_noise = f64::from(emitted_bearing_noise_f32(frame));
    if !lambda_min.is_finite()
        || !lambda_max.is_finite()
        || lambda_max <= 0.0
        || lambda_min < -q.covariance_tolerance * lambda_max
        || lambda_max.sqrt() > q.max_angular_std_rad
        || !emitted_noise.is_finite()
        || (emitted_noise - expected_noise).abs() > expected_noise * 0.05
    {
        return Err(RydbergGateFailure::InvalidAngularCovariance);
    }
    Ok(())
}

fn validate_scalar(name: &'static str, value: f64) -> Result<(), RydbergGateFailure> {
    let emitted = value as f32;
    if !emitted.is_finite() || (value != 0.0 && emitted == 0.0) {
        Err(RydbergGateFailure::FeatureNotRepresentable(name))
    } else {
        Ok(())
    }
}

fn norm3(vector: [f32; 3]) -> f64 {
    vector
        .iter()
        .map(|value| f64::from(*value).powi(2))
        .sum::<f64>()
        .sqrt()
}
