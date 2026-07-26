//! Fail-closed quality policy for Rydberg quantum RF replay frames.

use crate::quantum_rf_replay::{RydbergFrame, RydbergReplayError};

/// Configurable quality thresholds. Defaults are intentionally conservative.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RydbergQualityThresholds {
    /// Minimum absolute polarization ellipticity; zero is linear/degenerate.
    pub min_abs_ellipticity: f64,
    /// Minimum accepted calibration quality in `0..=1`.
    pub min_calibration_quality: f64,
    /// Minimum accepted optical lock quality in `0..=1`.
    pub min_lock_quality: f64,
    /// Minimum receiver-reported SNR in dB.
    pub min_snr_db: f64,
    /// Maximum tangent-plane angular standard deviation, in radians.
    pub max_angular_std_rad: f64,
    /// Absolute tolerance on `abs(norm(k_hat) - 1)`.
    pub k_norm_tolerance: f64,
    /// Symmetry and positive-semidefinite numerical tolerance.
    pub covariance_tolerance: f64,
    /// Maximum axial disagreement between `k_hat` and `Re(E) x Im(E)`.
    pub max_axis_misalignment_rad: f64,
    /// Maximum disagreement between reported ellipticity and phasor `q_axis`.
    pub ellipticity_consistency_tolerance: f64,
    /// Absolute tolerance on `abs(norm(sensor_orientation_xyzw) - 1)`.
    pub quaternion_norm_tolerance: f64,
}

impl Default for RydbergQualityThresholds {
    fn default() -> Self {
        Self {
            min_abs_ellipticity: 0.05,
            min_calibration_quality: 0.80,
            min_lock_quality: 0.90,
            min_snr_db: 6.0,
            max_angular_std_rad: 0.174_532_925_199_432_95,
            k_norm_tolerance: 1.0e-5,
            covariance_tolerance: 1.0e-9,
            max_axis_misalignment_rad: 0.174_532_925_199_432_95,
            ellipticity_consistency_tolerance: 0.10,
            quaternion_norm_tolerance: 1.0e-5,
        }
    }
}

/// A specific fail-closed quality-gate violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RydbergGateFailure {
    /// Caller supplied malformed quality thresholds to frame validation.
    InvalidThresholds,
    /// A named numeric input is NaN, infinite, or cannot be represented as f32.
    NonFinite(&'static str),
    /// A named numeric input is outside its physical or configured range.
    OutOfRange(&'static str),
    /// The supplied direction is not unit length.
    DirectionNotNormalized,
    /// The emitted f32 direction candidates are not exact antipodes.
    DirectionNotAntipodal,
    /// A producer incorrectly claimed that the antipodal sign was resolved.
    DirectionSignResolved,
    /// Polarization is linear or too close to linear for stable direction.
    EllipticityDegenerate,
    /// `k_hat` disagrees with the electric-field polarization axis.
    FieldDirectionMismatch,
    /// Reported ellipticity disagrees with the complex phasor geometry.
    EllipticityMismatch,
    /// Sensor-to-world quaternion is not unit length.
    OrientationNotNormalized,
    /// Coordinate frame is empty, contains control bytes, or exceeds its bound.
    InvalidCoordinateFrame,
    /// Signal identifier is empty, contains control bytes, or exceeds its bound.
    InvalidSignalId,
    /// The angular covariance is not symmetric positive semidefinite.
    InvalidAngularCovariance,
    /// Angular uncertainty exceeds the configured ceiling.
    AngularUncertaintyTooHigh,
    /// The calibration identifier is empty or exceeds its wire bound.
    InvalidCalibrationId,
    /// Calibration timestamps do not form a valid window.
    InvalidCalibrationWindow,
    /// The frame timestamp is outside its calibration validity window.
    StaleCalibration,
    /// Calibration quality is below the configured floor.
    CalibrationQualityTooLow,
    /// Optical lock quality is below the configured floor.
    OpticalLockQualityTooLow,
    /// Receiver SNR is below the configured floor.
    SignalToNoiseTooLow,
    /// Frame timestamps are not strictly increasing.
    NonMonotonicTimestamp,
    /// Pose or calibration fields changed within one adapter recording.
    CalibrationContractChanged,
    /// A nonzero raw phasor component would become zero on the f32 wire.
    RawPhasorUnderflow,
    /// A named canonical f32 tensor or feature value is not representable.
    FeatureNotRepresentable(&'static str),
}

impl std::fmt::Display for RydbergGateFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl RydbergQualityThresholds {
    pub(crate) fn validate(self) -> Result<(), RydbergReplayError> {
        if !self.min_abs_ellipticity.is_finite()
            || !(0.0..=1.0).contains(&self.min_abs_ellipticity)
            || self.min_abs_ellipticity == 0.0
        {
            return Err(RydbergReplayError::InvalidConfig(
                "minimum ellipticity must be finite in 0..=1".into(),
            ));
        }
        if [self.min_calibration_quality, self.min_lock_quality]
            .iter()
            .any(|v| !v.is_finite() || !(0.0..=1.0).contains(v))
        {
            return Err(RydbergReplayError::InvalidConfig(
                "quality floors must be finite in 0..=1".into(),
            ));
        }
        let positive = [
            self.max_angular_std_rad,
            self.k_norm_tolerance,
            self.covariance_tolerance,
            self.max_axis_misalignment_rad,
            self.ellipticity_consistency_tolerance,
            self.quaternion_norm_tolerance,
        ];
        if positive.iter().any(|v| !v.is_finite() || *v <= 0.0)
            || !self.min_snr_db.is_finite()
            || !(-300.0..=300.0).contains(&self.min_snr_db)
            || self.max_axis_misalignment_rad > std::f64::consts::FRAC_PI_2
            || self.max_angular_std_rad > std::f64::consts::FRAC_PI_2
            || self.k_norm_tolerance > 1.0e-5
            || self.quaternion_norm_tolerance > 1.0e-5
            || self.covariance_tolerance > 1.0e-6
            || self.ellipticity_consistency_tolerance > 1.0
        {
            return Err(RydbergReplayError::InvalidConfig(
                "quality thresholds must be finite and physically valid".into(),
            ));
        }
        Ok(())
    }
}

impl RydbergFrame {
    /// Validate every structural and quality invariant without repairing input.
    pub fn validate(&self, q: RydbergQualityThresholds) -> Result<(), RydbergGateFailure> {
        if q.validate().is_err() {
            return Err(RydbergGateFailure::InvalidThresholds);
        }
        finite_f32("sensor_position_m", self.sensor_position_m)?;
        finite_f32("sensor_orientation_xyzw", self.sensor_orientation_xyzw)?;
        finite_f32("carrier_hz", [self.carrier_hz])?;
        finite_f32(
            "e_field_sensor_vpm",
            self.e_field_sensor_vpm.iter().flatten().copied(),
        )?;
        finite_f32("k_hat_sensor", self.k_hat_sensor)?;
        finite_f32("ellipticity", [self.ellipticity])?;
        finite_f32("snr_db", [self.snr_db])?;
        finite_f32("integration_ms", [self.integration_ms])?;
        finite_f32(
            "angular_covariance_rad2",
            self.angular_covariance_rad2.iter().flatten().copied(),
        )?;
        finite_f32("calibration_quality", [self.calibration_quality])?;
        finite_f32("lock_quality", [self.lock_quality])?;
        if self
            .sensor_position_m
            .iter()
            .any(|value| value.abs() > 1.0e6)
        {
            return Err(RydbergGateFailure::OutOfRange("sensor_position_m"));
        }
        if self.carrier_hz <= 0.0
            || self.carrier_hz > 1.0e12
            || self.integration_ms <= 0.0
            || self.integration_ms > 60_000.0
            || !(-300.0..=300.0).contains(&self.snr_db)
        {
            return Err(RydbergGateFailure::OutOfRange(
                "carrier_hz, integration_ms, or snr_db",
            ));
        }
        // Time-window decisions use the canonical f32 value carried on wire,
        // so an accepted adapter event cannot expand its interval in fusion.
        let integration_ns = (f64::from(self.integration_ms as f32) * 1_000_000.0).round() as u64;
        if integration_ns == 0 {
            return Err(RydbergGateFailure::OutOfRange(
                "integration_ms rounds to zero nanoseconds",
            ));
        }
        let field_strength = self.field_strength_vpm();
        if !field_strength.is_finite() || field_strength <= 0.0 || field_strength > f32::MAX as f64
        {
            return Err(RydbergGateFailure::NonFinite("field_strength_vpm"));
        }
        let noise_floor = self.noise_floor_vpm();
        if !noise_floor.is_finite() || noise_floor < 0.0 || noise_floor > f32::MAX as f64 {
            return Err(RydbergGateFailure::NonFinite("noise_floor_vpm"));
        }
        let norm = dot(self.k_hat_sensor, self.k_hat_sensor).sqrt();
        if (norm - 1.0).abs() > q.k_norm_tolerance {
            return Err(RydbergGateFailure::DirectionNotNormalized);
        }
        let orientation_norm = self
            .sensor_orientation_xyzw
            .iter()
            .map(|value| value * value)
            .sum::<f64>()
            .sqrt();
        if (orientation_norm - 1.0).abs() > q.quaternion_norm_tolerance {
            return Err(RydbergGateFailure::OrientationNotNormalized);
        }
        if self.coordinate_frame.trim().is_empty()
            || self.coordinate_frame.len() > super::quantum_rf_replay::MAX_ID_BYTES
            || self.coordinate_frame.chars().any(char::is_control)
        {
            return Err(RydbergGateFailure::InvalidCoordinateFrame);
        }
        if !super::quantum_rf_support::valid_id(&self.signal_id) {
            return Err(RydbergGateFailure::InvalidSignalId);
        }
        if !self.sign_ambiguous {
            return Err(RydbergGateFailure::DirectionSignResolved);
        }
        if self.ellipticity.abs() < q.min_abs_ellipticity || self.ellipticity.abs() > 1.0 {
            return Err(RydbergGateFailure::EllipticityDegenerate);
        }
        self.validate_field_axis(q)?;
        self.validate_covariance(q)?;
        if self.calibration_id.trim().is_empty()
            || self.calibration_id.len() > super::quantum_rf_replay::MAX_ID_BYTES
            || self.calibration_id.chars().any(char::is_control)
        {
            return Err(RydbergGateFailure::InvalidCalibrationId);
        }
        if self.calibration_created_ns >= self.calibration_expires_ns {
            return Err(RydbergGateFailure::InvalidCalibrationWindow);
        }
        let before = i128::from(integration_ns / 2);
        let after = i128::from(integration_ns - integration_ns / 2);
        let integration_start = i128::from(self.timestamp_ns) - before;
        let integration_end = i128::from(self.timestamp_ns) + after;
        if integration_start < i128::from(self.calibration_created_ns)
            || integration_end >= i128::from(self.calibration_expires_ns)
        {
            return Err(RydbergGateFailure::StaleCalibration);
        }
        if !(0.0..=1.0).contains(&self.calibration_quality)
            || self.calibration_quality < q.min_calibration_quality
        {
            return Err(RydbergGateFailure::CalibrationQualityTooLow);
        }
        if !(0.0..=1.0).contains(&self.lock_quality) || self.lock_quality < q.min_lock_quality {
            return Err(RydbergGateFailure::OpticalLockQualityTooLow);
        }
        if self.snr_db < q.min_snr_db {
            return Err(RydbergGateFailure::SignalToNoiseTooLow);
        }
        crate::quantum_rf_wire::validate_emitted_f32(self, q)
    }

    fn validate_field_axis(&self, q: RydbergQualityThresholds) -> Result<(), RydbergGateFailure> {
        let re = [
            self.e_field_sensor_vpm[0][0],
            self.e_field_sensor_vpm[1][0],
            self.e_field_sensor_vpm[2][0],
        ];
        let im = [
            self.e_field_sensor_vpm[0][1],
            self.e_field_sensor_vpm[1][1],
            self.e_field_sensor_vpm[2][1],
        ];
        let axis = cross(re, im);
        let axis_norm = dot(axis, axis).sqrt();
        let energy = dot(re, re) + dot(im, im);
        let q_axis = 2.0 * axis_norm / energy;
        if !q_axis.is_finite() || q_axis < q.min_abs_ellipticity {
            return Err(RydbergGateFailure::EllipticityDegenerate);
        }
        if (q_axis - self.ellipticity.abs()).abs() > q.ellipticity_consistency_tolerance {
            return Err(RydbergGateFailure::EllipticityMismatch);
        }
        let normalized = axis.map(|v| v / axis_norm);
        if dot(normalized, self.k_hat_sensor).abs() < q.max_axis_misalignment_rad.cos() {
            return Err(RydbergGateFailure::FieldDirectionMismatch);
        }
        Ok(())
    }

    fn validate_covariance(&self, q: RydbergQualityThresholds) -> Result<(), RydbergGateFailure> {
        let [[a, b], [c, d]] = self.angular_covariance_rad2;
        let off_diagonal = (b + c) / 2.0;
        let discriminant = ((a - d).powi(2) + 4.0 * off_diagonal.powi(2)).sqrt();
        let lambda_min = (a + d - discriminant) / 2.0;
        let lambda_max = (a + d + discriminant) / 2.0;
        if a <= 0.0
            || d <= 0.0
            || (b - c).abs() > q.covariance_tolerance
            || !lambda_max.is_finite()
            || lambda_max <= 0.0
            || lambda_min < -q.covariance_tolerance * lambda_max
        {
            return Err(RydbergGateFailure::InvalidAngularCovariance);
        }
        if lambda_max.sqrt() > q.max_angular_std_rad {
            return Err(RydbergGateFailure::AngularUncertaintyTooHigh);
        }
        Ok(())
    }
}

fn finite_f32(
    values_name: &'static str,
    values: impl IntoIterator<Item = f64>,
) -> Result<(), RydbergGateFailure> {
    if values
        .into_iter()
        .any(|v| !v.is_finite() || v.abs() > f32::MAX as f64)
    {
        Err(RydbergGateFailure::NonFinite(values_name))
    } else {
        Ok(())
    }
}

fn dot(a: [f64; 3], b: [f64; 3]) -> f64 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

fn cross(a: [f64; 3], b: [f64; 3]) -> [f64; 3] {
    [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]
}
