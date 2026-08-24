//! Sign-invariant fusion for quantum RF propagation-axis observations
//! (ADR-266).
//!
//! A single electrically-small Rydberg vector sensor recovers a propagation
//! axis, not range, and the axis is ambiguous under `k -> -k`.  This module
//! therefore fuses the *lines* defined by two or more sensors.  The projector
//! `I - k k^T` is sign invariant, so the least-squares estimate never invents
//! a preferred direction for an ambiguous measurement.

use crate::bearing_math::{
    condition_number_inf, dot, invert_3x3, mat_vec, max_axis_separation, max_sensor_baseline,
    projector, rotate_vector_xyzw, scale_matrix, sub, weighted_system,
};
use crate::bearing_trust::BearingTrustPolicy;
use rufield_core::{FieldAxis, FieldEvent, Modality, PrivacyClass, SPEC_VERSION};
use std::collections::BTreeSet;

/// Maximum number of bearing events retained in one fusion window.
pub const MAX_BEARINGS: usize = 64;

/// Default maximum timestamp separation inside one fusion window: 100 ms.
pub const DEFAULT_MAX_TIME_SKEW_NS: u64 = 100_000_000;

/// Minimum sign-invariant angular diversity accepted between sensor axes.
pub const MIN_GEOMETRY_ANGLE_RAD: f64 = 5.0_f64.to_radians();

/// Defence-in-depth ellipticity gate used even after adapter validation.
pub const MIN_FUSABLE_ELLIPTICITY: f64 = 0.05;

/// Defence-in-depth optical lock gate used even after adapter validation.
pub const MIN_FUSABLE_LOCK_QUALITY: f64 = 0.90;

/// Defence-in-depth calibration quality gate used after adapter validation.
pub const MIN_FUSABLE_CALIBRATION_QUALITY: f64 = 0.80;

const VECTOR_TOLERANCE: f64 = 1.0e-5;
const PSD_RELATIVE_TOLERANCE: f64 = 1.0e-6;
const MAX_ABS_POSITION_M: f64 = 1.0e6;
const MAX_INTEGRATION_MS: f64 = 60_000.0;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_CARRIER_HZ: f64 = 1.0e12;
const MIN_RANGE_M: f64 = 0.10;

/// Geometry, synchronization, and evidence-grouping policy.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BearingFusionConfig {
    /// Maximum timestamp span in one estimate.
    pub max_time_skew_ns: u64,
    /// Minimum sign-invariant angle between at least two axes.
    pub min_geometry_angle_rad: f64,
    /// Minimum surveyed distance between at least two sensors.
    pub min_sensor_baseline_m: f64,
    /// Maximum infinity-norm condition number of the final information matrix.
    pub max_condition_number: f64,
    /// Maximum carrier difference allowed inside one evidence group.
    pub carrier_tolerance_hz: f64,
    /// Validity interval attached to a produced estimate.
    pub estimate_ttl_ns: u64,
}

impl Default for BearingFusionConfig {
    fn default() -> Self {
        Self {
            max_time_skew_ns: DEFAULT_MAX_TIME_SKEW_NS,
            min_geometry_angle_rad: MIN_GEOMETRY_ANGLE_RAD,
            min_sensor_baseline_m: 0.25,
            max_condition_number: 1.0e8,
            carrier_tolerance_hz: 1.0e6,
            estimate_ttl_ns: 200_000_000,
        }
    }
}

impl BearingFusionConfig {
    fn validate(self) -> Result<Self, BearingFusionError> {
        if !self.min_geometry_angle_rad.is_finite()
            || !(0.0..=std::f64::consts::FRAC_PI_2).contains(&self.min_geometry_angle_rad)
            || self.min_geometry_angle_rad == 0.0
        {
            return Err(BearingFusionError::InvalidConfiguration(
                "minimum geometry angle must be finite and in (0, pi/2]".into(),
            ));
        }
        if !self.min_sensor_baseline_m.is_finite() || self.min_sensor_baseline_m <= 0.0 {
            return Err(BearingFusionError::InvalidConfiguration(
                "minimum sensor baseline must be finite and positive".into(),
            ));
        }
        if !self.max_condition_number.is_finite() || self.max_condition_number < 1.0 {
            return Err(BearingFusionError::InvalidConfiguration(
                "maximum condition number must be finite and at least one".into(),
            ));
        }
        if !self.carrier_tolerance_hz.is_finite() || self.carrier_tolerance_hz < 0.0 {
            return Err(BearingFusionError::InvalidConfiguration(
                "carrier tolerance must be finite and nonnegative".into(),
            ));
        }
        if self.estimate_ttl_ns == 0 {
            return Err(BearingFusionError::InvalidConfiguration(
                "estimate TTL must be positive".into(),
            ));
        }
        Ok(self)
    }
}

/// One validated propagation-axis observation extracted from a `FieldEvent`.
#[derive(Debug, Clone, PartialEq)]
pub struct BearingObservation {
    /// Source event id.
    pub event_id: String,
    /// Physical sensor id.
    pub sensor_id: String,
    /// Capture timestamp.
    pub timestamp_ns: u64,
    /// Width of the capture interval centred on `timestamp_ns`.
    pub integration_ns: u64,
    /// Sensor origin in the shared Cartesian frame, metres.
    pub sensor_position_m: [f64; 3],
    /// One of the two equivalent unit vectors rotated into the shared frame.
    pub direction_axis: [f64; 3],
    /// Conservative angular variance, radians squared.
    pub angular_variance_rad2: f64,
    /// Adapter confidence in `0..=1`.
    pub confidence: f64,
    /// Shared Cartesian frame identifier.
    pub coordinate_frame: String,
    /// Authenticated or upstream-classified signal/evidence identifier.
    pub signal_id: String,
    /// RF carrier frequency.
    pub carrier_hz: f64,
    /// Calibration receipt identifier bound into the signed event.
    pub calibration_id: String,
    /// Exact half-open calibration validity start bound into the signed event.
    pub calibration_created_ns: u64,
    /// Exact half-open calibration expiry bound into the signed event.
    pub calibration_expires_ns: u64,
}

/// A position estimate from two or more propagation axes.
#[derive(Debug, Clone, PartialEq)]
pub struct BearingEstimate {
    /// Least-squares emitter position in the shared Cartesian frame, metres.
    pub position_m: [f64; 3],
    /// Approximate position covariance, metres squared.
    pub covariance_m2: [[f64; 3]; 3],
    /// Shared coordinate frame for the position and covariance.
    pub coordinate_frame: String,
    /// Signal/evidence group fused into this estimate.
    pub signal_id: String,
    /// Representative carrier frequency for the evidence group.
    pub carrier_hz: f64,
    /// Unweighted perpendicular line residual, metres RMS.
    pub residual_rmse_m: f64,
    /// Greatest sign-invariant separation between any two input axes.
    pub geometry_angle_rad: f64,
    /// Uncalibrated bounded geometry and fit quality score in `0..=1`.
    pub quality_score: f64,
    /// Output privacy classification.
    pub privacy_class: PrivacyClass,
    /// Latest contributing timestamp.
    pub produced_ns: u64,
    /// Time after which this estimate must not be used without refresh.
    pub expires_ns: u64,
    /// Always true because fusion uses sign-invariant line projectors.
    pub sign_invariant: bool,
    /// Calibration id for each event in `supporting_events`, in matching order.
    pub calibration_ids: Vec<String>,
    /// Events contributing to the estimate.
    pub supporting_events: Vec<String>,
}

/// Fail-closed validation and geometry errors.
#[derive(Debug, Clone, PartialEq)]
pub enum BearingFusionError {
    /// Geometry, synchronization, or output-lifetime policy was malformed.
    InvalidConfiguration(String),
    /// Trust registry, replay allowlist, or freshness policy was malformed.
    InvalidTrustPolicy(String),
    /// Event signature/provenance did not satisfy the fusability invariant.
    NotFusable(String),
    /// Synthetic input reached a production fusion policy.
    SyntheticRejected(String),
    /// A valid signature came from a key outside the selected trust policy.
    UntrustedSigner(String),
    /// No production deployment binding existed for the asserted sensor.
    UnknownTrustedSensor(String),
    /// The enrolled sensor has been revoked.
    RevokedTrustedSensor(String),
    /// A signed live event disagreed with its enrolled deployment binding.
    TrustedSensorBindingMismatch {
        device_id: String,
        field: &'static str,
    },
    /// The enrolled calibration was expired at the trusted evaluation time.
    TrustedCalibrationExpired { device_id: String, expires_ns: u64 },
    /// A live event was older than the trusted freshness window.
    StaleLiveEvent { event_id: String, age_ns: u64 },
    /// A live event timestamp was too far ahead of trusted time.
    FutureLiveEvent { event_id: String, skew_ns: u64 },
    /// A live sensor timestamp was not strictly newer than its watermark.
    LiveReplayDetected {
        device_id: String,
        timestamp_ns: u64,
    },
    /// Signed evidence state did not match the selected trust policy.
    EvidenceKindRejected {
        event_id: String,
        expected: &'static str,
        actual: String,
    },
    /// Events did not use the same shared coordinate frame.
    CoordinateFrameMismatch { expected: String, actual: String },
    /// Events did not identify the same emitter or pilot evidence group.
    SignalMismatch { expected: String, actual: String },
    /// Carrier frequencies exceeded the configured grouping tolerance.
    CarrierMismatch { expected_hz: f64, actual_hz: f64 },
    /// Event was not a quantum RF vector observation.
    WrongModality(String),
    /// Bearing tensor or quality metadata violated ADR-266 invariants.
    InvalidObservation(String),
    /// A required named observation feature was absent.
    MissingFeature(&'static str),
    /// Events in one estimate exceeded the configured synchronization window.
    TimeSkew { event_id: String, skew_ns: u64 },
    /// Capture integration intervals did not overlap.
    IntegrationWindowMismatch { event_id: String, gap_ns: u64 },
    /// More than one event from a sensor would overweight that viewpoint.
    DuplicateSensor(String),
    /// The bounded fusion window is full.
    CapacityExceeded,
    /// At least two independent viewpoints are required.
    InsufficientObservations(usize),
    /// Axes were parallel or too poorly conditioned to locate a point.
    DegenerateGeometry { angle_rad: f64 },
    /// Surveyed sensor origins did not provide spatial diversity.
    InsufficientBaseline { baseline_m: f64 },
    /// Final information matrix exceeded the configured condition number.
    IllConditioned { condition_number: f64 },
    /// Calibration expiry made the computed estimate stale on arrival.
    EstimateExpired { produced_ns: u64, expires_ns: u64 },
}

impl std::fmt::Display for BearingFusionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => {
                write!(f, "invalid bearing fusion configuration: {message}")
            }
            Self::InvalidTrustPolicy(message) => write!(f, "invalid trust policy: {message}"),
            Self::NotFusable(id) => write!(f, "event {id} failed provenance verification"),
            Self::SyntheticRejected(id) => {
                write!(f, "synthetic event {id} is forbidden by production policy")
            }
            Self::UntrustedSigner(id) => write!(f, "event {id} has an untrusted signer"),
            Self::UnknownTrustedSensor(id) => {
                write!(f, "sensor {id} has no production deployment binding")
            }
            Self::RevokedTrustedSensor(id) => write!(f, "sensor {id} is revoked"),
            Self::TrustedSensorBindingMismatch { device_id, field } => {
                write!(
                    f,
                    "sensor {device_id} disagrees with trusted binding field {field}"
                )
            }
            Self::TrustedCalibrationExpired {
                device_id,
                expires_ns,
            } => write!(
                f,
                "sensor {device_id} calibration expired at {expires_ns} ns"
            ),
            Self::StaleLiveEvent { event_id, age_ns } => {
                write!(f, "live event {event_id} is {age_ns} ns old and stale")
            }
            Self::FutureLiveEvent { event_id, skew_ns } => {
                write!(
                    f,
                    "live event {event_id} is ahead of trusted time by {skew_ns} ns"
                )
            }
            Self::LiveReplayDetected {
                device_id,
                timestamp_ns,
            } => write!(
                f,
                "sensor {device_id} replayed or reordered timestamp {timestamp_ns} ns"
            ),
            Self::EvidenceKindRejected {
                event_id,
                expected,
                actual,
            } => write!(
                f,
                "event {event_id} has evidence kind {actual}; policy requires {expected}"
            ),
            Self::CoordinateFrameMismatch { expected, actual } => {
                write!(
                    f,
                    "coordinate frame mismatch: expected {expected}, got {actual}"
                )
            }
            Self::SignalMismatch { expected, actual } => {
                write!(f, "signal mismatch: expected {expected}, got {actual}")
            }
            Self::CarrierMismatch {
                expected_hz,
                actual_hz,
            } => write!(
                f,
                "carrier mismatch: expected {expected_hz} Hz, got {actual_hz} Hz"
            ),
            Self::WrongModality(id) => write!(f, "event {id} is not quantum_rf"),
            Self::InvalidObservation(message) => write!(f, "invalid bearing: {message}"),
            Self::MissingFeature(name) => write!(f, "missing bearing feature {name}"),
            Self::TimeSkew { event_id, skew_ns } => {
                write!(f, "event {event_id} exceeds fusion window by {skew_ns} ns")
            }
            Self::IntegrationWindowMismatch { event_id, gap_ns } => write!(
                f,
                "event {event_id} has a nonoverlapping integration window separated by {gap_ns} ns"
            ),
            Self::DuplicateSensor(id) => write!(f, "duplicate sensor {id} in fusion window"),
            Self::CapacityExceeded => write!(f, "bearing fusion capacity exceeded"),
            Self::InsufficientObservations(n) => {
                write!(f, "at least two bearing observations required, got {n}")
            }
            Self::DegenerateGeometry { angle_rad } => write!(
                f,
                "bearing geometry is degenerate at {:.3} degrees",
                angle_rad.to_degrees()
            ),
            Self::InsufficientBaseline { baseline_m } => {
                write!(f, "sensor baseline {baseline_m} m is insufficient")
            }
            Self::IllConditioned { condition_number } => {
                write!(f, "bearing condition number {condition_number} is too high")
            }
            Self::EstimateExpired {
                produced_ns,
                expires_ns,
            } => write!(
                f,
                "bearing estimate produced at {produced_ns} ns already expires at {expires_ns} ns"
            ),
        }
    }
}

impl std::error::Error for BearingFusionError {}

fn feature(event: &FieldEvent, name: &'static str) -> Result<f64, BearingFusionError> {
    let value = f64::from(
        *event
            .observation
            .features
            .get(name)
            .ok_or(BearingFusionError::MissingFeature(name))?,
    );
    if !value.is_finite() {
        return Err(BearingFusionError::InvalidObservation(format!(
            "feature {name} is not finite"
        )));
    }
    Ok(value)
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_identifier(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && !value.chars().any(char::is_control)
}

impl BearingObservation {
    /// Validate and decode the ADR-266 derived-bearing event contract.
    pub fn try_from_event(
        event: &FieldEvent,
        trust: &BearingTrustPolicy,
    ) -> Result<Self, BearingFusionError> {
        trust.authorize(event)?;
        if event.spec_version != SPEC_VERSION || event.tensor.spec_version != SPEC_VERSION {
            return Err(BearingFusionError::InvalidObservation(
                "event and tensor must use the current MFS wire version".into(),
            ));
        }
        if event.tensor.modality != Modality::QuantumRf || event.sensor.modality != "quantum_rf" {
            return Err(BearingFusionError::WrongModality(event.event_id.clone()));
        }
        if !valid_identifier(&event.event_id) || !valid_identifier(&event.sensor.device_id) {
            return Err(BearingFusionError::InvalidObservation(
                "event and sensor ids must be bounded and control-free".into(),
            ));
        }
        if event.tensor.axes != [FieldAxis::DirectionCandidate, FieldAxis::CartesianComponent]
            || event.tensor.shape != [2, 3]
            || event.tensor.values.len() != 6
        {
            return Err(BearingFusionError::InvalidObservation(
                "expected [direction_candidate, cartesian_component] tensor with shape [2,3]"
                    .into(),
            ));
        }
        let tensor_calibration = event.tensor.calibration_id.as_deref().unwrap_or_default();
        if !valid_identifier(tensor_calibration)
            || !valid_identifier(&event.provenance.calibration_id)
        {
            return Err(BearingFusionError::InvalidObservation(
                "calibration id must be bounded and control-free".into(),
            ));
        }
        if tensor_calibration != event.provenance.calibration_id {
            return Err(BearingFusionError::InvalidObservation(
                "tensor and provenance calibration ids differ".into(),
            ));
        }
        if event.tensor.timestamp_ns != event.timestamp_ns {
            return Err(BearingFusionError::InvalidObservation(
                "event and tensor timestamps differ".into(),
            ));
        }
        if event.tensor.privacy_class != PrivacyClass::P1
            || event.observation.privacy_class != PrivacyClass::P1
        {
            return Err(BearingFusionError::InvalidObservation(
                "derived bearing event must be classified P1".into(),
            ));
        }
        if event.observation.range_m.is_some()
            || event.observation.velocity_mps.is_some()
            || event.observation.motion_vector.is_some()
        {
            return Err(BearingFusionError::InvalidObservation(
                "a single bearing must not claim range, velocity, or motion".into(),
            ));
        }
        if feature(event, "quality_valid")? != 1.0 {
            return Err(BearingFusionError::InvalidObservation(
                "adapter quality gate must equal one".into(),
            ));
        }
        if feature(event, "sign_ambiguous")? != 1.0 {
            return Err(BearingFusionError::InvalidObservation(
                "single-head bearing must preserve the k sign ambiguity".into(),
            ));
        }
        let ellipticity = feature(event, "ellipticity")?.abs();
        if !(MIN_FUSABLE_ELLIPTICITY..=1.0).contains(&ellipticity) {
            return Err(BearingFusionError::InvalidObservation(
                "polarization ellipticity is not observable".into(),
            ));
        }
        let lock_quality = feature(event, "lock_quality")?;
        if !(MIN_FUSABLE_LOCK_QUALITY..=1.0).contains(&lock_quality) {
            return Err(BearingFusionError::InvalidObservation(
                "optical lock quality is outside the fusion range".into(),
            ));
        }
        let calibration_quality = feature(event, "calibration_quality")?;
        if !(MIN_FUSABLE_CALIBRATION_QUALITY..=1.0).contains(&calibration_quality) {
            return Err(BearingFusionError::InvalidObservation(
                "calibration quality is outside the fusion range".into(),
            ));
        }
        let calibration_remaining_s = feature(event, "calibration_remaining_s")?;
        if calibration_remaining_s <= 0.0 {
            return Err(BearingFusionError::InvalidObservation(
                "calibration is expired".into(),
            ));
        }
        let carrier_hz = feature(event, "carrier_hz")?;
        let integration_ms = feature(event, "integration_ms")?;
        let field_strength_vpm = feature(event, "field_strength_vpm")?;
        let _snr_db = feature(event, "snr_db")?;
        if carrier_hz <= 0.0
            || carrier_hz > MAX_CARRIER_HZ
            || field_strength_vpm <= 0.0
            || !(0.0..=MAX_INTEGRATION_MS).contains(&integration_ms)
            || integration_ms == 0.0
        {
            return Err(BearingFusionError::InvalidObservation(
                "carrier and field strength must be positive and integration_ms must be in (0, 60000]"
                    .into(),
            ));
        }
        let integration_ns_f64 = (integration_ms * 1_000_000.0).round();
        if !integration_ns_f64.is_finite()
            || integration_ns_f64 < 1.0
            || integration_ns_f64 > u64::MAX as f64
        {
            return Err(BearingFusionError::InvalidObservation(
                "integration interval cannot be represented in nanoseconds".into(),
            ));
        }
        let integration_ns = integration_ns_f64 as u64;

        let values: Vec<f64> = event.tensor.values.iter().map(|&v| f64::from(v)).collect();
        if values.iter().any(|v| !v.is_finite()) {
            return Err(BearingFusionError::InvalidObservation(
                "direction tensor contains a non-finite value".into(),
            ));
        }
        let k_sensor = [values[0], values[1], values[2]];
        let neg_k = [values[3], values[4], values[5]];
        let norm = dot(k_sensor, k_sensor).sqrt();
        if (norm - 1.0).abs() > VECTOR_TOLERANCE {
            return Err(BearingFusionError::InvalidObservation(format!(
                "direction norm {norm} is not unit length"
            )));
        }
        if (0..3).any(|i| (k_sensor[i] + neg_k[i]).abs() > VECTOR_TOLERANCE) {
            return Err(BearingFusionError::InvalidObservation(
                "second direction candidate is not -k".into(),
            ));
        }
        let k_sensor = k_sensor.map(|component| component / norm);

        let coordinate_frame = event
            .sensor
            .coordinate_frame
            .as_deref()
            .filter(|frame| valid_identifier(frame))
            .ok_or_else(|| {
                BearingFusionError::InvalidObservation(
                    "typed sensor coordinate frame is required".into(),
                )
            })?
            .to_string();
        let position_f32 = event.sensor.position_m.ok_or_else(|| {
            BearingFusionError::InvalidObservation("typed sensor position is required".into())
        })?;
        let position = position_f32.map(f64::from);
        if position
            .iter()
            .any(|v| !v.is_finite() || v.abs() > MAX_ABS_POSITION_M)
        {
            return Err(BearingFusionError::InvalidObservation(
                "sensor position is outside the supported coordinate envelope".into(),
            ));
        }
        for (name, canonical) in [
            ("sensor_x_m", position_f32[0]),
            ("sensor_y_m", position_f32[1]),
            ("sensor_z_m", position_f32[2]),
        ] {
            let mirror = *event
                .observation
                .features
                .get(name)
                .ok_or(BearingFusionError::MissingFeature(name))?;
            if !mirror.is_finite() || mirror.to_bits() != canonical.to_bits() {
                return Err(BearingFusionError::InvalidObservation(format!(
                    "legacy pose mirror {name} differs from typed pose"
                )));
            }
        }
        let orientation_f32 = event.sensor.orientation_xyzw.ok_or_else(|| {
            BearingFusionError::InvalidObservation("typed sensor orientation is required".into())
        })?;
        let orientation = orientation_f32.map(f64::from);
        let orientation_norm = orientation.iter().map(|v| v * v).sum::<f64>().sqrt();
        if orientation.iter().any(|v| !v.is_finite())
            || (orientation_norm - 1.0).abs() > VECTOR_TOLERANCE
        {
            return Err(BearingFusionError::InvalidObservation(
                "sensor orientation quaternion is not normalized".into(),
            ));
        }
        let orientation = orientation.map(|component| component / orientation_norm);
        let direction_axis = rotate_vector_xyzw(k_sensor, orientation);

        if event
            .observation
            .attributes
            .get("tensor_frame")
            .map(String::as_str)
            != Some("sensor_local")
        {
            return Err(BearingFusionError::InvalidObservation(
                "signed observation attribute tensor_frame must equal sensor_local".into(),
            ));
        }

        let c00 = feature(event, "angle_cov_00_rad2")?;
        let c01 = feature(event, "angle_cov_01_rad2")?;
        let c11 = feature(event, "angle_cov_11_rad2")?;
        let trace = c00 + c11;
        let discriminant = ((c00 - c11).powi(2) + 4.0 * c01.powi(2)).sqrt();
        let lambda_min = (trace - discriminant) / 2.0;
        let lambda_max = (trace + discriminant) / 2.0;
        if c00 <= 0.0
            || c11 <= 0.0
            || !lambda_max.is_finite()
            || lambda_max <= 0.0
            || lambda_min < -PSD_RELATIVE_TOLERANCE * lambda_max
        {
            return Err(BearingFusionError::InvalidObservation(
                "angular covariance is not positive semidefinite".into(),
            ));
        }
        let noise_floor = f64::from(event.tensor.noise_floor);
        let expected_noise = lambda_max.sqrt();
        if !noise_floor.is_finite()
            || noise_floor <= 0.0
            || (noise_floor - expected_noise).abs() > expected_noise * 0.05 + 1.0e-9
        {
            return Err(BearingFusionError::InvalidObservation(
                "tensor noise floor does not match angular covariance".into(),
            ));
        }
        let confidence = f64::from(event.observation.confidence);
        if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) || confidence == 0.0 {
            return Err(BearingFusionError::InvalidObservation(
                "confidence must be finite and in 0<confidence<=1".into(),
            ));
        }
        let tensor_confidence = f64::from(event.tensor.confidence);
        if !tensor_confidence.is_finite() || (tensor_confidence - confidence).abs() > 1.0e-5 {
            return Err(BearingFusionError::InvalidObservation(
                "tensor and observation confidence differ".into(),
            ));
        }
        let signal_id = event
            .observation
            .attributes
            .get("signal_id")
            .filter(|id| valid_identifier(id))
            .ok_or_else(|| {
                BearingFusionError::InvalidObservation(
                    "signed observation attribute signal_id is required".into(),
                )
            })?
            .clone();
        if !event
            .observation
            .attributes
            .get("calibration_data_hash")
            .is_some_and(|hash| valid_sha256(hash))
        {
            return Err(BearingFusionError::InvalidObservation(
                "signed calibration_data_hash attribute is required".into(),
            ));
        }
        let calibration_created_ns = event
            .observation
            .attributes
            .get("calibration_created_ns")
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| {
                BearingFusionError::InvalidObservation(
                    "signed calibration_created_ns attribute is required".into(),
                )
            })?;
        let calibration_expires_ns = event
            .observation
            .attributes
            .get("calibration_expires_ns")
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| {
                BearingFusionError::InvalidObservation(
                    "signed calibration_expires_ns attribute is required".into(),
                )
            })?;
        let before = i128::from(integration_ns / 2);
        let after = i128::from(integration_ns - integration_ns / 2);
        let integration_start = i128::from(event.timestamp_ns) - before;
        let integration_end = i128::from(event.timestamp_ns) + after;
        if calibration_created_ns >= calibration_expires_ns
            || integration_start < i128::from(calibration_created_ns)
            || integration_end >= i128::from(calibration_expires_ns)
        {
            return Err(BearingFusionError::InvalidObservation(
                "integration interval lies outside the signed calibration validity window".into(),
            ));
        }
        let expected_remaining_s =
            (i128::from(calibration_expires_ns) - integration_end) as f64 / 1_000_000_000.0;
        if (calibration_remaining_s - expected_remaining_s).abs()
            > expected_remaining_s.abs() * 1.0e-5 + 1.0e-6
        {
            return Err(BearingFusionError::InvalidObservation(
                "calibration_remaining_s disagrees with the signed validity window".into(),
            ));
        }
        Ok(Self {
            event_id: event.event_id.clone(),
            sensor_id: event.sensor.device_id.clone(),
            timestamp_ns: event.timestamp_ns,
            integration_ns,
            sensor_position_m: position,
            direction_axis,
            angular_variance_rad2: lambda_max,
            confidence,
            coordinate_frame,
            signal_id,
            carrier_hz,
            calibration_id: tensor_calibration.to_string(),
            calibration_created_ns,
            calibration_expires_ns,
        })
    }
}

/// A bounded, synchronized collection of quantum RF bearing observations.
#[derive(Debug, Clone)]
pub struct QuantumBearingFusion {
    observations: Vec<BearingObservation>,
    sensor_ids: BTreeSet<String>,
    event_ids: BTreeSet<String>,
    config: BearingFusionConfig,
    trust: BearingTrustPolicy,
}

impl QuantumBearingFusion {
    /// Construct an empty fusion window with the requested synchronization
    /// tolerance.
    #[must_use]
    pub fn new(max_time_skew_ns: u64, trust: BearingTrustPolicy) -> Self {
        let config = BearingFusionConfig {
            max_time_skew_ns,
            ..BearingFusionConfig::default()
        };
        Self::from_validated_config(config, trust)
    }

    /// Construct with an explicit geometry and evidence-grouping policy.
    pub fn with_config(
        config: BearingFusionConfig,
        trust: BearingTrustPolicy,
    ) -> Result<Self, BearingFusionError> {
        Ok(Self::from_validated_config(config.validate()?, trust))
    }

    fn from_validated_config(config: BearingFusionConfig, trust: BearingTrustPolicy) -> Self {
        Self {
            observations: Vec::new(),
            sensor_ids: BTreeSet::new(),
            event_ids: BTreeSet::new(),
            config,
            trust,
        }
    }

    /// Construct an explicit simulation-only fusion window.
    #[must_use]
    pub fn for_simulation(max_time_skew_ns: u64) -> Self {
        Self::new(max_time_skew_ns, BearingTrustPolicy::simulation())
    }

    /// Validate and retain one signed derived-bearing event.
    pub fn ingest(&mut self, event: &FieldEvent) -> Result<(), BearingFusionError> {
        if self.observations.len() >= MAX_BEARINGS {
            return Err(BearingFusionError::CapacityExceeded);
        }
        let observation = BearingObservation::try_from_event(event, &self.trust)?;
        if self.event_ids.contains(&observation.event_id) {
            return Err(BearingFusionError::InvalidObservation(
                "duplicate event id in fusion window".into(),
            ));
        }
        if self.sensor_ids.contains(&observation.sensor_id) {
            return Err(BearingFusionError::DuplicateSensor(observation.sensor_id));
        }
        if let Some(first) = self.observations.first() {
            if observation.coordinate_frame != first.coordinate_frame {
                return Err(BearingFusionError::CoordinateFrameMismatch {
                    expected: first.coordinate_frame.clone(),
                    actual: observation.coordinate_frame,
                });
            }
            if observation.signal_id != first.signal_id {
                return Err(BearingFusionError::SignalMismatch {
                    expected: first.signal_id.clone(),
                    actual: observation.signal_id,
                });
            }
            let min_carrier_hz = self
                .observations
                .iter()
                .map(|item| item.carrier_hz)
                .fold(observation.carrier_hz, f64::min);
            let max_carrier_hz = self
                .observations
                .iter()
                .map(|item| item.carrier_hz)
                .fold(observation.carrier_hz, f64::max);
            if max_carrier_hz - min_carrier_hz > self.config.carrier_tolerance_hz {
                return Err(BearingFusionError::CarrierMismatch {
                    expected_hz: first.carrier_hz,
                    actual_hz: observation.carrier_hz,
                });
            }
            let min_timestamp = self
                .observations
                .iter()
                .map(|item| item.timestamp_ns)
                .min()
                .unwrap_or(observation.timestamp_ns)
                .min(observation.timestamp_ns);
            let max_timestamp = self
                .observations
                .iter()
                .map(|item| item.timestamp_ns)
                .max()
                .unwrap_or(observation.timestamp_ns)
                .max(observation.timestamp_ns);
            let skew = max_timestamp.saturating_sub(min_timestamp);
            if skew > self.config.max_time_skew_ns {
                return Err(BearingFusionError::TimeSkew {
                    event_id: observation.event_id,
                    skew_ns: skew,
                });
            }

            // `timestamp_ns` is the integration midpoint. Requiring a common
            // intersection prevents fusing sequential captures merely because
            // their midpoints happen to fit inside the coarse skew limit.
            let integration_bounds = |item: &BearingObservation| {
                let before = i128::from(item.integration_ns / 2);
                let after = i128::from(item.integration_ns - item.integration_ns / 2);
                (
                    i128::from(item.timestamp_ns) - before,
                    i128::from(item.timestamp_ns) + after,
                )
            };
            let (new_start, new_end) = integration_bounds(&observation);
            let latest_start = self
                .observations
                .iter()
                .map(|item| integration_bounds(item).0)
                .max()
                .unwrap_or(new_start)
                .max(new_start);
            let earliest_end = self
                .observations
                .iter()
                .map(|item| integration_bounds(item).1)
                .min()
                .unwrap_or(new_end)
                .min(new_end);
            if latest_start >= earliest_end {
                let gap_ns =
                    u64::try_from((latest_start - earliest_end).max(0)).unwrap_or(u64::MAX);
                return Err(BearingFusionError::IntegrationWindowMismatch {
                    event_id: observation.event_id,
                    gap_ns,
                });
            }
        }
        self.trust.record_validated(event);
        self.event_ids.insert(observation.event_id.clone());
        self.sensor_ids.insert(observation.sensor_id.clone());
        self.observations.push(observation);
        Ok(())
    }

    /// Discard all observations and start a new synchronization window.
    pub fn clear(&mut self) {
        self.observations.clear();
        self.sensor_ids.clear();
        self.event_ids.clear();
    }

    /// Advance the trusted production clock while preserving replay
    /// watermarks and the current trust registry.
    ///
    /// The supplied time must come from a trusted deployment clock and may
    /// not move backward. This operation is rejected for replay and
    /// simulation policies.
    pub fn advance_live_evaluation_time(
        &mut self,
        evaluation_time_ns: u64,
    ) -> Result<(), BearingFusionError> {
        if !self.observations.is_empty() {
            return Err(BearingFusionError::InvalidTrustPolicy(
                "trusted evaluation time may advance only between empty fusion windows".into(),
            ));
        }
        self.trust.advance_evaluation_time(evaluation_time_ns)
    }

    /// Number of validated viewpoints currently retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.observations.len()
    }

    /// Whether the current fusion window is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }

    /// Estimate the common point minimizing weighted perpendicular distance
    /// to every propagation axis.
    pub fn estimate(&self) -> Result<BearingEstimate, BearingFusionError> {
        let n = self.observations.len();
        if n < 2 {
            return Err(BearingFusionError::InsufficientObservations(n));
        }
        let geometry_angle = max_axis_separation(&self.observations);
        if geometry_angle < self.config.min_geometry_angle_rad {
            return Err(BearingFusionError::DegenerateGeometry {
                angle_rad: geometry_angle,
            });
        }
        let sensor_baseline = max_sensor_baseline(&self.observations);
        if sensor_baseline < self.config.min_sensor_baseline_m {
            return Err(BearingFusionError::InsufficientBaseline {
                baseline_m: sensor_baseline,
            });
        }

        // Start with unweighted line intersection, then use the estimated
        // ranges to convert angular variance into lateral position variance:
        // sigma_perp^2 ~= range^2 * sigma_angle^2. Two refinements are enough
        // for this small smooth problem and retain the absolute uncertainty
        // scale instead of normalizing it away.
        let mut weights = vec![1.0; n];
        let (mut information, b) = weighted_system(&self.observations, &weights);
        let mut inverse =
            invert_3x3(information).ok_or(BearingFusionError::DegenerateGeometry {
                angle_rad: geometry_angle,
            })?;
        let mut position = mat_vec(inverse, b);
        for _ in 0..2 {
            weights = self
                .observations
                .iter()
                .map(|observation| {
                    let delta = sub(position, observation.sensor_position_m);
                    let range = dot(delta, delta).sqrt().max(MIN_RANGE_M);
                    observation.confidence.powi(2)
                        / (range.powi(2) * observation.angular_variance_rad2)
                })
                .collect();
            let (next_information, b) = weighted_system(&self.observations, &weights);
            information = next_information;
            inverse = invert_3x3(information).ok_or(BearingFusionError::DegenerateGeometry {
                angle_rad: geometry_angle,
            })?;
            position = mat_vec(inverse, b);
        }
        let condition_number = condition_number_inf(information, inverse);
        if !condition_number.is_finite() || condition_number > self.config.max_condition_number {
            return Err(BearingFusionError::IllConditioned { condition_number });
        }

        let mut weighted_sq = 0.0;
        let mut unweighted_sq = 0.0;
        for (observation, weight) in self.observations.iter().zip(&weights) {
            let delta = sub(position, observation.sensor_position_m);
            let perpendicular = mat_vec(projector(observation.direction_axis), delta);
            let distance_sq = dot(perpendicular, perpendicular);
            weighted_sq += weight * distance_sq;
            unweighted_sq += distance_sq;
        }
        let residual_rmse = (unweighted_sq / n as f64).sqrt();
        let dof = (2 * n).saturating_sub(3).max(1) as f64;
        // `inverse` already carries square-metre units from the absolute
        // lateral variances. Inflate it only when residuals exceed the stated
        // noise model; never shrink a perfect intersection below that model.
        let reduced_chi_squared = (weighted_sq / dof).max(1.0);
        let covariance = scale_matrix(inverse, reduced_chi_squared);
        let mean_confidence =
            self.observations.iter().map(|o| o.confidence).sum::<f64>() / n as f64;
        let geometry_score = geometry_angle.sin().clamp(0.0, 1.0);
        let fit_score = 1.0 / (1.0 + residual_rmse);
        let produced_ns = self
            .observations
            .iter()
            .map(|observation| observation.timestamp_ns)
            .max()
            .unwrap_or_default();
        let first = &self.observations[0];
        let calibration_ids = self
            .observations
            .iter()
            .map(|observation| observation.calibration_id.clone())
            .collect();
        let earliest_calibration_expiry = self
            .observations
            .iter()
            .map(|observation| observation.calibration_expires_ns)
            .min()
            .unwrap_or(produced_ns);
        let expires_ns = produced_ns
            .saturating_add(self.config.estimate_ttl_ns)
            .min(earliest_calibration_expiry);
        if expires_ns <= produced_ns {
            return Err(BearingFusionError::EstimateExpired {
                produced_ns,
                expires_ns,
            });
        }

        Ok(BearingEstimate {
            position_m: position,
            covariance_m2: covariance,
            coordinate_frame: first.coordinate_frame.clone(),
            signal_id: first.signal_id.clone(),
            carrier_hz: first.carrier_hz,
            residual_rmse_m: residual_rmse,
            geometry_angle_rad: geometry_angle,
            quality_score: (mean_confidence * geometry_score * fit_score).clamp(0.0, 1.0),
            privacy_class: PrivacyClass::P1,
            produced_ns,
            expires_ns,
            sign_invariant: true,
            calibration_ids,
            supporting_events: self
                .observations
                .iter()
                .map(|o| o.event_id.clone())
                .collect(),
        })
    }
}

impl Default for QuantumBearingFusion {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_TIME_SKEW_NS, BearingTrustPolicy::deny_all())
    }
}
