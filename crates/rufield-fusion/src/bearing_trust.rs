//! Trust policy for quantum RF bearing fusion (ADR-266).

use crate::bearing::BearingFusionError;
use rufield_core::FieldEvent;
use rufield_provenance::{normalize_verifying_key_hex, verify_event};
use std::collections::{BTreeMap, BTreeSet};

const MAX_ID_BYTES: usize = 256;
const POSE_NORM_TOLERANCE: f64 = 1.0e-5;
const MAX_ABS_POSITION_M: f32 = 1.0e6;

/// One externally enrolled live-sensor trust binding.
///
/// Enrollment is assumed to happen only after the deployment has verified the
/// device key and calibration authority. This type records that decision; it
/// does not itself attest hardware or calibration quality.
#[derive(Debug, Clone, PartialEq)]
pub struct TrustedSensorBinding {
    /// Stable device id carried by `SensorDescriptor`.
    pub device_id: String,
    /// Device Ed25519 public key encoded as 64 hexadecimal characters.
    pub signer_pubkey_hex: String,
    /// Calibration-bound shared coordinate frame.
    pub coordinate_frame: String,
    /// Calibration-bound sensor position in the shared frame.
    pub position_m: [f32; 3],
    /// Calibration-bound sensor-local to shared-frame quaternion `[x,y,z,w]`.
    pub orientation_xyzw: [f32; 4],
    /// Enrolled calibration identifier.
    pub calibration_id: String,
    /// Enrolled `sha256:<hex>` calibration sidecar hash.
    pub calibration_data_hash: String,
    /// Exact half-open calibration validity start timestamp.
    pub calibration_created_ns: u64,
    /// Exact half-open calibration expiry timestamp.
    pub calibration_expires_ns: u64,
    /// Revoked devices always fail closed.
    pub revoked: bool,
}

impl TrustedSensorBinding {
    fn validated(mut self) -> Result<Self, BearingFusionError> {
        if !valid_id(&self.device_id)
            || !valid_id(&self.coordinate_frame)
            || !valid_id(&self.calibration_id)
        {
            return Err(BearingFusionError::InvalidTrustPolicy(
                "device, coordinate-frame, and calibration ids must be bounded and control-free"
                    .into(),
            ));
        }
        self.signer_pubkey_hex = normalize_signer(&self.signer_pubkey_hex)?;
        self.calibration_data_hash = normalize_sha256(&self.calibration_data_hash)?;
        if self.calibration_created_ns >= self.calibration_expires_ns {
            return Err(BearingFusionError::InvalidTrustPolicy(
                "calibration validity interval must be nonempty".into(),
            ));
        }
        if self
            .position_m
            .iter()
            .any(|value| !value.is_finite() || value.abs() > MAX_ABS_POSITION_M)
        {
            return Err(BearingFusionError::InvalidTrustPolicy(
                "trusted sensor position is nonfinite or outside the coordinate envelope".into(),
            ));
        }
        let quaternion_norm = self
            .orientation_xyzw
            .iter()
            .map(|value| f64::from(*value).powi(2))
            .sum::<f64>()
            .sqrt();
        if self.orientation_xyzw.iter().any(|value| !value.is_finite())
            || (quaternion_norm - 1.0).abs() > POSE_NORM_TOLERANCE
        {
            return Err(BearingFusionError::InvalidTrustPolicy(
                "trusted sensor orientation is not a unit quaternion".into(),
            ));
        }
        Ok(self)
    }
}

/// Trusted evaluation time and admissible live-event clock error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveTrustWindow {
    /// Trusted deployment evaluation time.
    pub evaluation_time_ns: u64,
    /// Oldest accepted event age relative to `evaluation_time_ns`.
    pub max_event_age_ns: u64,
    /// Maximum accepted event timestamp lead over `evaluation_time_ns`.
    pub max_future_skew_ns: u64,
}

impl LiveTrustWindow {
    fn validate(self) -> Result<Self, BearingFusionError> {
        if self.max_event_age_ns == 0 {
            return Err(BearingFusionError::InvalidTrustPolicy(
                "live maximum event age must be positive".into(),
            ));
        }
        Ok(self)
    }
}

/// Explicit trust policy for quantum bearing events.
///
/// Signature verification alone is not authorization because an attacker can
/// sign with a new key. Production policy therefore binds each enrolled device
/// to one signer, pose, coordinate frame, and calibration sidecar.
#[derive(Debug, Clone, PartialEq)]
pub struct BearingTrustPolicy {
    mode: TrustMode,
    trusted_signer_pubkeys: BTreeSet<String>,
    production_bindings: BTreeMap<String, TrustedSensorBinding>,
    live_window: Option<LiveTrustWindow>,
    last_timestamp_by_sensor: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustMode {
    DenyAll,
    Simulation,
    CapturedReplay,
    Production,
}

impl BearingTrustPolicy {
    /// Deny every event until production trust anchors are configured.
    #[must_use]
    pub fn deny_all() -> Self {
        Self {
            mode: TrustMode::DenyAll,
            trusted_signer_pubkeys: BTreeSet::new(),
            production_bindings: BTreeMap::new(),
            live_window: None,
            last_timestamp_by_sensor: BTreeMap::new(),
        }
    }

    /// Create a live production policy from externally enrolled sensor
    /// bindings and a trusted freshness window.
    pub fn production<I>(
        bindings: I,
        live_window: LiveTrustWindow,
    ) -> Result<Self, BearingFusionError>
    where
        I: IntoIterator<Item = TrustedSensorBinding>,
    {
        let live_window = live_window.validate()?;
        let mut registry = BTreeMap::new();
        let mut assigned_signers = BTreeSet::new();
        for binding in bindings {
            let binding = binding.validated()?;
            let device_id = binding.device_id.clone();
            if !assigned_signers.insert(binding.signer_pubkey_hex.clone()) {
                return Err(BearingFusionError::InvalidTrustPolicy(
                    "one production signer key cannot be enrolled for multiple devices".into(),
                ));
            }
            if registry.insert(device_id.clone(), binding).is_some() {
                return Err(BearingFusionError::InvalidTrustPolicy(format!(
                    "duplicate production binding for device {device_id}"
                )));
            }
        }
        if registry.is_empty() {
            return Err(BearingFusionError::InvalidTrustPolicy(
                "production policy requires at least one trusted sensor binding".into(),
            ));
        }
        Ok(Self {
            mode: TrustMode::Production,
            trusted_signer_pubkeys: BTreeSet::new(),
            production_bindings: registry,
            live_window: Some(live_window),
            last_timestamp_by_sensor: BTreeMap::new(),
        })
    }

    /// Create an explicit captured-replay policy. Replay signatures attest
    /// packaging integrity, not live sensor identity, so this policy is kept
    /// separate from [`Self::production`].
    pub fn captured_replay<I, S>(signers: I) -> Result<Self, BearingFusionError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let trusted_signer_pubkeys = validated_signers(signers)?;
        Ok(Self {
            mode: TrustMode::CapturedReplay,
            trusted_signer_pubkeys,
            production_bindings: BTreeMap::new(),
            live_window: None,
            last_timestamp_by_sensor: BTreeMap::new(),
        })
    }

    /// Explicit test and simulation policy. Never use for live decisions.
    #[must_use]
    pub fn simulation() -> Self {
        Self {
            mode: TrustMode::Simulation,
            trusted_signer_pubkeys: BTreeSet::new(),
            production_bindings: BTreeMap::new(),
            live_window: None,
            last_timestamp_by_sensor: BTreeMap::new(),
        }
    }

    /// Advance the trusted production clock without replacing replay state.
    ///
    /// Callers must source this timestamp from their deployment's trusted
    /// clock. Reconstructing the policy for each time update would erase the
    /// per-device replay watermarks, so production time is deliberately
    /// updated in place and may never move backward.
    pub(crate) fn advance_evaluation_time(
        &mut self,
        evaluation_time_ns: u64,
    ) -> Result<(), BearingFusionError> {
        if self.mode != TrustMode::Production {
            return Err(BearingFusionError::InvalidTrustPolicy(
                "trusted evaluation time is available only in production mode".into(),
            ));
        }
        let window = self.live_window.as_mut().ok_or_else(|| {
            BearingFusionError::InvalidTrustPolicy("production freshness window is absent".into())
        })?;
        if evaluation_time_ns < window.evaluation_time_ns {
            return Err(BearingFusionError::InvalidTrustPolicy(
                "trusted evaluation time must not move backward".into(),
            ));
        }
        window.evaluation_time_ns = evaluation_time_ns;
        Ok(())
    }

    pub(crate) fn authorize(&self, event: &FieldEvent) -> Result<(), BearingFusionError> {
        if event.provenance.synthetic {
            if self.mode != TrustMode::Simulation {
                return Err(BearingFusionError::SyntheticRejected(
                    event.event_id.clone(),
                ));
            }
            return self.require_evidence_kind(event, "synthetic_replay");
        }

        verify_event(event).map_err(|_| BearingFusionError::NotFusable(event.event_id.clone()))?;
        let signer = event
            .provenance
            .signer_pubkey_hex
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        match self.mode {
            TrustMode::CapturedReplay => {
                if !self.trusted_signer_pubkeys.contains(&signer) {
                    return Err(BearingFusionError::UntrustedSigner(event.event_id.clone()));
                }
                self.require_evidence_kind(event, "captured_replay")
            }
            TrustMode::Production => self.authorize_production(event, &signer),
            TrustMode::DenyAll | TrustMode::Simulation => {
                Err(BearingFusionError::UntrustedSigner(event.event_id.clone()))
            }
        }
    }

    fn authorize_production(
        &self,
        event: &FieldEvent,
        signer: &str,
    ) -> Result<(), BearingFusionError> {
        self.require_evidence_kind(event, "live")?;
        let device_id = event.sensor.device_id.as_str();
        let binding = self
            .production_bindings
            .get(device_id)
            .ok_or_else(|| BearingFusionError::UnknownTrustedSensor(device_id.to_string()))?;
        if binding.revoked {
            return Err(BearingFusionError::RevokedTrustedSensor(
                device_id.to_string(),
            ));
        }
        if signer != binding.signer_pubkey_hex {
            return Err(BearingFusionError::UntrustedSigner(event.event_id.clone()));
        }
        require_binding(
            device_id,
            "coordinate_frame",
            event.sensor.coordinate_frame.as_deref() == Some(binding.coordinate_frame.as_str()),
        )?;
        require_binding(
            device_id,
            "position_m",
            event.sensor.position_m == Some(binding.position_m),
        )?;
        require_binding(
            device_id,
            "orientation_xyzw",
            event.sensor.orientation_xyzw == Some(binding.orientation_xyzw),
        )?;
        require_binding(
            device_id,
            "calibration_id",
            event.tensor.calibration_id.as_deref() == Some(binding.calibration_id.as_str())
                && event.provenance.calibration_id == binding.calibration_id,
        )?;
        require_binding(
            device_id,
            "calibration_data_hash",
            event.observation.attributes.get("calibration_data_hash")
                == Some(&binding.calibration_data_hash),
        )?;
        require_binding(
            device_id,
            "calibration_created_ns",
            event
                .observation
                .attributes
                .get("calibration_created_ns")
                .and_then(|value| value.parse::<u64>().ok())
                == Some(binding.calibration_created_ns),
        )?;
        require_binding(
            device_id,
            "calibration_expires_ns",
            event
                .observation
                .attributes
                .get("calibration_expires_ns")
                .and_then(|value| value.parse::<u64>().ok())
                == Some(binding.calibration_expires_ns),
        )?;

        let window = self.live_window.ok_or_else(|| {
            BearingFusionError::InvalidTrustPolicy("production freshness window is absent".into())
        })?;
        if window.evaluation_time_ns >= binding.calibration_expires_ns {
            return Err(BearingFusionError::TrustedCalibrationExpired {
                device_id: device_id.to_string(),
                expires_ns: binding.calibration_expires_ns,
            });
        }
        if event.timestamp_ns > window.evaluation_time_ns {
            let skew_ns = event.timestamp_ns - window.evaluation_time_ns;
            if skew_ns > window.max_future_skew_ns {
                return Err(BearingFusionError::FutureLiveEvent {
                    event_id: event.event_id.clone(),
                    skew_ns,
                });
            }
        } else {
            let age_ns = window.evaluation_time_ns - event.timestamp_ns;
            if age_ns > window.max_event_age_ns {
                return Err(BearingFusionError::StaleLiveEvent {
                    event_id: event.event_id.clone(),
                    age_ns,
                });
            }
        }
        if event.timestamp_ns >= binding.calibration_expires_ns {
            return Err(BearingFusionError::TrustedCalibrationExpired {
                device_id: device_id.to_string(),
                expires_ns: binding.calibration_expires_ns,
            });
        }
        if self
            .last_timestamp_by_sensor
            .get(device_id)
            .is_some_and(|last| event.timestamp_ns <= *last)
        {
            return Err(BearingFusionError::LiveReplayDetected {
                device_id: device_id.to_string(),
                timestamp_ns: event.timestamp_ns,
            });
        }
        Ok(())
    }

    /// Record only a completely validated live observation. This intentionally
    /// happens after tensor, pose, and covariance validation so malformed signed
    /// events cannot consume the device replay watermark.
    pub(crate) fn record_validated(&mut self, event: &FieldEvent) {
        if self.mode == TrustMode::Production {
            self.last_timestamp_by_sensor
                .insert(event.sensor.device_id.clone(), event.timestamp_ns);
        }
    }

    fn require_evidence_kind(
        &self,
        event: &FieldEvent,
        expected: &'static str,
    ) -> Result<(), BearingFusionError> {
        let actual = event
            .observation
            .attributes
            .get("evidence_kind")
            .map(String::as_str)
            .unwrap_or("<missing>");
        if actual != expected {
            return Err(BearingFusionError::EvidenceKindRejected {
                event_id: event.event_id.clone(),
                expected,
                actual: actual.to_string(),
            });
        }
        Ok(())
    }
}

fn validated_signers<I, S>(signers: I) -> Result<BTreeSet<String>, BearingFusionError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut trusted = BTreeSet::new();
    for signer in signers {
        trusted.insert(normalize_signer(signer.as_ref())?);
    }
    if trusted.is_empty() {
        return Err(BearingFusionError::InvalidTrustPolicy(
            "captured replay policy requires at least one trusted signer".into(),
        ));
    }
    Ok(trusted)
}

fn normalize_signer(value: &str) -> Result<String, BearingFusionError> {
    normalize_verifying_key_hex(value).map_err(|_| {
        BearingFusionError::InvalidTrustPolicy(
            "trusted signer must be a non-weak 32-byte hexadecimal Ed25519 public key".into(),
        )
    })
}

fn normalize_sha256(value: &str) -> Result<String, BearingFusionError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(BearingFusionError::InvalidTrustPolicy(
            "calibration hash must use sha256:<hex> encoding".into(),
        ));
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BearingFusionError::InvalidTrustPolicy(
            "calibration hash must contain 32 hexadecimal bytes".into(),
        ));
    }
    Ok(format!("sha256:{}", hex.to_ascii_lowercase()))
}

fn valid_id(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_ID_BYTES && !value.chars().any(char::is_control)
}

fn require_binding(
    device_id: &str,
    field: &'static str,
    matches: bool,
) -> Result<(), BearingFusionError> {
    if matches {
        Ok(())
    } else {
        Err(BearingFusionError::TrustedSensorBindingMismatch {
            device_id: device_id.to_string(),
            field,
        })
    }
}
