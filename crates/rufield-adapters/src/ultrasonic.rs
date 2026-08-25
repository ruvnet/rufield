//! The `UltrasonicReplayAdapter` — the first RuField adapter for
//! [`Modality::Ultrasonic`] (registry code 7, ADR-260 §8).
//!
//! # What this is
//!
//! It replays a recording produced by **BatVu** (<https://github.com/ruvnet/batvu>),
//! a handheld ultrasonic sonar that runs entirely in a phone browser: the
//! speaker emits a 17.5–20.5 kHz linear-FM chirp, the microphone records the
//! echo, and a matched filter compresses it into a **range profile** — echo
//! amplitude as a function of distance along the beam. One line of the
//! `.ultrasonic.jsonl` recording is one ping.
//!
//! Each ping becomes a [`FieldEvent`] carrying:
//!
//! * a [`FieldTensor`] over the single axis [`FieldAxis::Range`], holding the
//!   compressed range profile — real numbers on a real distance grid, described
//!   by `start_range_m` and `range_step_m`;
//! * the beam direction, in [`SensorDescriptor::orientation_xyzw`], because the
//!   pointing direction is genuinely sensor *pose* and not a measurement (see
//!   "Why not `FieldAxis::Angle`" below);
//! * an [`Observation`] whose `range_m` is the nearest detected echo and whose
//!   features are the detector's own outputs — echo count, peak SNR, noise
//!   floor. No person inference, no occupancy-of-a-human claim;
//! * a [`ProvenanceRef`] whose `raw_hash` is a genuine SHA-256 over the raw
//!   recorded line, signed with a deterministic replay key.
//!
//! # Why not `FieldAxis::Angle`
//!
//! A two-dimensional `[Angle, Range]` tensor is the obvious shape for a sonar
//! and it would be a lie here. [`FieldAxis::Angle`] means *angle-of-arrival
//! bins* — the output of an array that measured direction. BatVu has one
//! microphone. It measures range and nothing else; the direction attached to an
//! echo is where the operator happened to be pointing the phone, which is pose,
//! not signal. Encoding it as an angle axis would present a beam-steering
//! measurement the hardware cannot make, and a consumer would be entitled to
//! believe it. So the range profile is one-dimensional and the pointing
//! direction rides in the sensor descriptor, where a pose belongs.
//!
//! # Honesty (read this before quoting any number from it)
//!
//! 1. **Replay, not live hardware.** As with [`crate::csi_replay`], the adapter
//!    reads a file. Live streaming from a phone is a transport problem, not an
//!    adapter problem, but it is not done here.
//! 2. **The recording declares its own origin, and it cannot lie upward.**
//!    Every line carries `source`, either `simulated` or `device_capture`, and
//!    the adapter is constructed with the source it is *willing* to accept.
//!    A file claiming `device_capture` fed to an adapter configured for
//!    simulation is rejected — [`UltrasonicError::SourceMismatch`] — so a
//!    recording can never talk its way into a higher trust tier by relabelling
//!    itself. `provenance.synthetic` is then derived from the accepted source
//!    rather than taken from the caller.
//! 3. **BatVu's published numbers are from its simulator.** At the time of
//!    writing BatVu has run no real-hardware measurement campaign; its range
//!    accuracy and detection statistics come from a model that agrees with the
//!    physics by construction. A `simulated` recording is `synthetic: true` and
//!    is fusable only under [`TrustMode::Simulation`](rufield_provenance::TrustMode).
//! 4. **No accuracy claim.** The detections are CFAR outputs at a documented
//!    false-alarm rate. That is a detector operating point, not validated
//!    accuracy against surveyed ground truth.
//!
//! # Privacy: two output modes, and why the safe one is the default
//!
//! The full per-bin range profile is a sensor frame. It is not a microphone
//! recording — it is the matched filter's output in a 3 kHz band centred at
//! 19 kHz, and speech at 0.3–3.4 kHz is rejected by the band separation plus
//! the full pulse-compression gain, so it cannot carry intelligible voice. It
//! is still the rawest thing this sensor produces, and RuField classifies the
//! analogous per-subcarrier CSI frame [`PrivacyClass::P0`]
//! ([`crate::csi_replay`]). Calling it anything gentler would be special
//! pleading for our own modality.
//!
//! So the adapter has two output modes, following
//! [`crate::quantum_rf_replay`]'s precedent:
//!
//! * [`UltrasonicOutput::CoarseProfile`] — **the default**. The profile is
//!   max-pooled down to [`COARSE_BINS`] bins: echo strength against distance at
//!   a resolution that describes a room's shape and cannot reconstruct the
//!   waveform. That is a derived non-identity feature, [`PrivacyClass::P1`],
//!   and [`DefaultPrivacyGuard`](rufield_privacy::DefaultPrivacyGuard) lets it
//!   cross a network under the stock policy.
//! * [`UltrasonicOutput::RangeProfile`] — every bin as recorded,
//!   [`PrivacyClass::P0`], denied to the network by the same stock policy and
//!   available edge-local. This is the mode for a fusion engine running on the
//!   phone, or for an operator who has decided otherwise on purpose.
//!
//! Max-pooling rather than averaging is deliberate: a mean smears a sharp echo
//! into its neighbours and a wall stops looking like a wall, whereas a maximum
//! keeps every peak the detector cared about and discards only the shape
//! between them — which is precisely the part that was worth not transmitting.
//!
//! Nothing this adapter emits can reach P4 or P5 by any route. P5 requires
//! `observation.identity_evidence`, which `validate_evidence_at` restricts to
//! `Modality::BleAdvertisementRssi` — an ultrasonic event carrying it is a hard
//! validation failure, so the ceiling is structural rather than a promise.
//!
//! # Determinism
//!
//! Same file ⇒ byte-identical event stream. Timestamps come from the file, the
//! signing key is a fixed seed, and there is no RNG and no wall-clock read.

use rufield_core::{
    AdapterCapabilities, CalibrationReceipt, CoreError, FieldAdapter, FieldAxis, FieldEvent,
    FieldTensor, Modality, Observation, PrivacyClass, ProvenanceRef, SensorDescriptor,
};
use rufield_provenance::{sha256_hex, Signer};
use serde::Deserialize;

/// Deterministic 32-byte ed25519 signing seed for ultrasonic replay events.
///
/// The signature is real, so downstream verification works; the key identifies
/// a *replay source*. Same posture as [`crate::csi_replay::REPLAY_SIGNER_SEED`].
pub const ULTRASONIC_SIGNER_SEED: [u8; 32] = *b"rufield-ultrasonic-replay-key-32";

/// Maximum pings accepted from one recording.
pub const MAX_PINGS: usize = 100_000;

/// Maximum UTF-8 bytes in one JSONL line.
///
/// A profile of [`MAX_PROFILE_BINS`] values at ~12 bytes each plus the envelope
/// of metadata fits inside this with room to spare, and it is checked *before*
/// `serde_json` is handed the line — which is the point. A cap applied after
/// parsing has already allowed the allocation it was meant to prevent.
pub const MAX_LINE_BYTES: usize = 262_144;

/// Maximum range bins in one profile.
///
/// 4096 bins at BatVu's 7.1 mm range step is 29 m — an order of magnitude past
/// the ~4.5 m the link budget actually reaches, so this bounds memory without
/// constraining any physically meaningful recording.
pub const MAX_PROFILE_BINS: usize = 4096;

/// Maximum detections reported for one ping. A 4.5 m profile at 9.6 cm
/// resolution cannot hold more than ~47 resolvable echoes; 64 is that with
/// headroom, and anything past it is a malformed or hostile record.
pub const MAX_DETECTIONS: usize = 64;

/// Maximum UTF-8 bytes in identifier and placement strings.
pub const MAX_ID_BYTES: usize = 256;

/// Bins in the network-safe coarse profile.
///
/// 32 bins across BatVu's ~4.5 m usable span is ~14 cm per bin — slightly
/// coarser than the 9.6 cm range resolution the waveform actually achieves, so
/// the reduction genuinely discards information rather than merely renaming it.
pub const COARSE_BINS: usize = 32;

/// Pings used to establish the empty-room baseline in
/// [`UltrasonicReplayAdapter::calibrate`].
pub const DEFAULT_CALIBRATION_PINGS: usize = 8;

/// Upper bound on a physically meaningful range, metres. Beyond this the
/// two-way spreading loss on a phone speaker leaves nothing above the noise,
/// and a "detection" at 400 m is a malformed record, not a long shot.
pub const MAX_RANGE_M: f32 = 50.0;

/// How much of the range profile an event exposes.
///
/// This is a privacy decision expressed as a data-shape decision, which is the
/// only kind that holds: a consumer cannot un-coarsen a coarse profile, so the
/// policy is enforced by what is on the wire rather than by a label asking
/// nicely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UltrasonicOutput {
    /// P1 tensor of [`COARSE_BINS`] max-pooled bins. The safe default, and the
    /// only mode the stock privacy policy allows onto a network.
    CoarseProfile,
    /// P0 tensor of every recorded range bin. Edge-local under the stock
    /// policy.
    RangeProfile,
}

impl UltrasonicOutput {
    /// The privacy class this mode's tensor carries.
    #[must_use]
    pub fn privacy_class(self) -> PrivacyClass {
        match self {
            UltrasonicOutput::CoarseProfile => PrivacyClass::P1,
            UltrasonicOutput::RangeProfile => PrivacyClass::P0,
        }
    }
}

/// Where a recording came from. Declared per line, and checked against what the
/// adapter was configured to accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UltrasonicSource {
    /// Rendered by BatVu's acoustic simulator. `provenance.synthetic = true`;
    /// fusable only under simulation trust.
    Simulated,
    /// Captured from a real phone microphone. `provenance.synthetic = false`;
    /// eligible for captured-replay trust once the sensor key is enrolled.
    DeviceCapture,
}

impl UltrasonicSource {
    /// Whether events from this source are marked synthetic on the wire.
    #[must_use]
    pub fn is_synthetic(self) -> bool {
        matches!(self, UltrasonicSource::Simulated)
    }

    fn as_str(self) -> &'static str {
        match self {
            UltrasonicSource::Simulated => "simulated",
            UltrasonicSource::DeviceCapture => "device_capture",
        }
    }
}

/// One detected echo, as BatVu's CFAR detector reported it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Echo {
    /// Range to the echo in metres, from the acoustic centre of the phone.
    pub range_m: f32,
    /// Detector signal-to-noise ratio in dB, above the local CFAR estimate.
    pub snr_db: f32,
    /// Width of the compressed return in metres — a resolution-limited extent,
    /// not a measurement of the object's size.
    pub width_m: f32,
}

/// One parsed ping: a real range profile on a real distance grid.
#[derive(Debug, Clone, PartialEq)]
pub struct UltrasonicPing {
    /// Capture time, nanoseconds since the Unix epoch.
    pub timestamp_ns: u64,
    /// Unit beam direction in the recording's coordinate frame.
    pub beam: [f32; 3],
    /// Range of the first profile bin, metres.
    pub start_range_m: f32,
    /// Distance between adjacent profile bins, metres.
    pub range_step_m: f32,
    /// Compressed echo amplitude per range bin, non-negative.
    pub profile: Vec<f32>,
    /// Detections the sender's CFAR reported.
    pub detections: Vec<Echo>,
    /// Noise-floor estimate in the same units as `profile`.
    pub noise_floor: f32,
    /// Amplitude of the direct speaker-to-microphone arrival — BatVu's timing
    /// reference. Zero means the ping had no direct path, which means the
    /// range scale is unanchored and the ping is unusable.
    pub blast_amplitude: f32,
    /// Whether the capture clipped.
    pub saturated: bool,
    /// SHA-256 over the raw recorded line, `sha256:...`.
    pub raw_hash: String,
}

/// Empty-room reference computed by [`UltrasonicReplayAdapter::calibrate`].
#[derive(Debug, Clone, PartialEq)]
pub struct Baseline {
    /// Mean noise floor across the calibration pings.
    pub noise_floor: f32,
    /// Mean direct-path amplitude — the transmit level, as measured rather
    /// than as configured.
    pub blast_amplitude: f32,
    /// Pings the baseline was computed from.
    pub pings: usize,
}

/// Errors raised while parsing or replaying an `.ultrasonic.jsonl` recording.
#[derive(Debug, Clone, PartialEq)]
pub enum UltrasonicError {
    /// A line could not be parsed.
    Parse {
        /// 1-based line number.
        line: usize,
        /// Underlying serde message.
        message: String,
    },
    /// A line exceeded [`MAX_LINE_BYTES`].
    LineTooLong {
        /// 1-based line number.
        line: usize,
        /// Observed byte length.
        bytes: usize,
    },
    /// The recording exceeded [`MAX_PINGS`].
    TooManyPings,
    /// The recording contained no usable pings.
    Empty,
    /// A line declared a source the adapter was not configured to accept.
    SourceMismatch {
        /// 1-based line number.
        line: usize,
        /// What the adapter accepts.
        expected: &'static str,
        /// What the line declared.
        found: &'static str,
    },
    /// A line mixed device identities. One recording is one sensor.
    DeviceMismatch {
        /// 1-based line number.
        line: usize,
    },
    /// A field failed a physical or structural bound.
    Invalid {
        /// 1-based line number.
        line: usize,
        /// What was wrong.
        message: String,
    },
    /// Timestamps did not strictly increase.
    NonMonotonic {
        /// 1-based line number.
        line: usize,
        /// Previous timestamp.
        previous_ns: u64,
        /// This line's timestamp.
        timestamp_ns: u64,
    },
    /// Constructing the [`FieldTensor`] failed its structural invariant.
    Tensor(String),
}

impl std::fmt::Display for UltrasonicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse { line, message } => write!(f, "parse error on line {line}: {message}"),
            Self::LineTooLong { line, bytes } => write!(
                f,
                "line {line} has {bytes} bytes; maximum is {MAX_LINE_BYTES}"
            ),
            Self::TooManyPings => {
                write!(f, "recording exceeds maximum of {MAX_PINGS} pings")
            }
            Self::Empty => f.write_str("recording contained no usable ultrasonic pings"),
            Self::SourceMismatch {
                line,
                expected,
                found,
            } => write!(
                f,
                "line {line} declares source {found} but this adapter accepts {expected}"
            ),
            Self::DeviceMismatch { line } => write!(
                f,
                "line {line} changes device_id; one recording is one sensor"
            ),
            Self::Invalid { line, message } => write!(f, "line {line}: {message}"),
            Self::NonMonotonic {
                line,
                previous_ns,
                timestamp_ns,
            } => write!(
                f,
                "line {line}: timestamp {timestamp_ns} does not exceed previous {previous_ns}"
            ),
            Self::Tensor(message) => write!(f, "tensor construction failed: {message}"),
        }
    }
}

impl std::error::Error for UltrasonicError {}

impl From<CoreError> for UltrasonicError {
    fn from(error: CoreError) -> Self {
        UltrasonicError::Tensor(error.to_string())
    }
}

/// One line of the recording. Unknown fields are tolerated so a future BatVu
/// can add diagnostics without breaking older consumers; every field this
/// adapter *uses* is validated below rather than trusted.
#[derive(Debug, Clone, Deserialize)]
struct PingRecord {
    /// Capture time in seconds since the Unix epoch (fractional).
    timestamp: f64,
    source: UltrasonicSource,
    device_id: String,
    /// Beam direction, not required to be normalized on the wire.
    beam: [f64; 3],
    start_range_m: f64,
    range_step_m: f64,
    profile: Vec<f64>,
    #[serde(default)]
    detections: Vec<EchoRecord>,
    #[serde(default)]
    noise_floor: f64,
    #[serde(default)]
    blast_amplitude: f64,
    #[serde(default)]
    saturated: bool,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct EchoRecord {
    range_m: f64,
    snr_db: f64,
    #[serde(default)]
    width_m: f64,
}

/// Configuration for [`UltrasonicReplayAdapter`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UltrasonicConfig {
    /// How much of the range profile to expose. See [`UltrasonicOutput`].
    pub output: UltrasonicOutput,
    /// The only source this adapter will accept. A recording declaring anything
    /// else is rejected outright rather than downgraded, so the trust tier of a
    /// stream is decided by the *deployment*, never by the file.
    pub accept: UltrasonicSource,
    /// Logical zone the recording was taken in.
    pub zone_id: String,
    /// Physical placement hint recorded on the sensor descriptor.
    pub placement: String,
}

impl Default for UltrasonicConfig {
    fn default() -> Self {
        UltrasonicConfig {
            output: UltrasonicOutput::CoarseProfile,
            // Simulated is the safe default: it produces `synthetic: true`
            // events, which the trust verifier will only fuse under simulation
            // policy. Defaulting the other way would mean a caller who never
            // read this file gets production-shaped provenance for free.
            accept: UltrasonicSource::Simulated,
            zone_id: "ultrasonic_zone".to_string(),
            placement: "handheld".to_string(),
        }
    }
}

/// Replays a BatVu `.ultrasonic.jsonl` recording as [`FieldEvent`]s.
#[derive(Debug)]
pub struct UltrasonicReplayAdapter {
    config: UltrasonicConfig,
    device_id: String,
    pings: Vec<UltrasonicPing>,
    cursor: usize,
    baseline: Option<Baseline>,
    calibration_id: String,
}

impl UltrasonicReplayAdapter {
    /// Parse a recording with the default configuration (simulated source).
    pub fn from_jsonl(text: &str) -> Result<Self, UltrasonicError> {
        Self::from_jsonl_with(text, UltrasonicConfig::default())
    }

    /// Parse a recording, declaring which source the deployment will accept.
    ///
    /// Everything is validated at parse time so that a malformed recording
    /// fails before any event is produced. A stream that half-replays and then
    /// dies mid-way is the worst outcome for a fusion consumer: it has already
    /// ingested and acted on the good prefix.
    pub fn from_jsonl_with(text: &str, config: UltrasonicConfig) -> Result<Self, UltrasonicError> {
        let mut pings: Vec<UltrasonicPing> = Vec::new();
        let mut device_id: Option<String> = None;
        let mut previous_ns: Option<u64> = None;

        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            if raw.len() > MAX_LINE_BYTES {
                return Err(UltrasonicError::LineTooLong {
                    line,
                    bytes: raw.len(),
                });
            }
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            if pings.len() >= MAX_PINGS {
                return Err(UltrasonicError::TooManyPings);
            }

            let record: PingRecord =
                serde_json::from_str(trimmed).map_err(|error| UltrasonicError::Parse {
                    line,
                    message: error.to_string(),
                })?;

            if record.source != config.accept {
                return Err(UltrasonicError::SourceMismatch {
                    line,
                    expected: config.accept.as_str(),
                    found: record.source.as_str(),
                });
            }

            let id = check_id(&record.device_id, line, "device_id")?;
            match &device_id {
                None => device_id = Some(id),
                Some(existing) if existing == &id => {}
                Some(_) => return Err(UltrasonicError::DeviceMismatch { line }),
            }

            let ping = build_ping(&record, trimmed, line)?;
            if let Some(previous) = previous_ns {
                if ping.timestamp_ns <= previous {
                    return Err(UltrasonicError::NonMonotonic {
                        line,
                        previous_ns: previous,
                        timestamp_ns: ping.timestamp_ns,
                    });
                }
            }
            previous_ns = Some(ping.timestamp_ns);
            pings.push(ping);
        }

        if pings.is_empty() {
            return Err(UltrasonicError::Empty);
        }

        Ok(UltrasonicReplayAdapter {
            device_id: device_id.unwrap_or_else(|| "batvu_unknown".to_string()),
            config,
            pings,
            cursor: 0,
            baseline: None,
            calibration_id: "ultrasonic_uncalibrated".to_string(),
        })
    }

    /// Number of parsed pings.
    #[must_use]
    pub fn ping_count(&self) -> usize {
        self.pings.len()
    }

    /// The parsed pings.
    #[must_use]
    pub fn pings(&self) -> &[UltrasonicPing] {
        &self.pings
    }

    /// The sensor identity the whole recording belongs to.
    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// The current baseline, if [`calibrate`](Self::calibrate) has run.
    #[must_use]
    pub fn baseline(&self) -> Option<&Baseline> {
        self.baseline.as_ref()
    }

    /// Establish the empty-room baseline from the first
    /// [`DEFAULT_CALIBRATION_PINGS`] pings and return a [`CalibrationReceipt`].
    ///
    /// Two numbers matter and both come from the recording rather than from a
    /// configuration file: the **noise floor**, which is what every SNR is
    /// measured against, and the **direct-path amplitude**, which is the
    /// transmit level *as actually radiated by this particular phone*. A phone
    /// held in a case, or one whose speaker is partly covered, transmits less;
    /// only the measurement knows.
    ///
    /// As in [`crate::csi_replay`], this does not require the room to have been
    /// empty. It is a documented reference, and calibrating against an occupied
    /// room simply raises it.
    pub fn calibrate(&mut self, zone_id: &str) -> Result<CalibrationReceipt, UltrasonicError> {
        let take = DEFAULT_CALIBRATION_PINGS.min(self.pings.len());
        if take == 0 {
            return Err(UltrasonicError::Empty);
        }
        let mut noise = 0.0f64;
        let mut blast = 0.0f64;
        for ping in &self.pings[..take] {
            noise += f64::from(ping.noise_floor);
            blast += f64::from(ping.blast_amplitude);
        }
        let baseline = Baseline {
            noise_floor: (noise / take as f64) as f32,
            blast_amplitude: (blast / take as f64) as f32,
            pings: take,
        };

        let mut bytes = Vec::with_capacity(take * 8 + 8);
        bytes.extend_from_slice(&baseline.noise_floor.to_le_bytes());
        bytes.extend_from_slice(&baseline.blast_amplitude.to_le_bytes());
        for ping in &self.pings[..take] {
            bytes.extend_from_slice(&ping.noise_floor.to_le_bytes());
            bytes.extend_from_slice(&ping.blast_amplitude.to_le_bytes());
        }
        let data_hash = sha256_hex(&bytes);
        let short = &data_hash["sha256:".len().."sha256:".len() + 12];
        let calibration_id = format!("ultrasonic_cal_{short}");

        let created_ns = self.pings.first().map_or(0, |p| p.timestamp_ns);
        let expires_ns = created_ns.saturating_add(3_600_000_000_000);

        self.calibration_id.clone_from(&calibration_id);
        self.baseline = Some(baseline);

        Ok(CalibrationReceipt {
            calibration_id,
            modality: Modality::Ultrasonic.as_str().to_string(),
            zone_id: check_id(zone_id, 0, "zone_id").unwrap_or_else(|_| "ultrasonic_zone".into()),
            task: "empty_room_baseline".to_string(),
            created_ns,
            expires_ns,
            data_hash,
        })
    }

    /// Rewind to the first ping.
    pub fn reset(&mut self) {
        self.cursor = 0;
    }

    /// Drain the whole recording into events.
    pub fn collect_events(&mut self) -> Result<Vec<FieldEvent>, UltrasonicError> {
        let mut out = Vec::with_capacity(self.pings.len().saturating_sub(self.cursor));
        while let Some(event) = self.next_event()? {
            out.push(event);
        }
        Ok(out)
    }

    fn build_event(&self, index: usize) -> Result<FieldEvent, UltrasonicError> {
        let ping = &self.pings[index];

        // Confidence in the MEASUREMENT, not in any label: how far the strongest
        // return stands above the noise, saturating at 20 dB. A ping with no
        // detections is not low-confidence — it is a confident measurement of
        // an empty direction, which is the most useful thing a sonar reports.
        let peak_snr = ping
            .detections
            .iter()
            .map(|d| d.snr_db)
            .fold(f32::NEG_INFINITY, f32::max);
        let confidence = if ping.detections.is_empty() {
            0.5
        } else {
            (peak_snr / 20.0).clamp(0.0, 1.0)
        };

        let values = match self.config.output {
            UltrasonicOutput::RangeProfile => ping.profile.clone(),
            UltrasonicOutput::CoarseProfile => max_pool(&ping.profile, COARSE_BINS),
        };

        let tensor = FieldTensor::new(
            ping.timestamp_ns,
            Modality::Ultrasonic,
            vec![FieldAxis::Range],
            vec![values.len()],
            values,
            confidence,
            ping.noise_floor,
            Some(self.calibration_id.clone()),
            self.config.output.privacy_class(),
        )?;

        // The observation is P1 in both modes. It carries derived scalars — a
        // range, an echo count, an SNR — and never the frame, so the raw-frame
        // classification belongs to the tensor alone. `authorize_event` is
        // conjunctive over both, so the P0 tensor still governs the event.
        let mut observation = Observation::occupancy(confidence, PrivacyClass::P1);
        observation.zone_id = Some(self.config.zone_id.clone());
        observation.range_m = ping.detections.first().map(|d| d.range_m);
        observation
            .features
            .insert("echo_count".into(), ping.detections.len() as f32);
        observation.features.insert(
            "peak_snr_db".into(),
            if ping.detections.is_empty() {
                0.0
            } else {
                peak_snr
            },
        );
        observation
            .features
            .insert("noise_floor".into(), ping.noise_floor);
        observation
            .features
            .insert("blast_amplitude".into(), ping.blast_amplitude);
        // `range_m` is one of exactly six feature keys the fusion engine reads
        // (`rufield-fusion/src/engine.rs`, `WindowItem` construction). The typed
        // `Observation::range_m` field above is NOT read by fusion — setting
        // only that produces a wire-correct, signature-valid event that
        // contributes nothing to any range rule, which is the single easiest
        // mistake to make against this schema.
        observation.features.insert(
            "range_m".into(),
            ping.detections.first().map_or(0.0, |d| d.range_m),
        );

        // `presence` is deliberately NOT set, though fusion reads it and
        // setting it would make BatVu light up the shipped `person_present`
        // rule. An echo at 2.4 m is a surface. One transducer pair cannot tell
        // a person from a coat on the back of a chair, and a range-only sensor
        // that reports `presence` is asserting exactly that distinction. A
        // deployment that wants presence from ultrasonic must derive it in a
        // rule it owns, from `range_m`, and wear the claim itself.

        // String context that must not be flattened into a lossy f32 feature.
        // `evidence_kind` is the load-bearing one and it is here because of a
        // second trust path most adapters never meet: `bearing_trust`'s
        // simulation policy accepts a synthetic event ONLY when this attribute
        // names the replay kind, and rejects it as `<missing>` otherwise. An
        // ultrasonic event has no bearing to fuse and should never reach that
        // engine — but "should never" is not a mechanism, and the honest value
        // is one this adapter already knows. It follows the accepted source, in
        // the same vocabulary `quantum_rf_support.rs` established.
        //
        // `attributes` is covered by the event signature, so this is attested
        // rather than advisory.
        observation.attributes.insert(
            "evidence_kind".into(),
            match self.config.accept {
                UltrasonicSource::Simulated => "synthetic_replay".into(),
                UltrasonicSource::DeviceCapture => "captured_replay".into(),
            },
        );
        observation
            .attributes
            .insert("tensor_frame".into(), "sensor_local".into());
        observation.attributes.insert(
            "profile_detail".into(),
            match self.config.output {
                UltrasonicOutput::CoarseProfile => "coarse".into(),
                UltrasonicOutput::RangeProfile => "full".into(),
            },
        );

        // Labels describe what the DETECTOR did, in the detector's own terms.
        // "surface_echo" is a claim about the signal; it is deliberately not
        // "person_present", because nothing in a range profile from one
        // transducer distinguishes a person from a coat on a chair.
        if ping.detections.is_empty() {
            observation.labels.push("clear_path".into());
        } else {
            observation.labels.push("surface_echo".into());
        }
        if ping.saturated {
            observation.labels.push("saturated".into());
        }

        // Beam direction as a sensor pose. Roll about the boresight is
        // unobservable with one transducer pair, so the MINIMAL rotation taking
        // sensor-local +Z onto the beam is used: it is the rotation that
        // asserts nothing about the axis nobody measured.
        let orientation = minimal_rotation_z_to(ping.beam);

        let sensor = SensorDescriptor {
            modality: Modality::Ultrasonic.as_str().to_string(),
            vendor: "batvu".to_string(),
            device_id: self.device_id.clone(),
            placement: self.config.placement.clone(),
            coordinate_frame: Some("enu_scan_local".to_string()),
            // Orientation-only pose (BatVu ADR-011): the scan origin is pinned
            // and never moves, so the position is the origin by definition, not
            // by measurement. Reporting anything else would be inventing a
            // translation the phone cannot observe.
            position_m: Some([0.0, 0.0, 0.0]),
            orientation_xyzw: Some(orientation),
            clock_domain: "device_monotonic".to_string(),
        };

        let provenance = ProvenanceRef {
            raw_hash: ping.raw_hash.clone(),
            firmware_hash: sha256_hex(b"batvu-ultrasonic-replay-v1"),
            model_id: "batvu.sonar.matched_filter.v1".to_string(),
            calibration_id: self.calibration_id.clone(),
            // Derived from the ACCEPTED source, never from a wire field a
            // recording could set for itself.
            synthetic: self.config.accept.is_synthetic(),
            signature_hex: None,
            signer_pubkey_hex: None,
        };

        let mut event = FieldEvent::new(
            format!(
                "ultrasonic_{:012}_{index:06}",
                ping.timestamp_ns / 1_000_000
            ),
            ping.timestamp_ns,
            sensor,
            tensor,
            observation,
            provenance,
        );

        let signer = Signer::from_seed(&ULTRASONIC_SIGNER_SEED);
        signer
            .sign_event(&mut event)
            .map_err(|error| UltrasonicError::Tensor(error.to_string()))?;
        Ok(event)
    }
}

impl FieldAdapter for UltrasonicReplayAdapter {
    type Error = UltrasonicError;

    fn modality(&self) -> Modality {
        Modality::Ultrasonic
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            modality: Modality::Ultrasonic.as_str().to_string(),
            // BatVu records at whatever the browser gives it; 48 kHz is what
            // every iPhone in the wild reports, and the 20.5 kHz upper edge of
            // the chirp is chosen to stay inside its Nyquist limit.
            sample_rate_hz: 48_000,
            can_calibrate: true,
            // Per output mode, and not a `.max()` over the classes emitted:
            // `PrivacyClass` orders P0 < P5, so the RAW mode's P0 is
            // numerically the SMALLEST while being the most sensitive. A
            // maximum would report P1 for the raw mode and understate it.
            max_privacy_class: self.config.output.privacy_class(),
        }
    }

    fn next_event(&mut self) -> Result<Option<FieldEvent>, Self::Error> {
        if self.cursor >= self.pings.len() {
            return Ok(None);
        }
        let event = self.build_event(self.cursor)?;
        self.cursor += 1;
        Ok(Some(event))
    }
}

/// Validate one record and turn it into a ping.
///
/// Every bound here is a physical or structural one, and each is checked before
/// anything is allocated on its behalf.
fn build_ping(
    record: &PingRecord,
    raw_line: &str,
    line: usize,
) -> Result<UltrasonicPing, UltrasonicError> {
    let invalid = |message: String| UltrasonicError::Invalid { line, message };

    if !record.timestamp.is_finite() || record.timestamp < 0.0 {
        return Err(invalid(format!("bad timestamp {}", record.timestamp)));
    }
    // Nanoseconds must fit a u64: ~584 years of epoch. Anything past that is a
    // wrapping attack on the replay watermark, not a clock.
    let timestamp_ns_f = record.timestamp * 1e9;
    if timestamp_ns_f >= u64::MAX as f64 {
        return Err(invalid(format!(
            "timestamp {} does not fit a nanosecond clock",
            record.timestamp
        )));
    }
    let timestamp_ns = timestamp_ns_f as u64;

    if record.profile.is_empty() || record.profile.len() > MAX_PROFILE_BINS {
        return Err(invalid(format!(
            "profile has {} bins (expected 1..={MAX_PROFILE_BINS})",
            record.profile.len()
        )));
    }
    if record.detections.len() > MAX_DETECTIONS {
        return Err(invalid(format!(
            "{} detections (maximum {MAX_DETECTIONS})",
            record.detections.len()
        )));
    }

    if !record.range_step_m.is_finite() || record.range_step_m <= 0.0 {
        return Err(invalid(format!(
            "range_step_m {} must be finite and positive",
            record.range_step_m
        )));
    }
    if !record.start_range_m.is_finite() || record.start_range_m < 0.0 {
        return Err(invalid(format!(
            "start_range_m {} must be finite and non-negative",
            record.start_range_m
        )));
    }
    let end_range = record.start_range_m + record.range_step_m * record.profile.len() as f64;
    if end_range > f64::from(MAX_RANGE_M) {
        return Err(invalid(format!(
            "profile spans to {end_range:.1} m, past the {MAX_RANGE_M} m physical bound"
        )));
    }

    let mut profile = Vec::with_capacity(record.profile.len());
    for (bin, value) in record.profile.iter().enumerate() {
        // Non-finite values propagate through every downstream statistic and
        // silently poison a fused map; a negative amplitude is not a quiet
        // echo, it is a corrupt record.
        if !value.is_finite() || *value < 0.0 {
            return Err(invalid(format!("profile bin {bin} is {value}")));
        }
        profile.push(*value as f32);
    }

    let mut beam = [0.0f32; 3];
    let mut norm = 0.0f64;
    for (axis, value) in record.beam.iter().enumerate() {
        if !value.is_finite() {
            return Err(invalid(format!("beam component {axis} is {value}")));
        }
        norm += value * value;
    }
    let norm = norm.sqrt();
    if norm < 1e-6 {
        return Err(invalid("beam direction has no length".to_string()));
    }
    for (component, value) in beam.iter_mut().zip(record.beam.iter()) {
        *component = (value / norm) as f32;
    }

    if !record.noise_floor.is_finite() || record.noise_floor < 0.0 {
        return Err(invalid(format!("noise_floor {}", record.noise_floor)));
    }
    if !record.blast_amplitude.is_finite() || record.blast_amplitude < 0.0 {
        return Err(invalid(format!(
            "blast_amplitude {}",
            record.blast_amplitude
        )));
    }

    let mut detections = Vec::with_capacity(record.detections.len());
    for (position, echo) in record.detections.iter().enumerate() {
        if !echo.range_m.is_finite() || echo.range_m < 0.0 || echo.range_m > f64::from(MAX_RANGE_M)
        {
            return Err(invalid(format!(
                "detection {position} range {} out of bounds",
                echo.range_m
            )));
        }
        // A detection outside the profile it was supposedly found in is not a
        // long-range return; it is an inconsistent record, and accepting it
        // would put an echo into the fused map that no measurement supports.
        if echo.range_m + 1e-6 < record.start_range_m || echo.range_m > end_range + 1e-6 {
            return Err(invalid(format!(
                "detection {position} at {} m lies outside the profile [{:.3}, {end_range:.3}] m",
                echo.range_m, record.start_range_m
            )));
        }
        if !echo.snr_db.is_finite() || !echo.width_m.is_finite() || echo.width_m < 0.0 {
            return Err(invalid(format!(
                "detection {position} has a bad snr or width"
            )));
        }
        detections.push(Echo {
            range_m: echo.range_m as f32,
            snr_db: echo.snr_db as f32,
            width_m: echo.width_m as f32,
        });
    }
    // Nearest first, so `observation.range_m` means what it says. `total_cmp`
    // rather than `partial_cmp`: finiteness is already enforced above, but a
    // sort comparator that can panic is not worth keeping in a parser.
    detections.sort_by(|a, b| a.range_m.total_cmp(&b.range_m));

    Ok(UltrasonicPing {
        timestamp_ns,
        beam,
        start_range_m: record.start_range_m as f32,
        range_step_m: record.range_step_m as f32,
        profile,
        detections,
        noise_floor: record.noise_floor as f32,
        blast_amplitude: record.blast_amplitude as f32,
        saturated: record.saturated,
        raw_hash: sha256_hex(raw_line.as_bytes()),
    })
}

/// Reduce a profile to `bins` values by taking the maximum of each contiguous
/// group.
///
/// A profile shorter than `bins` is returned unchanged: padding it would invent
/// range cells the recording never measured, and the point of the reduction is
/// to remove information, never to add it.
fn max_pool(profile: &[f32], bins: usize) -> Vec<f32> {
    if profile.len() <= bins || bins == 0 {
        return profile.to_vec();
    }
    let mut out = Vec::with_capacity(bins);
    for bin in 0..bins {
        // Integer arithmetic on the boundaries, so every input bin lands in
        // exactly one output bin and none is dropped by a rounding seam.
        let start = bin * profile.len() / bins;
        let end = ((bin + 1) * profile.len() / bins).max(start + 1);
        let mut peak = 0.0f32;
        for value in &profile[start..end.min(profile.len())] {
            peak = peak.max(*value);
        }
        out.push(peak);
    }
    out
}

fn check_id(value: &str, line: usize, what: &str) -> Result<String, UltrasonicError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_ID_BYTES {
        return Err(UltrasonicError::Invalid {
            line,
            message: format!("{what} must be 1..={MAX_ID_BYTES} bytes"),
        });
    }
    // Identifiers reach logs, filenames and a viewer UI. Control characters in
    // any of those are somebody else's bug being handed a foothold.
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(UltrasonicError::Invalid {
            line,
            message: format!("{what} contains control characters"),
        });
    }
    Ok(trimmed.to_string())
}

/// Quaternion `[x, y, z, w]` for the minimal rotation taking sensor-local `+Z`
/// onto `beam`, which the caller has already normalized.
fn minimal_rotation_z_to(beam: [f32; 3]) -> [f32; 4] {
    let [bx, by, bz] = beam;
    // Antiparallel is the degenerate case: every rotation axis in the XY plane
    // works, so pick one deterministically rather than dividing by zero.
    if bz <= -1.0 + 1e-6 {
        return [1.0, 0.0, 0.0, 0.0];
    }
    // Half-angle form: q = (axis * sin(theta/2), cos(theta/2)) with
    // axis = normalize(z_hat x beam) and theta the angle between them. The
    // usual shortcut avoids the trig entirely.
    let w = 1.0 + bz;
    let (x, y, z) = (-by, bx, 0.0);
    let norm = (x * x + y * y + z * z + w * w).sqrt();
    [x / norm, y / norm, z / norm, w / norm]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rufield_core::{Destination, PrivacyDecision};
    use rufield_privacy::DefaultPrivacyGuard;
    use rufield_provenance::{is_fusable, verify_event, TrustPolicy, TrustVerifier};

    fn line(timestamp: f64, source: &str, range: f64) -> String {
        format!(
            r#"{{"timestamp":{timestamp},"source":"{source}","device_id":"batvu_test_01","beam":[0.0,1.0,0.0],"start_range_m":0.3,"range_step_m":0.00714,"profile":[0.01,0.02,0.9,0.03],"detections":[{{"range_m":{range},"snr_db":18.5,"width_m":0.1}}],"noise_floor":0.0004,"blast_amplitude":0.31,"saturated":false}}"#
        )
    }

    fn sample(source: &str) -> String {
        (0..4)
            .map(|i| line(1_756_162_800.0 + f64::from(i) * 0.0667, source, 0.31))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn simulated_adapter() -> UltrasonicReplayAdapter {
        UltrasonicReplayAdapter::from_jsonl(&sample("simulated")).expect("parse")
    }

    #[test]
    fn parses_and_emits_one_event_per_ping() {
        let mut adapter = simulated_adapter();
        assert_eq!(adapter.ping_count(), 4);
        assert_eq!(adapter.modality(), Modality::Ultrasonic);
        let events = adapter.collect_events().expect("events");
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].tensor.modality, Modality::Ultrasonic);
        assert_eq!(events[0].tensor.axes, vec![FieldAxis::Range]);
        assert_eq!(events[0].tensor.shape, vec![4]);
    }

    #[test]
    fn events_pass_core_evidence_validation() {
        let mut adapter = simulated_adapter();
        for event in adapter.collect_events().expect("events") {
            event
                .validate_evidence_at(event.timestamp_ns)
                .expect("evidence valid");
        }
    }

    #[test]
    fn events_carry_a_real_signature_that_verifies() {
        let mut adapter = simulated_adapter();
        let events = adapter.collect_events().expect("events");
        for event in &events {
            verify_event(event).expect("signature verifies");
            assert!(is_fusable(event));
        }
        // And a tampered event does not.
        let mut tampered = events[0].clone();
        tampered.tensor.values[0] = 999.0;
        assert!(verify_event(&tampered).is_err());
    }

    #[test]
    fn simulated_events_are_marked_synthetic_and_only_fuse_under_simulation_trust() {
        let mut adapter = simulated_adapter();
        let events = adapter.collect_events().expect("events");
        assert!(events.iter().all(|e| e.provenance.synthetic));

        let mut simulation = TrustVerifier::simulation();
        for event in &events {
            simulation
                .verify_and_record_at(event, event.timestamp_ns)
                .expect("simulation trust accepts a simulated recording");
        }

        // The same events under captured-replay trust are refused, because a
        // simulator is not a capture however well signed it is.
        let mut replay = TrustVerifier::new(TrustPolicy::captured_replay(), Default::default());
        assert!(replay
            .verify_and_record_at(&events[0], events[0].timestamp_ns)
            .is_err());
    }

    #[test]
    fn a_recording_cannot_relabel_itself_into_a_higher_trust_tier() {
        // The whole point of `accept`: a file claiming to be a device capture,
        // handed to an adapter configured for simulation, is rejected outright
        // rather than quietly downgraded or quietly believed.
        let error = UltrasonicReplayAdapter::from_jsonl(&sample("device_capture"))
            .expect_err("must reject");
        assert!(matches!(error, UltrasonicError::SourceMismatch { .. }));

        // ...and the reverse, so neither direction is a silent reinterpretation.
        let config = UltrasonicConfig {
            accept: UltrasonicSource::DeviceCapture,
            ..Default::default()
        };
        let error = UltrasonicReplayAdapter::from_jsonl_with(&sample("simulated"), config)
            .expect_err("must reject");
        assert!(matches!(error, UltrasonicError::SourceMismatch { .. }));
    }

    #[test]
    fn device_capture_recordings_are_not_synthetic() {
        let config = UltrasonicConfig {
            accept: UltrasonicSource::DeviceCapture,
            ..Default::default()
        };
        let mut adapter =
            UltrasonicReplayAdapter::from_jsonl_with(&sample("device_capture"), config)
                .expect("parse");
        let events = adapter.collect_events().expect("events");
        assert!(events.iter().all(|e| !e.provenance.synthetic));
        // Real signature, so captured-replay trust can accept it once the key
        // is enrolled — which is the point of the tier.
        verify_event(&events[0]).expect("verifies");
    }

    #[test]
    fn declared_capability_matches_what_each_mode_actually_emits() {
        // Not `<=`: `PrivacyClass` orders P0 < P5, so a raw P0 tensor is
        // numerically BELOW a P1 one while being more sensitive. The capability
        // has to state the mode's class exactly, and this is the test that
        // notices if the two ever drift apart.
        for (output, expected) in [
            (UltrasonicOutput::CoarseProfile, PrivacyClass::P1),
            (UltrasonicOutput::RangeProfile, PrivacyClass::P0),
        ] {
            let config = UltrasonicConfig {
                output,
                ..Default::default()
            };
            let mut adapter =
                UltrasonicReplayAdapter::from_jsonl_with(&sample("simulated"), config)
                    .expect("parse");
            assert_eq!(adapter.capabilities().max_privacy_class, expected);
            for event in adapter.collect_events().expect("events") {
                assert_eq!(event.tensor.privacy_class, expected);
                assert_eq!(event.observation.privacy_class, PrivacyClass::P1);
            }
        }
    }

    #[test]
    fn ultrasonic_cannot_reach_p4_or_p5_by_any_route() {
        let mut adapter = simulated_adapter();
        for event in adapter.collect_events().expect("events") {
            assert!(event.tensor.privacy_class < PrivacyClass::P4);
            assert!(event.observation.privacy_class < PrivacyClass::P4);
            // P5 is only reachable through identity evidence, and core rejects
            // identity evidence on any modality but BLE advertisement RSSI — so
            // the ceiling is structural, not a promise we are keeping.
            assert!(event.observation.identity_evidence.is_none());
            assert!(event.observation.channel_sounding_provenance.is_none());
        }
    }

    #[test]
    fn the_stock_privacy_policy_lets_the_coarse_profile_onto_a_network_and_refuses_the_raw_one() {
        // The privacy claim tested with rufield's own guard rather than by
        // reading the class off the struct and agreeing with ourselves.
        let guard = DefaultPrivacyGuard::default();

        let mut coarse = simulated_adapter();
        let event = coarse.collect_events().expect("events").remove(0);
        assert_eq!(
            guard.authorize_event(&event, Destination::Network, false, false),
            PrivacyDecision::Allow
        );

        let config = UltrasonicConfig {
            output: UltrasonicOutput::RangeProfile,
            ..Default::default()
        };
        let mut raw =
            UltrasonicReplayAdapter::from_jsonl_with(&sample("simulated"), config).expect("parse");
        let event = raw.collect_events().expect("events").remove(0);
        assert!(matches!(
            guard.authorize_event(&event, Destination::Network, false, false),
            PrivacyDecision::Deny(_)
        ));
        // ...but it is available on the device, which is where a phone-local
        // fusion engine would consume it.
        assert_eq!(
            guard.authorize_event(&event, Destination::EdgeLocal, false, false),
            PrivacyDecision::Allow
        );
    }

    #[test]
    fn the_coarse_profile_keeps_peaks_and_drops_the_shape_between_them() {
        let profile: Vec<f32> = (0..256)
            .map(|i| if i == 100 { 0.9 } else { 0.01 })
            .collect();
        let pooled = max_pool(&profile, COARSE_BINS);
        assert_eq!(pooled.len(), COARSE_BINS);
        // The peak survives at full height — a mean would have divided it by 8.
        assert!((pooled.iter().copied().fold(0.0f32, f32::max) - 0.9).abs() < 1e-6);
        assert_eq!(pooled.iter().filter(|v| **v > 0.5).count(), 1);
        // And it lands in the bin the sample was actually in.
        assert!(pooled[100 * COARSE_BINS / 256] > 0.5);
        // A profile shorter than the target is passed through, not padded.
        assert_eq!(max_pool(&[0.1, 0.2], COARSE_BINS), vec![0.1, 0.2]);
    }

    #[test]
    fn events_name_their_evidence_kind_for_the_stricter_trust_path() {
        // `bearing_trust`'s simulation policy accepts a synthetic event only
        // when `attributes["evidence_kind"]` names the replay kind; a missing
        // one is rejected as `<missing>`. BatVu has no bearing to fuse and
        // should never reach that engine, but the value is one this adapter
        // knows for certain, so it says it.
        for (accept, expected) in [
            (UltrasonicSource::Simulated, "synthetic_replay"),
            (UltrasonicSource::DeviceCapture, "captured_replay"),
        ] {
            let text = sample(if accept == UltrasonicSource::Simulated {
                "simulated"
            } else {
                "device_capture"
            });
            let config = UltrasonicConfig {
                accept,
                ..Default::default()
            };
            let mut adapter =
                UltrasonicReplayAdapter::from_jsonl_with(&text, config).expect("parse");
            let event = adapter.collect_events().expect("events").remove(0);
            assert_eq!(
                event
                    .observation
                    .attributes
                    .get("evidence_kind")
                    .map(String::as_str),
                Some(expected)
            );
            // Attributes are inside the signed bytes, so this is attested.
            verify_event(&event).expect("verifies with attributes present");
        }
    }

    #[test]
    fn the_fused_range_lands_on_the_feature_key_the_engine_actually_reads() {
        // `Observation::range_m` is the typed field; `features["range_m"]` is
        // what `rufield-fusion`'s window reads. Both are set, and this test
        // exists because setting only the first produces an event that is
        // wire-correct, signature-valid and invisible to every range rule.
        let mut adapter = simulated_adapter();
        let event = adapter.collect_events().expect("events").remove(0);
        assert_eq!(event.observation.range_m, Some(0.31));
        assert_eq!(event.observation.features.get("range_m"), Some(&0.31));

        // `presence` is deliberately absent: a range-only sensor asserting
        // presence would be claiming it can tell a person from a chair.
        assert!(!event.observation.features.contains_key("presence"));
        assert!(!event.observation.features.contains_key("breathing_band"));
    }

    #[test]
    fn calibration_receipt_hashes_real_baseline_data() {
        let mut adapter = simulated_adapter();
        let receipt = adapter.calibrate("living_room").expect("calibrate");
        assert_eq!(receipt.modality, "ultrasonic");
        assert_eq!(receipt.zone_id, "living_room");
        assert!(receipt.data_hash.starts_with("sha256:"));
        assert!(receipt.calibration_id.starts_with("ultrasonic_cal_"));
        assert_eq!(adapter.baseline().expect("baseline").pings, 4);
        // The receipt id reaches the tensor, so a consumer can tell which
        // calibration a number was produced under.
        let events = adapter.collect_events().expect("events");
        assert_eq!(
            events[0].tensor.calibration_id.as_deref(),
            Some(receipt.calibration_id.as_str())
        );
    }

    #[test]
    fn replay_is_byte_identical() {
        let mut a = simulated_adapter();
        let mut b = simulated_adapter();
        let first = serde_json::to_string(&a.collect_events().unwrap()).unwrap();
        let second = serde_json::to_string(&b.collect_events().unwrap()).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn rejects_an_oversized_line_before_parsing_it() {
        let big = format!(
            r#"{{"timestamp":1.0,"source":"simulated","device_id":"d","beam":[0,1,0],"start_range_m":0.3,"range_step_m":0.007,"profile":[{}],"padding":"{}"}}"#,
            "0.1,".repeat(10).trim_end_matches(','),
            "A".repeat(MAX_LINE_BYTES)
        );
        let error = UltrasonicReplayAdapter::from_jsonl(&big).expect_err("must reject");
        assert!(matches!(error, UltrasonicError::LineTooLong { .. }));
    }

    #[test]
    fn rejects_a_profile_longer_than_the_bin_cap() {
        let profile = vec!["0.001"; MAX_PROFILE_BINS + 1].join(",");
        let text = format!(
            r#"{{"timestamp":1.0,"source":"simulated","device_id":"d","beam":[0,1,0],"start_range_m":0.3,"range_step_m":0.00714,"profile":[{profile}]}}"#
        );
        // The bin cap has to fire on its own here: 4097 compact values is
        // ~25 KB, comfortably inside the line-length cap, so a parser relying
        // on byte length alone would sail straight past it.
        assert!(text.len() < MAX_LINE_BYTES);
        let error = UltrasonicReplayAdapter::from_jsonl(&text).expect_err("must reject");
        assert!(matches!(error, UltrasonicError::Invalid { .. }));
    }

    #[test]
    fn rejects_non_finite_and_negative_values() {
        for bad in [
            r#""profile":[0.1,null,0.2]"#,
            r#""profile":[0.1,-0.5]"#,
            r#""noise_floor":-1.0"#,
            r#""blast_amplitude":-0.1"#,
            r#""range_step_m":0.0"#,
            r#""start_range_m":-1.0"#,
        ] {
            let text = format!(
                r#"{{"timestamp":1.0,"source":"simulated","device_id":"d","beam":[0,1,0],"start_range_m":0.3,"range_step_m":0.00714,"profile":[0.1,0.2],{bad}}}"#
            );
            assert!(
                UltrasonicReplayAdapter::from_jsonl(&text).is_err(),
                "accepted a record it should have refused: {bad}"
            );
        }
    }

    #[test]
    fn rejects_a_detection_outside_the_profile_it_came_from() {
        let text = r#"{"timestamp":1.0,"source":"simulated","device_id":"d","beam":[0,1,0],"start_range_m":0.3,"range_step_m":0.00714,"profile":[0.1,0.2],"detections":[{"range_m":9.0,"snr_db":20.0,"width_m":0.1}]}"#;
        let error = UltrasonicReplayAdapter::from_jsonl(text).expect_err("must reject");
        assert!(matches!(error, UltrasonicError::Invalid { .. }));
    }

    #[test]
    fn rejects_a_zero_length_beam() {
        let text = r#"{"timestamp":1.0,"source":"simulated","device_id":"d","beam":[0,0,0],"start_range_m":0.3,"range_step_m":0.00714,"profile":[0.1]}"#;
        let error = UltrasonicReplayAdapter::from_jsonl(text).expect_err("must reject");
        assert!(matches!(error, UltrasonicError::Invalid { .. }));
    }

    #[test]
    fn rejects_non_monotonic_time_so_the_replay_watermark_cannot_be_walked_backwards() {
        let text = format!(
            "{}\n{}",
            line(2.0, "simulated", 0.31),
            line(1.0, "simulated", 0.31)
        );
        let error = UltrasonicReplayAdapter::from_jsonl(&text).expect_err("must reject");
        assert!(matches!(error, UltrasonicError::NonMonotonic { .. }));

        // A repeated timestamp is the same attack with one fewer step.
        let text = format!(
            "{}\n{}",
            line(2.0, "simulated", 0.31),
            line(2.0, "simulated", 0.31)
        );
        assert!(matches!(
            UltrasonicReplayAdapter::from_jsonl(&text).expect_err("must reject"),
            UltrasonicError::NonMonotonic { .. }
        ));
    }

    #[test]
    fn rejects_a_recording_that_changes_sensor_identity_midway() {
        let a = line(1.0, "simulated", 0.31);
        let b = line(2.0, "simulated", 0.31).replace("batvu_test_01", "batvu_test_02");
        let error =
            UltrasonicReplayAdapter::from_jsonl(&format!("{a}\n{b}")).expect_err("must reject");
        assert!(matches!(error, UltrasonicError::DeviceMismatch { .. }));
    }

    #[test]
    fn rejects_control_characters_in_an_identifier() {
        let text = line(1.0, "simulated", 0.31).replace("batvu_test_01", "batvu\\u0000evil");
        assert!(UltrasonicReplayAdapter::from_jsonl(&text).is_err());
    }

    #[test]
    fn rejects_an_empty_recording() {
        assert!(matches!(
            UltrasonicReplayAdapter::from_jsonl("").expect_err("must reject"),
            UltrasonicError::Empty
        ));
        assert!(matches!(
            UltrasonicReplayAdapter::from_jsonl("\n\n   \n").expect_err("must reject"),
            UltrasonicError::Empty
        ));
    }

    #[test]
    fn a_replayed_event_cannot_be_ingested_twice() {
        let mut adapter = simulated_adapter();
        let events = adapter.collect_events().expect("events");
        let mut verifier = TrustVerifier::simulation();
        verifier
            .verify_and_record_at(&events[0], events[0].timestamp_ns)
            .expect("first ingest");
        // The same event again is a duplicate; an older one walks the watermark
        // backwards. Both are refused by the trust verifier, and the adapter's
        // own monotonicity check means a recording cannot smuggle either in.
        assert!(verifier
            .verify_and_record_at(&events[0], events[0].timestamp_ns)
            .is_err());
    }

    #[test]
    fn beam_direction_survives_the_quaternion_round_trip() {
        for beam in [
            [0.0f32, 1.0, 0.0],
            [1.0, 0.0, 0.0],
            [0.0, 0.0, 1.0],
            [0.0, 0.0, -1.0],
            [0.577, 0.577, 0.577],
        ] {
            let norm = (beam[0] * beam[0] + beam[1] * beam[1] + beam[2] * beam[2]).sqrt();
            let unit = [beam[0] / norm, beam[1] / norm, beam[2] / norm];
            let q = minimal_rotation_z_to(unit);
            let rotated = rotate_z_axis_by(q);
            for axis in 0..3 {
                assert!(
                    (rotated[axis] - unit[axis]).abs() < 1e-5,
                    "beam {unit:?} came back as {rotated:?}"
                );
            }
        }
    }

    /// Apply quaternion `[x, y, z, w]` to the unit `+Z` vector.
    fn rotate_z_axis_by(q: [f32; 4]) -> [f32; 3] {
        let [x, y, z, w] = q;
        [
            2.0 * (x * z + w * y),
            2.0 * (y * z - w * x),
            1.0 - 2.0 * (x * x + y * y),
        ]
    }

    #[test]
    fn silence_is_a_measurement_not_a_failure() {
        let text = r#"{"timestamp":1.0,"source":"simulated","device_id":"d","beam":[0,1,0],"start_range_m":0.3,"range_step_m":0.00714,"profile":[0.001,0.001],"detections":[],"noise_floor":0.0004,"blast_amplitude":0.3}"#;
        let mut adapter = UltrasonicReplayAdapter::from_jsonl(text).expect("parse");
        let events = adapter.collect_events().expect("events");
        assert_eq!(events[0].observation.labels, vec!["clear_path".to_string()]);
        assert_eq!(events[0].observation.range_m, None);
        // A clear path is a mid-confidence statement about a direction, not a
        // zero-confidence non-answer.
        assert!(events[0].observation.confidence > 0.0);
    }
}
