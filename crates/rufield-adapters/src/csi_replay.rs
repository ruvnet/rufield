//! The `CsiReplayAdapter` — the first RuField adapter driven by **real captured
//! WiFi CSI** instead of the synthetic simulator (ADR-260 §17 MVP adapters).
//!
//! # What this is
//!
//! This adapter replays a recording of **real WiFi Channel State Information**
//! (per-subcarrier amplitude) captured from real hardware, in RuView's
//! `.csi.jsonl` format (one JSON object per line:
//! `{"timestamp": <seconds>, "subcarriers": [<amplitude>, ...]}`). Each frame is
//! turned into a [`FieldEvent`] carrying:
//!
//! * a real [`FieldTensor`] (`wifi_csi` modality, `[frequency]` axis) holding the
//!   real per-subcarrier amplitudes and the frame's real `timestamp_ns`,
//! * a real [`ProvenanceRef`] whose `raw_hash` is a genuine SHA-256 over the raw
//!   subcarrier bytes, signed with a deterministic replay key, and
//! * an [`Observation`] whose privacy class and labels are derived from a
//!   **physically-grounded CSI-variance motion/presence proxy** (see below).
//!
//! # Honesty (this is the prove-everything project — read this)
//!
//! 1. **Replay, not live hardware.** The signal is real, but it is read from a
//!    file, not streamed from a live radio. Live-hardware streaming is roadmap.
//! 2. **Unlabeled data ⇒ no validated accuracy.** The recordings carry no
//!    ground truth. The `motion` / `presence` output is a *standard CSI-variance
//!    motion heuristic* — it compares each frame's per-subcarrier amplitude
//!    against a calibrated empty-room baseline and thresholds the deviation. It
//!    is a **physically-grounded proxy, NOT a validated-accuracy classifier.**
//!    We make **no** pose or accuracy claims.
//! 3. **The win** is that RuField now ingests *real* WiFi CSI and produces fused
//!    events from it — a real step beyond the synthetic simulator — not an
//!    accuracy number.
//!
//! # Determinism
//!
//! Same file ⇒ byte-identical event stream. Timestamps come from the file; the
//! signing key is a fixed seed; there is no RNG and no wall-clock read.

use rufield_core::{
    AdapterCapabilities, CalibrationReceipt, CoreError, FieldAxis, FieldEvent, FieldTensor,
    Modality, Observation, PrivacyClass, ProvenanceRef, SensorDescriptor,
};
use rufield_provenance::{sha256_hex, Signer};
use serde::Deserialize;

/// Default deterministic 32-byte ed25519 signing seed for replay events.
///
/// Replay events carry a **real** signature so downstream verification works,
/// but the key identifies a *replay source* — the data is real, the source is a
/// file. This is the honest provenance posture: real `raw_hash`, replay signer.
pub const REPLAY_SIGNER_SEED: [u8; 32] = *b"rufield-csi-replay-signer-key-32";

/// Number of leading frames used to establish the empty-room baseline during
/// [`CsiReplayAdapter::calibrate`].
pub const DEFAULT_CALIBRATION_FRAMES: usize = 16;

/// Upper bound on subcarriers accepted per frame (defensive; real CSI is far
/// below this — ESP32 ≈ 52–64, 802.11ac ≈ 114, 802.11ax ≈ 256/484).
pub const MAX_SUBCARRIERS: usize = 2048;

/// Motion proxy: amplitude-deviation (vs baseline) at/above this normalized
/// level flags **motion** (and therefore presence) ⇒ privacy class P2.
///
/// This is a documented heuristic threshold on a CSI-variance proxy, **not** a
/// validated-accuracy operating point.
pub const MOTION_THRESHOLD: f32 = 0.15;

/// Presence proxy: a smaller deviation than [`MOTION_THRESHOLD`] still flags a
/// static **presence** (a body perturbs the field even when still) ⇒ P2.
pub const PRESENCE_THRESHOLD: f32 = 0.06;

/// One line of the `.csi.jsonl` recording. Extra fields present in some RuView
/// recordings (`rssi`, `noise_floor`, `features`, ...) are ignored so the
/// parser stays tolerant of the documented minimal schema.
#[derive(Debug, Clone, Deserialize)]
struct CsiFrameRecord {
    /// Capture time in **seconds** since the Unix epoch (fractional).
    timestamp: f64,
    /// Per-subcarrier amplitude (real f64 values).
    subcarriers: Vec<f64>,
}

/// Errors raised while parsing or replaying a `.csi.jsonl` recording.
#[derive(Debug, Clone, PartialEq)]
pub enum CsiReplayError {
    /// A line could not be parsed as a CSI frame record.
    Parse {
        /// 1-based line number in the source file.
        line: usize,
        /// Underlying serde message.
        message: String,
    },
    /// A frame had zero subcarriers or more than [`MAX_SUBCARRIERS`].
    BadSubcarrierCount {
        /// 1-based line number.
        line: usize,
        /// Observed subcarrier count.
        count: usize,
    },
    /// A frame's timestamp was negative or non-finite.
    BadTimestamp {
        /// 1-based line number.
        line: usize,
        /// Observed timestamp (seconds).
        seconds: f64,
    },
    /// Constructing the [`FieldTensor`] failed its structural invariant.
    Tensor(String),
    /// The recording contained no usable frames.
    Empty,
}

impl std::fmt::Display for CsiReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CsiReplayError::Parse { line, message } => {
                write!(f, "parse error on line {line}: {message}")
            }
            CsiReplayError::BadSubcarrierCount { line, count } => write!(
                f,
                "line {line}: bad subcarrier count {count} (expected 1..={MAX_SUBCARRIERS})"
            ),
            CsiReplayError::BadTimestamp { line, seconds } => {
                write!(f, "line {line}: bad timestamp {seconds} seconds")
            }
            CsiReplayError::Tensor(m) => write!(f, "tensor construction failed: {m}"),
            CsiReplayError::Empty => write!(f, "recording contained no usable CSI frames"),
        }
    }
}

impl std::error::Error for CsiReplayError {}

impl From<CoreError> for CsiReplayError {
    fn from(e: CoreError) -> Self {
        CsiReplayError::Tensor(e.to_string())
    }
}

/// A single parsed real CSI frame: real timestamp + real per-subcarrier
/// amplitudes.
#[derive(Debug, Clone, PartialEq)]
pub struct CsiFrame {
    /// Capture time in nanoseconds since the Unix epoch (from the file's
    /// `timestamp` seconds × 1e9).
    pub timestamp_ns: u64,
    /// Real per-subcarrier amplitude values.
    pub amplitudes: Vec<f32>,
}

/// Per-subcarrier empty-room baseline computed by [`CsiReplayAdapter::calibrate`]
/// via streaming Welford statistics over the first K frames.
#[derive(Debug, Clone, PartialEq)]
pub struct Baseline {
    /// Per-subcarrier mean amplitude over the calibration frames.
    pub mean: Vec<f32>,
    /// Per-subcarrier variance over the calibration frames.
    pub variance: Vec<f32>,
    /// Number of frames the baseline was computed from.
    pub frames: usize,
}

impl Baseline {
    /// Mean of the per-subcarrier means — the overall amplitude scale of the
    /// empty room, used to normalize the motion proxy.
    fn mean_scale(&self) -> f32 {
        if self.mean.is_empty() {
            return 1.0;
        }
        let sum: f32 = self.mean.iter().sum();
        let scale = sum / self.mean.len() as f32;
        if scale.abs() < f32::EPSILON {
            1.0
        } else {
            scale
        }
    }
}

/// Compute a per-subcarrier baseline (Welford) over the first `k` frames.
fn compute_baseline(frames: &[CsiFrame], k: usize) -> Baseline {
    let take = k.min(frames.len());
    let width = frames.first().map_or(0, |f| f.amplitudes.len());
    let mut mean = vec![0.0f32; width];
    let mut m2 = vec![0.0f32; width];
    let mut count = 0u32;

    for frame in frames.iter().take(take) {
        count += 1;
        for (i, &x) in frame.amplitudes.iter().enumerate().take(width) {
            let delta = x - mean[i];
            mean[i] += delta / count as f32;
            let delta2 = x - mean[i];
            m2[i] += delta * delta2;
        }
    }

    let variance = if count > 1 {
        m2.iter().map(|&v| v / (count - 1) as f32).collect()
    } else {
        vec![0.0f32; width]
    };

    Baseline {
        mean,
        variance,
        frames: take,
    }
}

/// The normalized motion proxy for a frame: the mean absolute deviation of the
/// frame's per-subcarrier amplitude from the calibrated baseline mean, divided
/// by the baseline's overall amplitude scale, clamped to `0.0..=1.0`.
///
/// This is the standard "CSI amplitude variance signals motion" heuristic. It is
/// **a physically-grounded proxy, not a validated-accuracy classifier.**
fn motion_proxy(frame: &CsiFrame, baseline: &Baseline) -> f32 {
    if baseline.mean.is_empty() {
        return 0.0;
    }
    let width = frame.amplitudes.len().min(baseline.mean.len());
    if width == 0 {
        return 0.0;
    }
    let mut acc = 0.0f32;
    for i in 0..width {
        acc += (frame.amplitudes[i] - baseline.mean[i]).abs();
    }
    let mad = acc / width as f32;
    (mad / baseline.mean_scale()).clamp(0.0, 1.0)
}

/// Adapter that replays real captured WiFi CSI frames from a `.csi.jsonl`
/// recording as [`FieldEvent`]s. See the module docs for the honesty posture.
pub struct CsiReplayAdapter {
    frames: Vec<CsiFrame>,
    baseline: Option<Baseline>,
    calibration_id: String,
    signer: Signer,
    device_id: String,
    cursor: usize,
}

impl CsiReplayAdapter {
    /// Parse a `.csi.jsonl` recording from text into a replay adapter.
    ///
    /// Empty and whitespace-only lines are skipped. Each remaining line must be
    /// a JSON object with a `timestamp` (seconds) and a non-empty `subcarriers`
    /// array of at most [`MAX_SUBCARRIERS`] values; extra fields are ignored.
    pub fn from_jsonl(text: &str) -> Result<Self, CsiReplayError> {
        Self::from_jsonl_with(text, "csi_replay_node_01", &REPLAY_SIGNER_SEED)
    }

    /// Parse a recording with an explicit device id and signing seed.
    pub fn from_jsonl_with(
        text: &str,
        device_id: &str,
        signer_seed: &[u8; 32],
    ) -> Result<Self, CsiReplayError> {
        let mut frames = Vec::new();
        // Index of the last non-empty line: a parse failure *there* is treated
        // as a trailing truncated record (partial write) and skipped, per the
        // `.csi.jsonl` "tolerate trailing lines" contract. A parse failure on
        // any interior line is a hard error.
        let lines: Vec<&str> = text.lines().collect();
        let last_nonempty = lines
            .iter()
            .rposition(|l| !l.trim().is_empty());

        for (idx, raw) in lines.iter().enumerate() {
            let line_no = idx + 1;
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let rec: CsiFrameRecord = match serde_json::from_str(trimmed) {
                Ok(rec) => rec,
                Err(e) => {
                    // Tolerate a truncated *trailing* record; error otherwise.
                    if Some(idx) == last_nonempty {
                        break;
                    }
                    return Err(CsiReplayError::Parse {
                        line: line_no,
                        message: e.to_string(),
                    });
                }
            };

            let n = rec.subcarriers.len();
            if n == 0 || n > MAX_SUBCARRIERS {
                return Err(CsiReplayError::BadSubcarrierCount {
                    line: line_no,
                    count: n,
                });
            }
            if !rec.timestamp.is_finite() || rec.timestamp < 0.0 {
                return Err(CsiReplayError::BadTimestamp {
                    line: line_no,
                    seconds: rec.timestamp,
                });
            }

            let timestamp_ns = (rec.timestamp * 1e9) as u64;
            let amplitudes: Vec<f32> = rec.subcarriers.iter().map(|&v| v as f32).collect();
            frames.push(CsiFrame {
                timestamp_ns,
                amplitudes,
            });
        }

        if frames.is_empty() {
            return Err(CsiReplayError::Empty);
        }

        Ok(CsiReplayAdapter {
            frames,
            baseline: None,
            calibration_id: "csi_replay_uncalibrated".to_string(),
            signer: Signer::from_seed(signer_seed),
            device_id: device_id.to_string(),
            cursor: 0,
        })
    }

    /// Number of parsed real CSI frames.
    #[must_use]
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// Read-only view of parsed frames.
    #[must_use]
    pub fn frames(&self) -> &[CsiFrame] {
        &self.frames
    }

    /// The current baseline, if [`calibrate`](Self::calibrate) has run.
    #[must_use]
    pub fn baseline(&self) -> Option<&Baseline> {
        self.baseline.as_ref()
    }

    /// Establish the empty-room baseline from the first
    /// [`DEFAULT_CALIBRATION_FRAMES`] frames (per-subcarrier Welford mean +
    /// variance) and return a [`CalibrationReceipt`].
    ///
    /// This does **not** require the room to actually be empty during those
    /// frames — it is a *documented baseline*, mirroring the calibration concept;
    /// it is the reference the motion proxy deviates from. Calibrating against
    /// occupied frames simply raises the baseline; the proxy then measures
    /// *change* relative to it.
    pub fn calibrate(&mut self, zone_id: &str) -> Result<CalibrationReceipt, CsiReplayError> {
        let baseline = compute_baseline(&self.frames, DEFAULT_CALIBRATION_FRAMES);
        if baseline.mean.is_empty() {
            return Err(CsiReplayError::Empty);
        }

        // Real hash over the baseline mean+variance bytes (deterministic).
        let mut bytes = Vec::with_capacity(baseline.mean.len() * 8);
        for &m in &baseline.mean {
            bytes.extend_from_slice(&m.to_le_bytes());
        }
        for &v in &baseline.variance {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        let data_hash = sha256_hex(&bytes);

        // Deterministic calibration id derived from the data hash (no clock).
        let short = &data_hash["sha256:".len().."sha256:".len() + 12];
        let calibration_id = format!("csi_replay_cal_{short}");

        // Timestamps come from the data, not the wall clock: created at the
        // first frame, "expires" a nominal window later (documented, not load-
        // bearing for the replay).
        let created_ns = self.frames.first().map_or(0, |f| f.timestamp_ns);
        let expires_ns = created_ns.saturating_add(3_600_000_000_000); // +1h nominal

        self.calibration_id = calibration_id.clone();
        self.baseline = Some(baseline);

        Ok(CalibrationReceipt {
            calibration_id,
            modality: "wifi_csi".to_string(),
            zone_id: zone_id.to_string(),
            task: "empty_room_baseline".to_string(),
            created_ns,
            expires_ns,
            data_hash,
        })
    }

    /// Build a [`FieldEvent`] for the frame at `idx`, signing it deterministically.
    fn build_event(&self, idx: usize) -> Result<FieldEvent, CsiReplayError> {
        let frame = &self.frames[idx];
        let n = frame.amplitudes.len();

        let tensor = FieldTensor::new(
            frame.timestamp_ns,
            Modality::WifiCsi,
            vec![FieldAxis::Frequency],
            vec![n],
            frame.amplitudes.clone(),
            // Confidence in the *measurement* (the frame is real CSI). This is a
            // signal-quality confidence, NOT an accuracy claim about any label.
            0.8,
            // Noise floor proxy from the baseline variance scale, if calibrated.
            self.baseline
                .as_ref()
                .map(|b| {
                    let mean_var =
                        b.variance.iter().sum::<f32>() / b.variance.len().max(1) as f32;
                    mean_var.sqrt()
                })
                .unwrap_or(0.0),
            Some(self.calibration_id.clone()),
            // The tensor holds raw-ish amplitude → P0 (rawest) per ADR-260 §10.
            PrivacyClass::P0,
        )?;

        // --- Physically-grounded CSI-variance motion/presence proxy ---
        let proxy = self
            .baseline
            .as_ref()
            .map_or(0.0, |b| motion_proxy(frame, b));

        let is_motion = proxy >= MOTION_THRESHOLD;
        let is_presence = proxy >= PRESENCE_THRESHOLD;

        // Map the single proxy onto the feature keys the fusion engine reads.
        // `presence` drives the `person_present` weighted-Bayes rule (wifi_csi
        // is one of its inputs); `motion_energy` and `breathing_band` are
        // populated from the same proxy so downstream rules have real evidence.
        // These are PROXY features, not validated detections.
        let presence_feat = proxy.clamp(0.0, 1.0);
        let motion_feat = if is_motion { proxy } else { 0.0 };

        // Observation privacy: motion/presence ⇒ P2 (occupancy/motion);
        // otherwise the event only carries a derived feature scalar ⇒ P1.
        let obs_privacy = if is_presence {
            PrivacyClass::P2
        } else {
            PrivacyClass::P1
        };

        let mut obs = Observation::occupancy(presence_feat, obs_privacy);
        obs.zone_id = Some("csi_replay_zone".into());
        obs.motion_vector = Some([motion_feat, 0.0, 0.0]);
        obs.velocity_mps = Some(motion_feat);
        obs.features.insert("presence".into(), presence_feat);
        obs.features.insert("motion_energy".into(), motion_feat);
        // Breathing band proxy is the residual sub-motion deviation (present but
        // below the motion threshold) — a documented proxy, not a vitals claim.
        obs.features.insert(
            "breathing_band".into(),
            if is_presence && !is_motion {
                (proxy / MOTION_THRESHOLD).clamp(0.0, 1.0)
            } else {
                0.0
            },
        );
        obs.features.insert("csi_variance_proxy".into(), proxy);
        // Labels are PROXY labels from the heuristic, NOT ground truth. The
        // recording is unlabeled; these document what the proxy flagged.
        if is_motion {
            obs.labels.push("motion_proxy".into());
        }
        if is_presence {
            obs.labels.push("presence_proxy".into());
        }

        // Real provenance: real SHA-256 over the raw subcarrier bytes; signed
        // with the replay key. Marked synthetic=false because the *data* is real
        // captured CSI — we rely on the real signature (not the synthetic escape
        // hatch) for §11 fusability.
        let raw_bytes: Vec<u8> = frame
            .amplitudes
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let provenance = ProvenanceRef {
            raw_hash: sha256_hex(&raw_bytes),
            firmware_hash: sha256_hex(b"rufield-csi-replay-source-v0.1"),
            model_id: "csi_variance_motion_proxy_v0_1".into(),
            calibration_id: self.calibration_id.clone(),
            synthetic: false,
            signature_hex: None,
            signer_pubkey_hex: None,
        };

        let event_id = format!("csi-replay-{}-{:06}", self.device_id, idx);

        let mut event = FieldEvent::new(
            event_id,
            frame.timestamp_ns,
            SensorDescriptor {
                modality: "wifi_csi".into(),
                vendor: "replay_wifi_csi".into(),
                device_id: self.device_id.clone(),
                placement: "replay".into(),
                clock_domain: "replay_file".into(),
            },
            tensor,
            obs,
            provenance,
        );

        // Real ed25519 signature over the real event (deterministic key).
        self.signer
            .sign_event(&mut event)
            .map_err(|e| CsiReplayError::Tensor(e.to_string()))?;

        Ok(event)
    }

    /// Reset the stream cursor to the first frame.
    pub fn reset(&mut self) {
        self.cursor = 0;
    }

    /// Collect the entire stream as a `Vec<FieldEvent>` (does not consume the
    /// adapter; resets the cursor afterward). Useful for tests / batch replay.
    pub fn collect_events(&mut self) -> Result<Vec<FieldEvent>, CsiReplayError> {
        let mut out = Vec::with_capacity(self.frames.len());
        for idx in 0..self.frames.len() {
            out.push(self.build_event(idx)?);
        }
        Ok(out)
    }
}

impl rufield_core::FieldAdapter for CsiReplayAdapter {
    type Error = CsiReplayError;

    fn modality(&self) -> Modality {
        Modality::WifiCsi
    }

    fn capabilities(&self) -> AdapterCapabilities {
        // Approximate sample rate from the median inter-frame interval in the
        // recording (deterministic; falls back to 10 Hz if undeterminable).
        let rate = self.estimated_rate_hz().unwrap_or(10);
        AdapterCapabilities {
            modality: "wifi_csi".into(),
            sample_rate_hz: rate,
            can_calibrate: true,
            max_privacy_class: PrivacyClass::P2,
        }
    }

    fn next_event(&mut self) -> Result<Option<FieldEvent>, Self::Error> {
        if self.cursor >= self.frames.len() {
            return Ok(None);
        }
        let idx = self.cursor;
        self.cursor += 1;
        Ok(Some(self.build_event(idx)?))
    }
}

impl CsiReplayAdapter {
    /// Estimate the sample rate (Hz) from the mean inter-frame interval.
    fn estimated_rate_hz(&self) -> Option<u32> {
        if self.frames.len() < 2 {
            return None;
        }
        let first = self.frames.first()?.timestamp_ns;
        let last = self.frames.last()?.timestamp_ns;
        let span_ns = last.saturating_sub(first);
        if span_ns == 0 {
            return None;
        }
        let intervals = (self.frames.len() - 1) as u64;
        let mean_ns = span_ns / intervals;
        if mean_ns == 0 {
            return None;
        }
        Some((1_000_000_000 / mean_ns) as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rufield_core::FieldAdapter;
    use rufield_provenance::{is_fusable, verify_event};

    const SMALL: &str = include_str!("../tests/fixtures/real_csi_small.jsonl");

    #[test]
    fn parses_small_fixture_into_three_frames() {
        let adapter = CsiReplayAdapter::from_jsonl(SMALL).unwrap();
        assert_eq!(adapter.frame_count(), 3);
        // 56 real subcarriers per frame in the fixture.
        assert_eq!(adapter.frames()[0].amplitudes.len(), 56);
    }

    #[test]
    fn timestamps_are_real_and_monotonic() {
        let adapter = CsiReplayAdapter::from_jsonl(SMALL).unwrap();
        let ts: Vec<u64> = adapter.frames().iter().map(|f| f.timestamp_ns).collect();
        assert!(ts[0] > 0);
        assert!(ts[1] > ts[0]);
        assert!(ts[2] > ts[1]);
    }

    #[test]
    fn events_are_wifi_csi_signed_and_verify() {
        let mut adapter = CsiReplayAdapter::from_jsonl(SMALL).unwrap();
        adapter.calibrate("test_zone").unwrap();
        assert_eq!(adapter.modality(), Modality::WifiCsi);
        let mut count = 0;
        while let Some(ev) = adapter.next_event().unwrap() {
            assert_eq!(ev.tensor.modality, Modality::WifiCsi);
            assert!(ev.provenance.signature_hex.is_some());
            assert!(verify_event(&ev).is_ok());
            assert!(is_fusable(&ev)); // real signature, not synthetic escape hatch
            assert!(!ev.provenance.synthetic);
            ev.tensor.validate().unwrap();
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[test]
    fn privacy_class_is_set_on_every_observation() {
        let mut adapter = CsiReplayAdapter::from_jsonl(SMALL).unwrap();
        adapter.calibrate("test_zone").unwrap();
        for ev in adapter.collect_events().unwrap() {
            let p = ev.observation.privacy_class;
            assert!(p == PrivacyClass::P1 || p == PrivacyClass::P2);
        }
    }

    #[test]
    fn calibration_receipt_is_real_and_deterministic() {
        let mut a = CsiReplayAdapter::from_jsonl(SMALL).unwrap();
        let mut b = CsiReplayAdapter::from_jsonl(SMALL).unwrap();
        let ra = a.calibrate("zone").unwrap();
        let rb = b.calibrate("zone").unwrap();
        assert_eq!(ra, rb);
        assert!(ra.data_hash.starts_with("sha256:"));
        assert_eq!(ra.task, "empty_room_baseline");
        assert!(a.baseline().is_some());
    }

    #[test]
    fn parsing_tolerates_blank_lines() {
        let text = format!("\n{}\n\n", SMALL.trim());
        let adapter = CsiReplayAdapter::from_jsonl(&text).unwrap();
        assert_eq!(adapter.frame_count(), 3);
    }

    #[test]
    fn rejects_empty_recording() {
        match CsiReplayAdapter::from_jsonl("\n\n  \n") {
            Err(CsiReplayError::Empty) => {}
            other => panic!("expected Empty, got {:?}", other.map(|_| "adapter")),
        }
    }

    #[test]
    fn rejects_malformed_interior_line() {
        // A malformed line that is NOT the trailing line is a hard error.
        let valid = SMALL.lines().next().unwrap();
        let text = format!("{valid}\n{{not json}}\n{valid}");
        match CsiReplayAdapter::from_jsonl(&text) {
            Err(CsiReplayError::Parse { line: 2, .. }) => {}
            other => panic!("expected Parse on line 2, got {:?}", other.map(|_| "adapter")),
        }
    }

    #[test]
    fn tolerates_truncated_trailing_record() {
        // A partial final line (mid-array, no closing bracket) is skipped — this
        // mirrors the real medium fixture's truncated 200th line.
        let truncated = r#"{"timestamp":1.0,"subcarriers":[0.0,3.0,4.1"#;
        let text = format!("{}\n{truncated}", SMALL.trim());
        let adapter = CsiReplayAdapter::from_jsonl(&text).unwrap();
        assert_eq!(adapter.frame_count(), 3, "3 complete frames, trailing partial dropped");
    }

    #[test]
    fn deterministic_event_stream_across_runs() {
        let mut a = CsiReplayAdapter::from_jsonl(SMALL).unwrap();
        let mut b = CsiReplayAdapter::from_jsonl(SMALL).unwrap();
        a.calibrate("z").unwrap();
        b.calibrate("z").unwrap();
        assert_eq!(a.collect_events().unwrap(), b.collect_events().unwrap());
    }
}
