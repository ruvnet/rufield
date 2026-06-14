//! The deterministic `SyntheticSim` adapter (ADR-260 §17 synthetic source,
//! §19 demo). Emits the full enter→sit→breathe→sleep→scratch→bed-exit→leave
//! sequence across 3 modalities (WiFi CSI, mmWave radar, thermal IR). Same seed
//! ⇒ identical event stream.

use crate::scenario::{demo_timeline, ticks, Phase};
use crate::signals::{generate, SignalFeatures};
use crate::rng::SplitMix64;
use rufield_core::{
    AdapterCapabilities, Destination, FieldAdapter, FieldEvent, Modality, Observation,
    PrivacyClass, ProvenanceRef, SensorDescriptor,
};
use rufield_provenance::{sha256_hex, Signer};

/// Tick interval in nanoseconds (10 Hz sampling — `100_000_000` ns).
pub const TICK_NS: u64 = 100_000_000;

/// Default PRNG seed for the demo (fixed for determinism).
pub const DEFAULT_SEED: u64 = 0x5246_4945_4C44; // "RFIELD" ascii-ish

/// Base timestamp the simulator starts from (fixed for determinism — NOT
/// `Date::now`). 2026-06-14T00:00:00Z in ns.
pub const BASE_TS_NS: u64 = 1_781_740_800_000_000_000;

/// A simulated event paired with its ground-truth phase + features, so the
/// benchmark can score produced inferences against known truth.
#[derive(Debug, Clone)]
pub struct SimEvent {
    /// The field event (signed, synthetic-flagged).
    pub event: FieldEvent,
    /// Ground-truth phase this event was drawn from.
    pub truth_phase: Phase,
    /// The summary features embedded for the fusion engine to read.
    pub features: SignalFeatures,
    /// The modality of this event.
    pub modality: Modality,
}

/// Configuration for the simulator.
#[derive(Debug, Clone)]
pub struct SimConfig {
    /// PRNG seed.
    pub seed: u64,
    /// 32-byte ed25519 signing seed (deterministic key).
    pub signer_seed: [u8; 32],
    /// Modalities to emit per tick (default: the 3 MVP modalities).
    pub modalities: Vec<Modality>,
}

impl Default for SimConfig {
    fn default() -> Self {
        SimConfig {
            seed: DEFAULT_SEED,
            signer_seed: *b"rufield-synthetic-sim-signer-32!",
            modalities: vec![
                Modality::WifiCsi,
                Modality::MmwaveRadar,
                Modality::InfraredThermal,
            ],
        }
    }
}

/// Never-failing adapter error (the simulator cannot fail at runtime).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimError {}

impl std::fmt::Display for SimError {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {}
    }
}
impl std::error::Error for SimError {}

/// The synthetic simulator. Implements [`FieldAdapter`] for one modality at a
/// time (call [`SyntheticSim::for_modality`]); use [`run_demo`] to get the full
/// interleaved multi-modality stream with ground truth.
pub struct SyntheticSim {
    modality: Modality,
    seed: u64,
    rng: SplitMix64,
    signer: Signer,
    phases: Vec<Phase>,
    cursor: usize,
}

impl SyntheticSim {
    /// Build a single-modality adapter over the demo timeline.
    #[must_use]
    pub fn for_modality(modality: Modality, seed: u64, signer_seed: &[u8; 32]) -> Self {
        let phases = ticks(&demo_timeline());
        // Per-modality RNG stream stays deterministic & independent by mixing
        // the modality code into the seed.
        let mixed = seed ^ (u64::from(modality.code()).wrapping_mul(0x9E37_79B9));
        SyntheticSim {
            modality,
            seed,
            rng: SplitMix64::new(mixed),
            signer: Signer::from_seed(signer_seed),
            phases,
            cursor: 0,
        }
    }

    fn build_event(&mut self, tick_idx: usize, phase: Phase) -> SimEvent {
        let (tensor, features, _privacy) =
            generate(self.modality, phase, tick_idx as u32, &mut self.rng);

        let timestamp_ns = BASE_TS_NS + (tick_idx as u64) * TICK_NS;
        let mut tensor = tensor;
        tensor.timestamp_ns = timestamp_ns;

        // Observation carries P2 (occupancy/motion) — derived, not raw.
        let mut obs = Observation::occupancy(tensor.confidence, PrivacyClass::P2);
        obs.zone_id = Some("room_01".into());
        obs.range_m = Some(features.range_m);
        obs.velocity_mps = Some(features.motion_energy * 1.5);
        obs.motion_vector = Some([features.motion_energy, 0.0, 0.0]);
        // Derived encoder features (P1) — what the fusion engine legitimately
        // reads. NOT the ground-truth labels.
        obs.features.insert("motion_energy".into(), features.motion_energy);
        obs.features.insert("breathing_band".into(), features.breathing_band);
        obs.features.insert("posture_height".into(), features.posture_height);
        obs.features.insert("transient".into(), features.transient);
        obs.features.insert("range_m".into(), features.range_m);
        obs.features.insert("presence".into(), features.presence);
        // Ground-truth labels — used ONLY by the benchmark to score against.
        obs.labels = phase.truth_labels().iter().map(|s| (*s).to_string()).collect();

        let event_id = format!(
            "{}-{}-{:05}",
            self.seed_tag(),
            modality_tag(self.modality),
            tick_idx
        );

        let raw_bytes: Vec<u8> = tensor
            .values
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let provenance = ProvenanceRef {
            raw_hash: sha256_hex(&raw_bytes),
            firmware_hash: sha256_hex(b"rufield-synthetic-firmware-v0.1"),
            model_id: "synthetic_field_encoder_v0_1".into(),
            calibration_id: "synthetic_room_cal_v1".into(),
            synthetic: true,
            signature_hex: None,
            signer_pubkey_hex: None,
        };

        let mut event = FieldEvent::new(
            event_id,
            timestamp_ns,
            SensorDescriptor {
                modality: modality_tag(self.modality).into(),
                vendor: synthetic_vendor(self.modality).into(),
                device_id: format!("sim_{}", modality_tag(self.modality)),
                placement: "ceiling_corner".into(),
                clock_domain: "sim_clock".into(),
            },
            tensor,
            obs,
            provenance,
        );

        // Sign deterministically (even synthetic events get a real signature so
        // verification still works; the synthetic flag is the §11 escape hatch).
        self.signer
            .sign_event(&mut event)
            .expect("synthetic event signs cleanly");

        SimEvent {
            event,
            truth_phase: phase,
            features,
            modality: self.modality,
        }
    }

    fn seed_tag(&self) -> String {
        format!("s{:x}", self.seed & 0xffff)
    }
}

impl FieldAdapter for SyntheticSim {
    type Error = SimError;

    fn modality(&self) -> Modality {
        self.modality
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            modality: modality_tag(self.modality).into(),
            sample_rate_hz: 10,
            can_calibrate: true,
            max_privacy_class: PrivacyClass::P2,
        }
    }

    fn next_event(&mut self) -> Result<Option<FieldEvent>, Self::Error> {
        if self.cursor >= self.phases.len() {
            return Ok(None);
        }
        let phase = self.phases[self.cursor];
        let idx = self.cursor;
        self.cursor += 1;
        Ok(Some(self.build_event(idx, phase).event))
    }
}

/// Run the full demo across all configured modalities, returning the
/// time-ordered interleaved stream **with ground truth** (for the benchmark).
///
/// Ordering is deterministic: for each tick, modalities are emitted in config
/// order. Same config ⇒ identical `Vec<SimEvent>`.
#[must_use]
pub fn run_demo(config: &SimConfig) -> Vec<SimEvent> {
    let phases = ticks(&demo_timeline());
    let mut sims: Vec<SyntheticSim> = config
        .modalities
        .iter()
        .map(|m| SyntheticSim::for_modality(*m, config.seed, &config.signer_seed))
        .collect();

    let mut out = Vec::with_capacity(phases.len() * config.modalities.len());
    for (tick_idx, &phase) in phases.iter().enumerate() {
        for sim in &mut sims {
            out.push(sim.build_event(tick_idx, phase));
        }
    }
    out
}

/// Default demo destination for default-transmitted events: the observations
/// are P2, so they target the network.
#[must_use]
pub fn default_destination() -> Destination {
    Destination::Network
}

fn modality_tag(m: Modality) -> &'static str {
    match m {
        Modality::WifiCsi => "wifi_csi",
        Modality::MmwaveRadar => "mmwave_radar",
        Modality::InfraredThermal => "infrared_thermal",
        _ => "synthetic_sim",
    }
}

fn synthetic_vendor(m: Modality) -> &'static str {
    match m {
        Modality::WifiCsi => "esp32_c6_sim",
        Modality::MmwaveRadar => "mr60bha2_sim",
        Modality::InfraredThermal => "ir_array_sim",
        _ => "sim",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rufield_provenance::{is_fusable, verify_event};

    fn cfg() -> SimConfig {
        SimConfig {
            seed: 42,
            ..SimConfig::default()
        }
    }

    #[test]
    fn demo_emits_three_modalities() {
        let evs = run_demo(&cfg());
        let mods: std::collections::HashSet<Modality> =
            evs.iter().map(|e| e.modality).collect();
        assert_eq!(mods.len(), 3);
        assert!(mods.contains(&Modality::WifiCsi));
        assert!(mods.contains(&Modality::MmwaveRadar));
        assert!(mods.contains(&Modality::InfraredThermal));
    }

    #[test]
    fn demo_is_deterministic() {
        let a = run_demo(&cfg());
        let b = run_demo(&cfg());
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.event, y.event);
        }
    }

    #[test]
    fn every_event_signed_and_fusable() {
        let evs = run_demo(&cfg());
        for se in &evs {
            assert!(se.event.provenance.signature_hex.is_some());
            assert!(verify_event(&se.event).is_ok());
            assert!(is_fusable(&se.event));
            assert_eq!(se.event.observation.privacy_class, PrivacyClass::P2);
        }
    }

    #[test]
    fn ground_truth_labels_present() {
        let evs = run_demo(&cfg());
        let has_breathing = evs
            .iter()
            .any(|e| e.event.observation.labels.iter().any(|l| l == "breathing"));
        let has_bed_exit = evs
            .iter()
            .any(|e| e.event.observation.labels.iter().any(|l| l == "bed_exit"));
        assert!(has_breathing);
        assert!(has_bed_exit);
    }

    #[test]
    fn single_modality_adapter_streams_then_ends() {
        let mut sim = SyntheticSim::for_modality(Modality::WifiCsi, 42, &cfg().signer_seed);
        let mut count = 0;
        while let Some(_ev) = sim.next_event().unwrap() {
            count += 1;
        }
        assert!(count > 0);
        assert_eq!(sim.next_event().unwrap(), None);
    }
}
