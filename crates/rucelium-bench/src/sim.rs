//! Deterministic 64-node biome simulator (ADR-264 §14, **SYNTHETIC**).
//!
//! Generates the chronological emission stream of a synthetic biome: genuine
//! signed spore-node envelopes (diurnal signal models per modality), plus the
//! adversarial stream the acceptance test requires — tampered envelopes,
//! exact replays, and forged-key packets — and the operational scenario:
//! a drifting sensor, a compromised (later revoked) device, a 7-day offline
//! window, and a flood-style anomaly.
//!
//! Same seed ⇒ byte-identical emission stream. No wall clocks, no OS entropy.

use rucelium_abi::{NodeSigner, RvEnvSampleV1, RV_ENV_FLAG_RETRANSMIT, RV_ENV_SCHEMA_V1};
use rucelium_core::{GeoPoint, SensorModality};

/// SplitMix64 — tiny deterministic PRNG (same generator the RuField synthetic
/// simulator uses).
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Seed the generator.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        SplitMix64 { state: seed }
    }

    /// Next raw `u64`.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform `f64` in `[0, 1)`.
    pub fn next_f64(&mut self) -> f64 {
        let bits = self.next_u64() >> 11; // 53 bits
        (bits as f64) / (1u64 << 53) as f64
    }

    /// Uniform integer in `[0, n)` (n > 0).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    /// Approximately normal noise (sum of 4 uniforms, centred), scaled by `sd`.
    pub fn noise(&mut self, sd: f64) -> f64 {
        let s = self.next_f64() + self.next_f64() + self.next_f64() + self.next_f64();
        (s - 2.0) * sd
    }
}

/// Nanoseconds per second / day.
pub const NS_PER_S: u64 = 1_000_000_000;
/// Seconds per simulated day.
pub const S_PER_DAY: u64 = 86_400;

/// Base device id for simulated spore nodes (`"MY"` prefix in the high bytes).
pub const NODE_ID_BASE: u64 = 0x4D59_0000_0000_0000;

/// Simulation configuration (ADR-264 §14 acceptance scenario).
#[derive(Debug, Clone, PartialEq)]
pub struct SimConfig {
    /// PRNG seed (determinism anchor).
    pub seed: u64,
    /// Number of spore nodes (acceptance: 64).
    pub nodes: u32,
    /// Simulated duration in days (acceptance: 30).
    pub days: u32,
    /// Per-node reporting interval, seconds (LoRaWAN-class cadence).
    pub sample_interval_s: u32,
    /// First day (0-based) of the uplink outage.
    pub offline_start_day: u32,
    /// Consecutive offline days (acceptance: 7).
    pub offline_days: u32,
    /// Node index that drifts.
    pub drift_node: u32,
    /// Day drift begins.
    pub drift_start_day: u32,
    /// Drift added per day, in the node's unit.
    pub drift_per_day: f64,
    /// Node index that is compromised and later revoked.
    pub compromised_node: u32,
    /// Day the compromised node is revoked.
    pub revoke_day: u32,
    /// Day of the water-surge anomaly.
    pub anomaly_day: u32,
    /// Tampered-envelope attacks injected per day.
    pub tamper_per_day: u32,
    /// Exact-replay attacks injected per day.
    pub replay_per_day: u32,
    /// Forged-key attacks injected per day.
    pub forge_per_day: u32,
}

/// Default seed (matches the repo convention of year-seeds).
pub const DEFAULT_SEED: u64 = 2026;

impl Default for SimConfig {
    fn default() -> Self {
        SimConfig {
            seed: DEFAULT_SEED,
            nodes: 64,
            days: 30,
            sample_interval_s: 1800, // 30-minute cadence
            offline_start_day: 10,
            offline_days: 7,
            drift_node: 2, // SoilMoisture — low-noise, so drift is attributable
            drift_start_day: 5,
            drift_per_day: 0.9,
            compromised_node: 13,
            revoke_day: 20,
            anomaly_day: 25,
            tamper_per_day: 4,
            replay_per_day: 4,
            forge_per_day: 2,
        }
    }
}

/// Simulated epoch start (fixed, arbitrary): 2025-06-15T00:00:00Z-ish.
pub const EPOCH_START_NS: u64 = 1_750_000_000 * NS_PER_S;

/// Provisioning seed for genuine device keys.
pub const PROVISION_SEED: &[u8; 32] = b"rucelium-biome-provision-v0.1!!!";
/// Seed the ATTACKER uses for forged-key packets (never registered).
pub const ATTACKER_SEED: &[u8; 32] = b"attacker-controlled-forged-key!!";

/// What a single emission on the "radio" is, from the gateway's perspective
/// unknown — the sim keeps ground truth for scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmissionKind {
    /// A genuine, correctly signed sample from a registered node.
    Genuine,
    /// A genuine envelope with one byte flipped in transit (tamper).
    Tampered,
    /// An exact byte-for-byte replay of a previously sent genuine envelope.
    Replayed,
    /// A well-formed envelope signed by an attacker key claiming a
    /// registered node id.
    ForgedKey,
    /// A genuine envelope from the compromised node sent AFTER its key was
    /// revoked (must be rejected by the registry).
    PostRevocation,
}

/// One on-air emission, with sim ground truth attached for scoring only —
/// the gateway pipeline never reads `kind` / `true_anomaly`.
#[derive(Debug, Clone)]
pub struct Emission {
    /// CBOR-encoded `SignedEnvRecordV1` bytes as they arrive at the gateway.
    pub envelope: Vec<u8>,
    /// Ground truth: what this emission actually is.
    pub kind: EmissionKind,
    /// Ground truth: emitting node index (attacker emissions reference the
    /// node they imitate).
    pub node_index: u32,
    /// Gateway reception time, ns.
    pub received_ns: u64,
    /// Simulated day (0-based).
    pub day: u32,
    /// Ground truth: this sample carries the anomaly surge.
    pub true_anomaly: bool,
    /// Whether the uplink to the biome/federation is down when this arrives.
    pub uplink_down: bool,
}

/// Per-node static description, shared with the gateway-side registry setup.
#[derive(Debug, Clone)]
pub struct NodeSpec {
    /// Device id.
    pub node_id: u64,
    /// Modality (physical modalities only — RF context is gateway-side).
    pub modality: SensorModality,
    /// Deployed location.
    pub geo: GeoPoint,
    /// Public key registered at provisioning.
    pub pubkey: [u8; 32],
    /// `sha256:` firmware hash registered at provisioning.
    pub firmware_hash: String,
}

/// The nine physical modalities, round-robin across nodes (WifiCsi is the
/// gateway-side RF context modality, not a spore node).
const PHYSICAL_MODALITIES: [SensorModality; 9] = [
    SensorModality::Weather,
    SensorModality::AirQuality,
    SensorModality::SoilMoisture,
    SensorModality::WaterQuality,
    SensorModality::Acoustic,
    SensorModality::Bioelectric,
    SensorModality::Radiation,
    SensorModality::Optical,
    SensorModality::Chemical,
];

/// Signal model: baseline, diurnal amplitude, noise sd per modality.
fn signal_model(m: SensorModality) -> (f64, f64, f64) {
    match m {
        SensorModality::Weather => (15.0, 8.0, 0.4),
        SensorModality::AirQuality => (12.0, 5.0, 0.8),
        SensorModality::SoilMoisture => (27.0, 2.0, 0.3),
        SensorModality::WaterQuality => (1.2, 0.15, 0.02),
        SensorModality::Acoustic => (0.5, 0.3, 0.05),
        SensorModality::Bioelectric => (40.0, 10.0, 1.5),
        SensorModality::Radiation => (0.10, 0.02, 0.005),
        SensorModality::Optical => (500.0, 480.0, 20.0),
        SensorModality::Chemical => (5.0, 1.0, 0.15),
        SensorModality::WifiCsi => (0.0, 0.0, 0.0),
    }
}

/// The full simulated biome: node specs + the chronological emission stream.
pub struct BiomeSim {
    /// Node descriptions (registry provisioning input).
    pub nodes: Vec<NodeSpec>,
    /// Chronological emissions.
    pub emissions: Vec<Emission>,
    /// Ground truth: number of genuine anomaly samples emitted.
    pub true_anomaly_samples: u32,
    /// Config used.
    pub config: SimConfig,
}

/// Noise standard deviation of a modality's signal model — the scale the
/// gateway uses to normalize anchor residuals before drift detection (so one
/// threshold works across modalities with very different units).
#[must_use]
pub fn noise_sd(modality: SensorModality) -> f64 {
    signal_model(modality).2
}

/// Expected (drift-free) value of a node's signal at time `t_s` — what a
/// co-located reference anchor would read. Used by the gateway's drift
/// detector as the anchor residual baseline.
#[must_use]
pub fn anchor_expectation(modality: SensorModality, node_index: u32, t_s: u64) -> f64 {
    let (base, amp, _sd) = signal_model(modality);
    let phase = f64::from(node_index % 9) * 0.7;
    let frac = (t_s % S_PER_DAY) as f64 / S_PER_DAY as f64;
    base + amp * (core::f64::consts::TAU * frac + phase).sin()
}

impl BiomeSim {
    /// Build the deterministic biome simulation.
    #[must_use]
    pub fn generate(config: SimConfig) -> Self {
        let mut rng = SplitMix64::new(config.seed);
        let mut nodes = Vec::with_capacity(config.nodes as usize);
        let mut signers = Vec::with_capacity(config.nodes as usize);

        // Provision nodes on a grid around a fixed centre (a synthetic
        // watershed at ~51.5N, 0.0E), one modality per node round-robin.
        for i in 0..config.nodes {
            let node_id = NODE_ID_BASE + u64::from(i);
            let modality = PHYSICAL_MODALITIES[(i as usize) % PHYSICAL_MODALITIES.len()];
            let signer = NodeSigner::for_node(PROVISION_SEED, node_id);
            let geo = GeoPoint {
                latitude_e7: 515_000_000 + i32::try_from(i / 8).unwrap_or(0) * 9_000,
                longitude_e7: -1_000_000 + i32::try_from(i % 8).unwrap_or(0) * 14_000,
                altitude_mm: 25_000,
            };
            nodes.push(NodeSpec {
                node_id,
                modality,
                geo,
                pubkey: signer.public_key(),
                firmware_hash: format!("sha256:spore-fw-1.4.2-{}", modality.as_str()),
            });
            signers.push(signer);
        }
        let attacker = NodeSigner::from_seed(ATTACKER_SEED);

        let ticks_per_day = (S_PER_DAY / u64::from(config.sample_interval_s)) as u32;
        let offline_end_day = config.offline_start_day + config.offline_days;
        let mut sequences = vec![0u32; config.nodes as usize];
        let mut sent_genuine: Vec<Vec<u8>> = Vec::new();
        let mut emissions = Vec::new();
        let mut true_anomaly_samples = 0u32;

        for day in 0..config.days {
            let uplink_down = day >= config.offline_start_day && day < offline_end_day;
            for tick in 0..ticks_per_day {
                let t_s = u64::from(day) * S_PER_DAY
                    + u64::from(tick) * u64::from(config.sample_interval_s);
                for (idx, spec) in nodes.iter().enumerate() {
                    let i = idx as u32;
                    let (base, amp, sd) = signal_model(spec.modality);
                    let phase = f64::from(i % 9) * 0.7;
                    let frac = (t_s % S_PER_DAY) as f64 / S_PER_DAY as f64;
                    let mut value =
                        base + amp * (core::f64::consts::TAU * frac + phase).sin() + rng.noise(sd);

                    // Drift injection: a slow additive bias on one node.
                    if i == config.drift_node && day >= config.drift_start_day {
                        let drift_days = f64::from(day - config.drift_start_day)
                            + f64::from(tick) / f64::from(ticks_per_day);
                        value += config.drift_per_day * drift_days;
                    }

                    // Anomaly: water-surge on all WaterQuality nodes during
                    // the anomaly day's second half (ramp to +2.0 m).
                    let mut is_anomaly = false;
                    if spec.modality == SensorModality::WaterQuality
                        && day == config.anomaly_day
                        && tick >= ticks_per_day / 2
                    {
                        let ramp =
                            f64::from(tick - ticks_per_day / 2) / f64::from(ticks_per_day / 2);
                        value += 2.0 * ramp.min(1.0) + 0.5;
                        is_anomaly = true;
                    }

                    let seq = sequences[idx];
                    sequences[idx] = seq.wrapping_add(1);
                    let measured_ns = EPOCH_START_NS + t_s * NS_PER_S;
                    let wire = RvEnvSampleV1 {
                        schema_version: RV_ENV_SCHEMA_V1,
                        sensor_type: spec.modality.code(),
                        flags: if uplink_down {
                            RV_ENV_FLAG_RETRANSMIT
                        } else {
                            0
                        },
                        node_id: spec.node_id,
                        timestamp_ns: measured_ns,
                        sequence: seq,
                        latitude_e7: spec.geo.latitude_e7,
                        longitude_e7: spec.geo.longitude_e7,
                        altitude_mm: spec.geo.altitude_mm,
                        value_q16: (value * 65_536.0)
                            .clamp(f64::from(i32::MIN), f64::from(i32::MAX))
                            as i32,
                        quality_q15: 0x7C00 + (rng.below(0x400) as u16), // 0.97..1.0
                        battery_mv: 3_650_u16.saturating_sub((t_s / 40_000) as u16),
                        calibration_id: 1000 + i,
                    };
                    let envelope = signers[idx].sign_sample(&wire).encode();
                    let received_ns = measured_ns + 120_000_000; // 120 ms uplink
                    let kind = if i == config.compromised_node && day >= config.revoke_day {
                        EmissionKind::PostRevocation
                    } else {
                        EmissionKind::Genuine
                    };
                    if kind == EmissionKind::Genuine {
                        if is_anomaly {
                            true_anomaly_samples += 1;
                        }
                        sent_genuine.push(envelope.clone());
                    }
                    emissions.push(Emission {
                        envelope,
                        kind,
                        node_index: i,
                        received_ns,
                        day,
                        true_anomaly: is_anomaly,
                        uplink_down,
                    });
                }
            }

            // Daily adversarial stream (arrives at end of day; ordering
            // within a day does not matter to the checks).
            let day_end_ns = EPOCH_START_NS + (u64::from(day) + 1) * S_PER_DAY * NS_PER_S;
            for a in 0..config.tamper_per_day {
                if sent_genuine.is_empty() {
                    break;
                }
                let pick = rng.below(sent_genuine.len() as u64) as usize;
                let mut env = sent_genuine[pick].clone();
                let flip = rng.below(env.len() as u64) as usize;
                env[flip] ^= 1 << (rng.below(8) as u8);
                emissions.push(Emission {
                    envelope: env,
                    kind: EmissionKind::Tampered,
                    node_index: config.nodes + a,
                    received_ns: day_end_ns + u64::from(a),
                    day,
                    true_anomaly: false,
                    uplink_down,
                });
            }
            for a in 0..config.replay_per_day {
                if sent_genuine.is_empty() {
                    break;
                }
                let pick = rng.below(sent_genuine.len() as u64) as usize;
                emissions.push(Emission {
                    envelope: sent_genuine[pick].clone(),
                    kind: EmissionKind::Replayed,
                    node_index: config.nodes + a,
                    received_ns: day_end_ns + 1_000 + u64::from(a),
                    day,
                    true_anomaly: false,
                    uplink_down,
                });
            }
            for a in 0..config.forge_per_day {
                // Attacker forges a plausible sample for a real node id with
                // their own (unregistered) key.
                let target = rng.below(u64::from(config.nodes)) as u32;
                let wire = RvEnvSampleV1 {
                    schema_version: RV_ENV_SCHEMA_V1,
                    sensor_type: nodes[target as usize].modality.code(),
                    flags: 0,
                    node_id: nodes[target as usize].node_id,
                    timestamp_ns: day_end_ns,
                    sequence: sequences[target as usize] + 100 + a, // fresh seq
                    latitude_e7: nodes[target as usize].geo.latitude_e7,
                    longitude_e7: nodes[target as usize].geo.longitude_e7,
                    altitude_mm: nodes[target as usize].geo.altitude_mm,
                    value_q16: 999 * 65_536, // absurd injected value
                    quality_q15: 0x8000,
                    battery_mv: 3_700,
                    calibration_id: 1000 + target,
                };
                emissions.push(Emission {
                    envelope: attacker.sign_sample(&wire).encode(),
                    kind: EmissionKind::ForgedKey,
                    node_index: target,
                    received_ns: day_end_ns + 2_000 + u64::from(a),
                    day,
                    true_anomaly: false,
                    uplink_down,
                });
            }
        }

        BiomeSim {
            nodes,
            emissions,
            true_anomaly_samples,
            config,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small() -> SimConfig {
        SimConfig {
            nodes: 8,
            days: 3,
            sample_interval_s: 7200,
            offline_start_day: 1,
            offline_days: 1,
            drift_node: 1,
            drift_start_day: 1,
            compromised_node: 2,
            revoke_day: 2,
            anomaly_day: 2,
            ..SimConfig::default()
        }
    }

    #[test]
    fn same_seed_identical_stream() {
        let a = BiomeSim::generate(small());
        let b = BiomeSim::generate(small());
        assert_eq!(a.emissions.len(), b.emissions.len());
        for (x, y) in a.emissions.iter().zip(&b.emissions) {
            assert_eq!(x.envelope, y.envelope);
            assert_eq!(x.kind, y.kind);
            assert_eq!(x.received_ns, y.received_ns);
        }
    }

    #[test]
    fn stream_contains_all_emission_kinds() {
        let sim = BiomeSim::generate(small());
        for kind in [
            EmissionKind::Genuine,
            EmissionKind::Tampered,
            EmissionKind::Replayed,
            EmissionKind::ForgedKey,
            EmissionKind::PostRevocation,
        ] {
            assert!(
                sim.emissions.iter().any(|e| e.kind == kind),
                "missing {kind:?}"
            );
        }
        assert!(sim.true_anomaly_samples > 0);
    }

    #[test]
    fn emissions_are_chronological_per_day() {
        let sim = BiomeSim::generate(small());
        let mut last_day = 0;
        for e in &sim.emissions {
            assert!(e.day >= last_day);
            last_day = e.day;
        }
    }

    #[test]
    fn offline_window_flagged() {
        let sim = BiomeSim::generate(small());
        assert!(sim.emissions.iter().any(|e| e.uplink_down));
        assert!(sim
            .emissions
            .iter()
            .all(|e| e.uplink_down == (e.day >= 1 && e.day < 2)));
    }
}
