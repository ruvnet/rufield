//! # sentinel-forest — ADR-266 §4 track B1 (research track, NOT a product)
//!
//! Bioelectric electrodes on six trees, each paired with a conventional
//! soil-moisture reference sensor and a stand-level air-temperature sensor.
//!
//! The scenario demonstrates the three things ADR-266 §4.1 says must be true
//! before anyone is allowed to believe a plant-electrophysiology signal:
//!
//! 1. **Per-organism baselines.** Every tree's resting bioelectric potential
//!    is different. A single global threshold is provably unable to separate
//!    the stressed trees from the healthy ones — the scenario asserts it.
//! 2. **Confounder rejection.** A hot afternoon shifts *every* tree's
//!    potential. Without the temperature covariate all six trees "detect
//!    drought"; with the per-organism temperature slope learned during the
//!    baseline period, exactly the two genuinely droughted trees deviate.
//! 3. **Capped evidence.** The resulting event is bioelectric-only, so it is
//!    routed through [`bio_only_severity_cap`] and can never exceed
//!    [`Severity::Advisory`], and its WorldGraph evidence edges are capped at
//!    [`BIO_MAX_EVIDENCE_WEIGHT`]. The paired soil-moisture sensor may raise
//!    *confidence*; it does not let biology raise *severity* on its own.
//!
//! Run it:
//!
//! ```bash
//! cargo run -p rucelium-examples --bin sentinel-forest
//! ```
//!
//! **The sensor values are simulated. The verification, graph, and severity
//! machinery is the real production code.** Nothing here is evidence that
//! plant electrophysiology predicts drought.

use rucelium_core::event::evidence_digest;
use rucelium_core::{
    EnvSample, EnvironmentalEvent, EventKind, EvidenceRef, GeoPoint, SensorModality, Severity,
    SPEC_VERSION,
};
use rucelium_examples::{
    banner, line, synthetic_footer, Gateway, Node, Rng, EPOCH_NS, NS_PER_S, S_PER_DAY,
};
use rucelium_worldgraph::{EdgeKind, GraphNode, WorldGraph};

// ---------------------------------------------------------------------------
// The two normative rules this example exists to enforce
// ---------------------------------------------------------------------------

/// Hard cap on the weight of any biology-derived evidence edge in the
/// WorldGraph.
///
/// This mirrors `rucelium_worldgraph::RF_MAX_EVIDENCE_WEIGHT` (ADR-264 §8)
/// because ADR-266 §4.1 item 3 says biological modalities get *the same*
/// discipline as RF until the biological acceptance bar is met: they may
/// nudge confidence, they may never dominate physical sensing.
pub const BIO_MAX_EVIDENCE_WEIGHT: f32 = 0.3;

/// Clamp a severity to at most [`Severity::Advisory`].
///
/// **The ADR-266 §4.1 item 3 rule, enforced:** an event whose only evidence
/// is a biological transducer may never exceed `Advisory`. Exact same
/// semantics as `rucelium_worldgraph::rf_only_severity_cap`, applied to the
/// biological frontier. Every biology-only severity in this file is routed
/// through this function.
#[must_use]
pub fn bio_only_severity_cap(severity: Severity) -> Severity {
    severity.min(Severity::Advisory)
}

// ---------------------------------------------------------------------------
// Simulation geometry
// ---------------------------------------------------------------------------

/// Measurement slots per simulated day (4-hourly).
pub const SLOTS: usize = 6;
/// Days of undisturbed baseline learning before anything is injected.
pub const BASELINE_DAYS: u64 = 20;
/// The day the heatwave confounder arrives — all trees still healthy.
pub const CONFOUNDER_DAY: u64 = BASELINE_DAYS;
/// The day drought stress is evaluated (heatwave still present).
pub const DROUGHT_DAY: u64 = BASELINE_DAYS + 3;
/// Slot index of the hot afternoon reading used for every evaluation.
pub const AFTERNOON_SLOT: usize = 3;
/// Deviation (in baseline standard deviations) that counts as a detection.
pub const TRIGGER_Z: f64 = 4.0;
/// Air-temperature offset per slot, degrees Celsius (a fixed diurnal shape).
pub const DIURNAL_C: [f64; SLOTS] = [-2.5, -3.0, -0.5, 3.0, 2.0, -1.0];
/// Extra degrees Celsius the heatwave adds to afternoon slots.
pub const HEATWAVE_C: f64 = 12.0;

/// One instrumented tree: a bioelectric electrode plus its paired
/// conventional soil-moisture probe.
#[derive(Debug, Clone)]
pub struct Tree {
    /// Human-readable label (appears in the WorldGraph).
    pub label: &'static str,
    /// Resting bioelectric potential of *this organism*, millivolts.
    pub base_mv: f64,
    /// This organism's own bioelectric noise, millivolts.
    pub sd_mv: f64,
    /// This organism's true bioelectric response to temperature, mV/°C.
    pub temp_beta: f64,
    /// Healthy soil volumetric water content, percent.
    pub base_soil_pct: f64,
    /// Whether this tree is genuinely droughted during the stress window.
    pub droughted: bool,
}

/// The six trees of the stand. Note the two droughted trees are also the two
/// with the *least negative* resting potentials — which is exactly why a
/// global millivolt threshold cannot work.
#[must_use]
pub fn stand() -> Vec<Tree> {
    vec![
        Tree {
            label: "oak-north",
            base_mv: -84.0,
            sd_mv: 1.6,
            temp_beta: 0.9,
            base_soil_pct: 27.0,
            droughted: false,
        },
        Tree {
            label: "oak-south",
            base_mv: -131.0,
            sd_mv: 2.4,
            temp_beta: 1.4,
            base_soil_pct: 29.0,
            droughted: false,
        },
        Tree {
            label: "beech-ridge",
            base_mv: -57.0,
            sd_mv: 1.2,
            temp_beta: 0.6,
            base_soil_pct: 26.0,
            droughted: true,
        },
        Tree {
            label: "birch-hollow",
            base_mv: -102.0,
            sd_mv: 2.0,
            temp_beta: 1.1,
            base_soil_pct: 31.0,
            droughted: false,
        },
        Tree {
            label: "pine-east",
            base_mv: -118.0,
            sd_mv: 2.8,
            temp_beta: 1.7,
            base_soil_pct: 24.0,
            droughted: false,
        },
        Tree {
            label: "beech-west",
            base_mv: -66.0,
            sd_mv: 1.4,
            temp_beta: 0.8,
            base_soil_pct: 28.0,
            droughted: true,
        },
    ]
}

// ---------------------------------------------------------------------------
// Baseline statistics
// ---------------------------------------------------------------------------

/// Streaming mean/variance (Welford), the same shape the calibration crate
/// uses for residual tracking.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Welford {
    /// Number of samples seen.
    pub n: u64,
    /// Running mean.
    pub mean: f64,
    /// Running sum of squared deviations.
    pub m2: f64,
}

impl Welford {
    /// Fold one observation in.
    pub fn push(&mut self, x: f64) {
        self.n += 1;
        let d = x - self.mean;
        self.mean += d / self.n as f64;
        self.m2 += d * (x - self.mean);
    }

    /// Sample standard deviation (0 for fewer than two observations).
    #[must_use]
    pub fn sd(&self) -> f64 {
        if self.n < 2 {
            0.0
        } else {
            (self.m2 / (self.n - 1) as f64).sqrt()
        }
    }
}

/// A learned per-organism baseline: the tree's own resting statistics *and*
/// its own temperature response. ADR-266 §4.1 item 2 ("organism-specific
/// baselines") is this struct.
#[derive(Debug, Clone, PartialEq)]
pub struct Baseline {
    /// Tree label.
    pub label: String,
    /// Mean resting potential, mV.
    pub mean_mv: f64,
    /// Standard deviation of the raw potential, mV.
    pub sd_mv: f64,
    /// Learned temperature slope, mV/°C.
    pub slope_mv_per_c: f64,
    /// Mean baseline air temperature, °C.
    pub mean_temp_c: f64,
    /// Standard deviation of the *temperature-adjusted* residual, mV. This is
    /// the scale a real detection has to beat.
    pub resid_sd_mv: f64,
    /// Mean baseline soil moisture, percent (the conventional reference).
    pub mean_soil_pct: f64,
}

impl Baseline {
    /// Raw z-score, ignoring the temperature covariate (the naive detector).
    #[must_use]
    pub fn raw_z(&self, value_mv: f64) -> f64 {
        if self.sd_mv <= 0.0 {
            0.0
        } else {
            (value_mv - self.mean_mv) / self.sd_mv
        }
    }

    /// Temperature-adjusted z-score: the residual against this organism's own
    /// fitted temperature response, scaled by its own residual spread.
    #[must_use]
    pub fn adjusted_z(&self, value_mv: f64, temp_c: f64) -> f64 {
        if self.resid_sd_mv <= 0.0 {
            return 0.0;
        }
        let expected = self.mean_mv + self.slope_mv_per_c * (temp_c - self.mean_temp_c);
        (value_mv - expected) / self.resid_sd_mv
    }
}

/// One tree's verdict at one evaluation time.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    /// Tree label.
    pub label: String,
    /// Bioelectric node id.
    pub node_id: u64,
    /// Sequence number of the evaluated bioelectric sample.
    pub sequence: u32,
    /// Measured potential, mV.
    pub value_mv: f64,
    /// Naive z-score (no temperature covariate).
    pub raw_z: f64,
    /// Temperature-adjusted z-score.
    pub adj_z: f64,
    /// Paired conventional soil-moisture reading, percent.
    pub soil_pct: f64,
    /// Whether the naive detector fired.
    pub naive_fired: bool,
    /// Whether the covariate-adjusted detector fired.
    pub adjusted_fired: bool,
    /// Whether the paired conventional sensor corroborates drought.
    pub soil_corroborates: bool,
    /// The verified observation itself, retained so the event can bind the
    /// *content* of its evidence and not merely its identity (ADR-266 §3.1).
    pub sample: EnvSample,
}

/// Everything one deterministic run produces. `main` prints it; the tests
/// assert on it; two runs compare equal.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// Learned per-organism baselines, in stand order.
    pub baselines: Vec<Baseline>,
    /// Air temperature at the confounder evaluation, °C.
    pub confounder_temp_c: f64,
    /// Air temperature at the drought evaluation, °C.
    pub drought_temp_c: f64,
    /// Verdicts on the heatwave-only day (every tree is healthy).
    pub confounder_only: Vec<Verdict>,
    /// Verdicts on the drought day (heatwave still present).
    pub drought_day: Vec<Verdict>,
    /// The bioelectric-only event, if the adjusted detector fired.
    pub event: Option<EnvironmentalEvent>,
    /// Severity the detector *wanted* before the biological cap was applied.
    pub uncapped_severity: Severity,
    /// Confidence before conventional corroboration.
    pub confidence_bio_only: f32,
    /// Confidence after the paired soil probe agreed (severity unchanged).
    pub confidence_corroborated: f32,
    /// Total envelopes the real ingest pipeline verified.
    pub verified_samples: usize,
    /// WorldGraph JSON (deterministic; `BTreeMap`-ordered).
    pub graph_json: String,
    /// Largest evidence weight on any biology-derived edge.
    pub max_bio_edge_weight: f32,
}

// ---------------------------------------------------------------------------
// Deterministic environment model
// ---------------------------------------------------------------------------

/// Simulated measurement time for `(day, slot)`, derived from `EPOCH_NS` —
/// never a wall clock.
#[must_use]
pub fn slot_ns(day: u64, slot: usize) -> u64 {
    EPOCH_NS + (day * S_PER_DAY + slot as u64 * 4 * 3_600) * NS_PER_S
}

/// Air temperature at `(day, slot)`: a seasonal drift, a fixed diurnal shape,
/// deterministic noise, and — from [`CONFOUNDER_DAY`] onwards — an afternoon
/// heatwave. The heatwave is the confounder of ADR-266 §4.1 item 1.
#[must_use]
pub fn air_temp_c(day: u64, slot: usize, rng: &mut Rng) -> f64 {
    let seasonal = 2.0 * (day as f64 * 0.21).sin();
    let heat = if day >= CONFOUNDER_DAY && (slot == 3 || slot == 4) {
        HEATWAVE_C
    } else {
        0.0
    };
    14.0 + seasonal + DIURNAL_C[slot] + heat + rng.noise(0.4)
}

/// How far drought has progressed on `day`, `0.0..=1.0`. Zero on the
/// confounder day: on that day every tree is genuinely healthy.
#[must_use]
pub fn drought_progress(day: u64) -> f64 {
    if day <= CONFOUNDER_DAY {
        0.0
    } else {
        ((day - CONFOUNDER_DAY) as f64 / (DROUGHT_DAY - CONFOUNDER_DAY) as f64).min(1.0)
    }
}

/// Full drought depression of the bioelectric potential, millivolts.
pub const DROUGHT_DEPTH_MV: f64 = -18.0;
/// Full drought depletion of soil moisture, percentage points.
pub const DROUGHT_SOIL_DROP_PCT: f64 = -17.0;

// ---------------------------------------------------------------------------
// The scenario
// ---------------------------------------------------------------------------

/// Run the whole scenario deterministically and return its report.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run() -> Report {
    let trees = stand();
    let mut rng = Rng::new(0x005E_171E_E1F0_2E57);

    // --- provision: one bioelectric electrode + one soil probe per tree,
    // plus a single stand-level air-temperature reference. ---
    let mut nodes: Vec<Node> = Vec::new();
    for (i, t) in trees.iter().enumerate() {
        let lat = 514_100_000 + (i as i32) * 1_100;
        let geo = GeoPoint::new(lat, -3_120_000, 96_000).expect("valid stand coordinates");
        nodes.push(Node::new(
            0x00B1_0000_0000_0001 + i as u64,
            SensorModality::Bioelectric,
            geo,
            t.label,
        ));
    }
    for (i, t) in trees.iter().enumerate() {
        let lat = 514_100_000 + (i as i32) * 1_100;
        let geo = GeoPoint::new(lat, -3_120_000, 96_000).expect("valid stand coordinates");
        nodes.push(Node::new(
            0x00B1_0000_0000_0101 + i as u64,
            SensorModality::SoilMoisture,
            geo,
            t.label,
        ));
    }
    nodes.push(Node::new(
        0x00B1_0000_0000_0201,
        SensorModality::Weather,
        GeoPoint::new(514_103_000, -3_120_000, 100_000).expect("valid mast coordinates"),
        "stand mast",
    ));
    let n_trees = trees.len();
    let mut gw = Gateway::with_nodes(&nodes);

    // Baseline accumulators: raw statistics, an ordinary-least-squares fit of
    // potential on temperature, and the paired soil reference.
    let mut raw: Vec<Welford> = vec![Welford::default(); n_trees];
    let mut soil: Vec<Welford> = vec![Welford::default(); n_trees];
    let mut fit_pairs: Vec<Vec<(f64, f64)>> = vec![Vec::new(); n_trees];
    let mut verified = 0usize;

    let mut graph = WorldGraph::new();
    graph.add_node(
        "ecosystem/mixed-stand",
        GraphNode::Ecosystem {
            name: "Upland mixed stand".into(),
            kind: "forest_stand".into(),
            geo: GeoPoint::new(514_103_000, -3_120_000, 96_000).expect("valid stand centroid"),
        },
    );

    // --- 1. baseline learning: 12 undisturbed days ---
    for day in 0..BASELINE_DAYS {
        for slot in 0..SLOTS {
            let ns = slot_ns(day, slot);
            let temp = air_temp_c(day, slot, &mut rng);
            let env = nodes[2 * n_trees].emit(temp, ns, 1);
            gw.ingest(&env, ns + 1_000_000)
                .expect("mast sample verifies");
            verified += 1;
            for (i, t) in trees.iter().enumerate() {
                let mv = t.base_mv + t.temp_beta * (temp - 14.0) + rng.noise(t.sd_mv);
                let env = nodes[i].emit(mv, ns, 1);
                let s = gw
                    .ingest(&env, ns + 1_000_000)
                    .expect("bioelectric sample verifies");
                let v = s.sample().value;
                raw[i].push(v);
                fit_pairs[i].push((temp, v));
                graph.register_observation(s.sample());
                verified += 1;

                let pct = t.base_soil_pct + rng.noise(0.6);
                let env = nodes[n_trees + i].emit(pct, ns, 1);
                let s = gw
                    .ingest(&env, ns + 1_000_000)
                    .expect("soil sample verifies");
                soil[i].push(s.sample().value);
                graph.register_observation(s.sample());
                verified += 1;
            }
        }
    }

    // Fit each organism's own temperature response, then measure the spread
    // of the residual around it. Both are per-organism: nothing global.
    let mut baselines = Vec::with_capacity(n_trees);
    for (i, t) in trees.iter().enumerate() {
        let pairs = &fit_pairs[i];
        let n = pairs.len() as f64;
        let mt = pairs.iter().map(|p| p.0).sum::<f64>() / n;
        let mv = pairs.iter().map(|p| p.1).sum::<f64>() / n;
        let sxy: f64 = pairs.iter().map(|p| (p.0 - mt) * (p.1 - mv)).sum();
        let sxx: f64 = pairs.iter().map(|p| (p.0 - mt).powi(2)).sum();
        let slope = if sxx > 0.0 { sxy / sxx } else { 0.0 };
        let mut resid = Welford::default();
        for (tc, val) in pairs {
            resid.push(val - (mv + slope * (tc - mt)));
        }
        baselines.push(Baseline {
            label: t.label.to_string(),
            mean_mv: raw[i].mean,
            sd_mv: raw[i].sd(),
            slope_mv_per_c: slope,
            mean_temp_c: mt,
            resid_sd_mv: resid.sd(),
            mean_soil_pct: soil[i].mean,
        });
    }

    // --- 2. evaluate two days: heatwave-only, then heatwave + drought ---
    let mut confounder_temp_c = 0.0;
    let mut drought_temp_c = 0.0;
    let mut confounder_only = Vec::new();
    let mut drought_day = Vec::new();

    for day in CONFOUNDER_DAY..=DROUGHT_DAY {
        for slot in 0..SLOTS {
            let ns = slot_ns(day, slot);
            let temp = air_temp_c(day, slot, &mut rng);
            let env = nodes[2 * n_trees].emit(temp, ns, 1);
            gw.ingest(&env, ns + 1_000_000)
                .expect("mast sample verifies");
            verified += 1;
            let progress = drought_progress(day);
            let evaluating =
                slot == AFTERNOON_SLOT && (day == CONFOUNDER_DAY || day == DROUGHT_DAY);
            let mut row = Vec::new();
            for (i, t) in trees.iter().enumerate() {
                let stress = if t.droughted {
                    DROUGHT_DEPTH_MV * progress
                } else {
                    0.0
                };
                let mv = t.base_mv + t.temp_beta * (temp - 14.0) + stress + rng.noise(t.sd_mv);
                let env = nodes[i].emit(mv, ns, 1);
                let bio = gw
                    .ingest(&env, ns + 1_000_000)
                    .expect("bioelectric sample verifies");
                verified += 1;

                let soil_stress = if t.droughted {
                    DROUGHT_SOIL_DROP_PCT * progress
                } else {
                    0.0
                };
                let pct = t.base_soil_pct + soil_stress + rng.noise(0.6);
                let env = nodes[n_trees + i].emit(pct, ns, 1);
                let sm = gw
                    .ingest(&env, ns + 1_000_000)
                    .expect("soil sample verifies");
                verified += 1;

                if !evaluating {
                    continue;
                }
                let b = &baselines[i];
                let value_mv = bio.sample().value;
                let soil_pct = sm.sample().value;
                let raw_z = b.raw_z(value_mv);
                let adj_z = b.adjusted_z(value_mv, temp);
                row.push(Verdict {
                    label: t.label.to_string(),
                    node_id: bio.sample().node_id,
                    sequence: bio.sample().sequence,
                    value_mv,
                    raw_z,
                    adj_z,
                    soil_pct,
                    naive_fired: raw_z.abs() >= TRIGGER_Z,
                    adjusted_fired: adj_z.abs() >= TRIGGER_Z,
                    // The conventional reference's own rule, independent of
                    // any biology: soil moisture 8 points below its baseline.
                    soil_corroborates: soil_pct < b.mean_soil_pct - 8.0,
                    sample: bio.sample().clone(),
                });
            }
            if evaluating {
                if day == CONFOUNDER_DAY {
                    confounder_temp_c = temp;
                    confounder_only = row;
                } else {
                    drought_temp_c = temp;
                    drought_day = row;
                }
            }
        }
    }

    // --- 3. build the (capped) bioelectric-only event ---
    let fired: Vec<&Verdict> = drought_day.iter().filter(|v| v.adjusted_fired).collect();
    let uncapped_severity = if fired.len() >= 2 {
        Severity::Warning
    } else {
        Severity::Watch
    };
    let confidence_bio_only = 0.61_f32;
    let corroborated = fired.iter().all(|v| v.soil_corroborates) && !fired.is_empty();
    let confidence_corroborated = if corroborated {
        // Conventional agreement raises CONFIDENCE. It does not raise
        // severity — this event's severity rests on biology alone.
        (confidence_bio_only + 0.24).min(1.0)
    } else {
        confidence_bio_only
    };

    let event = if fired.is_empty() {
        None
    } else {
        Some(EnvironmentalEvent {
            evidence_digest: Some(evidence_digest(
                &fired.iter().map(|v| &v.sample).collect::<Vec<_>>(),
            )),
            spec_version: SPEC_VERSION.into(),
            event_id: "evt-b1-sentinel-forest-0001".into(),
            biome_id: "biome/upland-catchment".into(),
            kind: EventKind::Anomaly,
            // THE RULE: biology-only evidence, so the cap applies.
            severity: bio_only_severity_cap(uncapped_severity),
            modality: SensorModality::Bioelectric,
            geo: GeoPoint::new(514_103_000, -3_120_000, 96_000).expect("valid event centroid"),
            window_start_ns: slot_ns(CONFOUNDER_DAY, 0),
            window_end_ns: slot_ns(DROUGHT_DAY, AFTERNOON_SLOT),
            detected_ns: slot_ns(DROUGHT_DAY, AFTERNOON_SLOT),
            evidence: fired
                .iter()
                .map(|v| EvidenceRef {
                    node_id: v.node_id,
                    sequence: v.sequence,
                })
                .collect(),
            confidence: confidence_corroborated,
            message: format!(
                "{} tree(s) deviate from their own temperature-adjusted baseline",
                fired.len()
            ),
            signature_hex: None,
            signer_pubkey_hex: None,
        })
    };

    // --- 4. capped evidence edges into the WorldGraph ---
    let mut max_bio_edge_weight = 0.0_f32;
    for v in &fired {
        let key = format!("sensor/{}", v.node_id);
        // Even a z-score of -13 buys at most BIO_MAX_EVIDENCE_WEIGHT.
        let want = (v.adj_z.abs() / 20.0) as f32;
        let weight = want.min(BIO_MAX_EVIDENCE_WEIGHT);
        graph
            .add_edge(
                &key,
                "ecosystem/mixed-stand",
                EdgeKind::Supports,
                weight,
                format!(
                    "bioelectric drought deviation z={:.1} (capped evidence)",
                    v.adj_z
                ),
            )
            .expect("both endpoints registered");
        max_bio_edge_weight = max_bio_edge_weight.max(weight);
    }

    Report {
        baselines,
        confounder_temp_c,
        drought_temp_c,
        confounder_only,
        drought_day,
        event,
        uncapped_severity,
        confidence_bio_only,
        confidence_corroborated,
        verified_samples: verified,
        graph_json: graph.to_json(),
        max_bio_edge_weight,
    }
}

/// True when no single global millivolt threshold separates the droughted
/// trees from the healthy ones on the drought day.
///
/// A global "alarm below τ mV" rule works only if every droughted reading is
/// below every healthy reading. This returns `true` when that is impossible.
#[must_use]
pub fn no_global_threshold_works(trees: &[Tree], day: &[Verdict]) -> bool {
    let worst_stressed = day
        .iter()
        .zip(trees)
        .filter(|(_, t)| t.droughted)
        .map(|(v, _)| v.value_mv)
        .fold(f64::NEG_INFINITY, f64::max);
    let calmest_healthy = day
        .iter()
        .zip(trees)
        .filter(|(_, t)| !t.droughted)
        .map(|(v, _)| v.value_mv)
        .fold(f64::INFINITY, f64::min);
    worst_stressed >= calmest_healthy
}

/// Print the ADR-266 §4.1 acceptance bar and state plainly that this
/// scenario is not evidence toward it.
fn print_not_validated() {
    println!("\n  NOT VALIDATED");
    println!("  ADR-266 §4 track B1 is a RESEARCH TRACK, not a roadmap item and not a");
    println!("  product claim. The §4.1 item 3 acceptance bar is: one biological signal");
    println!("  predicts a CONFIRMED environmental condition >= 30 MINUTES EARLIER than the");
    println!("  conventional sensor, at > 90% PRECISION, across 3 INDEPENDENT LOCATIONS,");
    println!("  with NO PER-LOCATION RETRAINING. This scenario is one simulated stand with");
    println!("  synthetic data and a hand-written stress model; it demonstrates the");
    println!("  DISCIPLINE (per-organism baselines, paired conventional references,");
    println!("  confounder rejection, capped evidence) and constitutes NO evidence toward");
    println!("  any part of that bar. Until it passes, biological modalities enter the");
    println!("  WorldGraph with capped weight and can never alone exceed Advisory.");
}

fn main() {
    banner(
        "sentinel-forest — ADR-266 B1 living sentinel forest",
        "6 bioelectric electrodes + paired soil-moisture and air-temperature references",
    );
    let r = run();
    let trees = stand();

    println!("  1. PER-ORGANISM BASELINES (20 undisturbed days, 4-hourly)\n");
    println!(
        "  {:<14} {:>10} {:>8} {:>12} {:>12} {:>10}",
        "tree", "mean mV", "sd mV", "mV per °C", "resid sd", "soil %"
    );
    for b in &r.baselines {
        println!(
            "  {:<14} {:>10.1} {:>8.2} {:>12.2} {:>12.2} {:>10.1}",
            b.label, b.mean_mv, b.sd_mv, b.slope_mv_per_c, b.resid_sd_mv, b.mean_soil_pct
        );
    }
    let lo = r
        .baselines
        .iter()
        .map(|b| b.mean_mv)
        .fold(f64::INFINITY, f64::min);
    let hi = r
        .baselines
        .iter()
        .map(|b| b.mean_mv)
        .fold(f64::NEG_INFINITY, f64::max);
    line(
        "baseline mean spread across organisms",
        format!("{:.1} mV", hi - lo),
    );
    println!(
        "  -> no global threshold is defensible: the healthiest tree rests {:.0} mV",
        hi - lo
    );
    println!("     away from its neighbour before anything is wrong.");

    println!("\n  2. CONFOUNDER ONLY — hot afternoon, every tree healthy\n");
    line(
        "air temperature at evaluation",
        format!("{:.1} °C", r.confounder_temp_c),
    );
    println!(
        "  {:<14} {:>10} {:>9} {:>9} {:>9} {:>10}",
        "tree", "mV", "raw z", "adj z", "soil %", "verdict"
    );
    for v in &r.confounder_only {
        println!(
            "  {:<14} {:>10.1} {:>9.2} {:>9.2} {:>9.1} {:>10}",
            v.label,
            v.value_mv,
            v.raw_z,
            v.adj_z,
            v.soil_pct,
            if v.adjusted_fired { "FIRED" } else { "quiet" }
        );
    }
    let naive_fp = r.confounder_only.iter().filter(|v| v.naive_fired).count();
    let adj_fp = r
        .confounder_only
        .iter()
        .filter(|v| v.adjusted_fired)
        .count();
    line("naive detector false positives", format!("{naive_fp} of 6"));
    line("covariate-adjusted detections", format!("{adj_fp} of 6"));
    println!("  -> temperature alone mimics the signal of interest on EVERY tree.");
    println!("     ADR-266 §4.1 item 1 is not a footnote; it is the dominant failure mode.");

    println!("\n  3. DROUGHT DAY — heatwave still present, 2 trees genuinely stressed\n");
    line(
        "air temperature at evaluation",
        format!("{:.1} °C", r.drought_temp_c),
    );
    println!(
        "  {:<14} {:>10} {:>9} {:>9} {:>9} {:>10} {:>8}",
        "tree", "mV", "raw z", "adj z", "soil %", "verdict", "truth"
    );
    for (v, t) in r.drought_day.iter().zip(&trees) {
        println!(
            "  {:<14} {:>10.1} {:>9.2} {:>9.2} {:>9.1} {:>10} {:>8}",
            v.label,
            v.value_mv,
            v.raw_z,
            v.adj_z,
            v.soil_pct,
            if v.adjusted_fired { "FIRED" } else { "quiet" },
            if t.droughted { "drought" } else { "healthy" }
        );
    }
    line(
        "global-threshold rule provably impossible",
        no_global_threshold_works(&trees, &r.drought_day),
    );

    println!("\n  4. THE CAP — biology may inform, never alarm\n");
    if let Some(ev) = &r.event {
        ev.validate().expect("event is structurally valid");
        line(
            "detector wanted severity",
            format!("{:?}", r.uncapped_severity),
        );
        line(
            "bio_only_severity_cap() emitted",
            format!("{:?}", ev.severity),
        );
        line(
            "event kind / modality",
            format!("{:?} / {}", ev.kind, ev.modality.as_str()),
        );
        line("evidence observations", ev.evidence.len());
        line(
            "confidence, bioelectric only",
            format!("{:.2}", r.confidence_bio_only),
        );
        line(
            "confidence, soil probe agreeing",
            format!("{:.2}  (severity UNCHANGED)", r.confidence_corroborated),
        );
        line(
            "max biology evidence edge weight",
            format!("{:.2}", r.max_bio_edge_weight),
        );
        line(
            "hard cap on that weight",
            format!("{BIO_MAX_EVIDENCE_WEIGHT:.2}"),
        );
        println!("  -> the conventional soil probe raised CONFIDENCE. It did not, and could");
        println!("     not, raise SEVERITY: this event's evidence is bioelectric.");
    }
    line("envelopes cryptographically verified", r.verified_samples);
    line("WorldGraph JSON bytes (deterministic)", r.graph_json.len());

    print_not_validated();
    synthetic_footer("Nothing here is evidence that trees predict drought.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baselines_differ_per_organism_so_no_global_threshold_exists() {
        let r = run();
        let trees = stand();
        assert_eq!(r.baselines.len(), 6);
        // Every organism's resting potential is materially different.
        for i in 0..r.baselines.len() {
            for j in (i + 1)..r.baselines.len() {
                assert!(
                    (r.baselines[i].mean_mv - r.baselines[j].mean_mv).abs() > 5.0,
                    "{} and {} have indistinguishable baselines",
                    r.baselines[i].label,
                    r.baselines[j].label
                );
            }
        }
        // And the learned temperature slopes are per-organism too.
        for (b, t) in r.baselines.iter().zip(&trees) {
            assert!(
                (b.slope_mv_per_c - t.temp_beta).abs() < 0.4,
                "{} slope {:.2} should recover {:.2}",
                b.label,
                b.slope_mv_per_c,
                t.temp_beta
            );
        }
        // No single global millivolt threshold can separate stressed from
        // healthy on the drought day.
        assert!(no_global_threshold_works(&trees, &r.drought_day));
    }

    #[test]
    fn drought_detected_on_exactly_the_two_stressed_trees() {
        let r = run();
        let trees = stand();
        let fired: Vec<&str> = r
            .drought_day
            .iter()
            .filter(|v| v.adjusted_fired)
            .map(|v| v.label.as_str())
            .collect();
        assert_eq!(fired, vec!["beech-ridge", "beech-west"]);
        for (v, t) in r.drought_day.iter().zip(&trees) {
            assert_eq!(
                v.adjusted_fired, t.droughted,
                "{} misclassified (adj z {:.2})",
                v.label, v.adj_z
            );
            // The paired conventional reference agrees with the truth too.
            assert_eq!(v.soil_corroborates, t.droughted, "{} soil probe", v.label);
        }
    }

    #[test]
    fn confounder_alone_produces_zero_events_but_fools_the_naive_detector() {
        let r = run();
        // Naive detector: every single healthy tree "detects drought".
        assert_eq!(
            r.confounder_only.iter().filter(|v| v.naive_fired).count(),
            6,
            "the heatwave must be a genuine confounder for all six trees"
        );
        // Covariate-adjusted detector: nothing fires, no event exists.
        assert_eq!(
            r.confounder_only
                .iter()
                .filter(|v| v.adjusted_fired)
                .count(),
            0
        );
        for v in &r.confounder_only {
            assert!(!v.soil_corroborates, "{} soil should look normal", v.label);
        }
    }

    #[test]
    fn bioelectric_only_evidence_is_capped_at_advisory() {
        // The cap function itself, over the whole ladder.
        assert_eq!(
            bio_only_severity_cap(Severity::Critical),
            Severity::Advisory
        );
        assert_eq!(bio_only_severity_cap(Severity::Warning), Severity::Advisory);
        assert_eq!(bio_only_severity_cap(Severity::Watch), Severity::Advisory);
        assert_eq!(
            bio_only_severity_cap(Severity::Advisory),
            Severity::Advisory
        );

        let r = run();
        let ev = r.event.as_ref().expect("drought event was raised");
        ev.validate().expect("valid event");
        assert_eq!(r.uncapped_severity, Severity::Warning);
        assert_eq!(ev.severity, Severity::Advisory);
        // The event binds the CONTENT of its evidence, not just its identity.
        let digest = ev.evidence_digest.as_ref().expect("content-bound");
        assert!(digest.starts_with("sha256:"));
        assert_eq!(ev.modality, SensorModality::Bioelectric);
        // Corroboration moved confidence, never severity.
        assert!(r.confidence_corroborated > r.confidence_bio_only);
        assert_eq!(bio_only_severity_cap(ev.severity), ev.severity);
        // Evidence weight in the graph is capped like RF evidence.
        assert!(r.max_bio_edge_weight <= BIO_MAX_EVIDENCE_WEIGHT);
        assert!(r.max_bio_edge_weight > 0.0);
    }

    #[test]
    fn scenario_is_fully_deterministic() {
        let a = run();
        let b = run();
        assert_eq!(a, b);
        assert!(a.verified_samples > 1_000);
    }
}
