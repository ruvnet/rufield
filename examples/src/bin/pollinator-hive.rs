//! # pollinator-hive — ADR-266 §4 track B4 (research track, NOT a product)
//!
//! Three honeybee colonies as biome nodes. Each hive emits an acoustic
//! activity index, an internal-temperature and internal-humidity reference
//! (conventional `Weather` sensors), and a colony electric-field reading
//! (`Bioelectric`); a hive weight series is derived locally from the same
//! observation window.
//!
//! Four things happen over sixty simulated days:
//!
//! 1. **A swarming precursor** builds on one hive: the acoustic index climbs
//!    for five days while daily weight gain stalls. Only that hive fires.
//! 2. **A single hive collapses.** One colony failing is a beekeeping
//!    problem, not a regional signal — so it is routed through
//!    [`bio_only_severity_cap`] and stays `Advisory`, however dramatic.
//! 3. **A cold snap** chills a healthy hive. Its activity index craters. The
//!    paired internal-temperature reference explains it, and nothing alarms —
//!    ADR-266 §4.1 item 1, the dominant failure mode, in one day.
//! 4. **A correlated multi-hive collapse.** All three colonies crash within
//!    the same window with normal internal temperatures. *That* is spatial
//!    replication plus a conventional exclusion, and only that escalates.
//!
//! ```bash
//! cargo run -p rucelium-examples --bin pollinator-hive
//! ```

use rucelium_core::event::evidence_digest;
use rucelium_core::{
    DataClass, EnvSample, EnvironmentalEvent, EventKind, EvidenceRef, GeoPoint, SensorModality,
    Severity, SPEC_VERSION,
};
use rucelium_examples::{
    banner, line, synthetic_footer, Gateway, Node, Rng, EPOCH_NS, NS_PER_S, S_PER_DAY,
};

// ---------------------------------------------------------------------------
// The normative rule
// ---------------------------------------------------------------------------

/// Hard cap on the weight of a colony-derived evidence edge, mirroring
/// `rucelium_worldgraph::RF_MAX_EVIDENCE_WEIGHT` (ADR-264 §8) as ADR-266
/// §4.1 item 3 requires of every biological modality.
pub const BIO_MAX_EVIDENCE_WEIGHT: f32 = 0.3;

/// Clamp a severity to at most [`Severity::Advisory`].
///
/// **The ADR-266 §4.1 item 3 rule, enforced.** A single colony is one
/// organism. Colonies die of queen failure, varroa, starvation, robbing and
/// bad luck; one hive's collapse is never evidence of a landscape-scale
/// exposure, so on its own it can only ever be `Advisory`.
#[must_use]
pub fn bio_only_severity_cap(severity: Severity) -> Severity {
    severity.min(Severity::Advisory)
}

// ---------------------------------------------------------------------------
// Apiary model
// ---------------------------------------------------------------------------

/// Observations per simulated day (6-hourly).
pub const SLOTS: usize = 4;
/// Days of undisturbed baseline before anything is injected.
pub const BASELINE_DAYS: usize = 20;
/// Total simulated days.
pub const TOTAL_DAYS: usize = 60;
/// Day on which the swarming precursor is evaluated.
pub const SWARM_EVAL_DAY: usize = 25;
/// Day on which the single-hive collapse is evaluated.
pub const SOLO_COLLAPSE_DAY: usize = 30;
/// Day on which the cold-snap confounder is evaluated.
pub const COLD_SNAP_DAY: usize = 38;
/// Day on which the correlated multi-hive collapse is evaluated.
pub const APIARY_COLLAPSE_DAY: usize = 45;
/// Acoustic drop (in baseline standard deviations) that counts as a collapse.
pub const COLLAPSE_ACOUSTIC_Z: f64 = -4.0;
/// Electric-field drop (in baseline standard deviations) that must agree.
pub const COLLAPSE_FIELD_Z: f64 = -3.0;
/// Internal-temperature deviation, °C, beyond which the *conventional*
/// reference explains the activity drop thermally and the biological detector
/// must stand down.
pub const THERMAL_EXPLAIN_C: f64 = 2.0;
/// Acoustic index rise, per day over five days, that counts as a swarming
/// precursor.
pub const SWARM_SLOPE: f64 = 1.5;
/// Fraction of baseline daily weight gain below which the gain has "stalled".
pub const SWARM_GAIN_FRACTION: f64 = 0.25;

/// One instrumented colony.
#[derive(Debug, Clone)]
pub struct Hive {
    /// Human-readable label.
    pub label: &'static str,
    /// This colony's own resting acoustic activity index.
    pub base_acoustic: f64,
    /// This colony's own acoustic noise.
    pub sd_acoustic: f64,
    /// This colony's own resting electric field, mV/m.
    pub base_field: f64,
    /// This colony's own field noise, mV/m.
    pub sd_field: f64,
    /// This colony's brood-nest set point, °C.
    pub base_temp: f64,
    /// This colony's starting weight, kg.
    pub base_weight: f64,
    /// Whether this colony builds a swarming precursor.
    pub swarms: bool,
    /// Whether this colony has the isolated (single-hive) collapse.
    pub solo_collapse: bool,
    /// Whether this colony gets the cold snap.
    pub cold_snap: bool,
}

/// The three colonies of the apiary.
#[must_use]
pub fn apiary() -> Vec<Hive> {
    vec![
        Hive {
            label: "H1 orchard-east",
            base_acoustic: 62.0,
            sd_acoustic: 2.4,
            base_field: 121.0,
            sd_field: 4.1,
            base_temp: 34.7,
            base_weight: 41.5,
            swarms: true,
            solo_collapse: false,
            cold_snap: false,
        },
        Hive {
            label: "H2 hedgerow",
            base_acoustic: 48.0,
            sd_acoustic: 1.9,
            base_field: 96.0,
            sd_field: 3.4,
            base_temp: 34.9,
            base_weight: 38.2,
            swarms: false,
            solo_collapse: true,
            cold_snap: false,
        },
        Hive {
            label: "H3 heath-margin",
            base_acoustic: 71.0,
            sd_acoustic: 3.1,
            base_field: 139.0,
            sd_field: 4.8,
            base_temp: 34.4,
            base_weight: 44.9,
            swarms: false,
            solo_collapse: false,
            cold_snap: true,
        },
    ]
}

/// Acoustic-index perturbation for `hive` on `day` (the biological signal).
#[must_use]
pub fn acoustic_effect(h: &Hive, day: usize) -> f64 {
    let mut e = 0.0;
    if h.swarms && (21..=26).contains(&day) {
        // Pre-swarm piping and queen-cell activity: a steady climb.
        e += (day - 20) as f64 * 3.0;
    }
    if h.swarms && day >= 27 {
        // The prime swarm has left: a permanently smaller colony.
        e -= 11.0;
    }
    if h.solo_collapse && (SOLO_COLLAPSE_DAY..SOLO_COLLAPSE_DAY + 4).contains(&day) {
        e -= 34.0;
    }
    if h.cold_snap && (COLD_SNAP_DAY - 1..COLD_SNAP_DAY + 3).contains(&day) {
        // Not a colony problem: a cold cluster simply flies less.
        e -= 22.0;
    }
    if (APIARY_COLLAPSE_DAY..APIARY_COLLAPSE_DAY + 4).contains(&day) {
        e -= 38.0;
    }
    e
}

/// Electric-field perturbation for `hive` on `day`, mV/m.
#[must_use]
pub fn field_effect(h: &Hive, day: usize) -> f64 {
    let mut e = 0.0;
    if h.swarms && (21..=26).contains(&day) {
        e += (day - 20) as f64 * 1.4;
    }
    if h.solo_collapse && (SOLO_COLLAPSE_DAY..SOLO_COLLAPSE_DAY + 4).contains(&day) {
        e -= 41.0;
    }
    if h.cold_snap && (COLD_SNAP_DAY - 1..COLD_SNAP_DAY + 3).contains(&day) {
        // A cold cluster is quieter but still very much alive: the field
        // barely moves. This is what separates "cold" from "poisoned".
        e -= 1.5;
    }
    if (APIARY_COLLAPSE_DAY..APIARY_COLLAPSE_DAY + 4).contains(&day) {
        e -= 44.0;
    }
    e
}

/// Internal-temperature perturbation for `hive` on `day`, °C. Only the cold
/// snap moves it — and it is a *conventional* sensor, so this is the
/// covariate that licenses the biological detector to stand down.
#[must_use]
pub fn temp_effect(h: &Hive, day: usize) -> f64 {
    if h.cold_snap && (COLD_SNAP_DAY - 1..COLD_SNAP_DAY + 3).contains(&day) {
        -6.4
    } else {
        0.0
    }
}

/// Daily weight gain for `hive` on `day`, kg — the derived series.
#[must_use]
pub fn weight_gain_kg(h: &Hive, day: usize) -> f64 {
    if h.swarms && day == 27 {
        // The swarm departs with roughly 1.9 kg of bees.
        return -1.9;
    }
    if h.swarms && (21..=26).contains(&day) {
        // The precursor signature: the colony stops storing.
        return 0.04;
    }
    let flow = (10..=40).contains(&day);
    let base = if flow { 0.85 } else { 0.18 };
    if (APIARY_COLLAPSE_DAY..APIARY_COLLAPSE_DAY + 4).contains(&day)
        || (h.solo_collapse && (SOLO_COLLAPSE_DAY..SOLO_COLLAPSE_DAY + 4).contains(&day))
    {
        return base * 0.1;
    }
    if h.cold_snap && (COLD_SNAP_DAY - 1..COLD_SNAP_DAY + 3).contains(&day) {
        return base * 0.3;
    }
    base
}

// ---------------------------------------------------------------------------
// Detection state
// ---------------------------------------------------------------------------

/// One colony's learned baseline.
#[derive(Debug, Clone, PartialEq)]
pub struct HiveBaseline {
    /// Hive label.
    pub label: String,
    /// Mean daily acoustic index.
    pub mean_acoustic: f64,
    /// Standard deviation of the daily acoustic index.
    pub sd_acoustic: f64,
    /// Mean colony electric field, mV/m.
    pub mean_field: f64,
    /// Standard deviation of the field, mV/m.
    pub sd_field: f64,
    /// Mean internal temperature, °C.
    pub mean_temp: f64,
    /// Mean daily weight gain, kg.
    pub mean_gain_kg: f64,
}

/// One colony's daily aggregate.
#[derive(Debug, Clone, PartialEq)]
pub struct HiveDay {
    /// Hive label.
    pub label: String,
    /// Simulated day index.
    pub day: usize,
    /// Acoustic node id.
    pub node_id: u64,
    /// Sequence number of the last acoustic sample of the day.
    pub sequence: u32,
    /// Daily mean acoustic activity index.
    pub acoustic: f64,
    /// Daily mean colony electric field, mV/m.
    pub field: f64,
    /// Daily mean internal temperature, °C.
    pub temp: f64,
    /// Daily mean internal relative humidity, percent.
    pub humidity: f64,
    /// Hive weight at end of day, kg (derived series).
    pub weight_kg: f64,
    /// Weight gained today, kg.
    pub gain_kg: f64,
    /// The last verified acoustic observation of the day, retained so events
    /// can bind the *content* of their evidence (ADR-266 §3.1).
    pub sample: EnvSample,
}

/// A per-hive verdict on one evaluated day.
#[derive(Debug, Clone, PartialEq)]
pub struct HiveVerdict {
    /// Hive label.
    pub label: String,
    /// Acoustic z-score against this colony's own baseline.
    pub acoustic_z: f64,
    /// Field z-score against this colony's own baseline.
    pub field_z: f64,
    /// Internal-temperature deviation from this colony's set point, °C.
    pub temp_dev_c: f64,
    /// Five-day acoustic slope, index per day.
    pub acoustic_slope: f64,
    /// Daily weight gain, kg.
    pub gain_kg: f64,
    /// Whether the naive detector (acoustic only) would have alarmed.
    pub naive_alarm: bool,
    /// Whether the conventional temperature reference explains the drop.
    pub thermally_explained: bool,
    /// Whether a genuine activity collapse was detected.
    pub collapse: bool,
    /// Whether a swarming precursor was detected.
    pub swarm_precursor: bool,
    /// Acoustic node id (evidence).
    pub node_id: u64,
    /// Sequence of the evidence sample.
    pub sequence: u32,
    /// The verified observation itself (content-binding evidence).
    pub sample: EnvSample,
}

/// A whole-apiary assessment on one evaluated day.
#[derive(Debug, Clone, PartialEq)]
pub struct Assessment {
    /// Narrative label.
    pub moment: String,
    /// Simulated day.
    pub day: usize,
    /// Per-hive verdicts.
    pub hives: Vec<HiveVerdict>,
    /// Hives collapsing within this window.
    pub correlated_hives: usize,
    /// Severity the evidence would justify before the biological cap.
    pub uncapped: Severity,
    /// Severity actually emitted.
    pub severity: Severity,
    /// Whether the evidence was biology alone (a single colony).
    pub bio_only: bool,
    /// Event raised, if any.
    pub event: Option<EnvironmentalEvent>,
}

/// Everything one deterministic run produces.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// Per-colony learned baselines.
    pub baselines: Vec<HiveBaseline>,
    /// Swarming-precursor assessment.
    pub swarm: Assessment,
    /// Single-hive collapse assessment.
    pub solo: Assessment,
    /// Cold-snap confounder assessment.
    pub cold: Assessment,
    /// Correlated multi-hive collapse assessment.
    pub apiary_wide: Assessment,
    /// Residency class of the derived weight series.
    pub weight_series_class: DataClass,
    /// Envelopes the real ingest pipeline verified.
    pub verified_samples: usize,
    /// Final hive weights, kg.
    pub final_weights: Vec<f64>,
}

/// Severity for `n` colonies collapsing inside one window.
///
/// * 1 colony — biology alone, so [`bio_only_severity_cap`] holds it at
///   `Advisory`. One hive failing is a beekeeping problem.
/// * 2 colonies — spatially replicated, thermally excluded: `Warning`.
/// * 3 or more — `Critical`.
#[must_use]
pub fn collapse_severity(n: usize) -> (Severity, Severity, bool) {
    match n {
        0 => (Severity::Advisory, Severity::Advisory, false),
        1 => {
            let wanted = Severity::Warning;
            (wanted, bio_only_severity_cap(wanted), true)
        }
        2 => (Severity::Warning, Severity::Warning, false),
        _ => (Severity::Critical, Severity::Critical, false),
    }
}

/// Simulated measurement time for `(day, slot)`, derived from `EPOCH_NS`.
#[must_use]
pub fn slot_ns(day: usize, slot: usize) -> u64 {
    EPOCH_NS + (day as u64 * S_PER_DAY + slot as u64 * 6 * 3_600) * NS_PER_S
}

// ---------------------------------------------------------------------------
// The scenario
// ---------------------------------------------------------------------------

/// Run the whole scenario deterministically.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run() -> Report {
    let hives = apiary();
    let n = hives.len();
    let mut rng = Rng::new(0x00B4_BEE5_1A5E_C7E1);

    let mut nodes: Vec<Node> = Vec::new();
    // Layout: [acoustic ×3][field ×3][temp ×3][humidity ×3].
    for (kind, base_id, modality) in [
        (
            "acoustic",
            0x00B4_0000_0000_0001_u64,
            SensorModality::Acoustic,
        ),
        ("field", 0x00B4_0000_0000_0101, SensorModality::Bioelectric),
        ("temp", 0x00B4_0000_0000_0201, SensorModality::Weather),
        ("humidity", 0x00B4_0000_0000_0301, SensorModality::Weather),
    ] {
        for (i, h) in hives.iter().enumerate() {
            let geo = GeoPoint::new(508_812_000 + (i as i32) * 900, 4_411_000, 62_000)
                .expect("valid apiary coordinates");
            nodes.push(Node::new(
                base_id + i as u64,
                modality,
                geo,
                &format!("{} {kind}", h.label),
            ));
        }
    }
    let mut gw = Gateway::with_nodes(&nodes);

    // Daily aggregation.
    let mut days: Vec<Vec<HiveDay>> = Vec::with_capacity(TOTAL_DAYS);
    let mut weights: Vec<f64> = hives.iter().map(|h| h.base_weight).collect();
    let mut verified = 0usize;

    for day in 0..TOTAL_DAYS {
        let mut row: Vec<HiveDay> = Vec::with_capacity(n);
        for (i, h) in hives.iter().enumerate() {
            let (mut a, mut f, mut t, mut hu) = (0.0, 0.0, 0.0, 0.0);
            let mut last_seq = 0;
            let mut node_id = 0;
            let mut last_sample: Option<EnvSample> = None;
            for slot in 0..SLOTS {
                let ns = slot_ns(day, slot);
                // Foraging is diurnal: the index peaks in the middle of the
                // day. Aggregating over the whole day removes it.
                let diurnal = [-9.0, 11.0, 7.0, -9.0][slot];
                let av =
                    h.base_acoustic + diurnal + acoustic_effect(h, day) + rng.noise(h.sd_acoustic);
                let env = nodes[i].emit(av, ns, 1);
                let s = gw
                    .ingest(&env, ns + 1_000_000)
                    .expect("acoustic sample verifies");
                a += s.sample().value;
                last_seq = s.sample().sequence;
                node_id = s.sample().node_id;
                last_sample = Some(s.sample().clone());

                let fv = h.base_field + field_effect(h, day) + rng.noise(h.sd_field);
                let env = nodes[n + i].emit(fv, ns, 1);
                let s = gw
                    .ingest(&env, ns + 1_000_000)
                    .expect("field sample verifies");
                f += s.sample().value;

                let tv = h.base_temp + temp_effect(h, day) + rng.noise(0.22);
                let env = nodes[2 * n + i].emit(tv, ns, 1);
                let s = gw
                    .ingest(&env, ns + 1_000_000)
                    .expect("temperature sample verifies");
                t += s.sample().value;

                let hv = 58.0 + rng.noise(1.6) - temp_effect(h, day) * 0.8;
                let env = nodes[3 * n + i].emit(hv, ns, 1);
                let s = gw
                    .ingest(&env, ns + 1_000_000)
                    .expect("humidity sample verifies");
                hu += s.sample().value;
                verified += 4;
            }
            let gain = weight_gain_kg(h, day);
            weights[i] += gain;
            let d = SLOTS as f64;
            row.push(HiveDay {
                label: h.label.to_string(),
                day,
                node_id,
                sequence: last_seq,
                acoustic: a / d,
                field: f / d,
                temp: t / d,
                humidity: hu / d,
                weight_kg: weights[i],
                gain_kg: gain,
                sample: last_sample.expect("at least one slot per day"),
            });
        }
        days.push(row);
    }

    // Per-colony baselines over the undisturbed window.
    let baselines: Vec<HiveBaseline> = (0..n)
        .map(|i| {
            let win: Vec<&HiveDay> = days[..BASELINE_DAYS].iter().map(|r| &r[i]).collect();
            let len = win.len() as f64;
            let mean =
                |f: fn(&HiveDay) -> f64, w: &[&HiveDay]| w.iter().map(|d| f(d)).sum::<f64>() / len;
            let sd = |f: fn(&HiveDay) -> f64, w: &[&HiveDay], m: f64| {
                (w.iter().map(|d| (f(d) - m).powi(2)).sum::<f64>() / (len - 1.0)).sqrt()
            };
            let ma = mean(|d| d.acoustic, &win);
            let mf = mean(|d| d.field, &win);
            HiveBaseline {
                label: hives[i].label.to_string(),
                mean_acoustic: ma,
                sd_acoustic: sd(|d| d.acoustic, &win, ma),
                mean_field: mf,
                sd_field: sd(|d| d.field, &win, mf),
                mean_temp: mean(|d| d.temp, &win),
                mean_gain_kg: mean(|d| d.gain_kg, &win),
            }
        })
        .collect();

    let assess = |moment: &str, day: usize| -> Assessment {
        let mut verdicts = Vec::with_capacity(n);
        for i in 0..n {
            let d = &days[day][i];
            let b = &baselines[i];
            let acoustic_z = (d.acoustic - b.mean_acoustic) / b.sd_acoustic;
            let field_z = (d.field - b.mean_field) / b.sd_field;
            let temp_dev_c = d.temp - b.mean_temp;
            let slope = (d.acoustic - days[day - 5][i].acoustic) / 5.0;
            let thermally_explained = temp_dev_c.abs() > THERMAL_EXPLAIN_C;
            let naive_alarm = acoustic_z <= COLLAPSE_ACOUSTIC_Z;
            let collapse = naive_alarm && field_z <= COLLAPSE_FIELD_Z && !thermally_explained;
            let swarm_precursor = slope >= SWARM_SLOPE
                && d.gain_kg < b.mean_gain_kg * SWARM_GAIN_FRACTION
                && !collapse;
            verdicts.push(HiveVerdict {
                label: d.label.clone(),
                acoustic_z,
                field_z,
                temp_dev_c,
                acoustic_slope: slope,
                gain_kg: d.gain_kg,
                naive_alarm,
                thermally_explained,
                collapse,
                swarm_precursor,
                node_id: d.node_id,
                sequence: d.sequence,
                sample: d.sample.clone(),
            });
        }
        let correlated_hives = verdicts.iter().filter(|v| v.collapse).count();
        let (uncapped, severity, bio_only) = collapse_severity(correlated_hives);
        let collapsing: Vec<&HiveVerdict> = verdicts.iter().filter(|v| v.collapse).collect();
        let swarming: Vec<&HiveVerdict> = verdicts.iter().filter(|v| v.swarm_precursor).collect();
        let event = if !collapsing.is_empty() {
            Some(EnvironmentalEvent {
                evidence_digest: Some(evidence_digest(
                    &collapsing.iter().map(|v| &v.sample).collect::<Vec<_>>(),
                )),
                spec_version: SPEC_VERSION.into(),
                event_id: format!("evt-b4-collapse-d{day:03}"),
                biome_id: "biome/orchard-apiary".into(),
                kind: EventKind::Anomaly,
                severity,
                modality: SensorModality::Acoustic,
                geo: GeoPoint::new(508_812_900, 4_411_000, 62_000).expect("valid apiary centroid"),
                window_start_ns: slot_ns(day, 0),
                window_end_ns: slot_ns(day, SLOTS - 1),
                detected_ns: slot_ns(day, SLOTS - 1),
                evidence: collapsing
                    .iter()
                    .map(|v| EvidenceRef {
                        node_id: v.node_id,
                        sequence: v.sequence,
                    })
                    .collect(),
                confidence: if bio_only { 0.52 } else { 0.88 },
                message: format!(
                    "{} colony(ies) collapsed within one window, thermally excluded",
                    collapsing.len()
                ),
                signature_hex: None,
                signer_pubkey_hex: None,
            })
        } else if !swarming.is_empty() {
            Some(EnvironmentalEvent {
                evidence_digest: Some(evidence_digest(
                    &swarming.iter().map(|v| &v.sample).collect::<Vec<_>>(),
                )),
                spec_version: SPEC_VERSION.into(),
                event_id: format!("evt-b4-swarm-d{day:03}"),
                biome_id: "biome/orchard-apiary".into(),
                kind: EventKind::Anomaly,
                // A swarm precursor is read purely from the colony: capped.
                severity: bio_only_severity_cap(Severity::Watch),
                modality: SensorModality::Acoustic,
                geo: GeoPoint::new(508_812_900, 4_411_000, 62_000).expect("valid apiary centroid"),
                window_start_ns: slot_ns(day - 5, 0),
                window_end_ns: slot_ns(day, SLOTS - 1),
                detected_ns: slot_ns(day, SLOTS - 1),
                evidence: swarming
                    .iter()
                    .map(|v| EvidenceRef {
                        node_id: v.node_id,
                        sequence: v.sequence,
                    })
                    .collect(),
                confidence: 0.66,
                message: format!(
                    "swarming precursor on {}: acoustic rising, weight gain stalled",
                    swarming[0].label
                ),
                signature_hex: None,
                signer_pubkey_hex: None,
            })
        } else {
            None
        };
        Assessment {
            moment: moment.to_string(),
            day,
            hives: verdicts,
            correlated_hives,
            uncapped,
            severity,
            bio_only,
            event,
        }
    };

    let swarm = assess("swarming precursor", SWARM_EVAL_DAY);
    let solo = assess("single-hive collapse", SOLO_COLLAPSE_DAY + 1);
    let cold = assess("cold snap — confounder", COLD_SNAP_DAY);
    let apiary_wide = assess("correlated apiary-wide collapse", APIARY_COLLAPSE_DAY + 1);

    Report {
        baselines,
        swarm,
        solo,
        cold,
        apiary_wide,
        // The weight series never leaves the biome: it is a derived feature.
        weight_series_class: DataClass::DerivedFeature,
        verified_samples: verified,
        final_weights: weights,
    }
}

/// Print the ADR-266 §4.1 acceptance bar and disclaim this scenario.
fn print_not_validated() {
    println!("\n  NOT VALIDATED");
    println!("  ADR-266 §4 track B4 is a RESEARCH TRACK, not a roadmap item and not a");
    println!("  product claim. The §4.1 item 3 acceptance bar is: one biological signal");
    println!("  predicts a CONFIRMED environmental condition >= 30 MINUTES EARLIER than the");
    println!("  conventional sensor, at > 90% PRECISION, across 3 INDEPENDENT LOCATIONS,");
    println!("  with NO PER-LOCATION RETRAINING. Three hives in ONE apiary are three");
    println!("  organisms at one location — they are NOT three independent sites, and a");
    println!("  correlated collapse across them is not proof of a common cause. Nothing");
    println!("  here is evidence that hive acoustics detect pesticide exposure; the");
    println!("  scenario only shows what the fabric does with such a signal if it exists.");
}

fn main() {
    banner(
        "pollinator-hive — ADR-266 B4 biohybrid pollinator nodes",
        "3 colonies: acoustic + electric field, paired internal temp/humidity, derived weight",
    );
    let r = run();

    println!("  PER-COLONY BASELINES (20 undisturbed days, 6-hourly)\n");
    println!(
        "  {:<18} {:>10} {:>8} {:>10} {:>8} {:>9} {:>10}",
        "hive", "acoustic", "sd", "field mV/m", "sd", "temp °C", "gain kg/d"
    );
    for b in &r.baselines {
        println!(
            "  {:<18} {:>10.1} {:>8.2} {:>10.1} {:>8.2} {:>9.2} {:>10.2}",
            b.label,
            b.mean_acoustic,
            b.sd_acoustic,
            b.mean_field,
            b.sd_field,
            b.mean_temp,
            b.mean_gain_kg
        );
    }
    println!("  -> three colonies, three different normals. No global threshold.");
    println!("     verdict legend: COLLAPSE = acoustic + electric field agree and the");
    println!("     internal-temperature reference does NOT explain it; thermal = the");
    println!("     conventional reference explains the drop; uncorrob. = the acoustic");
    println!("     index alone moved (e.g. against a stale post-swarm baseline) and the");
    println!("     colony electric field refused to confirm it. Only COLLAPSE counts.");

    for a in [&r.swarm, &r.solo, &r.cold, &r.apiary_wide] {
        println!("\n  DAY {} — {}\n", a.day, a.moment.to_uppercase());
        println!(
            "  {:<18} {:>9} {:>9} {:>9} {:>9} {:>9} {:>12}",
            "hive", "acou z", "field z", "ΔT °C", "slope/d", "gain kg", "verdict"
        );
        for v in &a.hives {
            let verdict = if v.collapse {
                "COLLAPSE"
            } else if v.swarm_precursor {
                "SWARM-PRE"
            } else if v.naive_alarm && v.thermally_explained {
                "thermal"
            } else if v.naive_alarm {
                "uncorrob."
            } else {
                "normal"
            };
            println!(
                "  {:<18} {:>9.2} {:>9.2} {:>9.2} {:>9.2} {:>9.2} {:>12}",
                v.label,
                v.acoustic_z,
                v.field_z,
                v.temp_dev_c,
                v.acoustic_slope,
                v.gain_kg,
                verdict
            );
        }
        let naive = a.hives.iter().filter(|v| v.naive_alarm).count();
        let thermal = a.hives.iter().filter(|v| v.thermally_explained).count();
        line("naive acoustic alarms", format!("{naive} of 3"));
        line(
            "thermally explained by the reference",
            format!("{thermal} of 3"),
        );
        line("colonies collapsing in this window", a.correlated_hives);
        if a.correlated_hives == 0 {
            line("collapse evidence", "none — nothing to cap");
        } else {
            line("evidence is a single colony (biology only)", a.bio_only);
            line(
                "collapse severity before the biological cap",
                format!("{:?}", a.uncapped),
            );
            line("collapse severity emitted", format!("{:?}", a.severity));
        }
        match &a.event {
            Some(ev) => {
                ev.validate().expect("event is structurally valid");
                line(
                    "event",
                    format!("{:?} / conf {:.2}", ev.severity, ev.confidence),
                );
                println!("  -> {}", ev.message);
            }
            None => line("event", "NONE"),
        }
    }

    println!("\n  DERIVED SERIES AND RESIDENCY\n");
    line(
        "hive weight series data class",
        format!("{:?}", r.weight_series_class),
    );
    line(
        "its residency",
        format!("{:?}", r.weight_series_class.residency()),
    );
    for (b, w) in r.baselines.iter().zip(&r.final_weights) {
        line(&format!("final weight — {}", b.label), format!("{w:.2} kg"));
    }
    line(
        "max colony evidence edge weight cap",
        format!("{BIO_MAX_EVIDENCE_WEIGHT:.2}"),
    );
    line("envelopes cryptographically verified", r.verified_samples);

    print_not_validated();
    synthetic_footer("Hive acoustics here are a hand-written model, not recordings.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swarm_precursor_fires_on_the_right_hive_only() {
        let r = run();
        let fired: Vec<&str> = r
            .swarm
            .hives
            .iter()
            .filter(|v| v.swarm_precursor)
            .map(|v| v.label.as_str())
            .collect();
        assert_eq!(fired, vec!["H1 orchard-east"]);
        let h1 = &r.swarm.hives[0];
        assert!(
            h1.acoustic_slope >= SWARM_SLOPE,
            "acoustic must be climbing"
        );
        assert!(h1.gain_kg < r.baselines[0].mean_gain_kg * SWARM_GAIN_FRACTION);
        // No collapse anywhere, and the event is a capped Watch → Advisory.
        assert_eq!(r.swarm.correlated_hives, 0);
        let ev = r.swarm.event.as_ref().expect("swarm precursor event");
        ev.validate().unwrap();
        assert_eq!(ev.severity, Severity::Advisory);
        assert_eq!(ev.evidence.len(), 1);
    }

    #[test]
    fn a_single_hive_collapse_stays_advisory() {
        assert_eq!(
            collapse_severity(1),
            (Severity::Warning, Severity::Advisory, true)
        );
        let r = run();
        let a = &r.solo;
        assert_eq!(a.correlated_hives, 1);
        let collapsed: Vec<&str> = a
            .hives
            .iter()
            .filter(|v| v.collapse)
            .map(|v| v.label.as_str())
            .collect();
        assert_eq!(collapsed, vec!["H2 hedgerow"]);
        assert!(a.bio_only);
        assert_eq!(a.uncapped, Severity::Warning);
        assert_eq!(a.severity, Severity::Advisory);
        let ev = a.event.as_ref().expect("advisory event");
        assert_eq!(ev.severity, Severity::Advisory);
        assert!(ev.confidence < 0.6);
    }

    #[test]
    fn correlated_multi_hive_collapse_escalates() {
        assert_eq!(collapse_severity(2).1, Severity::Warning);
        assert_eq!(collapse_severity(3).1, Severity::Critical);
        let r = run();
        let a = &r.apiary_wide;
        assert_eq!(a.correlated_hives, 3);
        assert!(!a.bio_only);
        assert_eq!(a.severity, Severity::Critical);
        // Every collapsing colony had a NORMAL internal temperature — the
        // conventional reference is what licenses the escalation.
        for v in a.hives.iter().filter(|v| v.collapse) {
            assert!(!v.thermally_explained);
            assert!(v.temp_dev_c.abs() < THERMAL_EXPLAIN_C);
            assert!(v.field_z <= COLLAPSE_FIELD_Z);
        }
        let ev = a.event.as_ref().expect("critical event");
        ev.validate().unwrap();
        assert_eq!(ev.evidence.len(), 3);
        assert!(ev
            .evidence_digest
            .as_ref()
            .is_some_and(|d| d.starts_with("sha256:")));
        assert!(ev.confidence > 0.8);
    }

    #[test]
    fn the_cold_confounded_hive_produces_no_event() {
        let r = run();
        let a = &r.cold;
        let h3 = a
            .hives
            .iter()
            .find(|v| v.label == "H3 heath-margin")
            .expect("H3 present");
        // The naive detector sees a huge activity drop...
        assert!(h3.naive_alarm);
        assert!(h3.acoustic_z < COLLAPSE_ACOUSTIC_Z);
        // ...but the paired conventional temperature reference explains it,
        // and the electric field says the colony is alive.
        assert!(h3.thermally_explained);
        assert!(h3.temp_dev_c < -THERMAL_EXPLAIN_C);
        assert!(h3.field_z > COLLAPSE_FIELD_Z);
        assert!(!h3.collapse);
        assert_eq!(a.correlated_hives, 0);
        assert!(a.event.is_none(), "a cold hive is not an incident");
        assert_eq!(a.severity, Severity::Advisory);
    }

    #[test]
    fn scenario_is_fully_deterministic() {
        let a = run();
        let b = run();
        assert_eq!(a, b);
        assert_eq!(a.verified_samples, TOTAL_DAYS * SLOTS * 3 * 4);
        assert_eq!(a.weight_series_class, DataClass::DerivedFeature);
    }
}
