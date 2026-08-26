//! # ecosystem-memory — ADR-266 §4 track B8 (research track, NOT a product)
//!
//! RuVector-style case-based reasoning over a biome's own history. Every day
//! of a ninety-day record is encoded as a six-feature state vector — water
//! level, soil moisture, air temperature, an optical chlorophyll proxy, an
//! acoustic index and rainfall — normalized against the record's own
//! statistics. A new state is then matched against that archive by cosine
//! similarity, and the nearest historical cases are reported *with their
//! provenance*: exactly which observations produced each retrieved vector.
//!
//! The archive contains two algal-bloom episodes, each preceded by a
//! three-day precursor window. Three new states are presented:
//!
//! 1. **A precursor-like state.** Retrieval returns labelled precursor days
//!    and reports "N % similar to conditions M days before the YYYY-MM-DD
//!    bloom".
//! 2. **An ordinary state.** Retrieval returns ordinary days — the archive is
//!    not simply attracted to the dramatic episodes.
//! 3. **A confounded state**: the optical chlorophyll proxy spikes as hard as
//!    a real precursor, but it is turbidity after heavy rain. The
//!    conventional references (rainfall, water level, soil moisture) put it
//!    nowhere near the precursor windows — the archive instead recognises it
//!    as the earlier turbidity event — and nothing escalates.
//!
//! Every verdict this file produces is routed through
//! [`bio_only_severity_cap`], because a retrieval similarity is not a
//! forecast: with two episodes in ninety days there is no seasonal cycle to
//! learn from, and ADR-266 §4 says B8 "needs ≥ 1 seasonal cycle" before any
//! predictive claim is admissible.
//!
//! ```bash
//! cargo run -p rucelium-examples --bin ecosystem-memory
//! ```

use rucelium_core::{EvidenceRef, GeoPoint, SensorModality, Severity};
use rucelium_examples::{
    banner, line, synthetic_footer, Gateway, Node, Rng, EPOCH_NS, NS_PER_S, S_PER_DAY,
};

// ---------------------------------------------------------------------------
// The normative rule
// ---------------------------------------------------------------------------

/// Clamp a severity to at most [`Severity::Advisory`].
///
/// **The ADR-266 §4.1 item 3 rule, enforced.** A historical-similarity score
/// is evidence that today resembles a past day. It is not a prediction, it
/// has no measured precision, and ADR-266 §4 records that B8 needs at least
/// one full seasonal cycle before it may claim anything. Every verdict here
/// goes through this function.
#[must_use]
pub fn bio_only_severity_cap(severity: Severity) -> Severity {
    severity.min(Severity::Advisory)
}

// ---------------------------------------------------------------------------
// State vectors
// ---------------------------------------------------------------------------

/// Number of features in a daily biome state vector.
pub const FEATURES: usize = 6;
/// Human-readable feature names, in vector order.
pub const FEATURE_NAMES: [&str; FEATURES] = [
    "water_level_m",
    "soil_moisture_pct",
    "air_temperature_c",
    "chlorophyll_ug_l",
    "acoustic_index",
    "rainfall_mm",
];
/// Days in the historical archive.
pub const HISTORY_DAYS: usize = 90;
/// Neighbours returned per query.
pub const TOP_K: usize = 4;
/// Days of the first bloom episode.
pub const BLOOM_A: usize = 27;
/// Days of the second bloom episode.
pub const BLOOM_B: usize = 64;
/// Length of the characteristic precursor window, days.
pub const PRECURSOR_DAYS: usize = 3;

/// What a historical day is known to be. Labels are the ground truth the
/// retrieval is scored against — they are never an input to the similarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DayLabel {
    /// An ordinary day.
    Normal,
    /// One of the three days immediately preceding a bloom.
    Precursor {
        /// The bloom this window precedes.
        bloom_day: usize,
    },
    /// A day during a bloom.
    Bloom {
        /// First day of that bloom.
        bloom_day: usize,
    },
    /// A day whose chlorophyll proxy spiked for a non-bloom reason.
    ConfoundedSpike,
}

impl DayLabel {
    /// Whether this day is a labelled precursor.
    #[must_use]
    pub fn is_precursor(self) -> bool {
        matches!(self, DayLabel::Precursor { .. })
    }
}

/// One day of biome state, with the evidence that produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct StateVector {
    /// Day index in the record.
    pub day: usize,
    /// Simulated calendar date, `YYYY-MM-DD`.
    pub date: String,
    /// Raw feature values in [`FEATURE_NAMES`] order.
    pub raw: [f64; FEATURES],
    /// Normalized (z-scored) features — what similarity is computed on.
    pub norm: [f64; FEATURES],
    /// Ground-truth label.
    pub label: DayLabel,
    /// **Provenance**: the accepted observations this vector was built from,
    /// one per feature, as `(node_id, sequence)` dedup keys.
    pub evidence: Vec<EvidenceRef>,
}

/// Cosine similarity between two feature vectors, in `[-1, 1]`.
///
/// Returns `0.0` when either vector has zero magnitude (undefined direction),
/// and clamps to `[-1, 1]` so floating-point error can never leak a value
/// outside the mathematically valid range.
#[must_use]
pub fn cosine(a: &[f64; FEATURES], b: &[f64; FEATURES]) -> f64 {
    let dot: f64 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let nb: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    if na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    (dot / (na * nb)).clamp(-1.0, 1.0)
}

/// One retrieved historical case.
#[derive(Debug, Clone, PartialEq)]
pub struct Retrieved {
    /// Day index of the retrieved case.
    pub day: usize,
    /// Its simulated date.
    pub date: String,
    /// Cosine similarity to the query.
    pub similarity: f64,
    /// Its ground-truth label.
    pub label: DayLabel,
    /// Days between this case and the bloom it preceded, if it was a
    /// precursor.
    pub days_before_bloom: Option<usize>,
    /// The date of that bloom, if any.
    pub bloom_date: Option<String>,
    /// **Provenance** carried through the retrieval, never dropped.
    pub evidence: Vec<EvidenceRef>,
}

impl Retrieved {
    /// The sentence a human actually reads.
    #[must_use]
    pub fn sentence(&self) -> String {
        match (self.days_before_bloom, &self.bloom_date) {
            (Some(m), Some(d)) => format!(
                "{:.0}% similar to conditions {m} day(s) before the {d} bloom",
                self.similarity * 100.0
            ),
            _ => format!(
                "{:.0}% similar to {} ({:?})",
                self.similarity * 100.0,
                self.date,
                self.label
            ),
        }
    }
}

/// One presented state and what the archive said about it.
#[derive(Debug, Clone, PartialEq)]
pub struct Query {
    /// Narrative name.
    pub name: String,
    /// The presented state.
    pub state: StateVector,
    /// The `TOP_K` nearest historical cases, most similar first.
    pub neighbours: Vec<Retrieved>,
    /// How many of them are labelled precursors.
    pub precursor_hits: usize,
    /// Severity the retrieval "wanted" before the cap.
    pub uncapped: Severity,
    /// Severity actually emitted — always `Advisory`.
    pub severity: Severity,
}

/// Everything one deterministic run produces.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// The ninety-day archive.
    pub history: Vec<StateVector>,
    /// Per-feature normalization means.
    pub means: [f64; FEATURES],
    /// Per-feature normalization standard deviations.
    pub sds: [f64; FEATURES],
    /// The three presented states.
    pub queries: Vec<Query>,
    /// Envelopes the real ingest pipeline verified.
    pub verified_samples: usize,
    /// Days of record available, against the seasonal cycle B8 requires.
    pub seasonal_cycles_available: f64,
}

// ---------------------------------------------------------------------------
// Calendar
// ---------------------------------------------------------------------------

/// Civil `(year, month, day)` from a days-since-Unix-epoch count
/// (Howard Hinnant's `civil_from_days`, exact integer arithmetic).
#[must_use]
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Simulated calendar date for `day`, derived from `EPOCH_NS` — never a wall
/// clock.
#[must_use]
pub fn date_of(day: usize) -> String {
    let epoch_days = (EPOCH_NS / NS_PER_S / S_PER_DAY) as i64;
    let (y, m, d) = civil_from_days(epoch_days + day as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Simulated measurement time for `day`, derived from `EPOCH_NS`.
#[must_use]
pub fn day_ns(day: usize) -> u64 {
    EPOCH_NS + day as u64 * S_PER_DAY * NS_PER_S
}

// ---------------------------------------------------------------------------
// Environment model
// ---------------------------------------------------------------------------

/// Ground-truth label for a day of the archive.
#[must_use]
pub fn label_of(day: usize) -> DayLabel {
    for bloom in [BLOOM_A, BLOOM_B] {
        if (bloom - PRECURSOR_DAYS..bloom).contains(&day) {
            return DayLabel::Precursor { bloom_day: bloom };
        }
        if (bloom..bloom + 4).contains(&day) {
            return DayLabel::Bloom { bloom_day: bloom };
        }
    }
    if day == 78 {
        return DayLabel::ConfoundedSpike;
    }
    DayLabel::Normal
}

/// Raw feature values for `day`, in [`FEATURE_NAMES`] order.
///
/// The precursor signature is deliberately *multivariate*: falling water
/// level, drying soil, rising temperature, rising chlorophyll, a slightly
/// quieter soundscape and no rain. A chlorophyll spike alone is not the
/// pattern — which is exactly what makes day 78 rejectable.
#[must_use]
pub fn features_for(day: usize, rng: &mut Rng) -> [f64; FEATURES] {
    let seasonal = (day as f64 * 0.055).sin();
    let mut f = [
        2.42 + 0.10 * seasonal + rng.noise(0.04),
        30.5 + 2.4 * seasonal + rng.noise(0.9),
        18.2 + 3.1 * seasonal + rng.noise(0.6),
        6.1 + 0.5 * seasonal + rng.noise(0.35),
        55.0 + 2.0 * seasonal + rng.noise(1.4),
        3.4 + rng.noise(1.1),
    ];
    match label_of(day) {
        DayLabel::Precursor { bloom_day } => {
            let ramp = (PRECURSOR_DAYS - (bloom_day - day)) as f64 + 1.0;
            f[0] -= 0.19 * ramp;
            f[1] -= 3.1 * ramp;
            f[2] += 1.7 * ramp;
            f[3] += 4.6 * ramp;
            f[4] -= 2.1 * ramp;
            f[5] = 0.0;
        }
        DayLabel::Bloom { .. } => {
            // The bloom itself is a different STATE, not just a bigger
            // precursor: the water deficit has broken, rain has returned, and
            // the chlorophyll proxy is saturated. Cosine similarity is
            // scale-invariant, so the two must differ in DIRECTION for
            // retrieval to tell them apart — and here they do.
            f[0] -= 0.12;
            f[1] += 2.2;
            f[2] += 1.4;
            f[3] += 37.0;
            f[4] -= 8.5;
            f[5] += 9.0;
        }
        DayLabel::ConfoundedSpike => {
            // Turbidity after a downpour: the optical proxy reads like a
            // precursor, every conventional reference says the opposite.
            f[0] += 0.44;
            f[1] += 7.2;
            f[2] -= 2.0;
            f[3] += 13.4;
            f[4] += 1.1;
            f[5] = 26.0;
        }
        DayLabel::Normal => {}
    }
    f[5] = f[5].max(0.0);
    f
}

// ---------------------------------------------------------------------------
// The scenario
// ---------------------------------------------------------------------------

/// Run the whole scenario deterministically.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run() -> Report {
    let mut rng = Rng::new(0x00B8_0E11_5EED_A17E);
    let site = GeoPoint::new(524_110_000, 5_940_000, 3_000).expect("valid lagoon coordinates");

    // One node per feature: four conventional references and two biological
    // proxies (the optical chlorophyll estimate and the acoustic index).
    let mut nodes = vec![
        Node::new(
            0x00B8_0000_0000_0001,
            SensorModality::WaterQuality,
            site,
            "lagoon stage gauge",
        ),
        Node::new(
            0x00B8_0000_0000_0002,
            SensorModality::SoilMoisture,
            site,
            "margin soil probe",
        ),
        Node::new(
            0x00B8_0000_0000_0003,
            SensorModality::Weather,
            site,
            "shore air temperature",
        ),
        Node::new(
            0x00B8_0000_0000_0004,
            SensorModality::Optical,
            site,
            "chlorophyll optical proxy",
        ),
        Node::new(
            0x00B8_0000_0000_0005,
            SensorModality::Acoustic,
            site,
            "lagoon acoustic index",
        ),
        Node::new(
            0x00B8_0000_0000_0006,
            SensorModality::Weather,
            site,
            "tipping-bucket rain gauge",
        ),
    ];
    let mut gw = Gateway::with_nodes(&nodes);
    let mut verified = 0usize;

    // --- build the archive through the real verified ingest path ---
    let mut raws: Vec<([f64; FEATURES], Vec<EvidenceRef>)> = Vec::with_capacity(HISTORY_DAYS);
    let collect = |day: usize,
                   rng: &mut Rng,
                   nodes: &mut Vec<Node>,
                   gw: &mut Gateway,
                   verified: &mut usize|
     -> ([f64; FEATURES], Vec<EvidenceRef>) {
        let target = features_for(day, rng);
        let ns = day_ns(day);
        let mut raw = [0.0; FEATURES];
        let mut evidence = Vec::with_capacity(FEATURES);
        for (i, node) in nodes.iter_mut().enumerate() {
            let env = node.emit(target[i], ns, 1);
            let s = gw
                .ingest(&env, ns + 1_000_000)
                .expect("state sample verifies");
            raw[i] = s.sample().value;
            evidence.push(EvidenceRef {
                node_id: s.sample().node_id,
                sequence: s.sample().sequence,
            });
            *verified += 1;
        }
        (raw, evidence)
    };

    for day in 0..HISTORY_DAYS {
        raws.push(collect(day, &mut rng, &mut nodes, &mut gw, &mut verified));
    }

    // Normalization statistics come from the archive itself, and the *same*
    // statistics normalize every query — no per-query refitting.
    let mut means = [0.0; FEATURES];
    let mut sds = [0.0; FEATURES];
    for i in 0..FEATURES {
        let m = raws.iter().map(|(r, _)| r[i]).sum::<f64>() / HISTORY_DAYS as f64;
        let v =
            raws.iter().map(|(r, _)| (r[i] - m).powi(2)).sum::<f64>() / (HISTORY_DAYS - 1) as f64;
        means[i] = m;
        sds[i] = v.sqrt();
    }
    let normalize = |raw: &[f64; FEATURES]| -> [f64; FEATURES] {
        let mut out = [0.0; FEATURES];
        for i in 0..FEATURES {
            out[i] = if sds[i] > 0.0 {
                (raw[i] - means[i]) / sds[i]
            } else {
                0.0
            };
        }
        out
    };

    let history: Vec<StateVector> = raws
        .iter()
        .enumerate()
        .map(|(day, (raw, evidence))| StateVector {
            day,
            date: date_of(day),
            raw: *raw,
            norm: normalize(raw),
            label: label_of(day),
            evidence: evidence.clone(),
        })
        .collect();

    // --- three new states, presented after the archive closes ---
    let query_specs: [(&str, DayLabel); 3] = [
        (
            "precursor-like state",
            DayLabel::Precursor { bloom_day: 93 },
        ),
        ("ordinary state", DayLabel::Normal),
        (
            "confounded state — chlorophyll spike after heavy rain",
            DayLabel::ConfoundedSpike,
        ),
    ];
    let mut queries = Vec::new();
    for (qi, (name, label)) in query_specs.iter().enumerate() {
        let day = HISTORY_DAYS + qi;
        // Synthesize the presented state from the same generator, so a query
        // is nothing more than "another day of the same instrument set".
        let target = match label {
            DayLabel::Precursor { .. } => features_for(BLOOM_A - 1, &mut rng),
            DayLabel::ConfoundedSpike => features_for(78, &mut rng),
            _ => features_for(44, &mut rng),
        };
        let ns = day_ns(day);
        let mut raw = [0.0; FEATURES];
        let mut evidence = Vec::with_capacity(FEATURES);
        for (i, node) in nodes.iter_mut().enumerate() {
            let env = node.emit(target[i], ns, 1);
            let s = gw
                .ingest(&env, ns + 1_000_000)
                .expect("query sample verifies");
            raw[i] = s.sample().value;
            evidence.push(EvidenceRef {
                node_id: s.sample().node_id,
                sequence: s.sample().sequence,
            });
            verified += 1;
        }
        let state = StateVector {
            day,
            date: date_of(day),
            raw,
            norm: normalize(&raw),
            label: *label,
            evidence,
        };

        let mut scored: Vec<(f64, &StateVector)> = history
            .iter()
            .map(|h| (cosine(&state.norm, &h.norm), h))
            .collect();
        // Deterministic ordering: similarity descending, then day ascending.
        scored.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.1.day.cmp(&b.1.day))
        });
        let neighbours: Vec<Retrieved> = scored
            .iter()
            .take(TOP_K)
            .map(|(sim, h)| {
                let (days_before_bloom, bloom_date) = match h.label {
                    DayLabel::Precursor { bloom_day } => {
                        (Some(bloom_day - h.day), Some(date_of(bloom_day)))
                    }
                    _ => (None, None),
                };
                Retrieved {
                    day: h.day,
                    date: h.date.clone(),
                    similarity: *sim,
                    label: h.label,
                    days_before_bloom,
                    bloom_date,
                    // Provenance is carried, never dropped.
                    evidence: h.evidence.clone(),
                }
            })
            .collect();
        let precursor_hits = neighbours.iter().filter(|r| r.label.is_precursor()).count();
        // Even a perfect retrieval is capped: it is a resemblance, not a
        // forecast.
        let uncapped = if precursor_hits >= TOP_K {
            Severity::Warning
        } else if precursor_hits > 0 {
            Severity::Watch
        } else {
            Severity::Advisory
        };
        queries.push(Query {
            name: (*name).to_string(),
            state,
            neighbours,
            precursor_hits,
            uncapped,
            severity: bio_only_severity_cap(uncapped),
        });
    }

    Report {
        history,
        means,
        sds,
        queries,
        verified_samples: verified,
        // 90 days against a 365-day cycle.
        seasonal_cycles_available: HISTORY_DAYS as f64 / 365.0,
    }
}

/// Print the ADR-266 §4.1 acceptance bar and disclaim this scenario.
fn print_not_validated(cycles: f64) {
    println!("\n  NOT VALIDATED");
    println!("  ADR-266 §4 track B8 is a RESEARCH TRACK, not a roadmap item and not a");
    println!("  product claim. The §4.1 item 3 acceptance bar is: one biological signal");
    println!("  predicts a CONFIRMED environmental condition >= 30 MINUTES EARLIER than the");
    println!("  conventional sensor, at > 90% PRECISION, across 3 INDEPENDENT LOCATIONS,");
    println!("  with NO PER-LOCATION RETRAINING. ADR-266 §4 additionally records that B8");
    println!("  NEEDS AT LEAST ONE FULL SEASONAL CYCLE before any predictive claim.");
    println!("  This archive holds {cycles:.2} of a seasonal cycle and TWO bloom episodes.");
    println!("  Two episodes cannot establish precision, cannot separate seasonality from");
    println!("  causation, and cannot generalize to another site. A similarity score is a");
    println!("  RESEMBLANCE, not a forecast: every verdict here is capped at Advisory.");
}

fn main() {
    banner(
        "ecosystem-memory — ADR-266 B8 RuVector-style ecosystem memory",
        "90 days of 6-feature biome state; retrieve the most similar past conditions",
    );
    let r = run();

    println!("  ARCHIVE\n");
    line("days of record", r.history.len());
    line(
        "labelled bloom episodes",
        format!(
            "{} ({} and {})",
            r.history
                .iter()
                .filter(|h| matches!(h.label, DayLabel::Bloom { .. }))
                .map(|h| match h.label {
                    DayLabel::Bloom { bloom_day } => bloom_day,
                    _ => 0,
                })
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            date_of(BLOOM_A),
            date_of(BLOOM_B)
        ),
    );
    line(
        "labelled precursor days",
        r.history.iter().filter(|h| h.label.is_precursor()).count(),
    );
    println!("\n  {:<20} {:>10} {:>10}", "feature", "mean", "sd");
    for (i, name) in FEATURE_NAMES.iter().enumerate() {
        println!("  {:<20} {:>10.2} {:>10.2}", name, r.means[i], r.sds[i]);
    }
    println!("  -> the same statistics normalize the archive AND every query:");
    println!("     no per-query refitting, which is the point of §4.1's");
    println!("     'no per-location retraining' clause.");

    for q in &r.queries {
        println!("\n  QUERY — {}\n", q.name.to_uppercase());
        print!("  raw state:");
        for (i, name) in FEATURE_NAMES.iter().enumerate() {
            print!(
                " {}={:.1}",
                name.split('_').next().unwrap_or(name),
                q.state.raw[i]
            );
        }
        println!();
        for (rank, n) in q.neighbours.iter().enumerate() {
            println!(
                "   #{}  day {:>2} ({})  cos {:+.4}  {:?}",
                rank + 1,
                n.day,
                n.date,
                n.similarity,
                n.label
            );
            println!("        {}", n.sentence());
            println!(
                "        provenance: {} observation(s), first = node {:#018x} seq {}",
                n.evidence.len(),
                n.evidence[0].node_id,
                n.evidence[0].sequence
            );
        }
        line(
            "labelled precursor days in top-k",
            format!("{} of {TOP_K}", q.precursor_hits),
        );
        line("severity before the cap", format!("{:?}", q.uncapped));
        line("severity emitted", format!("{:?}", q.severity));
    }

    println!("\n  CONFOUNDER CHECK\n");
    let conf = &r.queries[2];
    line(
        "chlorophyll in the confounded state",
        format!("{:.1} µg/L", conf.state.raw[3]),
    );
    line(
        "chlorophyll in a real precursor state",
        format!("{:.1} µg/L", r.queries[0].state.raw[3]),
    );
    line(
        "rainfall in the confounded state",
        format!("{:.1} mm", conf.state.raw[5]),
    );
    line(
        "rainfall in a real precursor state",
        format!("{:.1} mm", r.queries[0].state.raw[5]),
    );
    println!("  -> the biological proxy alone looks like a precursor. The conventional");
    println!("     references (rainfall, stage, soil moisture) point the state vector in");
    println!("     a different direction entirely, so the archive returns the earlier");
    println!("     turbidity event and bloom days — and NOT ONE precursor window. No");
    println!("     precursor advisory is issued; nothing escalates.");

    line("envelopes cryptographically verified", r.verified_samples);
    print_not_validated(r.seasonal_cycles_available);
    synthetic_footer("Two synthetic bloom episodes are not a validated bloom predictor.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precursor_query_retrieves_labelled_precursor_days_in_top_k() {
        let r = run();
        let q = &r.queries[0];
        assert_eq!(
            q.precursor_hits, TOP_K,
            "every neighbour must be a precursor"
        );
        for n in &q.neighbours {
            assert!(n.label.is_precursor(), "day {} is {:?}", n.day, n.label);
            // Precursor days really are the labelled windows.
            let m = n.days_before_bloom.expect("precursor has a bloom");
            assert!((1..=PRECURSOR_DAYS).contains(&m));
            assert!(n.bloom_date.is_some());
            assert!(n.sentence().contains("before the"));
        }
        // Both episodes are represented, not just the nearest one.
        let blooms: std::collections::BTreeSet<&str> = q
            .neighbours
            .iter()
            .filter_map(|n| n.bloom_date.as_deref())
            .collect();
        assert_eq!(blooms.len(), 2, "retrieval spans both bloom episodes");
        // Similarity is high and strictly ordered.
        assert!(q.neighbours[0].similarity > 0.9);
        for w in q.neighbours.windows(2) {
            assert!(w[0].similarity >= w[1].similarity);
        }
    }

    #[test]
    fn ordinary_query_retrieves_non_precursor_neighbours() {
        let r = run();
        let q = &r.queries[1];
        assert_eq!(q.precursor_hits, 0);
        for n in &q.neighbours {
            assert!(!n.label.is_precursor(), "day {} is {:?}", n.day, n.label);
            assert!(!matches!(n.label, DayLabel::Bloom { .. }));
            assert!(n.days_before_bloom.is_none());
        }
        assert_eq!(q.severity, Severity::Advisory);
    }

    #[test]
    fn confounded_chlorophyll_spike_retrieves_no_precursors_and_never_escalates() {
        let r = run();
        let q = &r.queries[2];
        // The biological proxy alone looks just like a precursor...
        let precursor_chl = r.queries[0].state.raw[3];
        assert!(q.state.raw[3] > precursor_chl * 0.7);
        // ...but the conventional references disagree, and the archive is not
        // fooled.
        assert!(q.state.raw[5] > 20.0, "heavy rain is the real cause");
        assert_eq!(q.precursor_hits, 0);
        assert_eq!(q.uncapped, Severity::Advisory);
        assert_eq!(q.severity, Severity::Advisory);
    }

    #[test]
    fn cosine_similarity_is_symmetric_and_bounded() {
        let r = run();
        for a in r.history.iter().take(30) {
            for b in r.history.iter().skip(40).take(30) {
                let ab = cosine(&a.norm, &b.norm);
                let ba = cosine(&b.norm, &a.norm);
                assert!((ab - ba).abs() < 1e-12, "cosine must be symmetric");
                assert!((-1.0..=1.0).contains(&ab), "cosine {ab} out of range");
            }
            // Self-similarity is 1.
            assert!((cosine(&a.norm, &a.norm) - 1.0).abs() < 1e-9);
        }
        // A zero vector has no direction, and that is reported as 0, not NaN.
        assert_eq!(cosine(&[0.0; FEATURES], &r.history[0].norm), 0.0);
    }

    #[test]
    fn every_retrieved_case_carries_provenance() {
        let r = run();
        for q in &r.queries {
            assert_eq!(q.neighbours.len(), TOP_K);
            for n in &q.neighbours {
                assert_eq!(
                    n.evidence.len(),
                    FEATURES,
                    "one evidence ref per feature, day {}",
                    n.day
                );
                // The refs really point at the archive day they claim to.
                let src = &r.history[n.day];
                assert_eq!(n.evidence, src.evidence);
                // And they are the real dedup keys of accepted observations.
                for (i, e) in n.evidence.iter().enumerate() {
                    assert_eq!(e.node_id, 0x00B8_0000_0000_0001 + i as u64);
                    assert_eq!(e.sequence as usize, n.day);
                }
            }
        }
    }

    #[test]
    fn scenario_is_fully_deterministic() {
        let a = run();
        let b = run();
        assert_eq!(a, b);
        assert_eq!(a.verified_samples, (HISTORY_DAYS + 3) * FEATURES);
        assert!(a.seasonal_cycles_available < 1.0);
        // Every verdict in the whole run is capped.
        for q in &a.queries {
            assert_eq!(q.severity, Severity::Advisory);
        }
    }
}
