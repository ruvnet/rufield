//! # airborne-dna — ADR-266 §4 track B3 (research track, NOT a product)
//!
//! An anomaly-triggered environmental-DNA observatory. An acoustic node and a
//! paired optical (illuminance) reference watch a river corridor; when the
//! acoustic anomaly survives the circadian cross-check, a DNA sampler is
//! triggered, and the metabarcoding result enriches the WorldGraph with taxon
//! nodes and typed evidence edges.
//!
//! Five episodes, each making one point:
//!
//! 1. **Confirmation** — an acoustic call is confirmed genetically. Two
//!    independent modalities agree, so confidence rises and a `Supports` edge
//!    is written from the sensor to the taxon.
//! 2. **Circadian confounder** — the dawn chorus spikes the acoustic activity
//!    index. The paired optical reference shows civil twilight, the
//!    circadian-adjusted detector refuses to call it an anomaly, and no
//!    sampler cartridge is burned. A naive detector would have fired.
//! 3. **Contradiction** — an acoustic classifier calls *Myotis daubentonii*;
//!    the DNA result contains zero *Myotis* reads. The disagreement is
//!    recorded as a `Contradicts` edge and tracked, never silently resolved,
//!    and **nothing escalates**.
//! 4. **Invasive detection** — DNA finds an invasive bivalve. An event is
//!    raised, but its only evidence is molecular, so
//!    [`bio_only_severity_cap`] holds it at `Advisory` until a conventional
//!    survey confirms it.
//! 5. **The privacy gate (ADR-266 §4.1 item 4)** — a sample from a riverside
//!    path contains human-classified reads. [`disclose`] refuses to release
//!    *anything* from that sample: no taxa, no counts, no location. The
//!    non-human taxa remain usable inside the biome, and every other sample
//!    discloses normally.
//!
//! ```bash
//! cargo run -p rucelium-examples --bin airborne-dna
//! ```

use rucelium_core::event::evidence_digest;
use rucelium_core::{
    EnvSample, EnvironmentalEvent, EventKind, EvidenceRef, GeoPoint, SensorModality, Severity,
    SPEC_VERSION,
};
use rucelium_examples::{banner, line, synthetic_footer, Gateway, Node, Rng, EPOCH_NS, NS_PER_S};
use rucelium_federation::{verify_event, Biome, BiomeConfig};
use rucelium_worldgraph::{EdgeKind, GraphNode, WorldGraph};

// ---------------------------------------------------------------------------
// The normative rules
// ---------------------------------------------------------------------------

/// Hard cap on the weight of a biology-derived evidence edge, mirroring
/// `rucelium_worldgraph::RF_MAX_EVIDENCE_WEIGHT` (ADR-264 §8) as ADR-266
/// §4.1 item 3 requires of every biological modality.
pub const BIO_MAX_EVIDENCE_WEIGHT: f32 = 0.3;

/// Clamp a severity to at most [`Severity::Advisory`].
///
/// **The ADR-266 §4.1 item 3 rule, enforced.** A metabarcoding hit is
/// evidence that DNA was present in a water sample — not that a live
/// population is established, not where it came from, and not when it was
/// shed. Until a conventional survey agrees, it informs and does not alarm.
#[must_use]
pub fn bio_only_severity_cap(severity: Severity) -> Severity {
    severity.min(Severity::Advisory)
}

// ---------------------------------------------------------------------------
// DNA results and the privacy gate
// ---------------------------------------------------------------------------

/// One taxon assignment from a metabarcoding run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxonRead {
    /// Binomial name as assigned by the reference database.
    pub taxon: String,
    /// Number of reads assigned to this taxon.
    pub reads: u32,
    /// Whether this taxon is on the biome's invasive-species list.
    pub invasive: bool,
    /// Whether this assignment is human (`Homo sapiens` or a human-classified
    /// bin). Any `true` here arms the privacy gate.
    pub human: bool,
}

/// The result of one triggered DNA sample.
///
/// Constructed only through [`DnaResult::new`], which derives
/// [`DnaResult::human_dna_present`] by scanning the assignments — the flag can
/// never be forgotten or set by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnaResult {
    /// Laboratory sample identifier.
    pub sample_id: String,
    /// When the sampler fired, ns since Unix epoch.
    pub sampled_ns: u64,
    /// Sampler node identity.
    pub node_id: u64,
    /// Sequence number of the sampler's own observation.
    pub sequence: u32,
    /// Total reads in the run.
    pub total_reads: u64,
    /// Taxon assignments, highest read count first.
    pub taxa: Vec<TaxonRead>,
    /// **The privacy gate's input.** True when any assignment is human.
    pub human_dna_present: bool,
}

impl DnaResult {
    /// Build a result, deriving the human-DNA flag from the assignments.
    #[must_use]
    pub fn new(
        sample_id: &str,
        sampled_ns: u64,
        node_id: u64,
        sequence: u32,
        mut taxa: Vec<TaxonRead>,
    ) -> Self {
        taxa.sort_by(|a, b| b.reads.cmp(&a.reads).then_with(|| a.taxon.cmp(&b.taxon)));
        let human_dna_present = taxa.iter().any(|t| t.human);
        DnaResult {
            sample_id: sample_id.to_string(),
            sampled_ns,
            node_id,
            sequence,
            total_reads: taxa.iter().map(|t| u64::from(t.reads)).sum(),
            taxa,
            human_dna_present,
        }
    }

    /// Non-human assignments. These stay usable **inside** the biome even
    /// when the privacy gate blocks the sample from disclosure.
    #[must_use]
    pub fn non_human_taxa(&self) -> Vec<&TaxonRead> {
        self.taxa.iter().filter(|t| !t.human).collect()
    }

    /// Reads assigned to `taxon` (0 if absent).
    #[must_use]
    pub fn reads_for(&self, taxon: &str) -> u32 {
        self.taxa
            .iter()
            .find(|t| t.taxon == taxon)
            .map_or(0, |t| t.reads)
    }
}

/// What actually leaves the biome for a disclosed DNA sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosedPayload {
    /// Sample identifier.
    pub sample_id: String,
    /// `(taxon, reads)` pairs — non-human assignments only.
    pub taxa: Vec<(String, u32)>,
    /// Location, coarsened per the biome disclosure policy (ADR-264 §6).
    pub geo: GeoPoint,
}

/// Outcome of the ADR-266 §4.1 item 4 privacy gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disclosure {
    /// The sample may be disclosed; here is exactly what leaves.
    Released(Box<DisclosedPayload>),
    /// The sample is blocked. Nothing derived from it leaves — not the taxa,
    /// not the counts, not the location.
    Refused {
        /// Sample identifier (the only thing the refusal itself names).
        sample_id: String,
        /// Why disclosure was refused.
        reason: String,
    },
}

impl Disclosure {
    /// The disclosed payload, if any.
    #[must_use]
    pub fn payload(&self) -> Option<&DisclosedPayload> {
        match self {
            Disclosure::Released(p) => Some(p),
            Disclosure::Refused { .. } => None,
        }
    }

    /// Whether the gate refused.
    #[must_use]
    pub fn is_refused(&self) -> bool {
        matches!(self, Disclosure::Refused { .. })
    }
}

/// **The ADR-266 §4.1 item 4 privacy gate.**
///
/// Airborne and waterborne DNA may contain human genetic material. If any
/// assignment in the run is human-classified, the *whole sample* is blocked
/// from disclosure — not filtered, not redacted, not coarsened. Filtering
/// would still disclose that a sample was taken at a place and time where a
/// person was present, which is the thing the rule exists to prevent.
///
/// ADR-264 §6 coarsening (applied here to released samples) is the ADR-266
/// §4.1 item 4 *minimum*, explicitly "not sufficient" — which is why this
/// gate sits in front of it.
#[must_use]
pub fn disclose(result: &DnaResult, geo: GeoPoint, coarsen_decimals: u32) -> Disclosure {
    if result.human_dna_present {
        return Disclosure::Refused {
            sample_id: result.sample_id.clone(),
            reason: "human-classified DNA present: disclosure blocked (ADR-266 §4.1 item 4)"
                .to_string(),
        };
    }
    Disclosure::Released(Box::new(DisclosedPayload {
        sample_id: result.sample_id.clone(),
        taxa: result
            .non_human_taxa()
            .into_iter()
            .map(|t| (t.taxon.clone(), t.reads))
            .collect(),
        geo: geo.coarsen(coarsen_decimals),
    }))
}

// ---------------------------------------------------------------------------
// Episodes
// ---------------------------------------------------------------------------

/// How the acoustic call and the DNA result relate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agreement {
    /// Both modalities name the same taxon.
    Confirmed,
    /// The DNA result contains no reads for the acoustically called taxon.
    Contradicted,
    /// No acoustic call to compare against (a DNA-first detection).
    NoAcousticCall,
    /// The sampler was never triggered.
    NotSampled,
}

/// One monitored episode from trigger to verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct Episode {
    /// Narrative label.
    pub label: String,
    /// Simulated time, ns since Unix epoch.
    pub at_ns: u64,
    /// Acoustic activity index as measured.
    pub acoustic_index: f64,
    /// Paired optical reference, lux.
    pub illuminance_lx: f64,
    /// Naive acoustic anomaly score (no circadian covariate).
    pub naive_z: f64,
    /// Circadian-adjusted anomaly score, using the optical reference.
    pub adjusted_z: f64,
    /// Whether the naive detector would have triggered the sampler.
    pub naive_would_trigger: bool,
    /// Whether the sampler was actually triggered.
    pub sampler_triggered: bool,
    /// Why, in one line.
    pub trigger_note: String,
    /// The acoustic classifier's species call, if it made one.
    pub acoustic_call: Option<String>,
    /// The DNA result, if a sample was taken.
    pub dna: Option<DnaResult>,
    /// Verdict of the acoustic/DNA cross-check.
    pub agreement: Agreement,
    /// Confidence in the acoustic call before the DNA result.
    pub confidence_before: f32,
    /// Confidence after the DNA result.
    pub confidence_after: f32,
    /// Disclosure outcome for this episode's sample.
    pub disclosure: Option<Disclosure>,
    /// Event raised, if any.
    pub event: Option<EnvironmentalEvent>,
    /// The disclosed (coarsened, re-signed) form of that event, if any.
    pub disclosed_event: Option<EnvironmentalEvent>,
}

/// Everything one deterministic run produces.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// The five episodes, in time order.
    pub episodes: Vec<Episode>,
    /// Contradictions recorded in the WorldGraph.
    pub contradiction_count: u64,
    /// Taxon nodes registered in the WorldGraph.
    pub taxon_nodes: Vec<String>,
    /// WorldGraph JSON (deterministic).
    pub graph_json: String,
    /// Largest weight on any DNA-derived evidence edge.
    pub max_bio_edge_weight: f32,
    /// Envelopes the real ingest pipeline verified.
    pub verified_samples: usize,
}

/// Acoustic anomaly trigger threshold (in baseline standard deviations).
pub const TRIGGER_Z: f64 = 3.0;
/// Illuminance above which a rise in acoustic activity is attributed to the
/// dawn/dusk chorus rather than to an anomaly.
pub const TWILIGHT_LX: f64 = 6.0;
/// Deterministic biome identity seed (examples only).
pub const BIOME_SEED: &[u8; 32] = b"rucelium-b3-dna-biome-seed-32b!!";

/// Slug a taxon name into a WorldGraph key.
#[must_use]
pub fn taxon_key(taxon: &str) -> String {
    format!("taxon/{}", taxon.to_lowercase().replace(' ', "-"))
}

// ---------------------------------------------------------------------------
// The scenario
// ---------------------------------------------------------------------------

/// Run the whole scenario deterministically.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run() -> Report {
    let mut rng = Rng::new(0x00B3_D4A0_5EED_1234);
    let station =
        GeoPoint::new(512_384_100, -32_117_400, 8_000).expect("valid station coordinates");

    let mut acoustic = Node::new(
        0x00B3_0000_0000_0001,
        SensorModality::Acoustic,
        station,
        "corridor acoustic array",
    );
    let mut optical = Node::new(
        0x00B3_0000_0000_0002,
        SensorModality::Optical,
        station,
        "corridor illuminance reference",
    );
    let mut sampler = Node::new(
        0x00B3_0000_0000_0003,
        SensorModality::Chemical,
        station,
        "eDNA autosampler",
    );
    let mut gw = Gateway::with_nodes(&[acoustic, optical, sampler]);
    // `Gateway::with_nodes` only reads the nodes; rebuild the emitting copies
    // so the signers keep their own sequence counters.
    acoustic = Node::new(
        0x00B3_0000_0000_0001,
        SensorModality::Acoustic,
        station,
        "corridor acoustic array",
    );
    optical = Node::new(
        0x00B3_0000_0000_0002,
        SensorModality::Optical,
        station,
        "corridor illuminance reference",
    );
    sampler = Node::new(
        0x00B3_0000_0000_0003,
        SensorModality::Chemical,
        station,
        "eDNA autosampler",
    );

    let mut graph = WorldGraph::new();
    graph.add_node(
        "ecosystem/river-corridor",
        GraphNode::Ecosystem {
            name: "Corridor survey reach".into(),
            kind: "river_corridor".into(),
            geo: station,
        },
    );
    let biome = Biome::new(BiomeConfig::new("biome/river-corridor"), BIOME_SEED);
    let coarsen = biome
        .config()
        .disclosure
        .coarsen_decimals
        .expect("the default disclosure policy coarsens");

    // Learn a nocturnal acoustic baseline over 40 dark quarter-hours.
    let baseline_mean = 41.0;
    let baseline_sd = 5.2;
    let mut verified = 0usize;
    for i in 0..40u64 {
        let ns = EPOCH_NS + i * 900 * NS_PER_S;
        let idx = baseline_mean + rng.noise(baseline_sd);
        let env = acoustic.emit(idx, ns, 1);
        gw.ingest(&env, ns + 1_000_000)
            .expect("acoustic sample verifies");
        let env = optical.emit(0.4 + rng.noise(0.1), ns, 1);
        gw.ingest(&env, ns + 1_000_000)
            .expect("optical sample verifies");
        verified += 2;
    }

    // Episode inputs: (label, hours after epoch, acoustic index, lux,
    // acoustic call, DNA taxa).
    struct Spec {
        label: &'static str,
        hour: u64,
        index: f64,
        lux: f64,
        call: Option<&'static str>,
        taxa: Vec<TaxonRead>,
    }
    let tr = |taxon: &str, reads: u32, invasive: bool, human: bool| TaxonRead {
        taxon: taxon.to_string(),
        reads,
        invasive,
        human,
    };
    let specs = [
        Spec {
            label: "22:10 roost pass — acoustic call, dark",
            hour: 12,
            index: 78.0,
            lux: 0.3,
            call: Some("Rhinolophus ferrumequinum"),
            taxa: vec![
                tr("Rhinolophus ferrumequinum", 4_180, false, false),
                tr("Pipistrellus pipistrellus", 611, false, false),
                tr("Salmo trutta", 208, false, false),
            ],
        },
        Spec {
            label: "05:05 dawn chorus — circadian confounder",
            hour: 19,
            index: 96.0,
            lux: 21.0,
            call: None,
            taxa: Vec::new(),
        },
        Spec {
            label: "23:40 Myotis call — genetically contradicted",
            hour: 25,
            index: 71.0,
            lux: 0.2,
            call: Some("Myotis daubentonii"),
            taxa: vec![
                tr("Pipistrellus pygmaeus", 2_905, false, false),
                tr("Anguilla anguilla", 774, false, false),
                tr("Gammarus pulex", 522, false, false),
            ],
        },
        Spec {
            label: "01:20 pontoon anomaly — invasive bivalve",
            hour: 27,
            index: 69.0,
            lux: 0.2,
            call: None,
            taxa: vec![
                tr("Dreissena polymorpha", 3_461, true, false),
                tr("Gammarus pulex", 940, false, false),
                tr("Salmo trutta", 305, false, false),
            ],
        },
        Spec {
            label: "02:55 riverside path — HUMAN DNA PRESENT",
            hour: 29,
            index: 66.0,
            lux: 0.5,
            call: None,
            taxa: vec![
                tr("Homo sapiens", 5_102, false, true),
                tr("Rattus norvegicus", 1_188, false, false),
                tr("Canis lupus familiaris", 640, false, false),
                tr("Salmo trutta", 121, false, false),
            ],
        },
    ];

    let mut episodes = Vec::new();
    let mut max_bio_edge_weight = 0.0_f32;

    for (i, spec) in specs.iter().enumerate() {
        let ns = EPOCH_NS + spec.hour * 3_600 * NS_PER_S;
        let env = acoustic.emit(spec.index, ns, 1);
        let ac = gw
            .ingest(&env, ns + 1_000_000)
            .expect("acoustic sample verifies");
        let env = optical.emit(spec.lux, ns, 1);
        let op = gw
            .ingest(&env, ns + 1_000_000)
            .expect("optical sample verifies");
        verified += 2;
        let sensor_key = graph.register_observation(ac.sample());
        graph.register_observation(op.sample());

        let naive_z = (ac.sample().value - baseline_mean) / baseline_sd;
        // Circadian adjustment: above civil-twilight illuminance the dawn/dusk
        // chorus explains a large slice of the activity index. The optical
        // reference — a conventional sensor — supplies the covariate.
        let circadian_lift = if op.sample().value > TWILIGHT_LX {
            42.0
        } else {
            0.0
        };
        let adjusted_z = (ac.sample().value - baseline_mean - circadian_lift) / baseline_sd;
        let naive_would_trigger = naive_z >= TRIGGER_Z;
        let sampler_triggered = adjusted_z >= TRIGGER_Z;

        let (dna, disclosure, sampler_obs): (_, _, Option<EnvSample>) = if sampler_triggered {
            // The sampler logs its own observation (eDNA yield, ng/L) through
            // the same verified path as every other node.
            let yield_ng = 18.0 + rng.noise(2.0);
            let env = sampler.emit(yield_ng, ns + 60 * NS_PER_S, 1);
            let sm = gw
                .ingest(&env, ns + 61 * NS_PER_S)
                .expect("sampler observation verifies");
            verified += 1;
            let seq = sm.sample().sequence;
            let result = DnaResult::new(
                &format!("edna-{:02}", i + 1),
                ns + 60 * NS_PER_S,
                sm.sample().node_id,
                seq,
                spec.taxa.clone(),
            );
            let d = disclose(&result, station, coarsen);
            (Some(result), Some(d), Some(sm.sample().clone()))
        } else {
            (None, None, None)
        };

        // Cross-check the acoustic call against the genetics.
        let agreement = match (&spec.call, &dna) {
            (_, None) => Agreement::NotSampled,
            (None, Some(_)) => Agreement::NoAcousticCall,
            (Some(call), Some(d)) => {
                if d.reads_for(call) > 0 {
                    Agreement::Confirmed
                } else {
                    Agreement::Contradicted
                }
            }
        };
        let confidence_before = if spec.call.is_some() { 0.58 } else { 0.0 };
        let confidence_after = match agreement {
            Agreement::Confirmed => 0.91,
            Agreement::Contradicted => 0.19,
            _ => confidence_before,
        };

        // Enrich the graph with taxon nodes and typed evidence edges.
        if let Some(d) = &dna {
            for t in d.non_human_taxa() {
                let key = taxon_key(&t.taxon);
                graph.add_node(
                    key.clone(),
                    GraphNode::Ecosystem {
                        name: t.taxon.clone(),
                        kind: "taxon".into(),
                        geo: station,
                    },
                );
                let want = (t.reads as f32 / 10_000.0).min(1.0);
                let weight = want.min(BIO_MAX_EVIDENCE_WEIGHT);
                graph
                    .add_edge(
                        &sensor_key,
                        &key,
                        EdgeKind::Supports,
                        weight,
                        format!("edna {} reads (capped evidence)", t.reads),
                    )
                    .expect("both endpoints registered");
                max_bio_edge_weight = max_bio_edge_weight.max(weight);
            }
            if agreement == Agreement::Contradicted {
                let call = spec.call.expect("contradiction implies a call");
                let key = taxon_key(call);
                graph.add_node(
                    key.clone(),
                    GraphNode::Ecosystem {
                        name: call.to_string(),
                        kind: "taxon".into(),
                        geo: station,
                    },
                );
                graph
                    .record_contradiction(
                        &sensor_key,
                        &key,
                        format!("acoustic called {call}; 0 reads in sample {}", d.sample_id),
                    )
                    .expect("both endpoints registered");
            }
        }

        // Invasive detection. Molecular evidence only, so the cap applies.
        let invasive: Vec<&TaxonRead> = dna
            .as_ref()
            .map(|d| {
                d.non_human_taxa()
                    .into_iter()
                    .filter(|t| t.invasive)
                    .collect()
            })
            .unwrap_or_default();
        let event = if invasive.is_empty() {
            None
        } else {
            let obs = sampler_obs.as_ref().expect("a sample was taken");
            Some(EnvironmentalEvent {
                evidence_digest: Some(evidence_digest(&[obs])),
                spec_version: SPEC_VERSION.into(),
                event_id: format!("evt-b3-invasive-{:02}", i + 1),
                biome_id: "biome/river-corridor".into(),
                kind: EventKind::Anomaly,
                severity: bio_only_severity_cap(Severity::Warning),
                modality: SensorModality::Chemical,
                geo: station,
                window_start_ns: ns,
                window_end_ns: ns + 60 * NS_PER_S,
                detected_ns: ns + 60 * NS_PER_S,
                evidence: vec![EvidenceRef {
                    node_id: obs.node_id,
                    sequence: obs.sequence,
                }],
                confidence: 0.74,
                message: format!(
                    "invasive taxon {} detected in eDNA ({} reads); conventional survey required \
                     before escalation",
                    invasive[0].taxon, invasive[0].reads
                ),
                signature_hex: None,
                signer_pubkey_hex: None,
            })
        };
        // Only samples that cleared the privacy gate may be disclosed.
        let disclosed_event = match (&event, &disclosure) {
            (Some(ev), Some(d)) if !d.is_refused() => {
                let mut signed = ev.clone();
                biome.sign_event(&mut signed);
                biome.disclose_event(&signed, ns + 120 * NS_PER_S)
            }
            _ => None,
        };

        episodes.push(Episode {
            label: spec.label.to_string(),
            at_ns: ns,
            acoustic_index: ac.sample().value,
            illuminance_lx: op.sample().value,
            naive_z,
            adjusted_z,
            naive_would_trigger,
            sampler_triggered,
            trigger_note: if sampler_triggered {
                "anomaly survives the circadian cross-check → sampler fired".into()
            } else {
                "activity explained by illuminance (dawn chorus) → NO sample taken".into()
            },
            acoustic_call: spec.call.map(str::to_string),
            dna,
            agreement,
            confidence_before,
            confidence_after,
            disclosure,
            event,
            disclosed_event,
        });
    }

    let taxon_nodes = {
        let mut v: Vec<String> = graph
            .edges()
            .filter(|e| e.to.starts_with("taxon/"))
            .map(|e| e.to.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    };

    Report {
        episodes,
        contradiction_count: graph.contradiction_count(),
        taxon_nodes,
        graph_json: graph.to_json(),
        max_bio_edge_weight,
        verified_samples: verified,
    }
}

/// Print the ADR-266 §4.1 acceptance bar and disclaim this scenario.
fn print_not_validated() {
    println!("\n  NOT VALIDATED");
    println!("  ADR-266 §4 track B3 is a RESEARCH TRACK, not a roadmap item and not a");
    println!("  product claim. The §4.1 item 3 acceptance bar is: one biological signal");
    println!("  predicts a CONFIRMED environmental condition >= 30 MINUTES EARLIER than the");
    println!("  conventional sensor, at > 90% PRECISION, across 3 INDEPENDENT LOCATIONS,");
    println!("  with NO PER-LOCATION RETRAINING. This scenario is one simulated station");
    println!("  with hand-written metabarcoding results; it demonstrates the DISCIPLINE");
    println!("  (paired optical reference, circadian confounder rejection, contradiction");
    println!("  edges, capped evidence, the human-DNA gate) and is NO evidence toward any");
    println!("  part of that bar. §4.1 item 4 additionally rates B3 privacy risk 5/5: no");
    println!("  airborne-DNA pilot may proceed without an explicit human-DNA handling");
    println!("  policy, and ADR-264 §6 coarsening/delay/access control are the MINIMUM,");
    println!("  explicitly NOT sufficient.");
}

fn main() {
    banner(
        "airborne-dna — ADR-266 B3 anomaly-triggered eDNA observatory",
        "acoustic + paired optical reference → DNA sampler → WorldGraph taxa",
    );
    let r = run();

    for ep in &r.episodes {
        println!("\n  {}\n", ep.label);
        line(
            "acoustic activity index",
            format!("{:.1}", ep.acoustic_index),
        );
        line(
            "paired optical reference",
            format!("{:.1} lx", ep.illuminance_lx),
        );
        line("naive anomaly z", format!("{:.2}", ep.naive_z));
        line(
            "circadian-adjusted anomaly z",
            format!("{:.2}", ep.adjusted_z),
        );
        line("naive detector would have sampled", ep.naive_would_trigger);
        line("sampler actually triggered", ep.sampler_triggered);
        println!("  -> {}", ep.trigger_note);
        if let Some(call) = &ep.acoustic_call {
            line("acoustic classifier call", call);
        }
        if let Some(d) = &ep.dna {
            line(
                "sample id / total reads",
                format!("{} / {}", d.sample_id, d.total_reads),
            );
            for t in &d.taxa {
                println!(
                    "      {:<32} {:>7} reads{}{}",
                    t.taxon,
                    t.reads,
                    if t.invasive { "  [INVASIVE]" } else { "" },
                    if t.human { "  [HUMAN]" } else { "" }
                );
            }
            line("human DNA present", d.human_dna_present);
        }
        line("acoustic/DNA agreement", format!("{:?}", ep.agreement));
        if ep.acoustic_call.is_some() {
            line(
                "confidence before → after DNA",
                format!("{:.2} → {:.2}", ep.confidence_before, ep.confidence_after),
            );
        }
        match &ep.disclosure {
            Some(Disclosure::Released(p)) => {
                line("disclosure", "RELEASED (coarsened per ADR-264 §6)");
                line("disclosed taxa", p.taxa.len());
                line(
                    "disclosed location",
                    format!("{:.2}, {:.2}", p.geo.latitude_deg(), p.geo.longitude_deg()),
                );
            }
            Some(Disclosure::Refused { sample_id, reason }) => {
                line("disclosure", "REFUSED");
                line("refused sample", sample_id);
                println!("  !! {reason}");
                println!("  !! nothing from this sample leaves: no taxa, no counts, no location.");
                let internal = ep.dna.as_ref().map_or(0, |d| d.non_human_taxa().len());
                line("non-human taxa still usable in-biome", internal);
            }
            None => line("disclosure", "n/a — no sample taken"),
        }
        if let Some(ev) = &ep.event {
            ev.validate().expect("event is structurally valid");
            line(
                "event severity (bio-only cap applied)",
                format!("{:?}", ev.severity),
            );
            line("event confidence", format!("{:.2}", ev.confidence));
            println!("  -> {}", ev.message);
        }
        if let Some(de) = &ep.disclosed_event {
            line("federated event verifies", verify_event(de));
            line(
                "federated event location (coarsened)",
                format!(
                    "{:.2}, {:.2}",
                    de.geo.latitude_deg(),
                    de.geo.longitude_deg()
                ),
            );
        }
    }

    println!("\n  WORLDGRAPH\n");
    line("taxon nodes linked by evidence edges", r.taxon_nodes.len());
    for t in &r.taxon_nodes {
        println!("      {t}");
    }
    println!("      (the WorldGraph is biome-resident DerivedFeature data: the blocked");
    println!("       sample's non-human taxa live here and NEVER federate; `Homo sapiens`");
    println!("       is never registered as a node at all.)");
    line(
        "contradictions recorded (never resolved)",
        r.contradiction_count,
    );
    line(
        "max DNA evidence edge weight",
        format!("{:.2}", r.max_bio_edge_weight),
    );
    line(
        "hard cap on that weight",
        format!("{BIO_MAX_EVIDENCE_WEIGHT:.2}"),
    );
    line("envelopes cryptographically verified", r.verified_samples);
    line("WorldGraph JSON bytes (deterministic)", r.graph_json.len());

    print_not_validated();
    synthetic_footer("Metabarcoding results here are hand-written, not sequenced.");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn episode<'a>(r: &'a Report, needle: &str) -> &'a Episode {
        r.episodes
            .iter()
            .find(|e| e.label.contains(needle))
            .expect("episode present")
    }

    #[test]
    fn genetic_confirmation_raises_confidence() {
        let r = run();
        let ep = episode(&r, "roost pass");
        assert_eq!(ep.agreement, Agreement::Confirmed);
        assert!(ep.confidence_after > ep.confidence_before);
        let d = ep.dna.as_ref().expect("sample taken");
        assert!(d.reads_for("Rhinolophus ferrumequinum") > 0);
        // The confirmation is a Supports edge to the taxon node, capped.
        assert!(r
            .taxon_nodes
            .contains(&taxon_key("Rhinolophus ferrumequinum")));
        assert!(r.max_bio_edge_weight <= BIO_MAX_EVIDENCE_WEIGHT);
    }

    #[test]
    fn contradiction_is_recorded_and_never_escalates() {
        let r = run();
        let ep = episode(&r, "Myotis call");
        assert_eq!(ep.agreement, Agreement::Contradicted);
        let d = ep.dna.as_ref().expect("sample taken");
        assert_eq!(d.reads_for("Myotis daubentonii"), 0);
        // Confidence fell, no event was raised, and the disagreement is
        // tracked in the graph rather than silently resolved.
        assert!(ep.confidence_after < ep.confidence_before);
        assert!(ep.event.is_none());
        assert!(ep.disclosed_event.is_none());
        assert_eq!(r.contradiction_count, 1);
        assert!(r.graph_json.contains("acoustic called Myotis daubentonii"));
    }

    #[test]
    fn invasive_detection_raises_an_event_capped_at_advisory() {
        assert_eq!(
            bio_only_severity_cap(Severity::Critical),
            Severity::Advisory
        );
        assert_eq!(bio_only_severity_cap(Severity::Warning), Severity::Advisory);
        let r = run();
        let ep = episode(&r, "pontoon anomaly");
        let ev = ep.event.as_ref().expect("invasive event raised");
        ev.validate().unwrap();
        assert_eq!(ev.severity, Severity::Advisory);
        assert!(ev.message.contains("Dreissena polymorpha"));
        assert!(ev
            .evidence_digest
            .as_ref()
            .is_some_and(|d| d.starts_with("sha256:")));
        // It federates, coarsened and re-signed by the biome.
        let de = ep.disclosed_event.as_ref().expect("event disclosed");
        assert!(verify_event(de));
        assert_ne!(de.geo, ev.geo, "disclosure must coarsen the location");
        // Exactly one event in the whole run.
        assert_eq!(r.episodes.iter().filter(|e| e.event.is_some()).count(), 1);
    }

    #[test]
    fn human_dna_blocks_disclosure_while_non_human_results_still_flow() {
        let r = run();
        let ep = episode(&r, "HUMAN DNA");
        let d = ep.dna.as_ref().expect("sample taken");
        assert!(d.human_dna_present);
        let disc = ep.disclosure.as_ref().expect("gate ran");
        assert!(disc.is_refused());
        assert!(disc.payload().is_none());
        assert!(ep.disclosed_event.is_none());
        // The non-human taxa remain usable inside the biome.
        assert_eq!(d.non_human_taxa().len(), 3);
        assert!(d.non_human_taxa().iter().all(|t| !t.human));
        // NO TAXA LEAK: nothing from the blocked sample appears in any
        // disclosed payload anywhere in the run.
        let blocked: Vec<&str> = d.taxa.iter().map(|t| t.taxon.as_str()).collect();
        let released: Vec<&DisclosedPayload> = r
            .episodes
            .iter()
            .filter_map(|e| e.disclosure.as_ref().and_then(Disclosure::payload))
            .collect();
        assert_eq!(released.len(), 3, "the three clean samples still flow");
        for p in &released {
            assert_ne!(p.sample_id, d.sample_id);
            for (taxon, _) in &p.taxa {
                assert!(
                    !taxon.contains("Homo"),
                    "human assignment leaked into a disclosed payload"
                );
            }
        }
        // The human assignment is never registered in the graph either.
        assert!(!r.graph_json.contains("Homo sapiens"));
        assert!(!r.taxon_nodes.contains(&taxon_key("Homo sapiens")));
        // Species unique to the blocked sample must appear in no payload.
        for name in blocked
            .iter()
            .filter(|n| **n != "Salmo trutta" && **n != "Gammarus pulex")
        {
            assert!(
                !released
                    .iter()
                    .any(|p| p.taxa.iter().any(|(t, _)| t == name)),
                "{name} leaked from the blocked sample"
            );
        }
    }

    #[test]
    fn circadian_confounder_is_rejected_and_no_sample_is_taken() {
        let r = run();
        let ep = episode(&r, "dawn chorus");
        // The naive detector sees the largest anomaly of the whole run.
        assert!(ep.naive_would_trigger);
        assert!(ep.naive_z > r.episodes.iter().map(|e| e.naive_z).fold(0.0, f64::max) - 1e-9);
        // The paired optical reference explains it: no trigger, no sample,
        // no event, nothing escalated.
        assert!(ep.illuminance_lx > TWILIGHT_LX);
        assert!(!ep.sampler_triggered);
        assert_eq!(ep.agreement, Agreement::NotSampled);
        assert!(ep.dna.is_none());
        assert!(ep.disclosure.is_none());
        assert!(ep.event.is_none());
    }

    #[test]
    fn scenario_is_fully_deterministic() {
        let a = run();
        let b = run();
        assert_eq!(a, b);
        assert!(a.verified_samples > 80);
    }
}
