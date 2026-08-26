//! # wildfire-risk — deployment wedge #4 (ADR-266 §3.1)
//!
//! Wildfire risk is the wedge that **monetizes evidence discipline**. The
//! buyers — forestry, utilities, insurers, resorts — are usually *not* the
//! fire service, which means the product is a defensible risk position, and a
//! single false Critical alert costs more credibility than a hundred correct
//! Advisories earn.
//!
//! So the guarantee this example exists to prove is the ADR-266 §3.1 line for
//! this wedge, verbatim:
//!
//! > **RF severity cap holds**: RF may support or contradict, never
//! > independently raise a critical fire alert.
//!
//! Concretely:
//!
//! * a composite risk index over temperature, humidity, wind, and soil
//!   moisture escalates Advisory → Watch → Warning as the fuel dries;
//! * an **RF-only "detection"**, however confident the radio is, is routed
//!   through [`rf_only_severity_cap`] and lands at
//!   [`Severity::Advisory`] — never higher;
//! * only **physical** evidence — a PM spike *and* optical smoke together —
//!   justifies [`Severity::Critical`]. A PM spike on its own (a harvester
//!   raising dust) does not;
//! * a humidity sensor cooked by the heat has its quality collapse, is
//!   excluded from the index, and its absence is **reported** as a signed
//!   event rather than silently absorbed.
//!
//! ```bash
//! cargo run  -p rucelium-examples --bin wildfire-risk
//! cargo test -p rucelium-examples --bin wildfire-risk
//! ```

use rucelium_core::{
    EnvironmentalEvent, EventKind, EvidenceRef, GeoPoint, SensorModality, Severity, SPEC_VERSION,
};
use rucelium_examples::{banner, line, synthetic_footer, Gateway, Node, Rng, EPOCH_NS, NS_PER_S};
use rucelium_worldgraph::{
    assess_plausibility, fuse_rf_context, rf_only_severity_cap, RfContext, WorldGraph,
    RF_MAX_EVIDENCE_WEIGHT,
};

// ---------------------------------------------------------------------------
// Scenario constants
// ---------------------------------------------------------------------------

/// The biome under fire watch.
pub const BIOME_ID: &str = "biome/ponderosa-ridge";

/// Simulated seconds between rounds (1 hour).
pub const ROUND_S: u64 = 3_600;

/// Number of rounds: a 16-hour drying day.
pub const ROUNDS: usize = 16;

/// Provisioned spore nodes.
pub const NODE_COUNT: usize = 7;

/// Quality below which an observation is excluded from the risk index.
pub const QUALITY_FLOOR: f32 = 0.50;

/// Composite risk at or above which an Advisory is raised.
pub const ADVISORY_RISK: f64 = 0.30;
/// Composite risk at or above which a Watch is raised.
pub const WATCH_RISK: f64 = 0.45;
/// Composite risk at or above which a Warning is raised — and the highest
/// severity any amount of *environmental* evidence can reach on its own.
pub const WARNING_RISK: f64 = 0.60;

/// PM2.5 (µg/m³) that counts as physical combustion evidence.
pub const PM_CRITICAL_UG_M3: f64 = 120.0;
/// Optical smoke-obscuration index that counts as physical combustion
/// evidence.
pub const SMOKE_CRITICAL_INDEX: f64 = 0.60;

/// Calibration record referenced by every node on the ridge.
pub const CALIBRATION_ID: u32 = 41;

/// Temporal window (ns) within which RF context says anything about a sample.
pub const RF_WINDOW_NS: u64 = 3_600 * NS_PER_S;

/// The round at which the humidity sensor at the exposed site cooks.
pub const SENSOR_FAILURE_ROUND: usize = 10;

/// The round at which a harvester raises a dust plume — PM only, no smoke.
pub const DUST_ROUND: usize = 12;

/// The round at which combustion actually starts — PM *and* optical smoke.
pub const IGNITION_ROUND: usize = 13;

// Node-table indices.
/// Air-temperature station.
pub const TEMP: usize = 0;
/// Relative-humidity sensor, sheltered site.
pub const RH_A: usize = 1;
/// Relative-humidity sensor, exposed site — this one fails in the heat.
pub const RH_B: usize = 2;
/// Anemometer.
pub const WIND: usize = 3;
/// Soil-moisture probe (fuel dryness proxy).
pub const SOIL: usize = 4;
/// PM2.5 monitor.
pub const PM: usize = 5;
/// Optical smoke-obscuration sensor.
pub const SMOKE: usize = 6;

// ---------------------------------------------------------------------------
// Synthetic drying day
// ---------------------------------------------------------------------------

/// Noise-free truth for sensor `idx` at `round`, in that sensor's unit.
#[must_use]
pub fn truth(idx: usize, round: usize) -> f64 {
    let t = round as f64;
    match idx {
        TEMP => 22.0 + 1.1 * t,
        // The exposed hygrometer stops reporting anything physical once its
        // element cooks — the value is nonsense and it says so via quality.
        RH_B if round >= SENSOR_FAILURE_ROUND => 3.0,
        RH_A | RH_B => 62.0 - 3.0 * t,
        WIND => 4.0 + 0.9 * t,
        SOIL => 24.0 - 1.2 * t,
        PM if round >= IGNITION_ROUND => 165.0,
        PM if round == DUST_ROUND => 130.0,
        PM => 10.0 + 1.5 * t,
        SMOKE if round >= IGNITION_ROUND => 0.84,
        _ => 0.02,
    }
}

/// Reported quality for sensor `idx` at `round`.
#[must_use]
pub fn quality(idx: usize, round: usize) -> f64 {
    if idx == RH_B && round >= SENSOR_FAILURE_ROUND {
        0.11
    } else {
        0.97
    }
}

/// Per-sensor noise standard deviation.
#[must_use]
pub fn noise_sd(idx: usize) -> f64 {
    match idx {
        TEMP => 0.03,
        RH_A | RH_B => 0.06,
        WIND | SOIL => 0.03,
        PM => 0.20,
        _ => 0.002,
    }
}

/// Measurement time of round `round`.
#[must_use]
pub fn round_ns(round: usize) -> u64 {
    EPOCH_NS + (round as u64) * ROUND_S * NS_PER_S
}

/// Build a geo point, panicking on a coordinate the example itself got wrong.
fn geo(latitude_e7: i32, longitude_e7: i32, altitude_mm: i32) -> GeoPoint {
    GeoPoint::new(latitude_e7, longitude_e7, altitude_mm).expect("example coordinates are in range")
}

/// Provision the seven spore nodes of the fire-watch cluster.
#[must_use]
pub fn provision() -> Vec<Node> {
    vec![
        Node::new(
            0x00F4_0000_0000_0001,
            SensorModality::Weather,
            geo(391_200_000, -1_064_000_000, 2_180_000),
            "AT-1 air temperature",
        ),
        Node::new(
            0x00F4_0000_0000_0002,
            SensorModality::Weather,
            geo(391_206_000, -1_064_004_000, 2_178_000),
            "RH-1 humidity, sheltered",
        ),
        Node::new(
            0x00F4_0000_0000_0003,
            SensorModality::Weather,
            geo(391_214_000, -1_063_988_000, 2_205_000),
            "RH-2 humidity, exposed ridge",
        ),
        Node::new(
            0x00F4_0000_0000_0004,
            SensorModality::Weather,
            geo(391_219_000, -1_063_980_000, 2_211_000),
            "AN-1 anemometer",
        ),
        Node::new(
            0x00F4_0000_0000_0005,
            SensorModality::SoilMoisture,
            geo(391_193_000, -1_064_012_000, 2_161_000),
            "SM-1 fuel-bed soil moisture",
        ),
        Node::new(
            0x00F4_0000_0000_0006,
            SensorModality::AirQuality,
            geo(391_188_000, -1_064_020_000, 2_154_000),
            "PM-1 particulate monitor",
        ),
        Node::new(
            0x00F4_0000_0000_0007,
            SensorModality::Optical,
            geo(391_190_000, -1_064_016_000, 2_158_000),
            "OS-1 optical smoke obscuration",
        ),
    ]
}

/// The RuView RF context observation for a given round. The radio is *very*
/// sure it sees a thermal plume moving — and it is still only context.
#[must_use]
pub fn rf_context(at_ns: u64, confidence: f32) -> RfContext {
    // Built directly rather than via `RfContext::from_field_event`: the
    // examples package does not depend on `rufield-core`. Every field is
    // exactly what the RuField MFS WiFi-CSI encoder would have produced.
    RfContext {
        source_event_id: "rf-ridge-plume-01".to_string(),
        device_id: "rf-ridge-01".to_string(),
        confidence,
        motion_energy: Some(0.90),
        labels: vec!["thermal_plume_motion".to_string()],
        timestamp_ns: at_ns,
    }
}

// ---------------------------------------------------------------------------
// Risk model
// ---------------------------------------------------------------------------

/// Normalize a value onto `0.0..=1.0` between `low` and `high`.
fn norm(value: f64, low: f64, high: f64) -> f64 {
    ((value - low) / (high - low)).clamp(0.0, 1.0)
}

/// Composite fire-risk index from the *environmental* sensors only.
///
/// Hotter, drier, windier, and drier-fuelled all push the index up, so a
/// drying day produces a monotonically rising index — which the tests assert.
#[must_use]
pub fn risk_index(temp_c: f64, humidity_pct: f64, wind_kmh: f64, soil_pct: f64) -> f64 {
    0.30 * norm(temp_c, 15.0, 45.0)
        + 0.30 * norm(70.0 - humidity_pct, 0.0, 60.0)
        + 0.20 * norm(wind_kmh, 0.0, 40.0)
        + 0.20 * norm(30.0 - soil_pct, 0.0, 30.0)
}

/// Severity for a risk index, given whether **physical** combustion evidence
/// is present.
///
/// Environmental risk alone tops out at [`Severity::Warning`]: dry, hot, and
/// windy is not a fire. [`Severity::Critical`] requires physical evidence that
/// something is actually burning.
#[must_use]
pub fn severity_for(risk: f64, physical_evidence: bool) -> Option<Severity> {
    if risk >= WARNING_RISK {
        Some(if physical_evidence {
            Severity::Critical
        } else {
            Severity::Warning
        })
    } else if risk >= WATCH_RISK {
        Some(Severity::Watch)
    } else if risk >= ADVISORY_RISK {
        Some(Severity::Advisory)
    } else {
        None
    }
}

/// One hour of the fire-watch day.
#[derive(Debug, Clone, PartialEq)]
pub struct RiskRound {
    /// Hour of the drying day.
    pub hour: usize,
    /// Composite environmental risk index.
    pub risk: f64,
    /// Severity raised this hour, if any.
    pub severity: Option<Severity>,
    /// Environmental sensors that contributed (quality above the floor).
    pub sensors_used: usize,
    /// Node ids excluded this hour for collapsed quality.
    pub excluded: Vec<u64>,
    /// Whether PM *and* optical smoke both indicated combustion.
    pub physical_evidence: bool,
    /// Measured PM2.5, µg/m³.
    pub pm_ug_m3: f64,
    /// Measured optical smoke-obscuration index.
    pub smoke_index: f64,
}

/// Everything one fire-watch day produced.
#[derive(Debug, Default)]
pub struct WildfireRun {
    /// Hour-by-hour risk assessment.
    pub rounds: Vec<RiskRound>,
    /// Escalation events, one per severity step up.
    pub events: Vec<EnvironmentalEvent>,
    /// The sensor-degradation report — the absence is announced, not hidden.
    pub degradation: Option<EnvironmentalEvent>,
    /// The WorldGraph, including the capped RF evidence edge.
    pub graph: WorldGraph,
    /// Node ids excluded from the index at any point in the day.
    pub excluded_nodes: Vec<u64>,
}

impl WildfireRun {
    /// The highest severity raised anywhere in the day.
    #[must_use]
    pub fn peak_severity(&self) -> Option<Severity> {
        self.events.iter().map(|e| e.severity).max()
    }
}

/// Assemble a fire event.
fn fire_event(
    id: &str,
    kind: EventKind,
    severity: Severity,
    modality: SensorModality,
    at: GeoPoint,
    window: (u64, u64),
    evidence: Vec<EvidenceRef>,
    confidence: f32,
    message: String,
) -> EnvironmentalEvent {
    let event = EnvironmentalEvent {
        evidence_digest: None,
        spec_version: SPEC_VERSION.to_string(),
        event_id: id.to_string(),
        biome_id: BIOME_ID.to_string(),
        kind,
        severity,
        modality,
        geo: at,
        window_start_ns: window.0,
        window_end_ns: window.1,
        detected_ns: window.1,
        evidence,
        confidence,
        message,
        signature_hex: None,
        signer_pubkey_hex: None,
    };
    event.validate().expect("scenario events are well-formed");
    event
}

/// Build the event an **RF-only** "detection" would produce.
///
/// The detector is allowed to *propose* whatever severity it likes; the
/// severity that reaches the event is whatever survives
/// [`rf_only_severity_cap`]. This is the ADR-264 §8 rule as a function call,
/// and it is the whole point of this example.
#[must_use]
pub fn rf_only_alert(rf: &RfContext, proposed: Severity, at: GeoPoint) -> EnvironmentalEvent {
    let severity = rf_only_severity_cap(proposed);
    fire_event(
        &format!("wildfire:rf-only:{}", rf.source_event_id),
        EventKind::WildfireRisk,
        severity,
        SensorModality::WifiCsi,
        at,
        (rf.timestamp_ns, rf.timestamp_ns),
        // RF context is not a spore node: node id 0 is the graph's convention
        // for a string-identified RF device (see `fuse_rf_context`).
        vec![EvidenceRef {
            node_id: 0,
            sequence: 0,
        }],
        rf.confidence,
        format!(
            "RF context `{}` from {} proposed {proposed:?} at confidence {:.2}; \
             capped to {severity:?} — RF is never independently sufficient (ADR-264 §8)",
            rf.labels.join(","),
            rf.device_id,
            rf.confidence
        ),
    )
}

/// Run the 16-hour fire-watch day.
#[must_use]
pub fn run_fire_watch() -> WildfireRun {
    let mut nodes = provision();
    let mut gateway = Gateway::with_nodes(&nodes);
    let mut rng = Rng::new(0x00F4_1FE0_0000_2026);
    let mut run = WildfireRun::default();
    let mut highest: Option<Severity> = None;

    for round in 0..ROUNDS {
        let measured = round_ns(round);
        let received = measured + 1_000_000;
        let mut values = [0.0f64; NODE_COUNT];
        let mut qualities = [0.0f32; NODE_COUNT];
        let mut sequences = [0u32; NODE_COUNT];
        let mut excluded = Vec::new();

        for idx in 0..NODE_COUNT {
            let value = truth(idx, round) + rng.noise(noise_sd(idx));
            let envelope =
                nodes[idx].emit_with_quality(value, measured, CALIBRATION_ID, quality(idx, round));
            let sealed = gateway
                .ingest(&envelope, received)
                .expect("a node's own signed envelope must ingest");
            let sample = sealed.sample();
            run.graph.register_observation(sample);
            values[idx] = sample.value;
            qualities[idx] = sample.quality;
            sequences[idx] = sample.sequence;
            if sample.quality < QUALITY_FLOOR {
                excluded.push(sample.node_id);
                if !run.excluded_nodes.contains(&sample.node_id) {
                    run.excluded_nodes.push(sample.node_id);
                    // The absence is announced. A quietly missing sensor is
                    // how a risk index silently becomes a lie.
                    run.degradation = Some(fire_event(
                        &format!("wildfire:sensor-degraded:{}", sample.node_id),
                        EventKind::SensorQuarantined,
                        Severity::Watch,
                        sample.modality,
                        sample.geo,
                        (measured, measured),
                        vec![EvidenceRef {
                            node_id: sample.node_id,
                            sequence: sample.sequence,
                        }],
                        0.98,
                        format!(
                            "{} quality collapsed to {:.2} (floor {QUALITY_FLOOR:.2}) at {:.1} C — \
                             excluded from the risk index and reported, not silently dropped",
                            nodes[idx].label,
                            sample.quality,
                            values[TEMP]
                        ),
                    ));
                }
            }
        }

        // Humidity is the mean of whatever hygrometers are still trustworthy.
        let humidity: Vec<f64> = [RH_A, RH_B]
            .into_iter()
            .filter(|&i| qualities[i] >= QUALITY_FLOOR)
            .map(|i| values[i])
            .collect();
        let humidity_pct = if humidity.is_empty() {
            0.0
        } else {
            humidity.iter().sum::<f64>() / humidity.len() as f64
        };
        let sensors_used = [TEMP, RH_A, RH_B, WIND, SOIL]
            .into_iter()
            .filter(|&i| qualities[i] >= QUALITY_FLOOR)
            .count();

        let risk = risk_index(values[TEMP], humidity_pct, values[WIND], values[SOIL]);
        let physical_evidence =
            values[PM] > PM_CRITICAL_UG_M3 && values[SMOKE] > SMOKE_CRITICAL_INDEX;
        let severity = severity_for(risk, physical_evidence);

        run.rounds.push(RiskRound {
            hour: round,
            risk,
            severity,
            sensors_used,
            excluded: excluded.clone(),
            physical_evidence,
            pm_ug_m3: values[PM],
            smoke_index: values[SMOKE],
        });

        // Escalate only when the severity actually steps up.
        if let Some(severity) = severity {
            if highest.is_none_or(|h| severity > h) {
                highest = Some(severity);
                let mut evidence: Vec<EvidenceRef> = [TEMP, RH_A, RH_B, WIND, SOIL]
                    .into_iter()
                    .filter(|&i| qualities[i] >= QUALITY_FLOOR)
                    .map(|i| EvidenceRef {
                        node_id: nodes[i].node_id,
                        sequence: sequences[i],
                    })
                    .collect();
                if physical_evidence {
                    for i in [PM, SMOKE] {
                        evidence.push(EvidenceRef {
                            node_id: nodes[i].node_id,
                            sequence: sequences[i],
                        });
                    }
                }
                run.events.push(fire_event(
                    &format!("wildfire:risk:h{round:02}"),
                    EventKind::WildfireRisk,
                    severity,
                    if physical_evidence {
                        SensorModality::AirQuality
                    } else {
                        SensorModality::Weather
                    },
                    nodes[TEMP].geo,
                    (measured, measured),
                    evidence,
                    0.85_f32.min(0.60 + risk as f32 * 0.4),
                    format!(
                        "risk {risk:.2} at hour {round} ({:.1} C, {humidity_pct:.0} % RH, \
                         {:.1} km/h, soil {:.1} %); physical evidence: {}; \
                         sensors_used={sensors_used}/5, excluded=[{}]",
                        values[TEMP],
                        values[WIND],
                        values[SOIL],
                        if physical_evidence {
                            format!("PM {:.0} ug/m3 AND smoke {:.2}", values[PM], values[SMOKE])
                        } else {
                            format!(
                                "none (PM {:.0} ug/m3, smoke {:.2})",
                                values[PM], values[SMOKE]
                            )
                        },
                        run.excluded_nodes
                            .iter()
                            .map(|id| format!("{id:#018x}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ));
            }
        }

        // RF context is fused as a capped evidence edge against the optical
        // sensor — support or contradiction, never a severity of its own.
        if round == IGNITION_ROUND {
            let rf = rf_context(measured, 0.99);
            let smoke_key = format!("sensor/{}", nodes[SMOKE].node_id);
            let plausibility = assess_plausibility(true, measured, &rf, RF_WINDOW_NS);
            let _ = fuse_rf_context(&mut run.graph, &smoke_key, &rf, plausibility);
        }
    }
    run
}

// ---------------------------------------------------------------------------
// Narrative
// ---------------------------------------------------------------------------

fn main() {
    banner(
        "WILDFIRE RISK & EARLY DETECTION — ADR-266 wedge #4",
        "7 signed spore nodes + RuView RF context; the RF severity cap is the product",
    );

    let run = run_fire_watch();

    println!("  Fire-watch cluster");
    for node in provision() {
        line(
            &format!("  {}", node.label),
            format!("{} / node {:#018x}", node.modality.as_str(), node.node_id),
        );
    }

    println!("\n  1. The drying day, hour by hour");
    for round in &run.rounds {
        line(
            &format!("  hour {:>2}", round.hour),
            format!(
                "risk {:.3}  {:<9} sensors {}/5  PM {:>5.0}  smoke {:.2}{}",
                round.risk,
                round.severity.map_or("—".to_string(), |s| format!("{s:?}")),
                round.sensors_used,
                round.pm_ug_m3,
                round.smoke_index,
                if round.physical_evidence {
                    "  <- physical combustion evidence"
                } else {
                    ""
                }
            ),
        );
    }

    println!("\n  2. Escalation ladder (one event per step up)");
    for event in &run.events {
        line(
            &format!("  {:?}", event.severity),
            format!("{} — {}", event.event_id, event.message),
        );
    }
    line(
        "peak severity reached",
        format!("{:?}", run.peak_severity().expect("the day escalates")),
    );

    println!("\n  3. RF-only 'detection' — the cap that makes this wedge sellable");
    let rf = rf_context(round_ns(IGNITION_ROUND), 0.99);
    for proposed in [
        Severity::Critical,
        Severity::Warning,
        Severity::Watch,
        Severity::Advisory,
    ] {
        let event = rf_only_alert(&rf, proposed, provision()[SMOKE].geo);
        line(
            &format!(
                "  RF proposes {proposed:?} at confidence {:.2}",
                rf.confidence
            ),
            format!(
                "event severity {:?}{}",
                event.severity,
                if event.severity > Severity::Advisory {
                    "  <- GUARANTEE BROKEN"
                } else {
                    ""
                }
            ),
        );
    }
    for edge in run.graph.edges_from("rf/rf-ridge-01") {
        line(
            &format!("  graph edge {} -> optical sensor", edge.from),
            format!(
                "{:?} w={:.2} (RF weight cap {RF_MAX_EVIDENCE_WEIGHT:.2})",
                edge.kind, edge.weight
            ),
        );
    }

    println!("\n  4. Physical evidence is what reaches Critical");
    let dust = &run.rounds[DUST_ROUND];
    let ignition = &run.rounds[IGNITION_ROUND];
    line(
        &format!("  hour {DUST_ROUND}: PM spike, no smoke"),
        format!(
            "PM {:.0} ug/m3, smoke {:.2} -> {:?}",
            dust.pm_ug_m3,
            dust.smoke_index,
            dust.severity.expect("a severity is raised")
        ),
    );
    line(
        &format!("  hour {IGNITION_ROUND}: PM + optical smoke"),
        format!(
            "PM {:.0} ug/m3, smoke {:.2} -> {:?}",
            ignition.pm_ug_m3,
            ignition.smoke_index,
            ignition.severity.expect("a severity is raised")
        ),
    );

    println!("\n  5. The sensor that failed in the heat");
    let degradation = run
        .degradation
        .as_ref()
        .expect("the exposed hygrometer fails");
    line(
        "event kind / severity",
        format!("{:?} / {:?}", degradation.kind, degradation.severity),
    );
    line("message", &degradation.message);
    line(
        "reported, not silently dropped",
        format!(
            "every event after hour {SENSOR_FAILURE_ROUND} names excluded=[{}]",
            run.excluded_nodes
                .iter()
                .map(|id| format!("{id:#018x}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    );

    synthetic_footer(
        "Weather, PM, and smoke values are simulated; the severity cap, the \
         quality gate, and the WorldGraph RF weight cap are the production code.",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rf_only_detection_is_capped_at_advisory() {
        let rf = rf_context(round_ns(IGNITION_ROUND), 0.99);
        assert_eq!(rf.confidence, 0.99, "the radio is as sure as it can be");
        for proposed in [
            Severity::Critical,
            Severity::Warning,
            Severity::Watch,
            Severity::Advisory,
        ] {
            let event = rf_only_alert(&rf, proposed, provision()[SMOKE].geo);
            assert_eq!(
                event.severity,
                Severity::Advisory,
                "RF-only evidence proposed {proposed:?} and must land at Advisory"
            );
            assert!(event.severity <= Severity::Advisory);
            event.validate().expect("the capped event is well-formed");
        }
    }

    #[test]
    fn physical_pm_plus_optical_smoke_reaches_critical() {
        let run = run_fire_watch();
        let ignition = &run.rounds[IGNITION_ROUND];
        assert!(ignition.physical_evidence);
        assert!(ignition.pm_ug_m3 > PM_CRITICAL_UG_M3);
        assert!(ignition.smoke_index > SMOKE_CRITICAL_INDEX);
        assert_eq!(ignition.severity, Some(Severity::Critical));
        assert_eq!(run.peak_severity(), Some(Severity::Critical));

        // The Critical event cites both physical sensors.
        let critical = run
            .events
            .iter()
            .find(|e| e.severity == Severity::Critical)
            .expect("a Critical event is raised");
        let nodes = provision();
        for idx in [PM, SMOKE] {
            assert!(
                critical
                    .evidence
                    .iter()
                    .any(|e| e.node_id == nodes[idx].node_id),
                "the Critical event must cite the physical evidence"
            );
        }
    }

    #[test]
    fn no_critical_without_physical_corroboration() {
        let run = run_fire_watch();
        // A PM spike alone (harvester dust) does not reach Critical, even
        // though the environmental risk is already in Warning territory.
        let dust = &run.rounds[DUST_ROUND];
        assert!(dust.pm_ug_m3 > PM_CRITICAL_UG_M3, "PM really did spike");
        assert!(dust.smoke_index < SMOKE_CRITICAL_INDEX, "no smoke though");
        assert!(!dust.physical_evidence);
        assert_eq!(dust.severity, Some(Severity::Warning));

        // And no round before ignition ever reaches Critical.
        for round in run.rounds.iter().take(IGNITION_ROUND) {
            assert!(
                round.severity < Some(Severity::Critical),
                "hour {}",
                round.hour
            );
        }
        // The severity function itself: environmental risk tops out at Warning.
        assert_eq!(severity_for(0.99, false), Some(Severity::Warning));
        assert_eq!(severity_for(0.99, true), Some(Severity::Critical));
    }

    #[test]
    fn degraded_sensor_is_excluded_and_its_absence_reported() {
        let run = run_fire_watch();
        let rh_b = provision()[RH_B].node_id;
        assert_eq!(run.excluded_nodes, vec![rh_b]);

        for round in &run.rounds {
            if round.hour < SENSOR_FAILURE_ROUND {
                assert_eq!(round.sensors_used, 5, "hour {}", round.hour);
                assert!(round.excluded.is_empty());
            } else {
                assert_eq!(round.sensors_used, 4, "hour {}", round.hour);
                assert_eq!(round.excluded, vec![rh_b]);
            }
        }

        // The absence is announced as a signed-able event, not swallowed.
        let report = run.degradation.expect("degradation reported");
        assert_eq!(report.kind, EventKind::SensorQuarantined);
        assert_eq!(report.evidence[0].node_id, rh_b);
        assert!(report.message.contains("excluded from the risk index"));

        // The failed sensor's nonsense reading never enters any event.
        for event in &run.events {
            assert!(
                !event.evidence.iter().any(|e| e.node_id == rh_b)
                    || event.detected_ns < round_ns(SENSOR_FAILURE_ROUND),
                "a degraded sensor must not back a post-failure event"
            );
        }
    }

    #[test]
    fn risk_index_is_monotonic_through_the_drying_day() {
        let run = run_fire_watch();
        for pair in run.rounds.windows(2) {
            assert!(
                pair[1].risk > pair[0].risk,
                "risk must rise as the fuel dries: hour {} {:.4} -> hour {} {:.4}",
                pair[0].hour,
                pair[0].risk,
                pair[1].hour,
                pair[1].risk
            );
        }
        // Severity is likewise non-decreasing across the raised events.
        for pair in run.events.windows(2) {
            assert!(pair[1].severity > pair[0].severity);
        }
        // ...and the day really does traverse the whole ladder.
        let severities: Vec<Severity> = run.events.iter().map(|e| e.severity).collect();
        assert_eq!(
            severities,
            vec![
                Severity::Advisory,
                Severity::Watch,
                Severity::Warning,
                Severity::Critical
            ]
        );
    }

    #[test]
    fn rf_evidence_weight_is_capped_in_the_worldgraph() {
        let run = run_fire_watch();
        let edges = run.graph.edges_from("rf/rf-ridge-01");
        assert_eq!(edges.len(), 1, "the RF context is fused exactly once");
        assert!(
            edges[0].weight <= RF_MAX_EVIDENCE_WEIGHT,
            "RF evidence weight {} exceeds the cap {RF_MAX_EVIDENCE_WEIGHT}",
            edges[0].weight
        );
        // Confidence 0.99 was clamped down to the cap, not honoured.
        assert_eq!(edges[0].weight, RF_MAX_EVIDENCE_WEIGHT);
    }
}
