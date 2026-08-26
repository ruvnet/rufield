//! # flood-watershed — deployment wedge #1 (ADR-266 §3)
//!
//! Flood and watershed intelligence is wedge #1 because the outcome is
//! *measurable* and the cost of a missed event is high. What this example has
//! to prove is therefore not "we can read a gauge" — it is the five things a
//! conservation authority actually buys:
//!
//! 1. **Lead time.** Rising water is detected *before* a fixed conventional
//!    gauge trigger, and the lead is reported in minutes.
//! 2. **Inference, not thresholds.** A blocked culvert is inferred from the
//!    *relationship* between two gauges (upstream rising, downstream flat) —
//!    neither gauge alone crosses anything.
//! 3. **Storm-time sensor displacement.** A node that physically moves during
//!    the storm is detected, quarantined, and — critically — its readings do
//!    not drive the alert. ADR-266 §3 calls this out as the load-bearing risk
//!    of the wedge.
//! 4. **Contradiction is recorded, never resolved silently.** RuView RF
//!    context that disagrees with a gauge becomes a `Contradicts` edge in the
//!    WorldGraph (ADR-264 §8: RF is context, never ground truth).
//! 5. **Latency budget.** ADR-266 §3 promises local alerts under 5 s. The
//!    detection path is timed and asserted.
//!
//! Sensor values are simulated; the signing, ingest verification, WorldGraph,
//! and RF-cap machinery is the production code.
//!
//! ```bash
//! cargo run  -p rucelium-examples --bin flood-watershed
//! cargo test -p rucelium-examples --bin flood-watershed
//! ```

use rucelium_core::{
    EnvironmentalEvent, EventKind, EvidenceRef, GeoPoint, SensorModality, Severity, SPEC_VERSION,
};
use rucelium_examples::{banner, line, synthetic_footer, Gateway, Node, Rng, EPOCH_NS, NS_PER_S};
use rucelium_worldgraph::{
    assess_plausibility, fuse_rf_context, haversine_m, RfContext, WorldGraph,
};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Scenario constants
// ---------------------------------------------------------------------------

/// The biome this watershed belongs to.
pub const BIOME_ID: &str = "biome/avon-headwaters";

/// Simulated seconds between sampling rounds (5 minutes).
pub const STEP_S: u64 = 300;

/// Number of sampling rounds: 72 × 5 min = 6 simulated hours.
pub const STEPS: usize = 72;

/// Provisioned spore nodes. The RuView RF context source is the twelfth
/// evidence source in the watershed but is **not** a signed spore node — it
/// never enters the sample path (ADR-264 §8).
pub const NODE_COUNT: usize = 11;

/// The fixed level (metres) at which a conventional telemetered gauge at the
/// outlet raises its alarm. This is the baseline RuCelium has to beat.
pub const CONVENTIONAL_TRIGGER_M: f64 = 2.50;

/// Catchment rainfall (mm/h) above which the storm is considered active.
pub const RAIN_ALERT_MM_H: f64 = 15.0;

/// Mean soil volumetric water content (%) above which the catchment is
/// considered saturated and runoff is imminent.
pub const SOIL_SATURATION_PCT: f64 = 44.5;

/// Upstream stage rise (metres per 15 minutes) that counts as a flood ramp.
pub const STAGE_RISE_M_PER_15MIN: f64 = 0.06;

/// Culvert-blockage rule: upstream stage rise (metres) over a 30-minute
/// window that must be matched by the downstream gauge.
pub const CULVERT_RISE_M: f64 = 0.30;

/// Culvert-blockage rule: the maximum downstream rise (metres) over the same
/// window that still counts as "flat".
pub const CULVERT_FLAT_M: f64 = 0.05;

/// Window length (sampling rounds) for the culvert comparison: 6 × 5 min.
pub const CULVERT_WINDOW: usize = 6;

/// Window length (sampling rounds) for the stage-rise rate: 3 × 5 min.
pub const RISE_WINDOW: usize = 3;

/// A node that has moved more than this far (metres) from its commissioned
/// position is treated as storm-displaced.
pub const DISPLACEMENT_LIMIT_M: f64 = 25.0;

/// The sampling round at which the storm rips one soil probe off its post.
pub const DISPLACEMENT_STEP: usize = 18;

/// Gateway reception delay applied to every envelope (1 ms).
pub const INGEST_LATENCY_NS: u64 = 1_000_000;

/// Calibration record referenced by every node in this scenario.
pub const CALIBRATION_ID: u32 = 11;

/// Temporal window (ns) within which RF context is considered to say anything
/// about a sample.
pub const RF_WINDOW_NS: u64 = 900 * NS_PER_S;

/// The ADR-266 §3 promise: a local alert in under five seconds.
pub const ALERT_BUDGET_MS: u128 = 5_000;

// Node-table indices.
/// Upstream reach water-level gauge.
pub const WL_UP: usize = 0;
/// Water-level gauge immediately upstream of the culvert.
pub const WL_CULVERT_IN: usize = 1;
/// Water-level gauge immediately downstream of the culvert.
pub const WL_CULVERT_OUT: usize = 2;
/// Outlet water-level gauge — co-located with the conventional gauge.
pub const WL_OUTLET: usize = 3;
/// Tipping-bucket rain gauge, north of the catchment.
pub const RAIN_A: usize = 4;
/// Tipping-bucket rain gauge, south of the catchment.
pub const RAIN_B: usize = 5;
/// Soil-moisture probe, north slope.
pub const SOIL_A: usize = 6;
/// Soil-moisture probe, valley floor.
pub const SOIL_B: usize = 7;
/// Soil-moisture probe, riverbank — the one the storm displaces.
pub const SOIL_C: usize = 8;
/// Weather station, catchment head.
pub const WX_A: usize = 9;
/// Weather station, outlet.
pub const WX_B: usize = 10;

// ---------------------------------------------------------------------------
// Synthetic storm
// ---------------------------------------------------------------------------

/// Storm intensity at `step`, ramping 0 → 1 between rounds 6 and 36.
#[must_use]
pub fn storm(step: usize) -> f64 {
    let s = step as f64;
    if s < 6.0 {
        0.0
    } else {
        ((s - 6.0) / 30.0).min(1.0)
    }
}

/// Storm intensity `lag` rounds ago (catchment response lag).
#[must_use]
pub fn lagged(step: usize, lag: usize) -> f64 {
    storm(step.saturating_sub(lag))
}

/// Noise-free truth for sensor `idx` at `step`, in that sensor's unit.
#[must_use]
pub fn truth(idx: usize, step: usize) -> f64 {
    match idx {
        WL_UP => 1.10 + 1.90 * lagged(step, 6),
        WL_CULVERT_IN => 1.05 + 2.10 * lagged(step, 7),
        // The culvert is blocked: almost nothing gets through it.
        WL_CULVERT_OUT => 0.95 + 0.05 * lagged(step, 7),
        WL_OUTLET => 1.00 + 1.90 * lagged(step, 14),
        RAIN_A | RAIN_B => 45.0 * storm(step),
        SOIL_C if step >= DISPLACEMENT_STEP => 98.0, // probe in the river
        SOIL_A | SOIL_B | SOIL_C => 28.0 + 30.0 * lagged(step, 3),
        // Weather stations: air temperature drops as the front arrives.
        _ => 12.0 - 4.0 * storm(step),
    }
}

/// Per-sensor noise standard deviation.
#[must_use]
pub fn noise_sd(idx: usize) -> f64 {
    match idx {
        WL_UP | WL_CULVERT_IN | WL_CULVERT_OUT | WL_OUTLET => 0.004,
        RAIN_A | RAIN_B => 0.30,
        SOIL_A | SOIL_B | SOIL_C => 0.08,
        _ => 0.05,
    }
}

/// Measurement time of sampling round `step`.
#[must_use]
pub fn step_ns(step: usize) -> u64 {
    EPOCH_NS + (step as u64) * STEP_S * NS_PER_S
}

/// Minutes into the storm at sampling round `step`.
#[must_use]
pub fn step_min(step: usize) -> u64 {
    (step as u64) * STEP_S / 60
}

/// Build a geo point, panicking on a coordinate the example itself got wrong.
#[must_use]
fn geo(latitude_e7: i32, longitude_e7: i32, altitude_mm: i32) -> GeoPoint {
    GeoPoint::new(latitude_e7, longitude_e7, altitude_mm).expect("example coordinates are in range")
}

/// Provision the eleven spore nodes of the watershed, in node-table order.
#[must_use]
pub fn provision() -> Vec<Node> {
    vec![
        Node::new(
            0x00F1_0000_0000_0001,
            SensorModality::WaterQuality,
            geo(513_820_000, -29_810_000, 74_000),
            "WL-1 upstream reach",
        ),
        Node::new(
            0x00F1_0000_0000_0002,
            SensorModality::WaterQuality,
            geo(513_795_000, -29_795_000, 68_000),
            "WL-2 culvert inlet",
        ),
        Node::new(
            0x00F1_0000_0000_0003,
            SensorModality::WaterQuality,
            geo(513_790_000, -29_788_000, 67_000),
            "WL-3 culvert outfall",
        ),
        Node::new(
            0x00F1_0000_0000_0004,
            SensorModality::WaterQuality,
            geo(513_745_000, -29_760_000, 59_000),
            "WL-4 outlet (conventional gauge site)",
        ),
        Node::new(
            0x00F1_0000_0000_0005,
            SensorModality::Weather,
            geo(513_860_000, -29_840_000, 91_000),
            "RG-1 rain gauge, north ridge",
        ),
        Node::new(
            0x00F1_0000_0000_0006,
            SensorModality::Weather,
            geo(513_710_000, -29_730_000, 55_000),
            "RG-2 rain gauge, south field",
        ),
        Node::new(
            0x00F1_0000_0000_0007,
            SensorModality::SoilMoisture,
            geo(513_845_000, -29_825_000, 88_000),
            "SM-1 north slope",
        ),
        Node::new(
            0x00F1_0000_0000_0008,
            SensorModality::SoilMoisture,
            geo(513_780_000, -29_775_000, 64_000),
            "SM-2 valley floor",
        ),
        Node::new(
            0x00F1_0000_0000_0009,
            SensorModality::SoilMoisture,
            geo(513_762_000, -29_768_000, 61_000),
            "SM-3 riverbank post",
        ),
        Node::new(
            0x00F1_0000_0000_000A,
            SensorModality::Weather,
            geo(513_855_000, -29_835_000, 90_000),
            "WX-1 catchment head",
        ),
        Node::new(
            0x00F1_0000_0000_000B,
            SensorModality::Weather,
            geo(513_740_000, -29_755_000, 57_000),
            "WX-2 outlet",
        ),
    ]
}

/// Where the storm dumps the riverbank soil probe: ~85 m downstream, in the
/// water.
#[must_use]
pub fn displaced_geo() -> GeoPoint {
    geo(513_754_000, -29_762_000, 58_000)
}

/// The single RuView RF context observation for this storm: the radio sees no
/// surface change in the outlet reach at all.
#[must_use]
pub fn rf_context(at_ns: u64) -> RfContext {
    // Built directly rather than via `RfContext::from_field_event`: the
    // examples package does not depend on `rufield-core`, so the
    // `FieldEvent` type is not in scope here. Every field carries exactly
    // what the RuField MFS WiFi-CSI encoder would have produced.
    RfContext {
        source_event_id: "rf-avon-storm-01".to_string(),
        device_id: "rf-gw-01".to_string(),
        confidence: 0.92,
        motion_energy: Some(0.08),
        labels: vec!["no_surface_change".to_string()],
        timestamp_ns: at_ns,
    }
}

// ---------------------------------------------------------------------------
// Detection output
// ---------------------------------------------------------------------------

/// Everything one 6-hour storm run produced.
#[derive(Debug, Default)]
pub struct StormRun {
    /// The flood-risk alert, if raised.
    pub alert: Option<EnvironmentalEvent>,
    /// The sampling round at which the alert was raised.
    pub alert_step: Option<usize>,
    /// The blocked-culvert inference, if raised.
    pub culvert: Option<EnvironmentalEvent>,
    /// The sensor-displacement event, if raised.
    pub displacement: Option<EnvironmentalEvent>,
    /// The sampling round at which the conventional gauge would have fired.
    pub conventional_step: Option<usize>,
    /// Node ids quarantined for displacement.
    pub quarantined: Vec<u64>,
    /// The WorldGraph, including any contradiction edges.
    pub graph: WorldGraph,
    /// Worst observed ingest + detection wall time for a single round.
    pub max_detect: Duration,
    /// Envelopes accepted by the gateway.
    pub accepted: u64,
}

impl StormRun {
    /// Lead time in minutes of the RuCelium alert over the conventional
    /// gauge trigger, when both fired.
    #[must_use]
    pub fn lead_time_min(&self) -> Option<u64> {
        let (a, c) = (self.alert_step?, self.conventional_step?);
        (c > a).then(|| step_min(c) - step_min(a))
    }
}

/// Mean of a slice; `0.0` for an empty slice.
#[must_use]
fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

/// Assemble an environmental event for this watershed.
fn watershed_event(
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

/// Run the full 6-hour storm.
///
/// When `honour_quarantine` is `true` the gateway excludes displaced sensors
/// from the alert logic — the shipped behaviour. Passing `false` reproduces
/// the naive pipeline that trusts a sensor no longer where it was
/// commissioned, and is used to show what that costs.
#[must_use]
pub fn run_storm(honour_quarantine: bool) -> StormRun {
    let mut nodes = provision();
    let commissioned: Vec<GeoPoint> = nodes.iter().map(|n| n.geo).collect();
    let mut gateway = Gateway::with_nodes(&nodes);
    let mut rng = Rng::new(0x00F1_00D5_EED0_2026);
    let mut history: Vec<Vec<f64>> = vec![Vec::new(); NODE_COUNT];
    let mut run = StormRun::default();

    for step in 0..STEPS {
        if step == DISPLACEMENT_STEP {
            nodes[SOIL_C].geo = displaced_geo();
        }
        let measured = step_ns(step);
        let received = measured + INGEST_LATENCY_NS;
        let started = Instant::now();
        let mut sequences = [0u32; NODE_COUNT];

        // --- ingest: every value is a real signed envelope ---------------
        for idx in 0..NODE_COUNT {
            let value = truth(idx, step) + rng.noise(noise_sd(idx));
            let envelope = nodes[idx].emit(value, measured, CALIBRATION_ID);
            let sealed = gateway
                .ingest(&envelope, received)
                .expect("a node's own signed envelope must ingest");
            let sample = sealed.sample();
            sequences[idx] = sample.sequence;
            let key = run.graph.register_observation(sample);
            history[idx].push(sample.value);
            run.accepted += 1;

            // Storm-time displacement: the geo the node signed no longer
            // matches where it was commissioned.
            let moved_m = haversine_m(commissioned[idx], sample.geo);
            if moved_m > DISPLACEMENT_LIMIT_M && !run.quarantined.contains(&sample.node_id) {
                run.quarantined.push(sample.node_id);
                run.displacement = Some(watershed_event(
                    &format!("flood:displaced:{}", sample.node_id),
                    EventKind::SensorTampered,
                    Severity::Warning,
                    sample.modality,
                    sample.geo,
                    (measured, measured),
                    vec![EvidenceRef {
                        node_id: sample.node_id,
                        sequence: sample.sequence,
                    }],
                    0.99,
                    format!(
                        "{key} moved {moved_m:.0} m from its commissioned position \
                         (limit {DISPLACEMENT_LIMIT_M:.0} m); quarantined, readings excluded"
                    ),
                ));
            }
        }

        // --- detection ---------------------------------------------------
        let latest = |idx: usize| history[idx][step];
        let usable_soil: Vec<f64> = [SOIL_A, SOIL_B, SOIL_C]
            .into_iter()
            .filter(|&i| !(honour_quarantine && run.quarantined.contains(&nodes[i].node_id)))
            .map(latest)
            .collect();
        let mean_rain = mean(&[latest(RAIN_A), latest(RAIN_B)]);
        let mean_soil = mean(&usable_soil);
        let stage_rise = if step >= RISE_WINDOW {
            latest(WL_UP) - history[WL_UP][step - RISE_WINDOW]
        } else {
            0.0
        };

        // Blocked culvert: upstream climbing while the outfall stays flat.
        if run.culvert.is_none() && step >= CULVERT_WINDOW {
            let rise_in = latest(WL_CULVERT_IN) - history[WL_CULVERT_IN][step - CULVERT_WINDOW];
            let rise_out = latest(WL_CULVERT_OUT) - history[WL_CULVERT_OUT][step - CULVERT_WINDOW];
            if rise_in >= CULVERT_RISE_M && rise_out <= CULVERT_FLAT_M {
                run.culvert = Some(watershed_event(
                    "flood:blocked-culvert:01",
                    EventKind::Anomaly,
                    Severity::Warning,
                    SensorModality::WaterQuality,
                    nodes[WL_CULVERT_IN].geo,
                    (step_ns(step - CULVERT_WINDOW), measured),
                    vec![
                        EvidenceRef {
                            node_id: nodes[WL_CULVERT_IN].node_id,
                            sequence: sequences[WL_CULVERT_IN],
                        },
                        EvidenceRef {
                            node_id: nodes[WL_CULVERT_OUT].node_id,
                            sequence: sequences[WL_CULVERT_OUT],
                        },
                    ],
                    0.93,
                    format!(
                        "culvert inlet rose {rise_in:.2} m in 30 min while the outfall \
                         moved {rise_out:.2} m — obstruction inferred, neither gauge \
                         crosses a level threshold"
                    ),
                ));
            }
        }

        // Flood risk: rain + saturation + stage ramp, from healthy nodes only.
        if run.alert.is_none()
            && mean_rain > RAIN_ALERT_MM_H
            && mean_soil > SOIL_SATURATION_PCT
            && stage_rise > STAGE_RISE_M_PER_15MIN
        {
            let evidence = [RAIN_A, RAIN_B, SOIL_A, SOIL_B, SOIL_C, WL_UP]
                .into_iter()
                .filter(|&i| !(honour_quarantine && run.quarantined.contains(&nodes[i].node_id)))
                .map(|i| EvidenceRef {
                    node_id: nodes[i].node_id,
                    sequence: sequences[i],
                })
                .collect();
            run.alert = Some(watershed_event(
                "flood:risk:01",
                EventKind::FloodRisk,
                Severity::Warning,
                SensorModality::WaterQuality,
                nodes[WL_UP].geo,
                (step_ns(step.saturating_sub(RISE_WINDOW)), measured),
                evidence,
                0.91,
                format!(
                    "catchment rainfall {mean_rain:.1} mm/h, soil {mean_soil:.1} % VWC, \
                     upstream stage +{stage_rise:.2} m/15min — runoff imminent"
                ),
            ));
            run.alert_step = Some(step);

            // RF context is consulted exactly once, at the alert, and it is
            // context only: it can support, it can contradict, it can never
            // raise the alert on its own (ADR-264 §8).
            let rf = rf_context(measured);
            let outlet_key = format!("sensor/{}", nodes[WL_OUTLET].node_id);
            let outfall_key = format!("sensor/{}", nodes[WL_CULVERT_OUT].node_id);
            // The outlet gauge says the water surface is moving; the radio
            // says it is not. That disagreement is recorded, not resolved.
            let disagree = assess_plausibility(true, measured, &rf, RF_WINDOW_NS);
            let _ = fuse_rf_context(&mut run.graph, &outlet_key, &rf, disagree);
            // The blocked outfall really is flat; the radio agrees.
            let agree = assess_plausibility(false, measured, &rf, RF_WINDOW_NS);
            let _ = fuse_rf_context(&mut run.graph, &outfall_key, &rf, agree);
        }

        // Baseline: what a conventional fixed-threshold gauge would do.
        if run.conventional_step.is_none() && latest(WL_OUTLET) >= CONVENTIONAL_TRIGGER_M {
            run.conventional_step = Some(step);
        }

        run.max_detect = run.max_detect.max(started.elapsed());
    }
    run
}

// ---------------------------------------------------------------------------
// Narrative
// ---------------------------------------------------------------------------

fn main() {
    banner(
        "FLOOD & WATERSHED INTELLIGENCE — ADR-266 wedge #1",
        "11 signed spore nodes + 1 RuView RF context source, 6-hour storm ramp",
    );

    let run = run_storm(true);
    let naive = run_storm(false);

    println!("  Catchment");
    for (idx, node) in provision().iter().enumerate() {
        line(
            &format!("  [{idx:>2}] {}", node.label),
            format!("{} / node {:#018x}", node.modality.as_str(), node.node_id),
        );
    }
    line(
        "  [11] rf-gw-01 (RuView context)",
        "wifi_csi / not a spore node",
    );
    println!();
    line("envelopes signed, verified, accepted", run.accepted);
    line(
        "simulated span",
        format!("{} h", STEPS as u64 * STEP_S / 3600),
    );

    println!("\n  1. Lead time over the conventional gauge");
    let alert = run.alert.as_ref().expect("the storm raises a flood alert");
    let alert_step = run.alert_step.expect("alert step recorded");
    let conv = run
        .conventional_step
        .expect("the conventional gauge eventually fires");
    line(
        "RuCelium flood-risk alert",
        format!("T+{} min (round {alert_step})", step_min(alert_step)),
    );
    line(
        &format!("conventional {CONVENTIONAL_TRIGGER_M:.2} m gauge trigger"),
        format!("T+{} min (round {conv})", step_min(conv)),
    );
    line(
        "LEAD TIME",
        format!(
            "{} minutes",
            run.lead_time_min().expect("alert precedes the gauge")
        ),
    );
    line(
        "alert severity / confidence",
        format!("{:?} / {:.2}", alert.severity, alert.confidence),
    );
    line("alert message", &alert.message);

    println!("\n  2. Blocked-culvert inference (no gauge crosses a threshold)");
    let culvert = run.culvert.as_ref().expect("the blockage is inferred");
    line(
        "event kind / severity",
        format!("{:?} / {:?}", culvert.kind, culvert.severity),
    );
    line(
        "detected at",
        format!("T+{} min", (culvert.detected_ns - EPOCH_NS) / NS_PER_S / 60),
    );
    line("evidence nodes", culvert.evidence.len());
    line("message", &culvert.message);

    println!("\n  3. Storm-displaced sensor");
    let displaced = run.displacement.as_ref().expect("the storm displaces SM-3");
    line(
        "event kind / severity",
        format!("{:?} / {:?}", displaced.kind, displaced.severity),
    );
    line(
        "quarantined node ids",
        run.quarantined
            .iter()
            .map(|id| format!("{id:#018x}"))
            .collect::<Vec<_>>()
            .join(", "),
    );
    line("message", &displaced.message);
    line(
        "displaced node in alert evidence?",
        if alert
            .evidence
            .iter()
            .any(|e| run.quarantined.contains(&e.node_id))
        {
            "YES — guarantee broken"
        } else {
            "no — excluded from the alert"
        },
    );
    let naive_step = naive.alert_step.expect("the naive pipeline also alerts");
    line(
        "same pipeline WITHOUT quarantine",
        format!(
            "alerts at T+{} min ({} min early, driven by a probe in the river)",
            step_min(naive_step),
            step_min(alert_step) - step_min(naive_step)
        ),
    );

    println!("\n  4. Contradiction between RF context and a gauge");
    line("WorldGraph nodes", run.graph.len());
    line("contradictions recorded", run.graph.contradiction_count());
    for edge in run.graph.contradictions() {
        line(
            &format!("  {} -> {}", edge.from, edge.to),
            format!("{:?} w={:.2} — {}", edge.kind, edge.weight, edge.note),
        );
    }
    for edge in run.graph.edges_from("rf/rf-gw-01") {
        if edge.kind != rucelium_worldgraph::EdgeKind::Contradicts {
            line(
                &format!("  {} -> {}", edge.from, edge.to),
                format!(
                    "{:?} w={:.2} (RF weight cap {:.2})",
                    edge.kind,
                    edge.weight,
                    rucelium_worldgraph::RF_MAX_EVIDENCE_WEIGHT
                ),
            );
        }
    }

    println!("\n  5. Local alert latency");
    line(
        "worst round: 11 verifications + detection",
        format!("{} ms", run.max_detect.as_millis()),
    );
    line("ADR-266 §3 budget", format!("{ALERT_BUDGET_MS} ms"));
    line(
        "verdict",
        if run.max_detect.as_millis() < ALERT_BUDGET_MS {
            "within budget"
        } else {
            "OVER BUDGET — guarantee broken"
        },
    );

    synthetic_footer(
        "The storm hydrograph is synthetic; the 5 s budget is measured on the \
         real ingest + detection path.",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_leads_the_conventional_gauge() {
        let run = run_storm(true);
        let lead = run.lead_time_min().expect("both triggers fire");
        assert!(lead > 0, "alert must precede the conventional gauge");
        assert_eq!(lead, 90, "the storm's lead time is deterministic");
        let alert = run.alert.expect("alert raised");
        assert_eq!(alert.kind, EventKind::FloodRisk);
        assert!(alert.severity >= Severity::Warning);
        // A second run of the same seed is identical.
        let again = run_storm(true);
        assert_eq!(again.alert_step, run.alert_step);
        assert_eq!(again.conventional_step, run.conventional_step);
    }

    #[test]
    fn blocked_culvert_is_inferred_from_the_gauge_relationship() {
        let run = run_storm(true);
        let culvert = run.culvert.expect("blockage inferred");
        assert_eq!(culvert.kind, EventKind::Anomaly);
        assert_eq!(culvert.evidence.len(), 2, "inlet and outfall both cited");
        // Neither gauge individually crosses the conventional trigger at the
        // moment the blockage is inferred — the inference is relational.
        let step = ((culvert.detected_ns - EPOCH_NS) / NS_PER_S / STEP_S) as usize;
        assert!(truth(WL_CULVERT_IN, step) < CONVENTIONAL_TRIGGER_M);
        assert!(truth(WL_CULVERT_OUT, step) < CONVENTIONAL_TRIGGER_M);
    }

    #[test]
    fn displaced_sensor_is_quarantined_and_never_drives_the_alert() {
        let run = run_storm(true);
        let displaced = run.displacement.expect("displacement detected");
        assert_eq!(displaced.kind, EventKind::SensorTampered);
        let soil_c = provision()[SOIL_C].node_id;
        assert_eq!(run.quarantined, vec![soil_c]);

        let alert = run.alert.expect("alert raised");
        assert!(
            !alert.evidence.iter().any(|e| e.node_id == soil_c),
            "a displaced sensor must not appear in alert evidence"
        );

        // Without quarantine the same pipeline alerts earlier — on a probe
        // that is in the river rather than in the soil.
        let naive = run_storm(false);
        let naive_step = naive.alert_step.expect("naive alert");
        assert!(
            naive_step < run.alert_step.expect("governed alert"),
            "the displaced probe would have triggered a spurious early alert"
        );
        assert!(naive
            .alert
            .expect("naive alert")
            .evidence
            .iter()
            .any(|e| e.node_id == soil_c));
    }

    #[test]
    fn rf_contradiction_is_recorded_and_rf_weight_stays_capped() {
        let run = run_storm(true);
        assert_eq!(run.graph.contradiction_count(), 1);
        let contradictions = run.graph.contradictions();
        assert_eq!(contradictions.len(), 1);
        assert_eq!(contradictions[0].from, "rf/rf-gw-01");
        assert_eq!(
            contradictions[0].to,
            format!("sensor/{}", provision()[WL_OUTLET].node_id)
        );
        // The supporting edge exists too, and RF evidence is capped.
        let supports: Vec<_> = run
            .graph
            .edges_from("rf/rf-gw-01")
            .iter()
            .filter(|e| e.kind == rucelium_worldgraph::EdgeKind::Supports)
            .collect();
        assert_eq!(supports.len(), 1);
        assert!(supports[0].weight <= rucelium_worldgraph::RF_MAX_EVIDENCE_WEIGHT);
    }

    #[test]
    fn alert_latency_is_within_the_five_second_budget() {
        let run = run_storm(true);
        assert!(
            run.max_detect.as_millis() < ALERT_BUDGET_MS,
            "worst round took {} ms, budget is {ALERT_BUDGET_MS} ms",
            run.max_detect.as_millis()
        );
        assert_eq!(run.accepted, (NODE_COUNT * STEPS) as u64);
    }

    #[test]
    fn every_alert_is_a_valid_federable_event() {
        let run = run_storm(true);
        for event in [&run.alert, &run.culvert, &run.displacement]
            .into_iter()
            .flatten()
        {
            event.validate().expect("event validates");
            assert_eq!(event.biome_id, BIOME_ID);
            assert!(!event.evidence.is_empty());
        }
    }
}
