//! # biodiversity-habitat — deployment wedge #5 (ADR-266 §3.1)
//!
//! Biodiversity and habitat monitoring is the wedge that **monetizes
//! sovereignty**. ADR-266 §3.1 states the demand on the fabric in one line:
//!
//! > **Disclosure policy as a feature**: coordinate coarsening and delayed
//! > release for sensitive species.
//!
//! That is not a privacy nicety — it is the reason a protected-area manager
//! can put a network in the ground at all. Publishing the exact location of a
//! nest in real time is how you get the nest robbed. So the biome here runs a
//! [`DisclosurePolicy`] that **withholds** an event until an embargo elapses
//! and then releases only a **coarsened** copy, and this example proves all
//! four halves of that:
//!
//! 1. internally the event keeps full precision — the reserve's own staff can
//!    act on it;
//! 2. [`Biome::disclose_event`] returns `None` for the entire embargo;
//! 3. after the embargo the released copy sits on a grid cell whose real size
//!    in metres is computed and printed — precision is genuinely destroyed,
//!    and five distinct sensor locations collapse onto one disclosed point;
//! 4. the coarsened copy is **re-signed**, so it still verifies with
//!    [`verify_event`]: sovereignty does not cost verifiability.
//!
//! Every accepted observation is also projected into *SensorThings-inspired*
//! entities (`rucelium_federation::project_sample`) — inspired by, not
//! conformant with, OGC SensorThings 1.1.
//!
//! ```bash
//! cargo run  -p rucelium-examples --bin biodiversity-habitat
//! cargo test -p rucelium-examples --bin biodiversity-habitat
//! ```

use rucelium_core::{
    EnvSample, EnvironmentalEvent, EventKind, EvidenceRef, GeoPoint, SensorModality, Severity,
    SPEC_VERSION,
};
use rucelium_examples::{banner, line, synthetic_footer, Gateway, Node, Rng, EPOCH_NS, NS_PER_S};
use rucelium_federation::{
    project_sample, verify_event, AcceptOutcome, Biome, BiomeConfig, DisclosurePolicy,
    SensorThingsBundle,
};
use rucelium_worldgraph::haversine_m;

// ---------------------------------------------------------------------------
// Scenario constants
// ---------------------------------------------------------------------------

/// The protected area's biome.
pub const BIOME_ID: &str = "biome/glen-feshie-reserve";

/// Deterministic seed for the biome's federated identity key.
pub const BIOME_SEED: &[u8; 32] = b"rucelium-example-habitat-biome!!";

/// Decimal degrees kept when disclosing a sensitive location.
pub const COARSEN_DECIMALS: u32 = 2;

/// Embargo before a sensitive detection may be disclosed (72 hours).
pub const DISCLOSURE_DELAY_NS: u64 = 72 * 3_600 * NS_PER_S;

/// Simulated seconds between sampling rounds (30 minutes).
pub const ROUND_S: u64 = 1_800;

/// Number of sampling rounds.
pub const ROUNDS: usize = 4;

/// Provisioned spore nodes.
pub const NODE_COUNT: usize = 5;

/// Acoustic activity index above which the classifier reports a sensitive
/// species call.
pub const SENSITIVE_CALL_INDEX: f64 = 0.75;

/// The round in which the sensitive species calls.
pub const DETECTION_ROUND: usize = 2;

/// Calibration record referenced by every node in the reserve.
pub const CALIBRATION_ID: u32 = 51;

// Node-table indices.
/// Acoustic recorder, birch stand.
pub const ACO_A: usize = 0;
/// Acoustic recorder, crag — the one that hears the sensitive species.
pub const ACO_B: usize = 1;
/// Acoustic recorder, riparian corridor.
pub const ACO_C: usize = 2;
/// Water-quality / stage sensor in the burn.
pub const WATER: usize = 3;
/// Weather station.
pub const WEATHER: usize = 4;

/// Build a geo point, panicking on a coordinate the example itself got wrong.
fn geo(latitude_e7: i32, longitude_e7: i32, altitude_mm: i32) -> GeoPoint {
    GeoPoint::new(latitude_e7, longitude_e7, altitude_mm).expect("example coordinates are in range")
}

/// Provision the five spore nodes of the reserve.
///
/// All five sit inside a single `COARSEN_DECIMALS`-degree grid cell but at
/// genuinely different places — which is exactly what makes the coarsening
/// irreversible rather than decorative.
#[must_use]
pub fn provision() -> Vec<Node> {
    vec![
        Node::new(
            0x00B5_0000_0000_0001,
            SensorModality::Acoustic,
            geo(570_834_120, -36_681_200, 512_000),
            "AR-1 acoustic recorder, birch stand",
        ),
        Node::new(
            0x00B5_0000_0000_0002,
            SensorModality::Acoustic,
            geo(570_838_770, -36_688_400, 559_000),
            "AR-2 acoustic recorder, crag",
        ),
        Node::new(
            0x00B5_0000_0000_0003,
            SensorModality::Acoustic,
            geo(570_831_050, -36_684_300, 487_000),
            "AR-3 acoustic recorder, riparian corridor",
        ),
        Node::new(
            0x00B5_0000_0000_0004,
            SensorModality::WaterQuality,
            geo(570_833_400, -36_686_900, 481_000),
            "WQ-1 burn stage and quality",
        ),
        Node::new(
            0x00B5_0000_0000_0005,
            SensorModality::Weather,
            geo(570_836_940, -36_683_100, 521_000),
            "WX-1 reserve weather station",
        ),
    ]
}

/// Noise-free truth for sensor `idx` at `round`, in that sensor's unit.
#[must_use]
pub fn truth(idx: usize, round: usize) -> f64 {
    match idx {
        ACO_A => 0.22,
        ACO_B if round == DETECTION_ROUND => 0.91,
        ACO_B => 0.18,
        ACO_C => 0.25,
        WATER => 1.42,
        _ => 11.4,
    }
}

/// Per-sensor noise standard deviation.
#[must_use]
pub fn noise_sd(idx: usize) -> f64 {
    match idx {
        ACO_A | ACO_B | ACO_C => 0.01,
        WATER => 0.004,
        _ => 0.05,
    }
}

/// Measurement time of round `round`.
#[must_use]
pub fn round_ns(round: usize) -> u64 {
    EPOCH_NS + (round as u64) * ROUND_S * NS_PER_S
}

/// The grid step, in 1e-7 degree units, that `keep_decimals` coarsening snaps
/// to.
#[must_use]
pub fn grid_step_e7(keep_decimals: u32) -> i32 {
    10_i32.pow(7 - keep_decimals.min(7))
}

/// North–south and east–west extent, in metres, of the disclosure grid cell
/// whose south-west corner is `corner`.
#[must_use]
pub fn cell_size_m(corner: GeoPoint, keep_decimals: u32) -> (f64, f64) {
    let step = grid_step_e7(keep_decimals);
    let north = GeoPoint {
        latitude_e7: corner.latitude_e7 + step,
        longitude_e7: corner.longitude_e7,
        altitude_mm: 0,
    };
    let east = GeoPoint {
        latitude_e7: corner.latitude_e7,
        longitude_e7: corner.longitude_e7 + step,
        altitude_mm: 0,
    };
    (haversine_m(corner, north), haversine_m(corner, east))
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

/// Everything one habitat-monitoring run produced.
#[derive(Debug)]
pub struct HabitatRun {
    /// Observations the biome accepted, in arrival order.
    pub observations: Vec<EnvSample>,
    /// SensorThings-inspired projections — one per accepted observation.
    pub bundles: Vec<SensorThingsBundle>,
    /// The internal, full-precision, biome-signed detection event.
    pub internal_event: EnvironmentalEvent,
    /// Disclosure attempted the instant the event was detected.
    pub at_detection: Option<EnvironmentalEvent>,
    /// Disclosure attempted one nanosecond before the embargo lifts.
    pub one_ns_early: Option<EnvironmentalEvent>,
    /// Disclosure attempted the instant the embargo lifts.
    pub at_release: Option<EnvironmentalEvent>,
    /// When the embargo lifts, ns since Unix epoch.
    pub release_ns: u64,
    /// The biome's federated public key.
    pub biome_pubkey_hex: String,
    /// The reserve's five true sensor locations.
    pub true_locations: Vec<GeoPoint>,
    /// Those five locations after coarsening.
    pub coarsened_locations: Vec<GeoPoint>,
}

/// Run the reserve for four rounds and disclose the sensitive detection.
///
/// # Panics
///
/// Panics if the scenario's own signed envelopes fail to ingest, or if the
/// sensitive species is never heard — the example is the specification.
#[must_use]
pub fn run_reserve() -> HabitatRun {
    let mut nodes = provision();
    let mut gateway = Gateway::with_nodes(&nodes);

    // Sovereignty configuration: coarsen to ~1 km, embargo for 72 hours, and
    // keep the raw acoustic material access-controlled.
    let mut config = BiomeConfig::new(BIOME_ID);
    config.disclosure = DisclosurePolicy {
        coarsen_decimals: Some(COARSEN_DECIMALS),
        delay_ns: DISCLOSURE_DELAY_NS,
        open_access: false,
    };
    let mut biome = Biome::new(config, BIOME_SEED);

    let mut rng = Rng::new(0x00B5_0B10_0000_2026);
    let mut observations = Vec::new();
    let mut detection: Option<(usize, EvidenceRef, GeoPoint, u64, f64)> = None;

    for round in 0..ROUNDS {
        let measured = round_ns(round);
        for (idx, node) in nodes.iter_mut().enumerate() {
            let value = truth(idx, round) + rng.noise(noise_sd(idx));
            let envelope = node.emit(value, measured, CALIBRATION_ID);
            let sealed = gateway
                .ingest(&envelope, measured + 1_000_000)
                .expect("a node's own signed envelope must ingest");
            let sample = sealed.sample().clone();
            if sample.modality == SensorModality::Acoustic
                && sample.value > SENSITIVE_CALL_INDEX
                && detection.is_none()
            {
                detection = Some((
                    idx,
                    EvidenceRef {
                        node_id: sample.node_id,
                        sequence: sample.sequence,
                    },
                    sample.geo,
                    measured,
                    sample.value,
                ));
            }
            assert_eq!(biome.accept(sealed), AcceptOutcome::Accepted);
            observations.push(sample);
        }
    }

    let (idx, evidence, at, measured, index) =
        detection.expect("the sensitive species is heard in the reserve");

    // The internal event carries the real location. Reserve staff need it.
    let mut internal_event = EnvironmentalEvent {
        evidence_digest: None,
        spec_version: SPEC_VERSION.to_string(),
        event_id: "habitat:sensitive-species:2026-001".to_string(),
        biome_id: BIOME_ID.to_string(),
        kind: EventKind::Anomaly,
        severity: Severity::Watch,
        modality: SensorModality::Acoustic,
        geo: at,
        window_start_ns: round_ns(0),
        window_end_ns: measured,
        detected_ns: measured,
        evidence: vec![evidence],
        confidence: 0.94,
        message: format!(
            "sensitive-species call classified on {} (acoustic activity index {index:.2}); \
             location withheld under the reserve's disclosure policy",
            nodes[idx].label
        ),
        signature_hex: None,
        signer_pubkey_hex: None,
    };
    internal_event.validate().expect("the event is well-formed");
    biome.sign_event(&mut internal_event);

    let release_ns = measured + DISCLOSURE_DELAY_NS;
    let bundles = observations.iter().map(project_sample).collect();
    let true_locations: Vec<GeoPoint> = nodes.iter().map(|n| n.geo).collect();
    let coarsened_locations = true_locations
        .iter()
        .map(|g| g.coarsen(COARSEN_DECIMALS))
        .collect();

    HabitatRun {
        observations,
        bundles,
        at_detection: biome.disclose_event(&internal_event, measured),
        one_ns_early: biome.disclose_event(&internal_event, release_ns - 1),
        at_release: biome.disclose_event(&internal_event, release_ns),
        internal_event,
        release_ns,
        biome_pubkey_hex: biome.public_key_hex(),
        true_locations,
        coarsened_locations,
    }
}

// ---------------------------------------------------------------------------
// Narrative
// ---------------------------------------------------------------------------

fn main() {
    banner(
        "BIODIVERSITY & HABITAT MONITORING — ADR-266 wedge #5",
        "5 signed spore nodes in a protected area; disclosure policy is the product",
    );

    let run = run_reserve();

    println!("  Reserve");
    for node in provision() {
        line(
            &format!("  {}", node.label),
            format!(
                "{} @ {:.6}, {:.6}",
                node.modality.as_str(),
                node.geo.latitude_deg(),
                node.geo.longitude_deg()
            ),
        );
    }
    line("observations accepted", run.observations.len());
    line(
        "disclosure policy",
        format!(
            "coarsen to {COARSEN_DECIMALS} dp, embargo {} h, raw access controlled",
            DISCLOSURE_DELAY_NS / NS_PER_S / 3_600
        ),
    );

    println!("\n  1. The detection, internally");
    let internal = &run.internal_event;
    line("event", &internal.event_id);
    line(
        "kind / severity / confidence",
        format!(
            "{:?} / {:?} / {:.2}",
            internal.kind, internal.severity, internal.confidence
        ),
    );
    line(
        "location (full precision)",
        format!(
            "{:.7}, {:.7} (alt {} mm)",
            internal.geo.latitude_deg(),
            internal.geo.longitude_deg(),
            internal.geo.altitude_mm
        ),
    );
    line("message", &internal.message);
    line("signature verifies", verify_event(internal));

    println!("\n  2. Disclosure during the embargo");
    line(
        "disclose_event at detection",
        if run.at_detection.is_none() {
            "None — withheld"
        } else {
            "RELEASED — guarantee broken"
        },
    );
    line(
        "disclose_event 1 ns before release",
        if run.one_ns_early.is_none() {
            "None — withheld"
        } else {
            "RELEASED — guarantee broken"
        },
    );
    line(
        "embargo lifts at",
        format!(
            "T+{} h after detection",
            (run.release_ns - internal.detected_ns) / NS_PER_S / 3_600
        ),
    );

    println!("\n  3. Disclosure after the embargo");
    let disclosed = run.at_release.as_ref().expect("the embargo lifts");
    line(
        "location (disclosed)",
        format!(
            "{:.7}, {:.7} (alt {} mm)",
            disclosed.geo.latitude_deg(),
            disclosed.geo.longitude_deg(),
            disclosed.geo.altitude_mm
        ),
    );
    line(
        "matches GeoPoint::coarsen",
        disclosed.geo == internal.geo.coarsen(COARSEN_DECIMALS),
    );
    line(
        "displacement from the true site",
        format!("{:.0} m", haversine_m(internal.geo, disclosed.geo)),
    );
    let (north_m, east_m) = cell_size_m(disclosed.geo, COARSEN_DECIMALS);
    line(
        "disclosure grid cell",
        format!(
            "{north_m:.0} m north-south x {east_m:.0} m east-west ({:.2} km^2)",
            north_m * east_m / 1_000_000.0
        ),
    );
    line(
        "the reserve's 5 true locations collapse to",
        format!("{} distinct disclosed point(s)", {
            let mut cells = run.coarsened_locations.clone();
            cells.sort_by_key(|g| (g.latitude_e7, g.longitude_e7));
            cells.dedup();
            cells.len()
        }),
    );
    line(
        "disclosed event still verifies",
        if verify_event(disclosed) {
            "yes — re-signed by the biome"
        } else {
            "NO — guarantee broken"
        },
    );
    let mut tampered = disclosed.clone();
    tampered.geo = internal.geo;
    line(
        "geo restored by a third party",
        if verify_event(&tampered) {
            "verifies — guarantee broken"
        } else {
            "signature breaks — the coarsening is bound in"
        },
    );

    println!("\n  4. SensorThings-inspired projection");
    line("accepted observations", run.observations.len());
    line("entity bundles produced", run.bundles.len());
    let first = &run.bundles[0];
    line("thing", &first.thing.iot_id);
    line("datastream", &first.datastream.iot_id);
    line("observation", &first.observation.iot_id);
    line(
        "phenomenonTime / result",
        format!(
            "{} / {:.3}",
            first.observation.phenomenon_time, first.observation.result
        ),
    );
    line(
        "note",
        "SensorThings-INSPIRED projection — not an OGC-conformant implementation",
    );

    synthetic_footer(
        "Acoustic indices are simulated; the disclosure policy, coarsening, \
         embargo, re-signing, and entity projection are the production code.",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disclosure_is_withheld_for_the_whole_embargo() {
        let run = run_reserve();
        assert!(
            run.at_detection.is_none(),
            "a sensitive location must not leave the biome at detection time"
        );
        assert!(
            run.one_ns_early.is_none(),
            "the embargo must hold to its last nanosecond"
        );
        assert_eq!(
            run.release_ns,
            run.internal_event.detected_ns + DISCLOSURE_DELAY_NS
        );
    }

    #[test]
    fn post_embargo_release_is_coarsened_and_still_verifies() {
        let run = run_reserve();
        let disclosed = run.at_release.expect("the embargo lifts");
        assert_eq!(
            disclosed.geo,
            run.internal_event.geo.coarsen(COARSEN_DECIMALS),
            "the disclosed geo must be exactly GeoPoint::coarsen of the true one"
        );
        assert_ne!(
            disclosed.geo, run.internal_event.geo,
            "coarsening must actually change the coordinates"
        );
        assert_eq!(disclosed.geo.altitude_mm, 0, "altitude is dropped");
        assert!(
            verify_event(&disclosed),
            "the disclosed copy is re-signed and must still verify"
        );
        assert_eq!(
            disclosed.signer_pubkey_hex.as_deref(),
            Some(run.biome_pubkey_hex.as_str())
        );
        // Everything except the location is unchanged.
        assert_eq!(disclosed.event_id, run.internal_event.event_id);
        assert_eq!(disclosed.severity, run.internal_event.severity);
        assert_eq!(disclosed.evidence, run.internal_event.evidence);
    }

    #[test]
    fn coarsening_destroys_precision_irreversibly() {
        let run = run_reserve();
        let disclosed = run.at_release.expect("the embargo lifts");
        let step = grid_step_e7(COARSEN_DECIMALS);

        // The disclosed point is a grid corner, not a location.
        assert_eq!(disclosed.geo.latitude_e7 % step, 0);
        assert_eq!(disclosed.geo.longitude_e7 % step, 0);

        // It is hundreds of metres from the true site, inside a cell of real,
        // computed size.
        let displacement = haversine_m(run.internal_event.geo, disclosed.geo);
        assert!(
            displacement > 100.0,
            "displacement was only {displacement} m"
        );
        let (north_m, east_m) = cell_size_m(disclosed.geo, COARSEN_DECIMALS);
        assert!(
            (north_m - 1_112.0).abs() < 5.0,
            "0.01 degrees of latitude is ~1112 m, got {north_m}"
        );
        assert!(east_m > 500.0 && east_m < north_m, "got {east_m} m");
        assert!(displacement < north_m, "displacement stays inside the cell");

        // Five genuinely different sensor sites, one disclosed point: the
        // mapping is many-to-one, so it cannot be inverted.
        let mut distinct = run.coarsened_locations.clone();
        distinct.sort_by_key(|g| (g.latitude_e7, g.longitude_e7));
        distinct.dedup();
        assert_eq!(distinct.len(), 1, "all five sites share one disclosed cell");
        let spread = haversine_m(run.true_locations[ACO_B], run.true_locations[ACO_C]);
        assert!(spread > 50.0, "the true sites really are {spread} m apart");
    }

    #[test]
    fn the_internal_copy_keeps_full_precision() {
        let run = run_reserve();
        let nodes = provision();
        assert_eq!(run.internal_event.geo, nodes[ACO_B].geo);
        assert_ne!(
            run.internal_event.geo,
            run.internal_event.geo.coarsen(COARSEN_DECIMALS)
        );
        assert!(verify_event(&run.internal_event));
        assert_eq!(
            run.internal_event.geo.altitude_mm,
            nodes[ACO_B].geo.altitude_mm
        );
    }

    #[test]
    fn a_third_party_cannot_restore_the_true_location() {
        let run = run_reserve();
        let disclosed = run.at_release.expect("the embargo lifts");
        for forged_geo in [run.internal_event.geo, run.true_locations[ACO_A]] {
            let mut tampered = disclosed.clone();
            tampered.geo = forged_geo;
            assert!(
                !verify_event(&tampered),
                "editing the disclosed location must break the biome signature"
            );
        }
    }

    #[test]
    fn every_accepted_observation_projects_to_sensorthings_entities() {
        let run = run_reserve();
        assert_eq!(run.observations.len(), ROUNDS * NODE_COUNT);
        assert_eq!(run.bundles.len(), run.observations.len());
        for (sample, bundle) in run.observations.iter().zip(&run.bundles) {
            assert_eq!(
                bundle.thing.iot_id,
                format!("thing:node:{}", sample.node_id)
            );
            assert_eq!(
                bundle.observation.iot_id,
                format!("obs:{}:{}", sample.node_id, sample.sequence)
            );
            assert_eq!(bundle.observation.result, sample.value);
            assert_eq!(bundle.datastream.thing_id, bundle.thing.iot_id);
            assert_eq!(bundle.datastream.sensor_id, bundle.sensor.iot_id);
            // GeoJSON is longitude-first.
            assert_eq!(
                bundle.location.location.coordinates,
                [sample.geo.longitude_deg(), sample.geo.latitude_deg()]
            );
            // And the whole bundle serializes for an external consumer.
            assert!(serde_json::to_string(bundle).is_ok());
        }
    }
}
