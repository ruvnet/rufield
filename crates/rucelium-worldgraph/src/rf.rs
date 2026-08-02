//! RuView RF context bridge (ADR-264 §8).
//!
//! **Normative rule (ADR-264 §8): RF is supporting evidence, NEVER ground
//! truth.** RuView outputs may raise or lower confidence and create
//! contradiction edges, but they may never be the sole basis for an
//! environmental event above [`rucelium_core::Severity::Advisory`], and
//! their evidence weight in the WorldGraph is capped at
//! [`RF_MAX_EVIDENCE_WEIGHT`].

use crate::graph::{EdgeKind, GraphError, GraphNode, WorldGraph};
use rucelium_core::{GeoPoint, SensorModality, Severity};
use serde::{Deserialize, Serialize};

/// Hard cap on the weight of any RF-derived evidence edge (ADR-264 §8).
/// RF context can nudge confidence; it can never dominate physical sensing.
pub const RF_MAX_EVIDENCE_WEIGHT: f32 = 0.3;

/// Contextual RF evidence distilled from a RuField MFS WiFi-CSI
/// [`rufield_core::FieldEvent`]. This is context, not measurement: it never
/// enters the sample path, only the evidence-edge path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RfContext {
    /// The originating `FieldEvent` id.
    pub source_event_id: String,
    /// The RF device id (e.g. `sensor_room_01`).
    pub device_id: String,
    /// Observation confidence `0.0..=1.0` as reported by the RF stack.
    pub confidence: f32,
    /// The `motion_energy` derived feature, if the encoder produced one.
    pub motion_energy: Option<f32>,
    /// Labels attached to the RF observation.
    pub labels: Vec<String>,
    /// Capture time, nanoseconds since Unix epoch.
    pub timestamp_ns: u64,
}

impl RfContext {
    /// Distill RF context from a RuField MFS field event. Accepts only
    /// events whose tensor modality is [`rufield_core::Modality::WifiCsi`]
    /// (the RuView RF-context modality, ADR-264 §5.2); every other modality
    /// yields `None` — this bridge never guesses.
    #[must_use]
    pub fn from_field_event(ev: &rufield_core::FieldEvent) -> Option<RfContext> {
        if ev.tensor.modality != rufield_core::Modality::WifiCsi {
            return None;
        }
        Some(RfContext {
            source_event_id: ev.event_id.clone(),
            device_id: ev.sensor.device_id.clone(),
            confidence: ev.observation.confidence,
            motion_energy: ev.observation.features.get("motion_energy").copied(),
            labels: ev.observation.labels.clone(),
            timestamp_ns: ev.timestamp_ns,
        })
    }
}

/// Outcome of checking an environmental observation against RF context
/// (ADR-264 §8 item 9: "validation that an observation is physically
/// plausible").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Plausibility {
    /// The RF context agrees with the observation.
    Supported,
    /// The RF context disagrees with the observation.
    Contradicted,
    /// The RF context is outside the temporal window — it says nothing.
    NoContext,
}

/// Assess whether RF context supports or contradicts an environmental
/// observation.
///
/// * `sample_indicates_change` — whether the environmental sample itself
///   indicates activity or an anomaly (decided by the caller's detector;
///   this function does not guess modality thresholds).
/// * `sample_measured_ns` — the sample's measurement time.
///
/// Returns [`Plausibility::NoContext`] when the RF observation is more than
/// `window_ns` away from the sample in time. Otherwise the RF motion signal
/// (`motion_energy > 0.5`, absent treated as no motion) is compared with
/// `sample_indicates_change`: agreement is [`Plausibility::Supported`],
/// disagreement is [`Plausibility::Contradicted`]. Either way the RF verdict
/// is context only — never ground truth (ADR-264 §8).
#[must_use]
pub fn assess_plausibility(
    sample_indicates_change: bool,
    sample_measured_ns: u64,
    rf: &RfContext,
    window_ns: u64,
) -> Plausibility {
    if rf.timestamp_ns.abs_diff(sample_measured_ns) > window_ns {
        return Plausibility::NoContext;
    }
    let rf_indicates_motion = rf.motion_energy.unwrap_or(0.0) > 0.5;
    if rf_indicates_motion == sample_indicates_change {
        Plausibility::Supported
    } else {
        Plausibility::Contradicted
    }
}

/// Fuse RF context into the WorldGraph as a capped evidence edge.
///
/// Ensures an RF node exists at key `rf/{device_id}` (a `Sensor` node with
/// modality [`SensorModality::WifiCsi`], zeroed geo, placement
/// `"rf_context"`), then:
///
/// * [`Plausibility::Supported`] — adds a `Supports` edge from the RF node
///   to `sensor_key` with weight `rf.confidence.min(RF_MAX_EVIDENCE_WEIGHT)`
///   (the §8 cap: RF evidence can never exceed 0.3, regardless of how
///   confident the RF stack is).
/// * [`Plausibility::Contradicted`] — records a contradiction (a
///   `Contradicts` edge, counted by the graph's contradiction counter).
/// * [`Plausibility::NoContext`] — adds nothing and returns `Ok(None)`.
///
/// On success returns `Ok(Some(rf_node_key))`.
pub fn fuse_rf_context(
    graph: &mut WorldGraph,
    sensor_key: &str,
    rf: &RfContext,
    plausibility: Plausibility,
) -> Result<Option<String>, GraphError> {
    if plausibility == Plausibility::NoContext {
        return Ok(None);
    }
    let rf_key = format!("rf/{}", rf.device_id);
    graph.add_node(
        rf_key.clone(),
        GraphNode::Sensor {
            node_id: 0,
            modality: SensorModality::WifiCsi,
            geo: GeoPoint {
                latitude_e7: 0,
                longitude_e7: 0,
                altitude_mm: 0,
            },
            placement: "rf_context".to_string(),
        },
    );
    match plausibility {
        Plausibility::Supported => {
            let weight = rf.confidence.min(RF_MAX_EVIDENCE_WEIGHT);
            graph.add_edge(
                &rf_key,
                sensor_key,
                EdgeKind::Supports,
                weight,
                format!("rf:{}", rf.source_event_id),
            )?;
        }
        Plausibility::Contradicted => {
            graph.record_contradiction(
                &rf_key,
                sensor_key,
                format!("rf context disagrees: rf:{}", rf.source_event_id),
            )?;
        }
        Plausibility::NoContext => unreachable!("handled above"),
    }
    Ok(Some(rf_key))
}

/// Clamp a severity to at most [`Severity::Advisory`].
///
/// **This is the ADR-264 §8 normative rule, enforced:** an event whose only
/// evidence is RF context may NEVER exceed `Advisory` severity. RF is
/// supporting evidence — it raises or lowers confidence in physically
/// sensed events, but on its own it can only ever inform, never alarm.
/// Callers MUST route any RF-only event severity through this cap.
#[must_use]
pub fn rf_only_severity_cap(severity: Severity) -> Severity {
    severity.min(Severity::Advisory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rucelium_core::EnvSample;
    use rucelium_core::SampleProvenance;
    use rucelium_core::Uncertainty;
    use rufield_core::{
        FieldAxis, FieldEvent, FieldTensor, Modality, Observation, PrivacyClass, ProvenanceRef,
        SensorDescriptor,
    };

    fn field_event(modality: Modality, motion_energy: f32, confidence: f32) -> FieldEvent {
        let tensor = FieldTensor::new(
            1_000,
            modality,
            vec![FieldAxis::Frequency],
            vec![2],
            vec![0.1, 0.2],
            0.9,
            0.01,
            Some("cal".into()),
            PrivacyClass::P2,
        )
        .unwrap();
        let mut observation = Observation::occupancy(confidence, PrivacyClass::P2);
        observation
            .features
            .insert("motion_energy".to_string(), motion_energy);
        observation.labels = vec!["person_present".to_string()];
        FieldEvent::new(
            "01JRF0000000000000000000EV",
            1_000,
            SensorDescriptor {
                modality: "wifi_csi".into(),
                vendor: "esp32_c6".into(),
                device_id: "rf_dev_01".into(),
                placement: "ceiling_corner".into(),
                clock_domain: "local_ptp".into(),
            },
            tensor,
            observation,
            ProvenanceRef {
                raw_hash: "sha256:raw".into(),
                firmware_hash: "sha256:fw".into(),
                model_id: "ruvector_field_encoder_v1".into(),
                calibration_id: "cal".into(),
                synthetic: true,
                signature_hex: None,
                signer_pubkey_hex: None,
            },
        )
    }

    fn env_sample(node_id: u64) -> EnvSample {
        EnvSample {
            node_id,
            sequence: 1,
            measured_ns: 1_000,
            received_ns: 2_000,
            geo: GeoPoint::new(514_778_216, -14_767, 0).unwrap(),
            modality: SensorModality::Acoustic,
            observed_property: "acoustic_activity_index".into(),
            unit: "1".into(),
            value: 0.8,
            quality: 0.95,
            uncertainty: Uncertainty::symmetric(0.8, 0.05),
            calibration_id: 1,
            flags: 0,
            battery_mv: 3600,
            provenance: SampleProvenance {
                firmware_hash: "sha256:abc".into(),
                signer_pubkey_hex: "00ff".into(),
                verified: true,
                lineage: vec![],
            },
        }
    }

    #[test]
    fn from_field_event_accepts_only_wifi_csi() {
        let ev = field_event(Modality::WifiCsi, 0.8, 0.9);
        let rf = RfContext::from_field_event(&ev).unwrap();
        assert_eq!(rf.source_event_id, "01JRF0000000000000000000EV");
        assert_eq!(rf.device_id, "rf_dev_01");
        assert_eq!(rf.confidence, 0.9);
        assert_eq!(rf.motion_energy, Some(0.8));
        assert_eq!(rf.labels, vec!["person_present".to_string()]);
        assert_eq!(rf.timestamp_ns, 1_000);

        let other = field_event(Modality::MmwaveRadar, 0.8, 0.9);
        assert_eq!(RfContext::from_field_event(&other), None);
    }

    #[test]
    fn rf_evidence_weight_never_exceeds_cap() {
        let ev = field_event(Modality::WifiCsi, 0.9, 0.99);
        let rf = RfContext::from_field_event(&ev).unwrap();

        let mut g = WorldGraph::new();
        let sensor_key = g.register_observation(&env_sample(7));
        let rf_key = fuse_rf_context(&mut g, &sensor_key, &rf, Plausibility::Supported)
            .unwrap()
            .unwrap();
        assert_eq!(rf_key, "rf/rf_dev_01");

        let edges = g.edges_from(&rf_key);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].kind, EdgeKind::Supports);
        assert!(edges[0].weight <= RF_MAX_EVIDENCE_WEIGHT);
        assert_eq!(edges[0].weight, RF_MAX_EVIDENCE_WEIGHT);

        // The rf node exists with the required shape.
        match g.node(&rf_key).unwrap() {
            GraphNode::Sensor {
                modality,
                placement,
                ..
            } => {
                assert_eq!(*modality, SensorModality::WifiCsi);
                assert_eq!(placement, "rf_context");
            }
            other => panic!("expected sensor node, got {other:?}"),
        }
    }

    #[test]
    fn plausibility_agreement_disagreement_and_window() {
        let ev = field_event(Modality::WifiCsi, 0.8, 0.9); // motion present
        let rf = RfContext::from_field_event(&ev).unwrap();

        // Agreement: sample indicates change, RF sees motion.
        assert_eq!(
            assess_plausibility(true, 1_500, &rf, 1_000),
            Plausibility::Supported
        );
        // Disagreement: sample indicates change, RF sees no motion.
        let still = field_event(Modality::WifiCsi, 0.1, 0.9);
        let rf_still = RfContext::from_field_event(&still).unwrap();
        assert_eq!(
            assess_plausibility(true, 1_500, &rf_still, 1_000),
            Plausibility::Contradicted
        );
        // No motion + no change agrees too.
        assert_eq!(
            assess_plausibility(false, 1_500, &rf_still, 1_000),
            Plausibility::Supported
        );
        // Outside window: no context, regardless of content.
        assert_eq!(
            assess_plausibility(true, 5_000_000, &rf, 1_000),
            Plausibility::NoContext
        );
    }

    #[test]
    fn fuse_contradiction_adds_contradicts_edge_and_no_context_adds_nothing() {
        let ev = field_event(Modality::WifiCsi, 0.1, 0.9);
        let rf = RfContext::from_field_event(&ev).unwrap();

        let mut g = WorldGraph::new();
        let sensor_key = g.register_observation(&env_sample(7));

        // NoContext adds nothing at all.
        assert_eq!(
            fuse_rf_context(&mut g, &sensor_key, &rf, Plausibility::NoContext).unwrap(),
            None
        );
        assert_eq!(g.len(), 1);
        assert_eq!(g.edges().count(), 0);

        // Contradicted records a tracked contradiction.
        let rf_key = fuse_rf_context(&mut g, &sensor_key, &rf, Plausibility::Contradicted)
            .unwrap()
            .unwrap();
        let c = g.contradictions();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].from, rf_key);
        assert_eq!(c[0].to, sensor_key);
        assert_eq!(g.contradiction_count(), 1);

        // Fusing against an unknown sensor fails cleanly.
        assert!(matches!(
            fuse_rf_context(&mut g, "sensor/none", &rf, Plausibility::Supported),
            Err(GraphError::UnknownNode(_))
        ));
    }

    #[test]
    fn rf_only_severity_is_capped_at_advisory() {
        assert_eq!(rf_only_severity_cap(Severity::Critical), Severity::Advisory);
        assert_eq!(rf_only_severity_cap(Severity::Warning), Severity::Advisory);
        assert_eq!(rf_only_severity_cap(Severity::Watch), Severity::Advisory);
        assert_eq!(rf_only_severity_cap(Severity::Advisory), Severity::Advisory);
    }
}
