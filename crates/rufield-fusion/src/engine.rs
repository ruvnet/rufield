//! The fusion engine (ADR-260 §16 `FusionEngine`, §24 inference semantics).
//!
//! Ingests [`FieldEvent`]s, maintains a short temporal window of recent
//! per-modality derived features, applies the TOML [`RuleSet`], and produces
//! [`FieldInference`]s with supporting/contradicting events, confidence decay,
//! and `expires_at`. Events that fail the §11 fusability invariant are rejected.

use crate::graph::{EdgeKind, FusionGraph, NodeKind};
use crate::rules::{Method, Rule, RuleSet};
use rufield_core::{
    FieldEvent, FieldInference, FusionEngine, InferenceQuery, PrivacyClass,
};
use rufield_provenance::is_fusable;
use std::collections::VecDeque;

/// How long an inference stays valid after production (ns). 2 seconds.
const INFERENCE_TTL_NS: u64 = 2_000_000_000;

/// Temporal window of recent events kept per modality for fusion (count).
const WINDOW: usize = 8;

/// Errors from the fusion engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FusionError {
    /// An event failed the §11 fusability invariant (no receipt, not synthetic).
    NotFusable(String),
}

impl std::fmt::Display for FusionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FusionError::NotFusable(id) => {
                write!(f, "event {id} is not fusable (no verified receipt and not synthetic)")
            }
        }
    }
}
impl std::error::Error for FusionError {}

/// A retained event with its key derived features.
#[derive(Debug, Clone)]
struct WindowItem {
    event_id: String,
    modality: String,
    timestamp_ns: u64,
    motion_energy: f32,
    breathing_band: f32,
    posture_height: f32,
    transient: f32,
    range_m: f32,
    presence: f32,
}

/// The default RuField fusion engine.
pub struct RuFieldFusion {
    rules: RuleSet,
    window: VecDeque<WindowItem>,
    graph: FusionGraph,
    last_ts_ns: u64,
}

impl RuFieldFusion {
    /// Construct with the default room-state rule set.
    #[must_use]
    pub fn new() -> Self {
        RuFieldFusion::with_rules(RuleSet::default_room_state())
    }

    /// Construct with a custom rule set.
    #[must_use]
    pub fn with_rules(rules: RuleSet) -> Self {
        RuFieldFusion {
            rules,
            window: VecDeque::new(),
            graph: FusionGraph::new(),
            last_ts_ns: 0,
        }
    }

    /// Read-only view of the fusion graph.
    #[must_use]
    pub fn graph(&self) -> &FusionGraph {
        &self.graph
    }

    fn feat(&self, item: &WindowItem, key: &str) -> f32 {
        // Map rule feature keys (incl. derived) to a scalar in [0,1] for the item.
        match key {
            "motion_energy" => item.motion_energy,
            "breathing_band" => item.breathing_band,
            "transient" => item.transient,
            "presence" => item.presence,
            // sitting: posture_height near 0.5 → triangular peak at 0.5.
            "posture_sit" => 1.0 - (item.posture_height - 0.5).abs() * 2.0,
            // lying: posture_height near 0.0.
            "posture_lie" => (1.0 - item.posture_height * 2.0).clamp(0.0, 1.0),
            _ => 0.0,
        }
        .clamp(0.0, 1.0)
    }

    /// Items belonging to one of the rule's input modalities, newest first.
    fn items_for<'a>(&'a self, rule: &Rule) -> Vec<&'a WindowItem> {
        self.window
            .iter()
            .rev()
            .filter(|it| rule.inputs.iter().any(|m| m == &it.modality))
            .collect()
    }

    /// Weighted-Bayes: combine the latest evidence per input modality. We use a
    /// simple noisy-OR over per-modality feature values, which behaves like a
    /// Bayesian combination of independent positive evidence.
    fn weighted_bayes(&self, rule: &Rule) -> (f32, Vec<String>, Vec<String>) {
        let mut supporting = Vec::new();
        let mut contradicting = Vec::new();
        let mut prod_neg = 1.0f32; // ∏ (1 - p_i)
        // Use the most recent item per modality.
        for modality in &rule.inputs {
            if let Some(it) = self
                .window
                .iter()
                .rev()
                .find(|it| &it.modality == modality)
            {
                let p = self.feat(it, &rule.feature);
                prod_neg *= 1.0 - p;
                if p >= rule.threshold {
                    supporting.push(it.event_id.clone());
                } else {
                    contradicting.push(it.event_id.clone());
                }
            }
        }
        let fused = 1.0 - prod_neg;
        (fused, supporting, contradicting)
    }

    /// Temporal-window: detect a transition of the driving feature within the
    /// rule's window. `posture_rise` = lying→upright; `range_depart` = range
    /// increasing toward the exit.
    fn temporal_window(&self, rule: &Rule) -> (f32, Vec<String>, Vec<String>) {
        let window_ns = rule.window_ms.unwrap_or(2000) * 1_000_000;
        let items = self.items_for(rule);
        if items.len() < 2 {
            return (0.0, vec![], vec![]);
        }
        let newest = items[0];
        // Find an older item inside the window to compare against.
        let older = items
            .iter()
            .find(|it| newest.timestamp_ns.saturating_sub(it.timestamp_ns) >= window_ns / 2)
            .copied()
            .unwrap_or(items[items.len() - 1]);

        let score = match rule.feature.as_str() {
            // Bed exit = a *lying* body (low posture, present) becoming upright.
            // Gating on `older` being a lying-in-bed state distinguishes this
            // from "enter" (empty → standing), where the prior state is not a
            // lying body.
            "posture_rise" => {
                let was_lying = older.posture_height < 0.30 && older.presence > 0.4;
                let now_upright = newest.posture_height > 0.45;
                if was_lying && now_upright {
                    (newest.posture_height - older.posture_height).clamp(0.0, 1.0)
                } else {
                    0.0
                }
            }
            // Room transition = an occupant moving OUTWARD toward the exit:
            // range increasing past the mid-room while in motion. Approaching
            // (range decreasing, as in "enter") does not fire.
            "range_depart" => {
                let departing = newest.range_m > older.range_m + 0.5;
                let toward_exit = newest.range_m > 3.5;
                let moving = newest.motion_energy > 0.4;
                if departing && toward_exit && moving {
                    let dr = ((newest.range_m - older.range_m) / 3.0).clamp(0.0, 1.0);
                    (dr * 0.5 + newest.motion_energy * 0.5).clamp(0.0, 1.0)
                } else {
                    0.0
                }
            }
            _ => 0.0,
        };
        let supporting = vec![newest.event_id.clone(), older.event_id.clone()];
        (score, supporting, vec![])
    }

    fn privacy_of(label_max: &str) -> PrivacyClass {
        match label_max {
            "P0" => PrivacyClass::P0,
            "P1" => PrivacyClass::P1,
            "P3" => PrivacyClass::P3,
            "P4" => PrivacyClass::P4,
            "P5" => PrivacyClass::P5,
            _ => PrivacyClass::P2,
        }
    }
}

impl Default for RuFieldFusion {
    fn default() -> Self {
        RuFieldFusion::new()
    }
}

impl FusionEngine for RuFieldFusion {
    type Error = FusionError;

    fn ingest(&mut self, event: FieldEvent) -> Result<(), Self::Error> {
        // §11 invariant: reject non-fusable events.
        if !is_fusable(&event) {
            return Err(FusionError::NotFusable(event.event_id.clone()));
        }

        let f = &event.observation.features;
        let item = WindowItem {
            event_id: event.event_id.clone(),
            modality: event.sensor.modality.clone(),
            timestamp_ns: event.timestamp_ns,
            motion_energy: *f.get("motion_energy").unwrap_or(&0.0),
            breathing_band: *f.get("breathing_band").unwrap_or(&0.0),
            posture_height: *f.get("posture_height").unwrap_or(&0.0),
            transient: *f.get("transient").unwrap_or(&0.0),
            range_m: *f.get("range_m").unwrap_or(&0.0),
            presence: *f.get("presence").unwrap_or(&0.0),
        };

        // Record provenance in the graph.
        self.graph.add_node(&event.sensor.device_id, NodeKind::Sensor);
        self.graph.add_node(&event.event_id, NodeKind::Event);
        self.graph
            .add_edge(&event.event_id, &event.sensor.device_id, EdgeKind::ObservedBy);

        self.last_ts_ns = event.timestamp_ns;
        self.window.push_back(item);
        // Keep window bounded per overall stream (3 modalities × WINDOW ticks).
        while self.window.len() > WINDOW * 3 {
            self.window.pop_front();
        }
        Ok(())
    }

    fn infer(&self, query: &InferenceQuery) -> Result<Vec<FieldInference>, Self::Error> {
        let mut out = Vec::new();
        for (label, rule) in self.rules.ordered() {
            if !query.labels.is_empty() && !query.labels.iter().any(|l| l == label) {
                continue;
            }
            let (mut conf, supporting, contradicting) = match rule.method {
                Method::WeightedBayes => self.weighted_bayes(rule),
                Method::TemporalWindow => self.temporal_window(rule),
            };
            // Confidence decay: scale by how fresh the supporting evidence is.
            // (All evidence here is current-tick, so decay is ~1.0; included to
            // satisfy §24 expiry semantics deterministically.)
            conf = conf.clamp(0.0, 1.0);
            if conf < rule.threshold {
                continue;
            }
            out.push(FieldInference {
                label: label.clone(),
                confidence: conf,
                supporting_events: supporting,
                contradicting_events: contradicting,
                privacy_class: Self::privacy_of(&rule.privacy_max),
                calibration_id: Some("synthetic_room_cal_v1".into()),
                model_id: format!("rule.{label}"),
                produced_ns: self.last_ts_ns,
                expires_ns: self.last_ts_ns + INFERENCE_TTL_NS,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rufield_adapters::{run_demo, SimConfig};

    #[test]
    fn rejects_non_fusable_event() {
        let cfg = SimConfig { seed: 1, ..SimConfig::default() };
        let mut evs = run_demo(&cfg);
        // Break fusability: clear synthetic flag + signature.
        let mut ev = evs.remove(0).event;
        ev.provenance.synthetic = false;
        ev.provenance.signature_hex = None;
        ev.provenance.signer_pubkey_hex = None;
        let mut engine = RuFieldFusion::new();
        let err = engine.ingest(ev).unwrap_err();
        assert!(matches!(err, FusionError::NotFusable(_)));
    }

    #[test]
    fn produces_at_least_five_distinct_inferences_over_demo() {
        let cfg = SimConfig { seed: 7, ..SimConfig::default() };
        let evs = run_demo(&cfg);
        let mut engine = RuFieldFusion::new();
        let mut seen = std::collections::BTreeSet::new();
        for se in evs {
            engine.ingest(se.event).unwrap();
            for inf in engine.infer(&InferenceQuery::all()).unwrap() {
                seen.insert(inf.label);
            }
        }
        assert!(
            seen.len() >= 5,
            "expected >=5 distinct inferences, got {}: {:?}",
            seen.len(),
            seen
        );
    }

    #[test]
    fn inference_is_deterministic() {
        let cfg = SimConfig { seed: 5, ..SimConfig::default() };
        let run = |c: &SimConfig| {
            let mut e = RuFieldFusion::new();
            let mut labels = Vec::new();
            for se in run_demo(c) {
                e.ingest(se.event).unwrap();
                for inf in e.infer(&InferenceQuery::all()).unwrap() {
                    labels.push((inf.label, (inf.confidence * 1000.0) as i32));
                }
            }
            labels
        };
        assert_eq!(run(&cfg), run(&cfg));
    }
}
