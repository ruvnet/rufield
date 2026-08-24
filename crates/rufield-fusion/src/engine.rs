//! The fusion engine (ADR-260 §16 `FusionEngine`, §24 inference semantics).
//!
//! Ingests [`FieldEvent`]s, maintains a short temporal window of recent
//! per-modality derived features, applies the TOML [`RuleSet`], and produces
//! [`FieldInference`]s with supporting/contradicting events, confidence decay,
//! and `expires_at`. Ingestion runs through a stateful provenance trust policy
//! before any event reaches the fusion window or graph.

use crate::graph::{EdgeKind, FusionGraph, NodeKind};
use crate::rules::{Method, Rule, RuleSet};
use rufield_core::{
    FieldEvent, FieldInference, FusionEngine, InferenceQuery, Modality, PrivacyClass,
};
// §11 fusability is not called directly here: `TrustVerifier` owns it in both
// modes. Simulation applies `is_fusable` itself, and production requires a
// valid signature from an enrolled, unrevoked, fresh key -- strictly more than
// `is_fusable`'s synthetic-or-valid-signature test. Calling it here as well
// would pre-empt the verifier and report `NotFusable` for a tampered event that
// the verifier can describe precisely.
use rufield_provenance::{TrustError, TrustMode, TrustPolicy, TrustVerifier, TrustedKeyRegistry};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

/// How long an inference stays valid after production (ns). 2 seconds.
const INFERENCE_TTL_NS: u64 = 2_000_000_000;

/// Temporal window of recent events kept per modality for fusion (count).
const WINDOW: usize = 8;

/// Track-partition sizing factor used by the global retained-item safety cap.
const MAX_TRACK_PARTITIONS: usize = 64;

/// Registry size used to bound total retained items after per-partition limits.
const MAX_MODALITIES: usize = 16;

/// Trust policy applied specifically to BLE events after provenance
/// verification and before semantic validation or graph insertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BleTrustPolicy {
    allow_synthetic: bool,
    allowed_signers: BTreeMap<String, BTreeSet<String>>,
}

impl BleTrustPolicy {
    /// Production policy. Synthetic BLE is denied and the signer allowlist is
    /// initially empty, so BLE fails closed until explicitly provisioned.
    #[must_use]
    pub fn production() -> Self {
        Self {
            allow_synthetic: false,
            allowed_signers: BTreeMap::new(),
        }
    }

    /// Deliberately permissive policy for deterministic synthetic tests only.
    /// Non-synthetic BLE remains subject to the signer allowlist.
    #[must_use]
    pub fn synthetic_test_only() -> Self {
        Self {
            allow_synthetic: true,
            allowed_signers: BTreeMap::new(),
        }
    }

    /// Allow one exact sensor-device and Ed25519 public-key pair.
    #[must_use]
    pub fn with_allowed_signer(
        mut self,
        device_id: impl Into<String>,
        signer_pubkey_hex: impl Into<String>,
    ) -> Self {
        self.allowed_signers
            .entry(device_id.into())
            .or_default()
            .insert(signer_pubkey_hex.into());
        self
    }

    fn validate(&self, event: &FieldEvent) -> Result<(), String> {
        if !matches!(
            event.tensor.modality,
            Modality::BleAdvertisementRssi | Modality::BleChannelSounding
        ) {
            return Ok(());
        }
        if event.provenance.synthetic {
            return if self.allow_synthetic {
                Ok(())
            } else {
                Err("synthetic BLE is disabled by the production trust policy".into())
            };
        }
        let signer = event
            .provenance
            .signer_pubkey_hex
            .as_deref()
            .ok_or_else(|| "BLE event has no signer key".to_string())?;
        let allowed = self
            .allowed_signers
            .get(&event.sensor.device_id)
            .is_some_and(|keys| keys.contains(signer));
        if allowed {
            Ok(())
        } else {
            Err("BLE sensor device and signer key are not allowlisted".into())
        }
    }
}

impl Default for BleTrustPolicy {
    fn default() -> Self {
        Self::production()
    }
}

/// Errors from the fusion engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FusionError {
    /// An event failed the legacy simulation fusability invariant.
    NotFusable(String),
    /// Captured replay or production policy rejected an event.
    TrustRejected {
        /// Rejected event id.
        event_id: String,
        /// Machine-readable trust-policy reason.
        reason: TrustError,
    },
    /// A signed or synthetic event still failed cross-field evidence rules.
    InvalidEvidence {
        /// Event identifier.
        event_id: String,
        /// Fail-closed validation reason.
        reason: String,
    },
    /// BLE provenance was valid but its device/signer trust policy denied it.
    UntrustedBle {
        /// Event identifier.
        event_id: String,
        /// Trust-policy denial reason.
        reason: String,
    },
}

impl std::fmt::Display for FusionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FusionError::NotFusable(id) => {
                write!(f, "event {id} is not fusable in simulation mode")
            }
            FusionError::TrustRejected { event_id, reason } => {
                write!(f, "event {event_id} rejected by trust policy: {reason}")
            }
            FusionError::InvalidEvidence { event_id, reason } => {
                write!(f, "event {event_id} carries invalid evidence: {reason}")
            }
            FusionError::UntrustedBle { event_id, reason } => {
                write!(f, "event {event_id} is untrusted BLE evidence: {reason}")
            }
        }
    }
}
impl std::error::Error for FusionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TrustRejected { reason, .. } => Some(reason),
            // These two carry a rendered reason string rather than a typed
            // source error, so there is nothing further to chain to.
            Self::NotFusable(_) | Self::InvalidEvidence { .. } | Self::UntrustedBle { .. } => None,
        }
    }
}

/// A retained event with its key derived features.
#[derive(Debug, Clone)]
struct WindowItem {
    event_id: String,
    modality: String,
    track_id: Option<String>,
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
    trust: TrustVerifier,
    window: VecDeque<WindowItem>,
    graph: FusionGraph,
    last_ts_ns: u64,
    ble_trust: BleTrustPolicy,
}

impl RuFieldFusion {
    /// Construct the backwards-compatible deterministic simulation engine.
    ///
    /// Live callers must instead construct a production [`TrustVerifier`] and
    /// pass it to [`Self::with_trust_verifier`].
    #[must_use]
    pub fn new() -> Self {
        RuFieldFusion::with_rules(RuleSet::default_room_state())
    }

    /// Construct with custom rules in explicit simulation mode.
    #[must_use]
    pub fn with_rules(rules: RuleSet) -> Self {
        Self::with_rules_trust_and_ble(
            rules,
            TrustVerifier::simulation(),
            BleTrustPolicy::production(),
        )
    }

    /// Construct with default rules and an explicit trust policy.
    #[must_use]
    pub fn with_trust_verifier(trust: TrustVerifier) -> Self {
        Self::with_rules_and_trust(RuleSet::default_room_state(), trust)
    }

    /// Construct a fail-closed live engine from independently enrolled keys.
    #[must_use]
    pub fn production(registry: TrustedKeyRegistry) -> Self {
        Self::with_trust_verifier(TrustVerifier::new(TrustPolicy::production(), registry))
    }

    /// Construct with custom rules and an explicit trust policy.
    #[must_use]
    pub fn with_rules_and_trust(rules: RuleSet, trust: TrustVerifier) -> Self {
        Self::with_rules_trust_and_ble(rules, trust, BleTrustPolicy::production())
    }

    /// Construct with default room rules and an explicit BLE trust policy.
    #[must_use]
    pub fn with_ble_trust(ble_trust: BleTrustPolicy) -> Self {
        Self::with_rules_and_ble_trust(RuleSet::default_room_state(), ble_trust)
    }

    /// Construct with custom rules and an explicit BLE trust policy.
    #[must_use]
    pub fn with_rules_and_ble_trust(rules: RuleSet, ble_trust: BleTrustPolicy) -> Self {
        Self::with_rules_trust_and_ble(rules, TrustVerifier::simulation(), ble_trust)
    }

    /// Construct with custom rules and both trust policies stated explicitly.
    ///
    /// The two gates are independent and both must pass: [`TrustVerifier`]
    /// governs provenance for every event, while [`BleTrustPolicy`] adds the
    /// device/signer allowlist that only BLE modalities are subject to.
    #[must_use]
    pub fn with_rules_trust_and_ble(
        rules: RuleSet,
        trust: TrustVerifier,
        ble_trust: BleTrustPolicy,
    ) -> Self {
        RuFieldFusion {
            rules,
            trust,
            window: VecDeque::new(),
            graph: FusionGraph::new(),
            last_ts_ns: 0,
            ble_trust,
        }
    }

    /// Read-only access to policy, enrollment and replay state.
    #[must_use]
    pub const fn trust_verifier(&self) -> &TrustVerifier {
        &self.trust
    }

    /// Mutable access for protected enrollment, revocation and replay-state
    /// restoration before ingestion starts.
    #[must_use]
    pub fn trust_verifier_mut(&mut self) -> &mut TrustVerifier {
        &mut self.trust
    }

    /// Read-only view of the fusion graph.
    #[must_use]
    pub fn graph(&self) -> &FusionGraph {
        &self.graph
    }

    /// Ingest using an explicit wall-clock value. This is the deterministic
    /// entry point for production tests and replay orchestration.
    pub fn ingest_at(&mut self, event: FieldEvent, now_ns: u64) -> Result<(), FusionError> {
        let event_id = event.event_id.clone();
        let mode = self.trust.mode();
        if let Err(reason) = self.trust.verify_and_record_at(&event, now_ns) {
            return if mode == TrustMode::Simulation {
                Err(FusionError::NotFusable(event_id))
            } else {
                Err(FusionError::TrustRejected { event_id, reason })
            };
        }
        // The provenance verifier proves origin and integrity. Two further
        // gates are independent of it and must also pass before anything
        // reaches the graph: BLE carries a device/signer allowlist, and every
        // event carries short-lived identity/privacy/modality invariants that
        // are only meaningful at the current stream watermark.
        if let Err(reason) = self.ble_trust.validate(&event) {
            return Err(FusionError::UntrustedBle { event_id, reason });
        }
        let evidence_watermark = self.last_ts_ns.max(event.timestamp_ns);
        if let Err(error) = event.validate_evidence_at(evidence_watermark) {
            return Err(FusionError::InvalidEvidence {
                event_id,
                reason: error.to_string(),
            });
        }
        self.commit_verified_event(event);
        Ok(())
    }

    fn commit_verified_event(&mut self, event: FieldEvent) {
        let f = &event.observation.features;
        let item = WindowItem {
            event_id: event.event_id.clone(),
            modality: event.sensor.modality.clone(),
            track_id: event.observation.track_id.clone(),
            timestamp_ns: event.timestamp_ns,
            motion_energy: *f.get("motion_energy").unwrap_or(&0.0),
            breathing_band: *f.get("breathing_band").unwrap_or(&0.0),
            posture_height: *f.get("posture_height").unwrap_or(&0.0),
            transient: *f.get("transient").unwrap_or(&0.0),
            range_m: *f.get("range_m").unwrap_or(&0.0),
            presence: *f.get("presence").unwrap_or(&0.0),
        };

        self.graph
            .add_node(&event.sensor.device_id, NodeKind::Sensor);
        self.graph.add_node(&event.event_id, NodeKind::Event);
        self.graph.add_edge(
            &event.event_id,
            &event.sensor.device_id,
            EdgeKind::ObservedBy,
        );

        self.last_ts_ns = self.last_ts_ns.max(event.timestamp_ns);
        self.window.push_back(item);
        // Bound each track and modality partition independently so one noisy
        // track cannot evict another track's recent evidence.
        let newest = self.window.back().expect("item was just inserted");
        let partition_track = newest.track_id.clone();
        let partition_modality = newest.modality.clone();
        while self
            .window
            .iter()
            .filter(|candidate| {
                candidate.track_id == partition_track && candidate.modality == partition_modality
            })
            .count()
            > WINDOW
        {
            if let Some((index, _)) = self
                .window
                .iter()
                .enumerate()
                .filter(|(_, candidate)| {
                    candidate.track_id == partition_track
                        && candidate.modality == partition_modality
                })
                .min_by_key(|(_, candidate)| candidate.timestamp_ns)
            {
                self.window.remove(index);
            }
        }
        while self.window.len() > WINDOW * MAX_MODALITIES * MAX_TRACK_PARTITIONS {
            self.window.pop_front();
        }
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
    fn items_for<'a>(&'a self, rule: &Rule, track_id: &Option<String>) -> Vec<&'a WindowItem> {
        let mut items: Vec<_> = self
            .window
            .iter()
            .filter(|it| &it.track_id == track_id && rule.inputs.iter().any(|m| m == &it.modality))
            .collect();
        items.sort_by_key(|item| std::cmp::Reverse(item.timestamp_ns));
        items
    }

    /// Weighted-Bayes: combine the latest evidence per input modality. We use a
    /// simple noisy-OR over per-modality feature values, which behaves like a
    /// Bayesian combination of independent positive evidence.
    fn weighted_bayes(
        &self,
        rule: &Rule,
        track_id: &Option<String>,
    ) -> (f32, Vec<String>, Vec<String>) {
        let mut supporting = Vec::new();
        let mut contradicting = Vec::new();
        let mut prod_neg = 1.0f32; // ∏ (1 - p_i)
                                   // Use the most recent item per modality.
        for modality in &rule.inputs {
            if let Some(it) = self
                .window
                .iter()
                .filter(|it| &it.track_id == track_id && &it.modality == modality)
                .max_by_key(|it| it.timestamp_ns)
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
    fn temporal_window(
        &self,
        rule: &Rule,
        track_id: &Option<String>,
    ) -> (f32, Vec<String>, Vec<String>) {
        let window_ns = rule.window_ms.unwrap_or(2000) * 1_000_000;
        let items = self.items_for(rule, track_id);
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

    fn partitions(&self, query: &InferenceQuery) -> Vec<Option<String>> {
        if let Some(track_id) = &query.track_id {
            return vec![Some(track_id.clone())];
        }
        self.window
            .iter()
            .map(|item| item.track_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn partition_timestamp(&self, track_id: &Option<String>) -> u64 {
        self.window
            .iter()
            .filter(|item| &item.track_id == track_id)
            .map(|item| item.timestamp_ns)
            .max()
            .unwrap_or(self.last_ts_ns)
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
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        self.ingest_at(event, now_ns)
    }

    fn infer(&self, query: &InferenceQuery) -> Result<Vec<FieldInference>, Self::Error> {
        let mut out = Vec::new();
        for (label, rule) in self.rules.ordered() {
            if !query.labels.is_empty() && !query.labels.iter().any(|l| l == label) {
                continue;
            }
            for track_id in self.partitions(query) {
                let (mut conf, supporting, contradicting) = match rule.method {
                    Method::WeightedBayes => self.weighted_bayes(rule, &track_id),
                    Method::TemporalWindow => self.temporal_window(rule, &track_id),
                };
                conf = conf.clamp(0.0, 1.0);
                if conf < rule.threshold {
                    continue;
                }
                let produced_ns = self.partition_timestamp(&track_id);
                out.push(FieldInference {
                    label: label.clone(),
                    track_id,
                    confidence: conf,
                    supporting_events: supporting,
                    contradicting_events: contradicting,
                    privacy_class: Self::privacy_of(&rule.privacy_max),
                    calibration_id: Some("synthetic_room_cal_v1".into()),
                    model_id: format!("rule.{label}"),
                    produced_ns,
                    expires_ns: produced_ns + INFERENCE_TTL_NS,
                });
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rufield_adapters::{run_demo, SimConfig};
    use rufield_provenance::Signer;

    #[test]
    fn rejects_non_fusable_event() {
        let cfg = SimConfig {
            seed: 1,
            ..SimConfig::default()
        };
        let mut evs = run_demo(&cfg);
        // Break fusability: clear synthetic flag + signature.
        let mut ev = evs.remove(0).event;
        ev.provenance.synthetic = false;
        ev.provenance.signature_hex = None;
        ev.provenance.signer_pubkey_hex = None;
        let mut engine = RuFieldFusion::with_ble_trust(BleTrustPolicy::synthetic_test_only());
        let err = engine.ingest(ev).unwrap_err();
        assert!(matches!(err, FusionError::NotFusable(_)));
    }

    #[test]
    fn production_rejection_cannot_mutate_graph_or_replay_watermark() {
        let cfg = SimConfig {
            seed: 2,
            ..SimConfig::default()
        };
        let mut event = run_demo(&cfg).remove(0).event;
        event.provenance.synthetic = false;
        let signer = Signer::from_seed(&[21; 32]);
        signer.sign_event(&mut event).unwrap();

        let mut engine = RuFieldFusion::production(TrustedKeyRegistry::new());
        let timestamp_ns = event.timestamp_ns;
        let error = engine.ingest_at(event, timestamp_ns).unwrap_err();
        assert!(matches!(
            error,
            FusionError::TrustRejected {
                reason: TrustError::UnknownKey,
                ..
            }
        ));
        assert_eq!(engine.graph().node_count(), 0);
        assert!(engine
            .trust_verifier()
            .export_replay_state()
            .watermarks
            .is_empty());
    }

    #[test]
    fn production_acceptance_mutates_graph_only_after_trust() {
        let cfg = SimConfig {
            seed: 3,
            ..SimConfig::default()
        };
        let mut event = run_demo(&cfg).remove(0).event;
        event.provenance.synthetic = false;
        let signer = Signer::from_seed(&[22; 32]);
        signer.sign_event(&mut event).unwrap();

        let mut registry = TrustedKeyRegistry::new();
        registry
            .enroll_sensor_key(&event.sensor.device_id, signer.public_hex())
            .unwrap();
        let timestamp_ns = event.timestamp_ns;
        let mut engine = RuFieldFusion::production(registry);
        engine.ingest_at(event, timestamp_ns).unwrap();

        assert_eq!(engine.graph().node_count(), 2);
        assert_eq!(
            engine
                .trust_verifier()
                .export_replay_state()
                .watermarks
                .len(),
            1
        );
    }

    #[test]
    fn empty_event_id_cannot_mutate_graph_or_replay_watermark() {
        let cfg = SimConfig {
            seed: 4,
            ..SimConfig::default()
        };
        let mut event = run_demo(&cfg).remove(0).event;
        event.event_id.clear();
        event.provenance.synthetic = false;
        let signer = Signer::from_seed(&[23; 32]);
        signer.sign_event(&mut event).unwrap();

        let mut registry = TrustedKeyRegistry::new();
        registry
            .enroll_sensor_key(&event.sensor.device_id, signer.public_hex())
            .unwrap();
        let timestamp_ns = event.timestamp_ns;
        let mut engine = RuFieldFusion::production(registry);
        let error = engine.ingest_at(event, timestamp_ns).unwrap_err();

        assert!(matches!(
            error,
            FusionError::TrustRejected {
                reason: TrustError::MalformedIdentity(_),
                ..
            }
        ));
        assert_eq!(engine.graph().node_count(), 0);
        assert!(engine
            .trust_verifier()
            .export_replay_state()
            .watermarks
            .is_empty());
    }

    #[test]
    fn rejects_expired_identity_evidence_before_graph_insert() {
        use rufield_adapters::two_person_ble_crossing_scenario;

        let scenario = two_person_ble_crossing_scenario();
        let mut identity = scenario
            .events
            .into_iter()
            .find(|event| event.observation.identity_evidence.is_some())
            .unwrap();
        let evidence = identity.observation.identity_evidence.as_mut().unwrap();
        evidence.expires_ns = evidence.observed_ns;

        // Synthetic fixtures remain provenance-fusable after mutation, so this
        // specifically proves semantic validation rather than signature logic.
        let mut engine = RuFieldFusion::with_ble_trust(BleTrustPolicy::synthetic_test_only());
        let error = engine.ingest(identity).unwrap_err();
        assert!(matches!(error, FusionError::InvalidEvidence { .. }));
        assert_eq!(engine.graph().node_count(), 0);
    }

    #[test]
    fn produces_at_least_five_distinct_inferences_over_demo() {
        let cfg = SimConfig {
            seed: 7,
            ..SimConfig::default()
        };
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
        let cfg = SimConfig {
            seed: 5,
            ..SimConfig::default()
        };
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

    #[test]
    fn out_of_order_ingest_does_not_move_inference_time_backwards() {
        let cfg = SimConfig {
            seed: 9,
            ..SimConfig::default()
        };
        let mut events: Vec<_> = run_demo(&cfg)
            .into_iter()
            .map(|item| item.event)
            .filter(|event| {
                event
                    .observation
                    .features
                    .get("presence")
                    .is_some_and(|presence| *presence > 0.5)
            })
            .collect();
        events.sort_by_key(|event| event.timestamp_ns);
        let older = events.first().unwrap().clone();
        let newer = events.last().unwrap().clone();
        let expected_timestamp = newer.timestamp_ns;

        let mut engine = RuFieldFusion::new();
        engine.ingest(newer).unwrap();
        engine.ingest(older).unwrap();
        let inferences = engine
            .infer(&InferenceQuery {
                labels: vec!["person_present".into()],
                zone_id: None,
                track_id: None,
                as_of_ns: None,
            })
            .unwrap();
        assert!(!inferences.is_empty());
        assert!(inferences
            .iter()
            .all(|inference| inference.produced_ns == expected_timestamp));
    }
    /// The two ingest gates are independent, and merging the provenance
    /// verifier in front of the BLE allowlist must not make the allowlist
    /// unreachable. A synthetic BLE event is fusable in simulation, so it
    /// passes the verifier -- and must still be refused by the default
    /// production `BleTrustPolicy`.
    #[test]
    fn the_ble_allowlist_still_fires_behind_the_provenance_verifier() {
        let scenario = rufield_adapters::two_person_ble_crossing_scenario();
        let ble = scenario
            .events
            .into_iter()
            .find(|event| {
                event.sensor.modality == Modality::BleAdvertisementRssi.as_str()
                    || event.sensor.modality == Modality::BleChannelSounding.as_str()
            })
            .expect("scenario contains a BLE event");

        let mut engine = RuFieldFusion::new();
        let error = engine.ingest(ble).unwrap_err();
        assert!(
            matches!(error, FusionError::UntrustedBle { .. }),
            "the BLE allowlist must still refuse untrusted BLE after the merge, got {error:?}"
        );
        assert_eq!(
            engine.graph().node_count(),
            0,
            "a refused event must not reach the graph"
        );
    }
}
