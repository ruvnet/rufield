//! # ecosystem-immune — ADR-266 §4 track B2 (research track, NOT a product)
//!
//! Electroactive microbial biofilm nodes at four points down a waterway, each
//! paired with a conventional chemical probe and a water-quality reference.
//! A toxic slug is released between the top two points.
//!
//! What the scenario is built to show — and what it refuses to show:
//!
//! * The biofilm current collapses **before** the chemical probe registers
//!   anything. That head start is a *hand-set model parameter here*, not a
//!   measurement; see the NOT VALIDATED block.
//! * A biofilm response on its own is routed through [`bio_only_severity_cap`]
//!   and can only ever be `Advisory` — no matter how large. Only agreement
//!   with the conventional chemical probes escalates to `Warning`, and only
//!   agreement at two or more points reaches `Critical`.
//! * A cold front depresses biofilm current at **every** point, including the
//!   one upstream of the release. Temperature-compensated detection rejects
//!   it; the naive detector does not. ADR-266 §4.1 item 1 in one screen.
//! * **Source localization**: the most-upstream responding point is reported,
//!   with the point upstream of it staying quiet as the control.
//! * **The governed control path** (ADR-264 §9 / ADR-266 §4.1 item 5): the
//!   agent only ever *proposes*. `PolicyEngine → SafetySimulator →
//!   AuthorityRegistry → CommandSigner → GatewayValidator` decides. An
//!   unauthorized agent submitting a byte-identical proposal is refused at
//!   the authority stage and no receipt is ever produced for it.
//!
//! ```bash
//! cargo run -p rucelium-examples --bin ecosystem-immune
//! ```

use rucelium_core::event::evidence_digest;
use rucelium_core::{
    EnvSample, EnvironmentalEvent, EventKind, EvidenceRef, GeoPoint, SensorModality, Severity,
    SPEC_VERSION,
};
use rucelium_examples::{banner, line, synthetic_footer, Gateway, Node, Rng, EPOCH_NS, NS_PER_S};
use rucelium_policy::{
    verify_receipt, AgentProposal, AuditTrail, AuthorityRegistry, CommandSigner, ControlError,
    ExecutionReceipt, GatewayValidator, PolicyConfig, PolicyEngine, ProposalKind, SafetyConfig,
    SafetySimulator,
};
use rucelium_worldgraph::{EdgeKind, GraphNode, WorldGraph};

// ---------------------------------------------------------------------------
// The normative rule
// ---------------------------------------------------------------------------

/// Hard cap on the weight of a biofilm-derived evidence edge, mirroring
/// `rucelium_worldgraph::RF_MAX_EVIDENCE_WEIGHT` (ADR-264 §8) as ADR-266
/// §4.1 item 3 requires for every biological modality.
pub const BIO_MAX_EVIDENCE_WEIGHT: f32 = 0.3;

/// Clamp a severity to at most [`Severity::Advisory`].
///
/// **The ADR-266 §4.1 item 3 rule, enforced.** A biofilm current collapse,
/// however dramatic, is one unverified transducer's opinion until a
/// conventional instrument agrees with it.
#[must_use]
pub fn bio_only_severity_cap(severity: Severity) -> Severity {
    severity.min(Severity::Advisory)
}

// ---------------------------------------------------------------------------
// Waterway model
// ---------------------------------------------------------------------------

/// Seconds between measurements (10 minutes).
pub const STEP_S: u64 = 600;
/// Commissioning steps: a deliberate temperature stimulus ramp used to
/// measure each biofilm's own temperature coefficient (ADR-266 §4.1 item 2,
/// "causal stimulus experiments").
pub const COMMISSION_STEPS: usize = 30;
/// Quiet baseline steps after commissioning.
pub const BASELINE_STEPS: usize = 30;
/// Step index at which the cold-front confounder is evaluated.
pub const COLD_FRONT_STEP: usize = 66;
/// Step index at which the toxic slug reaches the first downstream point.
pub const RELEASE_STEP: usize = 90;
/// Total simulated steps.
pub const TOTAL_STEPS: usize = 102;
/// Biofilm deviation (in baseline standard deviations) that counts as a
/// response.
pub const BIOFILM_TRIGGER_Z: f64 = 5.0;
/// Chemical concentration above baseline, µmol/L, that the conventional
/// probe treats as a detection. This is the *conventional* rule and owes
/// nothing to biology.
pub const CHEMICAL_TRIGGER_UMOL: f64 = 2.0;

/// One monitoring point: a biofilm anode plus its paired conventional
/// chemical probe and water-quality reference.
#[derive(Debug, Clone)]
pub struct Point {
    /// Short identifier used in the narrative and the WorldGraph.
    pub label: &'static str,
    /// Distance downstream from the top of the reach, kilometres. Ordering
    /// on this field is what "most upstream" means.
    pub river_km: f64,
    /// This colony's own resting current density, µA/cm².
    pub base_ua: f64,
    /// This colony's own current noise, µA/cm².
    pub sd_ua: f64,
    /// This colony's true temperature coefficient, µA/cm² per °C.
    pub temp_coeff: f64,
    /// Step at which the slug arrives (`None` = upstream of the release, the
    /// spatial control).
    pub slug_step: Option<usize>,
}

/// The four instrumented points, ordered upstream → downstream.
#[must_use]
pub fn reach() -> Vec<Point> {
    vec![
        Point {
            label: "P0 headwater-intake",
            river_km: 0.0,
            base_ua: 322.0,
            sd_ua: 5.0,
            temp_coeff: 6.4,
            slug_step: None,
        },
        Point {
            label: "P1 bankside-weir",
            river_km: 1.4,
            base_ua: 281.0,
            sd_ua: 4.1,
            temp_coeff: 5.1,
            slug_step: Some(RELEASE_STEP),
        },
        Point {
            label: "P2 mill-pool",
            river_km: 3.1,
            base_ua: 356.0,
            sd_ua: 6.2,
            temp_coeff: 7.9,
            slug_step: Some(RELEASE_STEP + 2),
        },
        Point {
            label: "P3 tidal-limit",
            river_km: 5.2,
            base_ua: 299.0,
            sd_ua: 5.5,
            temp_coeff: 6.9,
            slug_step: Some(RELEASE_STEP + 4),
        },
    ]
}

/// Water temperature at `step`, °C.
///
/// Commissioning is a deliberate 8 → 22 °C ramp (the causal stimulus that
/// identifies each colony's temperature coefficient). After that the reach
/// runs at ~15 °C with a gentle diurnal, until a cold front drops it by 9 °C
/// — the confounder.
#[must_use]
pub fn water_temp_c(step: usize, rng: &mut Rng) -> f64 {
    let base = if step < COMMISSION_STEPS {
        8.0 + 14.0 * (step as f64 / (COMMISSION_STEPS - 1) as f64)
    } else {
        15.0 + 1.6 * ((step as f64) * 0.18).sin()
    };
    let cold = if (COLD_FRONT_STEP - 6..COLD_FRONT_STEP + 6).contains(&step) {
        -9.0
    } else {
        0.0
    };
    base + cold + rng.noise(0.25)
}

/// Toxic-slug intensity at a point, `0.0..=1.0`, as a sharp arrival followed
/// by slow washout.
#[must_use]
pub fn slug_intensity(step: usize, arrival: Option<usize>) -> f64 {
    match arrival {
        Some(a) if step >= a => (1.0 - (step - a) as f64 * 0.04).max(0.55),
        _ => 0.0,
    }
}

/// Full-strength biofilm current collapse under toxic exposure, µA/cm².
pub const TOXIC_CURRENT_DROP_UA: f64 = -74.0;
/// Full-strength chemical concentration once the plume is measurable, µmol/L.
pub const TOXIC_CHEMICAL_UMOL: f64 = 8.4;
/// Steps between the biofilm response and the chemical probe registering the
/// plume at the same point. **A model parameter, not a measurement.**
pub const CHEMICAL_LAG_STEPS: usize = 3;

// ---------------------------------------------------------------------------
// Detection state
// ---------------------------------------------------------------------------

/// Per-colony baseline: its own temperature coefficient (measured by the
/// commissioning stimulus) and its own compensated-current statistics.
#[derive(Debug, Clone, PartialEq)]
pub struct ColonyBaseline {
    /// Point label.
    pub label: String,
    /// Measured temperature coefficient, µA/cm² per °C.
    pub temp_coeff: f64,
    /// Mean temperature-compensated current, µA/cm².
    pub mean_comp_ua: f64,
    /// Standard deviation of the compensated current, µA/cm².
    pub sd_comp_ua: f64,
    /// Mean raw (uncompensated) current, µA/cm².
    pub mean_raw_ua: f64,
    /// Standard deviation of the raw current, µA/cm².
    pub sd_raw_ua: f64,
    /// Mean baseline chemical concentration, µmol/L.
    pub mean_chem_umol: f64,
}

/// One point's state at one evaluated step.
#[derive(Debug, Clone, PartialEq)]
pub struct PointState {
    /// Point label.
    pub label: String,
    /// Distance downstream, km.
    pub river_km: f64,
    /// Biofilm node id.
    pub node_id: u64,
    /// Sequence number of the evaluated biofilm sample.
    pub sequence: u32,
    /// Measured biofilm current, µA/cm².
    pub current_ua: f64,
    /// Naive z-score with no temperature compensation.
    pub raw_z: f64,
    /// Temperature-compensated z-score.
    pub comp_z: f64,
    /// Conventional chemical probe reading, µmol/L.
    pub chem_umol: f64,
    /// Whether the compensated biofilm detector responded.
    pub biofilm_fired: bool,
    /// Whether the naive (uncompensated) detector responded.
    pub naive_fired: bool,
    /// Whether the conventional chemical probe detected the analyte.
    pub chemical_fired: bool,
    /// The verified observation itself, retained so the event can bind the
    /// *content* of its evidence and not merely its identity (ADR-266 §3.1).
    pub sample: EnvSample,
}

/// A cross-checked assessment at one moment in the incident.
#[derive(Debug, Clone, PartialEq)]
pub struct Assessment {
    /// Narrative label for this moment.
    pub moment: String,
    /// Simulated step.
    pub step: usize,
    /// Per-point state.
    pub points: Vec<PointState>,
    /// Severity the evidence would justify before the biological cap.
    pub uncapped: Severity,
    /// Severity actually emitted.
    pub severity: Severity,
    /// Whether biology was the only evidence.
    pub bio_only: bool,
    /// Most-upstream responding point, if any.
    pub source_label: Option<String>,
    /// The emitted event, if one was raised.
    pub event: Option<EnvironmentalEvent>,
}

/// One trip (or attempted trip) through the governed control path.
#[derive(Debug, Clone, PartialEq)]
pub struct GovernanceOutcome {
    /// Proposing agent.
    pub agent_id: String,
    /// Whether the biome owner had granted this agent the actuator.
    pub granted: bool,
    /// Stage at which the proposal stopped, or `"executed"`.
    pub stopped_at: String,
    /// The refusal, if it was refused.
    pub error: Option<String>,
    /// The signed execution receipt, produced only on the authorized path.
    pub receipt: Option<ExecutionReceipt>,
    /// Whether the receipt's gateway attestation verifies.
    pub receipt_verifies: bool,
    /// Audit entries recorded for this proposal.
    pub audit_stages: Vec<String>,
}

/// Everything one deterministic run produces.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// Per-colony learned baselines.
    pub baselines: Vec<ColonyBaseline>,
    /// The cold-front confounder assessment.
    pub cold_front: Assessment,
    /// The biofilm-only moment of the toxic incident.
    pub biofilm_only: Assessment,
    /// The chemically corroborated moment of the same incident.
    pub corroborated: Assessment,
    /// Steps between the biofilm response and chemical corroboration.
    pub lead_steps: usize,
    /// Authorized agent's governed intervention.
    pub authorized: GovernanceOutcome,
    /// Unauthorized agent's byte-identical proposal.
    pub unauthorized: GovernanceOutcome,
    /// Envelopes the real ingest pipeline verified.
    pub verified_samples: usize,
    /// WorldGraph JSON (deterministic).
    pub graph_json: String,
    /// Largest weight on any biofilm-derived evidence edge.
    pub max_bio_edge_weight: f32,
}

/// Simulated measurement time for `step`, derived from `EPOCH_NS`.
#[must_use]
pub fn step_ns(step: usize) -> u64 {
    EPOCH_NS + step as u64 * STEP_S * NS_PER_S
}

/// Cross-check biofilm evidence against the conventional chemical probes and
/// return `(uncapped severity, emitted severity, bio_only)`.
///
/// * biofilm alone → whatever the biology "wanted", clamped by
///   [`bio_only_severity_cap`] to `Advisory`;
/// * biofilm + chemical agreement at one point → `Warning`;
/// * agreement at two or more points → `Critical`.
#[must_use]
pub fn cross_check(points: &[PointState]) -> (Severity, Severity, bool) {
    let bio = points.iter().filter(|p| p.biofilm_fired).count();
    let agree = points
        .iter()
        .filter(|p| p.biofilm_fired && p.chemical_fired)
        .count();
    if bio == 0 {
        return (Severity::Advisory, Severity::Advisory, false);
    }
    if agree == 0 {
        // Biology alone. It wanted to shout; the cap says Advisory.
        let wanted = Severity::Warning;
        return (wanted, bio_only_severity_cap(wanted), true);
    }
    let sev = if agree >= 2 {
        Severity::Critical
    } else {
        Severity::Warning
    };
    (sev, sev, false)
}

/// Most-upstream point whose biofilm responded — the localized source.
#[must_use]
pub fn localize_source(points: &[PointState]) -> Option<String> {
    points
        .iter()
        .filter(|p| p.biofilm_fired)
        .min_by(|a, b| {
            a.river_km
                .partial_cmp(&b.river_km)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|p| p.label.clone())
}

// ---------------------------------------------------------------------------
// Governed control path
// ---------------------------------------------------------------------------

/// The actuator the biome owner has installed at the localized source.
pub const ISOLATION_GATE: &str = "isolation-gate/reach-b";
/// Deterministic command-signing seed (examples only).
pub const SIGNER_SEED: &[u8; 32] = b"rucelium-b2-immune-signer-seed!!";
/// Deterministic gateway receipt-signing seed (examples only).
pub const GATEWAY_SEED: &[u8; 32] = b"rucelium-b2-immune-gateway-seed!";

/// Run one proposal through every stage of the governed control path.
///
/// The agent's entire power is constructing the [`AgentProposal`]. Nothing in
/// this function lets it actuate: each stage consumes the previous stage's
/// privately-constructed witness, and a missing authority grant ends the
/// journey before any command is ever signed.
#[must_use]
pub fn govern(agent_id: &str, granted: bool, now_ns: u64) -> GovernanceOutcome {
    let mut audit = AuditTrail::new();
    let proposal = AgentProposal {
        proposal_id: format!("prop-b2-{}", agent_id.replace('/', "-")),
        agent_id: agent_id.to_string(),
        biome_id: "biome/reach-b".into(),
        kind: ProposalKind::ActuatorCommand {
            actuator_id: ISOLATION_GATE.into(),
            action: "close".into(),
            magnitude: 0.75,
        },
        justification: "biofilm collapse at P1 corroborated by chemical probe; isolate reach"
            .into(),
        proposed_ns: now_ns,
    };

    let mut policy_cfg = PolicyConfig::default();
    policy_cfg.allowed_actuators.insert(ISOLATION_GATE.into());
    let engine = PolicyEngine::new(policy_cfg);
    let mut safety = SafetySimulator::new(SafetyConfig::default());
    let mut authority = AuthorityRegistry::new();
    if granted {
        authority.grant("biome/reach-b", agent_id, ISOLATION_GATE);
    }
    let signer = CommandSigner::from_seed(SIGNER_SEED);
    let mut gateway = GatewayValidator::new(vec![signer.public_hex()], GATEWAY_SEED)
        .with_max_commands_per_actuator(2);

    let finish = |stopped_at: &str,
                  error: Option<ControlError>,
                  receipt: Option<ExecutionReceipt>,
                  audit: &AuditTrail| GovernanceOutcome {
        agent_id: agent_id.to_string(),
        granted,
        stopped_at: stopped_at.to_string(),
        error: error.map(|e| e.to_string()),
        receipt_verifies: receipt.as_ref().is_some_and(verify_receipt),
        receipt,
        audit_stages: audit
            .entries()
            .iter()
            .map(|e| e.stage.to_string())
            .collect(),
    };

    let evaluated = match engine.evaluate(proposal, now_ns, &mut audit) {
        Ok(v) => v,
        Err(e) => return finish("policy", Some(e), None, &audit),
    };
    let simulated = match safety.simulate(evaluated, now_ns, &mut audit) {
        Ok(v) => v,
        Err(e) => return finish("safety", Some(e), None, &audit),
    };
    let authorized = match authority.authorize(simulated, now_ns, &mut audit) {
        Ok(v) => v,
        Err(e) => return finish("authority", Some(e), None, &audit),
    };
    let signed = signer.sign(authorized, now_ns, 60 * NS_PER_S, &mut audit);
    let receipt = match gateway.validate_and_execute(
        &signed,
        now_ns + NS_PER_S,
        |kind| match kind {
            ProposalKind::ActuatorCommand { action, .. } => {
                Ok(format!("isolation gate {action}d locally"))
            }
            _ => Err("unexpected command kind".into()),
        },
        &mut audit,
    ) {
        Ok(r) => r,
        Err(e) => return finish("gateway", Some(e), None, &audit),
    };
    safety.record_execution(ISOLATION_GATE);
    finish("executed", None, Some(receipt), &audit)
}

// ---------------------------------------------------------------------------
// The scenario
// ---------------------------------------------------------------------------

/// Run the whole scenario deterministically.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run() -> Report {
    let points = reach();
    let n = points.len();
    let mut rng = Rng::new(0x00B2_1F1E_1DEC_0DE1);

    let mut nodes: Vec<Node> = Vec::new();
    for (i, p) in points.iter().enumerate() {
        let lon = -2_400_000 + (i as i32) * 21_000;
        let geo = GeoPoint::new(535_400_000, lon, 11_000).expect("valid reach coordinates");
        nodes.push(Node::new(
            0x00B2_0000_0000_0001 + i as u64,
            SensorModality::Bioelectric,
            geo,
            p.label,
        ));
    }
    for (i, p) in points.iter().enumerate() {
        let lon = -2_400_000 + (i as i32) * 21_000;
        let geo = GeoPoint::new(535_400_000, lon, 11_000).expect("valid reach coordinates");
        nodes.push(Node::new(
            0x00B2_0000_0000_0101 + i as u64,
            SensorModality::Chemical,
            geo,
            p.label,
        ));
    }
    for (i, p) in points.iter().enumerate() {
        let lon = -2_400_000 + (i as i32) * 21_000;
        let geo = GeoPoint::new(535_400_000, lon, 11_000).expect("valid reach coordinates");
        nodes.push(Node::new(
            0x00B2_0000_0000_0201 + i as u64,
            SensorModality::WaterQuality,
            geo,
            p.label,
        ));
    }
    let mut gw = Gateway::with_nodes(&nodes);
    let mut graph = WorldGraph::new();
    graph.add_node(
        "ecosystem/reach-b",
        GraphNode::Ecosystem {
            name: "Reach B discharge corridor".into(),
            kind: "river_reach".into(),
            geo: GeoPoint::new(535_400_000, -2_368_000, 11_000).expect("valid reach centroid"),
        },
    );

    // Commissioning + baseline accumulation.
    let mut commission: Vec<Vec<(f64, f64)>> = vec![Vec::new(); n];
    let mut base_comp: Vec<Vec<f64>> = vec![Vec::new(); n];
    let mut base_raw: Vec<Vec<f64>> = vec![Vec::new(); n];
    let mut base_chem: Vec<Vec<f64>> = vec![Vec::new(); n];
    let mut verified = 0usize;
    let mut assessments: Vec<(usize, Vec<PointState>)> = Vec::new();
    let mut coeffs = vec![0.0_f64; n];
    let mut baselines: Vec<ColonyBaseline> = Vec::new();

    for step in 0..TOTAL_STEPS {
        let ns = step_ns(step);
        let temp = water_temp_c(step, &mut rng);
        let mut row: Vec<PointState> = Vec::new();
        for (i, p) in points.iter().enumerate() {
            let intensity = slug_intensity(step, p.slug_step);
            let current = p.base_ua
                + p.temp_coeff * (temp - 15.0)
                + TOXIC_CURRENT_DROP_UA * intensity
                + rng.noise(p.sd_ua);
            let env = nodes[i].emit(current, ns, 1);
            let bio = gw
                .ingest(&env, ns + 1_000_000)
                .expect("biofilm sample verifies");
            verified += 1;

            let chem_arrival = p.slug_step.map(|a| a + CHEMICAL_LAG_STEPS);
            let chem_intensity = slug_intensity(step, chem_arrival);
            let chem = 0.21 + TOXIC_CHEMICAL_UMOL * chem_intensity + rng.noise(0.06);
            let env = nodes[n + i].emit(chem.max(0.0), ns, 1);
            let ch = gw
                .ingest(&env, ns + 1_000_000)
                .expect("chemical sample verifies");
            verified += 1;

            let env = nodes[2 * n + i].emit(temp, ns, 1);
            gw.ingest(&env, ns + 1_000_000)
                .expect("water-quality sample verifies");
            verified += 1;

            let current = bio.sample().value;
            let chem = ch.sample().value;

            if step < COMMISSION_STEPS {
                commission[i].push((temp, current));
                continue;
            }
            let comp = current - coeffs[i] * (temp - 15.0);
            if step < COMMISSION_STEPS + BASELINE_STEPS {
                base_comp[i].push(comp);
                base_raw[i].push(current);
                base_chem[i].push(chem);
                continue;
            }
            let b = &baselines[i];
            let raw_z = if b.sd_raw_ua > 0.0 {
                (current - b.mean_raw_ua) / b.sd_raw_ua
            } else {
                0.0
            };
            let comp_z = if b.sd_comp_ua > 0.0 {
                (comp - b.mean_comp_ua) / b.sd_comp_ua
            } else {
                0.0
            };
            graph.register_observation(bio.sample());
            graph.register_observation(ch.sample());
            row.push(PointState {
                label: p.label.to_string(),
                river_km: p.river_km,
                node_id: bio.sample().node_id,
                sequence: bio.sample().sequence,
                current_ua: current,
                raw_z,
                comp_z,
                chem_umol: chem,
                biofilm_fired: comp_z.abs() >= BIOFILM_TRIGGER_Z,
                naive_fired: raw_z.abs() >= BIOFILM_TRIGGER_Z,
                chemical_fired: chem > b.mean_chem_umol + CHEMICAL_TRIGGER_UMOL,
                sample: bio.sample().clone(),
            });
        }

        // End of commissioning: fit each colony's own temperature coefficient
        // from the deliberate stimulus ramp.
        if step == COMMISSION_STEPS - 1 {
            for (i, pairs) in commission.iter().enumerate() {
                let len = pairs.len() as f64;
                let mt = pairs.iter().map(|q| q.0).sum::<f64>() / len;
                let mc = pairs.iter().map(|q| q.1).sum::<f64>() / len;
                let sxy: f64 = pairs.iter().map(|q| (q.0 - mt) * (q.1 - mc)).sum();
                let sxx: f64 = pairs.iter().map(|q| (q.0 - mt).powi(2)).sum();
                coeffs[i] = if sxx > 0.0 { sxy / sxx } else { 0.0 };
            }
        }
        // End of baseline: freeze per-colony statistics.
        if step == COMMISSION_STEPS + BASELINE_STEPS - 1 {
            baselines = points
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    let mean = |v: &Vec<f64>| v.iter().sum::<f64>() / v.len() as f64;
                    let sd = |v: &Vec<f64>, m: f64| {
                        (v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (v.len() - 1) as f64)
                            .sqrt()
                    };
                    let mc = mean(&base_comp[i]);
                    let mr = mean(&base_raw[i]);
                    ColonyBaseline {
                        label: p.label.to_string(),
                        temp_coeff: coeffs[i],
                        mean_comp_ua: mc,
                        sd_comp_ua: sd(&base_comp[i], mc),
                        mean_raw_ua: mr,
                        sd_raw_ua: sd(&base_raw[i], mr),
                        mean_chem_umol: mean(&base_chem[i]),
                    }
                })
                .collect();
        }
        if !row.is_empty() {
            assessments.push((step, row));
        }
    }

    let pick = |step: usize, moment: &str| -> Assessment {
        let pts = assessments
            .iter()
            .find(|(s, _)| *s == step)
            .map(|(_, r)| r.clone())
            .unwrap_or_default();
        let (uncapped, severity, bio_only) = cross_check(&pts);
        let source_label = localize_source(&pts);
        let fired: Vec<&PointState> = pts.iter().filter(|p| p.biofilm_fired).collect();
        let event = if fired.is_empty() {
            None
        } else {
            Some(EnvironmentalEvent {
                evidence_digest: Some(evidence_digest(
                    &fired.iter().map(|p| &p.sample).collect::<Vec<_>>(),
                )),
                spec_version: SPEC_VERSION.into(),
                event_id: format!("evt-b2-immune-{step:04}"),
                biome_id: "biome/reach-b".into(),
                kind: EventKind::ThresholdExceeded,
                severity,
                modality: SensorModality::Bioelectric,
                geo: GeoPoint::new(535_400_000, -2_368_000, 11_000).expect("valid centroid"),
                window_start_ns: step_ns(step.saturating_sub(3)),
                window_end_ns: step_ns(step),
                detected_ns: step_ns(step),
                evidence: fired
                    .iter()
                    .map(|p| EvidenceRef {
                        node_id: p.node_id,
                        sequence: p.sequence,
                    })
                    .collect(),
                confidence: if bio_only { 0.55 } else { 0.93 },
                message: format!(
                    "{} biofilm node(s) responding; source localized to {}",
                    fired.len(),
                    source_label.clone().unwrap_or_else(|| "unknown".into())
                ),
                signature_hex: None,
                signer_pubkey_hex: None,
            })
        };
        Assessment {
            moment: moment.to_string(),
            step,
            points: pts,
            uncapped,
            severity,
            bio_only,
            source_label,
            event,
        }
    };

    let cold_front = pick(COLD_FRONT_STEP, "cold front — confounder, no toxin");
    let biofilm_only = pick(RELEASE_STEP + 1, "toxic slug — biofilm only");
    let corroborated = pick(
        RELEASE_STEP + CHEMICAL_LAG_STEPS + 3,
        "toxic slug — chemical probes agree",
    );

    // Capped biofilm evidence edges for the corroborated moment.
    let mut max_bio_edge_weight = 0.0_f32;
    for p in corroborated.points.iter().filter(|p| p.biofilm_fired) {
        let key = format!("sensor/{}", p.node_id);
        let want = (p.comp_z.abs() / 30.0) as f32;
        let weight = want.min(BIO_MAX_EVIDENCE_WEIGHT);
        graph
            .add_edge(
                &key,
                "ecosystem/reach-b",
                EdgeKind::Supports,
                weight,
                format!("biofilm response z={:.1} (capped evidence)", p.comp_z),
            )
            .expect("both endpoints registered");
        max_bio_edge_weight = max_bio_edge_weight.max(weight);
    }

    let now_ns = step_ns(RELEASE_STEP + CHEMICAL_LAG_STEPS + 4);
    let authorized = govern("agent/water-guardian", true, now_ns);
    let unauthorized = govern("agent/unbound-optimizer", false, now_ns);

    Report {
        baselines,
        cold_front,
        biofilm_only,
        corroborated,
        lead_steps: CHEMICAL_LAG_STEPS,
        authorized,
        unauthorized,
        verified_samples: verified,
        graph_json: graph.to_json(),
        max_bio_edge_weight,
    }
}

/// Print the ADR-266 §4.1 acceptance bar and disclaim this scenario.
fn print_not_validated() {
    println!("\n  NOT VALIDATED");
    println!("  ADR-266 §4 track B2 is a RESEARCH TRACK, not a roadmap item and not a");
    println!("  product claim. The §4.1 item 3 acceptance bar is: one biological signal");
    println!("  predicts a CONFIRMED environmental condition >= 30 MINUTES EARLIER than the");
    println!("  conventional sensor, at > 90% PRECISION, across 3 INDEPENDENT LOCATIONS,");
    println!("  with NO PER-LOCATION RETRAINING. The 30-minute head start printed above is");
    println!("  a HAND-SET SIMULATION PARAMETER (CHEMICAL_LAG_STEPS), not a measurement:");
    println!("  it demonstrates what the pipeline does WITH such a lead, and is NOT");
    println!("  evidence that any lead exists. One simulated waterway is also not three");
    println!("  independent locations, and precision is undefined for a single incident.");
}

fn main() {
    banner(
        "ecosystem-immune — ADR-266 B2 electroactive biofilm sentinels",
        "4 biofilm anodes + paired chemical probes and water-quality references",
    );
    let r = run();

    println!("  1. COMMISSIONING — per-colony temperature coefficients\n");
    println!(
        "  {:<22} {:>12} {:>12} {:>10} {:>12}",
        "point", "µA per °C", "mean comp µA", "sd comp", "mean chem"
    );
    for b in &r.baselines {
        println!(
            "  {:<22} {:>12.2} {:>12.1} {:>10.2} {:>12.2}",
            b.label, b.temp_coeff, b.mean_comp_ua, b.sd_comp_ua, b.mean_chem_umol
        );
    }
    println!("  -> each colony has its own resting current and its own temperature");
    println!("     response, measured by a deliberate stimulus ramp (§4.1 item 2).");

    for a in [&r.cold_front, &r.biofilm_only, &r.corroborated] {
        println!("\n  {}\n", a.moment.to_uppercase());
        println!(
            "  {:<22} {:>8} {:>10} {:>9} {:>9} {:>10} {:>10}",
            "point", "km", "µA/cm²", "raw z", "comp z", "chem µM", "biofilm"
        );
        for p in &a.points {
            println!(
                "  {:<22} {:>8.1} {:>10.1} {:>9.2} {:>9.2} {:>10.2} {:>10}",
                p.label,
                p.river_km,
                p.current_ua,
                p.raw_z,
                p.comp_z,
                p.chem_umol,
                if p.biofilm_fired { "RESPOND" } else { "quiet" }
            );
        }
        let naive = a.points.iter().filter(|p| p.naive_fired).count();
        let bio = a.points.iter().filter(|p| p.biofilm_fired).count();
        let chem = a.points.iter().filter(|p| p.chemical_fired).count();
        line(
            "naive / compensated / chemical detections",
            format!("{naive} / {bio} / {chem}"),
        );
        if bio == 0 {
            line("biological evidence", "none — nothing to cap");
        } else {
            line("evidence is biology only", a.bio_only);
            line(
                "severity before the biological cap",
                format!("{:?}", a.uncapped),
            );
            line("severity emitted", format!("{:?}", a.severity));
        }
        line(
            "source localized (most upstream responder)",
            a.source_label.clone().unwrap_or_else(|| "—".into()),
        );
        if let Some(ev) = &a.event {
            ev.validate().expect("event is structurally valid");
            line("event confidence", format!("{:.2}", ev.confidence));
        }
    }
    println!(
        "  -> the biofilm responded {} steps ({} min) before the chemical probe.",
        r.lead_steps,
        r.lead_steps as u64 * STEP_S / 60
    );
    println!("     Until corroborated, the fabric refused to say more than Advisory.");

    println!("\n  GOVERNED INTERVENTION — the agent proposes, policy decides\n");
    for g in [&r.authorized, &r.unauthorized] {
        println!("  agent {}", g.agent_id);
        line("  biome owner granted the actuator", g.granted);
        line("  journey ended at stage", &g.stopped_at);
        line(
            "  refusal",
            g.error.clone().unwrap_or_else(|| "none".into()),
        );
        line("  audit stages recorded", g.audit_stages.join(" → "));
        match &g.receipt {
            Some(rc) => {
                line("  execution receipt", &rc.outcome);
                line("  verify_receipt()", g.receipt_verifies);
            }
            None => line("  execution receipt", "NONE — nothing was actuated"),
        }
        println!();
    }
    line(
        "max biofilm evidence edge weight",
        format!("{:.2}", r.max_bio_edge_weight),
    );
    line(
        "hard cap on that weight",
        format!("{BIO_MAX_EVIDENCE_WEIGHT:.2}"),
    );
    line("envelopes cryptographically verified", r.verified_samples);
    line("WorldGraph JSON bytes (deterministic)", r.graph_json.len());

    print_not_validated();
    synthetic_footer("The 30-minute biological lead is a model input, not a result.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn biofilm_only_evidence_is_capped_at_advisory() {
        assert_eq!(
            bio_only_severity_cap(Severity::Critical),
            Severity::Advisory
        );
        assert_eq!(bio_only_severity_cap(Severity::Warning), Severity::Advisory);
        assert_eq!(bio_only_severity_cap(Severity::Watch), Severity::Advisory);

        let r = run();
        let a = &r.biofilm_only;
        assert!(a.bio_only, "no chemical probe has fired yet");
        assert!(a.points.iter().any(|p| p.biofilm_fired));
        assert!(a.points.iter().all(|p| !p.chemical_fired));
        assert_eq!(a.uncapped, Severity::Warning);
        assert_eq!(a.severity, Severity::Advisory);
        let ev = a.event.as_ref().expect("an advisory event was raised");
        ev.validate().unwrap();
        assert_eq!(ev.severity, Severity::Advisory);
        assert!(ev
            .evidence_digest
            .as_ref()
            .is_some_and(|d| d.starts_with("sha256:")));
    }

    #[test]
    fn corroboration_escalates_and_the_cold_front_never_does() {
        let r = run();
        // Chemical agreement at two or more points reaches Critical.
        let c = &r.corroborated;
        assert!(!c.bio_only);
        assert!(
            c.points
                .iter()
                .filter(|p| p.biofilm_fired && p.chemical_fired)
                .count()
                >= 2
        );
        assert_eq!(c.severity, Severity::Critical);

        // The confounder: the naive detector fires everywhere, including the
        // control point upstream of the release; the compensated detector
        // fires nowhere, no chemical agrees, and nothing escalates.
        let f = &r.cold_front;
        assert_eq!(f.points.iter().filter(|p| p.naive_fired).count(), 4);
        assert_eq!(f.points.iter().filter(|p| p.biofilm_fired).count(), 0);
        assert_eq!(f.points.iter().filter(|p| p.chemical_fired).count(), 0);
        assert_eq!(f.severity, Severity::Advisory);
        assert!(f.event.is_none(), "a cold front is not an incident");
    }

    #[test]
    fn source_localizes_to_the_most_upstream_responding_point() {
        let r = run();
        for a in [&r.biofilm_only, &r.corroborated] {
            assert_eq!(a.source_label.as_deref(), Some("P1 bankside-weir"));
            // The spatial control upstream of the release stays quiet.
            let p0 = &a.points[0];
            assert_eq!(p0.label, "P0 headwater-intake");
            assert!(!p0.biofilm_fired, "the upstream control must not respond");
            assert!(!p0.chemical_fired);
        }
        // Localization really is the minimum river_km among responders.
        let responders: Vec<f64> = r
            .corroborated
            .points
            .iter()
            .filter(|p| p.biofilm_fired)
            .map(|p| p.river_km)
            .collect();
        assert!(responders.iter().all(|km| *km >= 1.4));
    }

    #[test]
    fn unauthorized_proposal_never_executes_and_leaves_no_receipt() {
        let r = run();
        assert_eq!(r.unauthorized.stopped_at, "authority");
        assert!(r.unauthorized.receipt.is_none());
        assert!(!r.unauthorized.receipt_verifies);
        assert!(r
            .unauthorized
            .error
            .as_ref()
            .expect("a refusal was recorded")
            .contains("not authorized"));
        // It never even reached the signing stage.
        assert!(!r.unauthorized.audit_stages.iter().any(|s| s == "signed"));
        assert!(!r.unauthorized.audit_stages.iter().any(|s| s == "executed"));
    }

    #[test]
    fn authorized_path_produces_exactly_one_verifiable_receipt() {
        let r = run();
        assert_eq!(r.authorized.stopped_at, "executed");
        let rc = r.authorized.receipt.as_ref().expect("receipt issued");
        assert!(verify_receipt(rc), "gateway attestation must verify");
        assert!(r.authorized.receipt_verifies);
        // Tampering with the attested outcome breaks the signature.
        let mut forged = rc.clone();
        forged.outcome.push('!');
        assert!(!verify_receipt(&forged));
        assert_eq!(
            r.authorized.audit_stages,
            vec![
                "proposed",
                "policy_evaluated",
                "safety_simulated",
                "authorized",
                "signed",
                "gateway_validated",
                "executed"
            ]
        );
    }

    #[test]
    fn scenario_is_fully_deterministic() {
        let a = run();
        let b = run();
        assert_eq!(a, b);
        assert!(a.verified_samples > 1_000);
        assert!(a.max_bio_edge_weight <= BIO_MAX_EVIDENCE_WEIGHT);
    }
}
