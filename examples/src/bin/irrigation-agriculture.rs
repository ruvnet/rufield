//! # irrigation-agriculture — deployment wedge #2 (ADR-266 §3.1)
//!
//! Precision agriculture is the wedge that **monetizes governed actuation**:
//! it is where the ADR-264 §9 control path stops being theoretical, because a
//! valve physically opens and water physically costs money. The thing the
//! grower is buying is not the irrigation decision — it is the guarantee that
//! nothing *else* can open that valve.
//!
//! Three irrigation zones, each with a soil-moisture probe, a temperature /
//! humidity station, and a leaf-wetness sensor. A per-zone water-stress index
//! drives valve commands through **every** stage of the governed path:
//!
//! ```text
//! PolicyEngine::evaluate → SafetySimulator::simulate → AuthorityRegistry::authorize
//!   → CommandSigner::sign → GatewayValidator::validate_and_execute → ExecutionReceipt
//! ```
//!
//! and four outcomes are demonstrated:
//!
//! | zone / actor                | stopped at | why |
//! |-----------------------------|------------|-----|
//! | zone A, authorized planner  | — executes | signed receipt, offline-verifiable |
//! | zone B, authorized planner  | **safety** | policy allowed the magnitude; the envelope did not |
//! | zone A, unauthorized bot    | **authority** | identical proposal, no `(biome, agent, actuator)` grant |
//! | zone A, replayed command id | **gateway** | fail-closed replay protection |
//!
//! ```bash
//! cargo run  -p rucelium-examples --bin irrigation-agriculture
//! cargo test -p rucelium-examples --bin irrigation-agriculture
//! ```

use rucelium_core::SensorModality;
use rucelium_examples::{banner, line, synthetic_footer, Gateway, Node, Rng, EPOCH_NS, NS_PER_S};
use rucelium_policy::{
    verify_receipt, AgentProposal, AuditTrail, AuthorityRegistry, CommandSigner, ControlError,
    ExecutionReceipt, GatewayValidator, PolicyConfig, PolicyEngine, ProposalKind, SafetyConfig,
    SafetySimulator, SignedCommand,
};
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Scenario constants
// ---------------------------------------------------------------------------

/// The farm biome. Actuator authority never leaves its owner (ADR-264 §6).
pub const BIOME_ID: &str = "biome/wold-farm";

/// The agent the grower actually granted valve authority to.
pub const PLANNER_AGENT: &str = "agent/irrigation-planner";

/// A contractor's agent with no valve grant at all.
pub const CONTRACTOR_AGENT: &str = "agent/contractor-bot";

/// Deterministic seed for the command-signing key.
pub const COMMAND_SEED: &[u8; 32] = b"rucelium-example-irrigation-cmd!";

/// Deterministic seed for the gateway's receipt-signing identity.
pub const GATEWAY_SEED: &[u8; 32] = b"rucelium-example-irrigation-gw!!";

/// Target soil volumetric water content (%) for these crops.
pub const TARGET_VWC_PCT: f64 = 30.0;

/// Water-stress index above which the planner asks for irrigation.
pub const STRESS_TRIGGER: f64 = 0.20;

/// Valve opening requested per unit of water stress.
pub const MAGNITUDE_PER_STRESS: f64 = 1.7;

/// Policy ceiling on any actuator magnitude.
pub const POLICY_MAX_MAGNITUDE: f64 = 1.0;

/// Safety envelope — deliberately tighter than policy.
pub const SAFE_MAGNITUDE: f64 = 0.8;

/// Command time-to-live (5 minutes).
pub const COMMAND_TTL_NS: u64 = 300 * NS_PER_S;

/// Calibration record referenced by every node on the farm.
pub const CALIBRATION_ID: u32 = 21;

/// The seven audit stages a completed governed command must leave behind.
pub const EXPECTED_STAGES: [&str; 7] = [
    "proposed",
    "policy_evaluated",
    "safety_simulated",
    "authorized",
    "signed",
    "gateway_validated",
    "executed",
];

/// One irrigation zone's identity and noise-free sensor truth.
pub struct ZoneSpec {
    /// Human-readable zone name.
    pub name: &'static str,
    /// The zone's valve actuator id.
    pub actuator_id: &'static str,
    /// Soil volumetric water content, %.
    pub vwc_pct: f64,
    /// Canopy air temperature, °C.
    pub temp_c: f64,
    /// Leaf wetness index, `0.0..=1.0`.
    pub leaf_wetness: f64,
}

/// The three zones of the farm, in node-table order.
pub const ZONES: [ZoneSpec; 3] = [
    ZoneSpec {
        name: "zone A — north block (winter wheat)",
        actuator_id: "valve/zone-a",
        vwc_pct: 20.0,
        temp_c: 30.0,
        leaf_wetness: 0.10,
    },
    ZoneSpec {
        name: "zone B — south block (potatoes, sandy)",
        actuator_id: "valve/zone-b",
        vwc_pct: 11.0,
        temp_c: 36.0,
        leaf_wetness: 0.03,
    },
    ZoneSpec {
        name: "zone C — riverside block (grass ley)",
        actuator_id: "valve/zone-c",
        vwc_pct: 32.0,
        temp_c: 23.0,
        leaf_wetness: 0.55,
    },
];

// ---------------------------------------------------------------------------
// Sensing
// ---------------------------------------------------------------------------

/// Provision three sensors per zone: soil moisture, canopy climate, leaf
/// wetness. Nine signed spore nodes in total.
#[must_use]
pub fn provision() -> Vec<Node> {
    let mut nodes = Vec::with_capacity(9);
    for (z, zone) in ZONES.iter().enumerate() {
        let base = 0x00A2_0000_0000_0000 | ((z as u64 + 1) << 8);
        let lat = 533_100_000 + (z as i32) * 24_000;
        let lon = -6_400_000 + (z as i32) * 31_000;
        nodes.push(Node::new(
            base | 1,
            SensorModality::SoilMoisture,
            geo(lat, lon, 42_000),
            &format!("{} soil probe", zone.name),
        ));
        nodes.push(Node::new(
            base | 2,
            SensorModality::Weather,
            geo(lat + 900, lon + 700, 44_000),
            &format!("{} canopy climate", zone.name),
        ));
        nodes.push(Node::new(
            base | 3,
            SensorModality::Weather,
            geo(lat - 800, lon + 500, 43_000),
            &format!("{} leaf wetness", zone.name),
        ));
    }
    nodes
}

/// Build a geo point, panicking on a coordinate the example itself got wrong.
fn geo(latitude_e7: i32, longitude_e7: i32, altitude_mm: i32) -> rucelium_core::GeoPoint {
    rucelium_core::GeoPoint::new(latitude_e7, longitude_e7, altitude_mm)
        .expect("example coordinates are in range")
}

/// One zone's fused water-stress assessment, computed from ingested samples.
#[derive(Debug, Clone, PartialEq)]
pub struct ZoneReading {
    /// Zone name.
    pub name: String,
    /// Valve actuator id.
    pub actuator_id: String,
    /// Measured soil volumetric water content, %.
    pub vwc_pct: f64,
    /// Measured canopy temperature, °C.
    pub temp_c: f64,
    /// Measured leaf wetness index.
    pub leaf_wetness: f64,
    /// Water-stress index, `0.0..=1.0`.
    pub stress: f64,
    /// Valve opening the planner will request (0 when no irrigation is due).
    pub magnitude: f64,
}

/// Water-stress index: soil deficit dominates, heat adds to it, and a wet
/// canopy subtracts from it. Deliberately simple and deterministic — the
/// point of this example is what happens to the *command*, not the agronomy.
#[must_use]
pub fn water_stress(vwc_pct: f64, temp_c: f64, leaf_wetness: f64) -> f64 {
    let deficit = 0.6 * (TARGET_VWC_PCT - vwc_pct) / TARGET_VWC_PCT;
    let heat = 0.3 * (temp_c - 20.0) / 25.0;
    let canopy = 0.2 * leaf_wetness;
    (deficit + heat - canopy).clamp(0.0, 1.0)
}

/// Ingest one sampling round from all nine nodes and fuse each zone.
#[must_use]
pub fn sense() -> Vec<ZoneReading> {
    let mut nodes = provision();
    let mut gateway = Gateway::with_nodes(&nodes);
    let mut rng = Rng::new(0x00A2_0FA1_0000_2026);
    let measured = EPOCH_NS;
    let mut readings = Vec::with_capacity(ZONES.len());

    for (z, zone) in ZONES.iter().enumerate() {
        let truth = [zone.vwc_pct, zone.temp_c, zone.leaf_wetness];
        let sd = [0.05, 0.05, 0.005];
        let mut measured_values = [0.0f64; 3];
        for k in 0..3 {
            let idx = z * 3 + k;
            let envelope = nodes[idx].emit(truth[k] + rng.noise(sd[k]), measured, CALIBRATION_ID);
            let sealed = gateway
                .ingest(&envelope, measured + 1_000_000)
                .expect("a node's own signed envelope must ingest");
            measured_values[k] = sealed.sample().value;
        }
        let stress = water_stress(measured_values[0], measured_values[1], measured_values[2]);
        let magnitude = if stress > STRESS_TRIGGER {
            (stress * MAGNITUDE_PER_STRESS).min(POLICY_MAX_MAGNITUDE)
        } else {
            0.0
        };
        readings.push(ZoneReading {
            name: zone.name.to_string(),
            actuator_id: zone.actuator_id.to_string(),
            vwc_pct: measured_values[0],
            temp_c: measured_values[1],
            leaf_wetness: measured_values[2],
            stress,
            magnitude,
        });
    }
    readings
}

// ---------------------------------------------------------------------------
// The governed control path
// ---------------------------------------------------------------------------

/// Everything one governed irrigation cycle produced.
#[derive(Debug)]
pub struct IrrigationRun {
    /// Fused per-zone water stress.
    pub readings: Vec<ZoneReading>,
    /// Zone A's signed execution receipt.
    pub receipt: Option<ExecutionReceipt>,
    /// Zone A's signed command (kept so the replay can be attempted).
    pub command: Option<SignedCommand>,
    /// Why zone B's larger command was refused.
    pub oversized: Option<ControlError>,
    /// Why the contractor's identical proposal was refused.
    pub unauthorized: Option<ControlError>,
    /// Whether the contractor ever produced a receipt (it must not).
    pub unauthorized_receipt: Option<ExecutionReceipt>,
    /// Why replaying zone A's command was refused.
    pub replay: Option<ControlError>,
    /// The full append-only audit trail across all four attempts.
    pub audit: AuditTrail,
    /// Executed-command budget charged against zone A's valve.
    pub zone_a_executions: u32,
}

impl IrrigationRun {
    /// The audit stages recorded for one proposal, in order.
    #[must_use]
    pub fn stages_for(&self, proposal_id: &str) -> Vec<&'static str> {
        self.audit
            .for_proposal(proposal_id)
            .iter()
            .map(|e| e.stage)
            .collect()
    }

    /// The verdict recorded at `stage` for one proposal.
    #[must_use]
    pub fn verdict(&self, proposal_id: &str, stage: &str) -> Option<String> {
        self.audit
            .for_proposal(proposal_id)
            .iter()
            .find(|e| e.stage == stage)
            .map(|e| e.verdict.clone())
    }
}

/// A valve proposal from `agent` for `zone`.
fn valve_proposal(
    proposal_id: &str,
    agent: &str,
    zone: &ZoneReading,
    now_ns: u64,
) -> AgentProposal {
    AgentProposal {
        proposal_id: proposal_id.to_string(),
        agent_id: agent.to_string(),
        biome_id: BIOME_ID.to_string(),
        kind: ProposalKind::ActuatorCommand {
            actuator_id: zone.actuator_id.clone(),
            action: "open".to_string(),
            magnitude: zone.magnitude,
        },
        justification: format!(
            "water stress {:.2} at {:.1} % VWC / {:.1} C — irrigate",
            zone.stress, zone.vwc_pct, zone.temp_c
        ),
        proposed_ns: now_ns,
    }
}

/// Run one full governed irrigation cycle.
#[must_use]
pub fn run_cycle() -> IrrigationRun {
    let readings = sense();
    let now = EPOCH_NS + 60 * NS_PER_S;

    // The grower's deterministic policy: only these three valves exist, and
    // no magnitude above 1.0 is even discussable.
    let policy = PolicyEngine::new(PolicyConfig {
        min_sampling_interval_s: 10,
        max_sampling_interval_s: 86_400,
        max_actuator_magnitude: POLICY_MAX_MAGNITUDE,
        allowed_actuators: ZONES
            .iter()
            .map(|z| z.actuator_id.to_string())
            .collect::<BTreeSet<_>>(),
    });
    let mut safety = SafetySimulator::new(SafetyConfig {
        safe_magnitude: SAFE_MAGNITUDE,
        max_commands_per_actuator: 4,
    });
    // The grower grants the planner both irrigable valves. Zone B will still
    // be refused — by safety, which runs first and is a different gate.
    let mut authority = AuthorityRegistry::new();
    authority.grant(BIOME_ID, PLANNER_AGENT, ZONES[0].actuator_id);
    authority.grant(BIOME_ID, PLANNER_AGENT, ZONES[1].actuator_id);

    let signer = CommandSigner::from_seed(COMMAND_SEED);
    let mut gateway = GatewayValidator::new(vec![signer.public_hex()], GATEWAY_SEED);
    let mut audit = AuditTrail::new();

    let mut run = IrrigationRun {
        readings,
        receipt: None,
        command: None,
        oversized: None,
        unauthorized: None,
        unauthorized_receipt: None,
        replay: None,
        audit: AuditTrail::new(),
        zone_a_executions: 0,
    };

    // --- 1. Zone A: the authorized, in-envelope command -------------------
    let zone_a = &run.readings[0];
    let proposal = valve_proposal("irr-zone-a-001", PLANNER_AGENT, zone_a, now);
    if let Ok(evaluated) = policy.evaluate(proposal, now, &mut audit) {
        if let Ok(simulated) = safety.simulate(evaluated, now, &mut audit) {
            if let Ok(authorized) = authority.authorize(simulated, now, &mut audit) {
                let command = signer.sign(authorized, now, COMMAND_TTL_NS, &mut audit);
                let result = gateway.validate_and_execute(
                    &command,
                    now,
                    |kind| match kind {
                        ProposalKind::ActuatorCommand {
                            actuator_id,
                            action,
                            magnitude,
                        } => Ok(format!("{actuator_id} {action} to {magnitude:.2}")),
                        other => Err(format!("gateway cannot execute {other:?}")),
                    },
                    &mut audit,
                );
                if let Ok(receipt) = result {
                    // Budgets are charged only when something really happened.
                    safety.record_execution(&zone_a.actuator_id);
                    run.zone_a_executions += 1;
                    run.receipt = Some(receipt);
                }
                run.command = Some(command);
            }
        }
    }

    // --- 2. Zone B: policy says yes, the safety envelope says no ----------
    let zone_b = &run.readings[1];
    let proposal = valve_proposal("irr-zone-b-001", PLANNER_AGENT, zone_b, now);
    match policy.evaluate(proposal, now, &mut audit) {
        Ok(evaluated) => {
            run.oversized = safety.simulate(evaluated, now, &mut audit).err();
        }
        Err(e) => run.oversized = Some(e),
    }

    // --- 3. The contractor's identical proposal ---------------------------
    let proposal = valve_proposal("irr-zone-a-002", CONTRACTOR_AGENT, zone_a, now);
    if let Ok(evaluated) = policy.evaluate(proposal, now, &mut audit) {
        if let Ok(simulated) = safety.simulate(evaluated, now, &mut audit) {
            match authority.authorize(simulated, now, &mut audit) {
                Ok(authorized) => {
                    // Unreachable if the guarantee holds; if it ever is
                    // reached the receipt is recorded so the test fails loudly.
                    let command = signer.sign(authorized, now, COMMAND_TTL_NS, &mut audit);
                    run.unauthorized_receipt = gateway
                        .validate_and_execute(&command, now, |_| Ok("executed".into()), &mut audit)
                        .ok();
                }
                Err(e) => run.unauthorized = Some(e),
            }
        }
    }

    // --- 4. Replay of zone A's signed command -----------------------------
    if let Some(command) = &run.command {
        run.replay = gateway
            .validate_and_execute(
                command,
                now + NS_PER_S,
                |_| Ok("replayed".into()),
                &mut audit,
            )
            .err();
    }

    run.audit = audit;
    run
}

// ---------------------------------------------------------------------------
// Narrative
// ---------------------------------------------------------------------------

fn main() {
    banner(
        "PRECISION IRRIGATION — ADR-266 wedge #2",
        "9 signed spore nodes, 3 zones, one governed valve command end to end",
    );

    let run = run_cycle();

    println!("  Per-zone water stress (fused from verified observations)");
    for reading in &run.readings {
        line(
            &format!("  {}", reading.name),
            format!(
                "{:.1} % VWC, {:.1} C, leaf {:.2} -> stress {:.2}, request {:.2}",
                reading.vwc_pct,
                reading.temp_c,
                reading.leaf_wetness,
                reading.stress,
                reading.magnitude
            ),
        );
    }
    line(
        "irrigation trigger",
        format!("stress > {STRESS_TRIGGER:.2}"),
    );
    line(
        "policy ceiling / safety envelope",
        format!("{POLICY_MAX_MAGNITUDE:.2} / {SAFE_MAGNITUDE:.2}"),
    );

    println!("\n  1. Zone A — authorized planner, inside the envelope");
    let receipt = run.receipt.as_ref().expect("zone A executes");
    line("command id", &receipt.command_id);
    line("outcome", &receipt.outcome);
    line("gateway receipt hash", &receipt.gateway_receipt_hash);
    line("gateway attestation key", &receipt.gateway_pubkey_hex);
    line(
        "verify_receipt(receipt)",
        if verify_receipt(receipt) {
            "VALID — offline-verifiable attestation"
        } else {
            "INVALID — guarantee broken"
        },
    );
    let mut tampered = receipt.clone();
    tampered.outcome.push_str(" (edited)");
    line(
        "verify_receipt(tampered outcome)",
        if verify_receipt(&tampered) {
            "VALID — guarantee broken"
        } else {
            "INVALID — tampering detected"
        },
    );
    line("safety budget charged", run.zone_a_executions);

    println!("\n  2. Zone B — policy allowed it, safety did not");
    let oversized = run.oversized.as_ref().expect("zone B is refused");
    line(
        "policy verdict",
        run.verdict("irr-zone-b-001", "policy_evaluated")
            .unwrap_or_default(),
    );
    line("safety verdict", format!("{oversized}"));
    line(
        "stopped at",
        if matches!(oversized, ControlError::Unsafe(_)) {
            "SafetySimulator (stage 2)"
        } else {
            "NOT safety — guarantee broken"
        },
    );

    println!("\n  3. The contractor's identical proposal");
    let unauthorized = run.unauthorized.as_ref().expect("contractor is refused");
    line("error", format!("{unauthorized}"));
    line(
        "stopped at",
        if matches!(unauthorized, ControlError::NotAuthorized { .. }) {
            "AuthorityRegistry (stage 3)"
        } else {
            "NOT authority — guarantee broken"
        },
    );
    line(
        "receipt issued to the contractor",
        if run.unauthorized_receipt.is_none() {
            "none — nothing was signed, nothing executed"
        } else {
            "ONE — guarantee broken"
        },
    );

    println!("\n  4. Replay of zone A's signed command");
    let replay = run.replay.as_ref().expect("the replay is refused");
    line("error", format!("{replay}"));
    line(
        "stopped at",
        if matches!(replay, ControlError::DuplicateCommand(_)) {
            "GatewayValidator (fail-closed, any recorded phase)"
        } else {
            "NOT the gateway — guarantee broken"
        },
    );

    println!("\n  Audit trail — every stage, every verdict, append-only");
    for entry in run.audit.entries() {
        line(
            &format!("  [{}] {}", entry.proposal_id, entry.stage),
            &entry.verdict,
        );
    }
    let zone_a_stages = run.stages_for("irr-zone-a-001");
    line(
        "zone A stages (completed path)",
        format!("{:?}", &zone_a_stages[..7]),
    );
    line(
        "zone A stages (after the replay attempt)",
        format!("{:?}", &zone_a_stages[7..]),
    );

    synthetic_footer(
        "Soil, canopy, and leaf-wetness values are simulated; the policy, \
         safety, authority, signing, and replay gates are the production path.",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorized_zone_opens_with_a_verifiable_signed_receipt() {
        let run = run_cycle();
        let receipt = run.receipt.expect("zone A executes");
        assert!(verify_receipt(&receipt), "the genuine receipt must verify");
        assert_eq!(receipt.command_id, "cmd-irr-zone-a-001");
        assert!(receipt.outcome.contains("valve/zone-a open"));

        // Any edit to the attestation breaks it.
        for mutate in [
            (|r: &mut ExecutionReceipt| r.outcome.push('!')) as fn(&mut ExecutionReceipt),
            |r: &mut ExecutionReceipt| r.executed_ns += 1,
            |r: &mut ExecutionReceipt| r.command_id.push('x'),
            |r: &mut ExecutionReceipt| r.gateway_receipt_hash.push('0'),
        ] {
            let mut tampered = receipt.clone();
            mutate(&mut tampered);
            assert!(
                !verify_receipt(&tampered),
                "tampered receipt must not verify"
            );
        }
        assert_eq!(run.zone_a_executions, 1);
    }

    #[test]
    fn unauthorized_agent_is_stopped_at_authority_with_no_receipt() {
        let run = run_cycle();
        let err = run.unauthorized.clone().expect("contractor refused");
        assert!(
            matches!(&err, ControlError::NotAuthorized { agent_id, actuator_id, .. }
                if agent_id == CONTRACTOR_AGENT && actuator_id == "valve/zone-a"),
            "expected NotAuthorized, got {err:?}"
        );
        assert!(
            run.unauthorized_receipt.is_none(),
            "an unauthorized agent must never obtain a receipt"
        );
        // Policy and safety both passed — the proposal was identical.
        assert_eq!(
            run.verdict("irr-zone-a-002", "policy_evaluated").as_deref(),
            Some("accepted")
        );
        assert_eq!(
            run.verdict("irr-zone-a-002", "safety_simulated").as_deref(),
            Some("within safety envelope")
        );
        // ...and the run stopped at "authorized" — it never reached "signed".
        let stages = run.stages_for("irr-zone-a-002");
        assert_eq!(
            stages,
            vec![
                "proposed",
                "policy_evaluated",
                "safety_simulated",
                "authorized"
            ]
        );
    }

    #[test]
    fn over_magnitude_is_stopped_at_safety_not_policy() {
        let run = run_cycle();
        let zone_b = &run.readings[1];
        assert!(
            zone_b.magnitude > SAFE_MAGNITUDE && zone_b.magnitude <= POLICY_MAX_MAGNITUDE,
            "zone B must sit between the safety envelope and the policy ceiling, got {}",
            zone_b.magnitude
        );
        let err = run.oversized.clone().expect("zone B refused");
        assert!(matches!(err, ControlError::Unsafe(_)), "got {err:?}");
        // Policy explicitly accepted it first.
        assert_eq!(
            run.verdict("irr-zone-b-001", "policy_evaluated").as_deref(),
            Some("accepted")
        );
        assert!(run
            .verdict("irr-zone-b-001", "safety_simulated")
            .expect("safety ran")
            .starts_with("rejected:"));
    }

    #[test]
    fn replaying_the_same_command_id_is_refused() {
        let run = run_cycle();
        let err = run.replay.clone().expect("replay refused");
        assert_eq!(
            err,
            ControlError::DuplicateCommand("cmd-irr-zone-a-001".to_string())
        );
        // The gateway recorded the duplicate rather than silently dropping it.
        let duplicates: Vec<_> = run
            .audit
            .entries()
            .iter()
            .filter(|e| e.verdict.starts_with("duplicate_rejected:"))
            .collect();
        assert_eq!(duplicates.len(), 1);
        assert_eq!(duplicates[0].stage, "gateway_validated");
        // And the valve was still only ever opened once.
        assert_eq!(run.zone_a_executions, 1);
    }

    #[test]
    fn the_executed_command_leaves_the_full_seven_stage_trail() {
        let run = run_cycle();
        let stages = run.stages_for("irr-zone-a-001");
        assert_eq!(
            stages[..7],
            EXPECTED_STAGES,
            "the completed governed path leaves exactly these seven stages, in order"
        );
        // The replay attempt is audited under the same proposal id (the
        // command id is derived from it), so it appends one more entry.
        assert_eq!(stages.len(), 8);
        assert_eq!(stages[7], "gateway_validated");
    }

    #[test]
    fn well_watered_zone_proposes_nothing() {
        let run = run_cycle();
        let zone_c = &run.readings[2];
        assert!(zone_c.stress <= STRESS_TRIGGER, "zone C is not stressed");
        assert_eq!(zone_c.magnitude, 0.0);
        assert!(
            run.audit
                .entries()
                .iter()
                .all(|e| !e.verdict.contains("valve/zone-c")),
            "no command should ever have been raised for zone C"
        );
        // Stress ordering is deterministic: B (driest, hottest) > A > C.
        assert!(run.readings[1].stress > run.readings[0].stress);
        assert!(run.readings[0].stress > run.readings[2].stress);
    }
}
