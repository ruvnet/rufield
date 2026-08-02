//! # rucelium-policy
//!
//! The **governed control path** of the RuCelium fabric (ADR-264 §9).
//! Agents propose; they can **never** execute. The only path from an agent's
//! idea to a physical effect is:
//!
//! ```text
//! AgentProposal
//! → deterministic policy evaluation   (PolicyEngine)
//! → safety simulation                 (SafetySimulator)
//! → authority check                   (AuthorityRegistry)
//! → signed command                    (CommandSigner)
//! → gateway validation                (GatewayValidator)
//! → local execution                   (caller-supplied closure)
//! → execution receipt                 (ExecutionReceipt)
//! ```
//!
//! ## Enforced by construction — skipping a stage is a compile error
//!
//! Each stage's output type ([`EvaluatedProposal`], [`SimulatedProposal`],
//! [`AuthorizedProposal`]) has **private fields and no public constructor**,
//! and is the only accepted input to the next stage. The compiler is the
//! enforcement mechanism: there is no sequence of safe Rust outside this
//! crate that produces an [`AuthorizedProposal`] without passing policy and
//! safety first. The single exception is [`SignedCommand`], which crosses the
//! network to the gateway — at that hop the gate is **cryptography, not type
//! privacy**: a forged or tampered `SignedCommand` fails
//! [`GatewayValidator`]'s ed25519 verification against its trusted keys.
//!
//! For example, feeding a raw [`AgentProposal`] straight to the gateway does
//! not compile:
//!
//! ```compile_fail
//! use rucelium_policy::{AgentProposal, AuditTrail, GatewayValidator, ProposalKind};
//!
//! let mut gateway = GatewayValidator::new(vec![], &[7u8; 32]);
//! let mut audit = AuditTrail::new();
//! let proposal = AgentProposal {
//!     proposal_id: "p-1".into(),
//!     agent_id: "agent-1".into(),
//!     biome_id: "biome-1".into(),
//!     kind: ProposalKind::SetSamplingRate { node_id: 1, interval_s: 60 },
//!     justification: "denser sampling during storm".into(),
//!     proposed_ns: 0,
//! };
//! // ERROR: expected `&SignedCommand`, found `&AgentProposal`.
//! let _ = gateway.validate_and_execute(&proposal, 0, |_| Ok(String::new()), &mut audit);
//! ```
//!
//! Likewise `AuthorityRegistry::authorize` only accepts a
//! [`SimulatedProposal`] (so authority cannot be checked before safety), and
//! `CommandSigner::sign` only accepts an [`AuthorizedProposal`] (so nothing
//! unauthorized can be signed).
//!
//! ## Determinism
//!
//! No clocks, no RNG: callers pass `now_ns` everywhere, and both command
//! signing and the gateway's receipt-signing identity are deterministic
//! ed25519 (RFC 8032) from fixed 32-byte seeds. Identical runs produce
//! identical signatures, receipts, and receipt hashes.
//!
//! ## Budgets: checked at safety, charged at execution
//!
//! [`SafetySimulator::simulate`] only **checks** the per-actuator command
//! budget — it never consumes it. The budget is charged only when a command
//! actually executes: the orchestrator calls
//! [`SafetySimulator::record_execution`] after the gateway confirms
//! execution. This means an unauthorized (or otherwise failing) proposal can
//! be replayed forever without draining another actuator's budget. As
//! defence in depth the gateway *also* enforces its own executed-command cap
//! per actuator ([`GatewayValidator::with_max_commands_per_actuator`]),
//! counted from commands it actually executed.
//!
//! ## Restart posture (§9 pipeline): journal + fail-closed `Executing`
//!
//! Execution at the gateway is **two-phase**. After all validation checks
//! pass, the command id is recorded as [`CommandPhase::Executing`] *before*
//! the execution closure runs; on success it becomes
//! [`CommandPhase::Executed`] (and a signed receipt is issued), on failure
//! [`CommandPhase::Failed`] (and [`ControlError::ExecutionFailed`] is
//! returned). A daemon that owns the gateway journals this table to disk via
//! [`GatewayValidator::export_phases`] and reloads it on restart via
//! [`GatewayValidator::restore_phases`]. Crash recovery is **fail-closed**:
//! a command id found in *any* phase — including an `Executing` entry left
//! behind by a crash mid-execution, whose physical effect is unknown — is
//! rejected as [`ControlError::DuplicateCommand`] and never re-executed.
//! Likewise a command replayed against a `Failed` entry is rejected;
//! retrying after failure deliberately requires a **new command id** (and
//! hence a fresh trip through the whole governed path).
//!
//! ## Receipts are attestations
//!
//! An [`ExecutionReceipt`] is signed by the gateway's own deterministic
//! ed25519 identity (seeded via [`GatewayValidator::new`]): it carries
//! `gateway_pubkey_hex` and `signature_hex` over the canonical receipt bytes
//! in addition to the receipt hash. Anyone can check it offline with
//! [`verify_receipt`].
//!
//! ## Audit
//!
//! Every stage — acceptances and rejections alike — appends to an
//! [`AuditTrail`]. A completed happy path leaves exactly seven entries, in
//! order: `"proposed"`, `"policy_evaluated"`, `"safety_simulated"`,
//! `"authorized"`, `"signed"`, `"gateway_validated"`, `"executed"`. Gateway
//! failure outcomes are recorded too: a replayed command id leaves a
//! `"gateway_validated"` entry whose verdict starts with
//! `"duplicate_rejected:"`, and a failed execution closure leaves an
//! `"executed"` entry whose verdict starts with `"execution_failed:"`.

#![doc(html_root_url = "https://docs.rs/rucelium-policy/0.1.0")]

pub mod audit;
pub mod pipeline;
pub mod proposal;

pub use audit::{AuditEntry, AuditTrail};
pub use pipeline::{
    verify_receipt, AuthorityRegistry, AuthorizedProposal, CommandPayload, CommandPhase,
    CommandSigner, EvaluatedProposal, ExecutionReceipt, GatewayValidator, PolicyConfig,
    PolicyEngine, ProposalKindView, SafetyConfig, SafetySimulator, SignedCommand,
    SimulatedProposal,
};
pub use proposal::{AgentProposal, ProposalKind};

/// Everything that can stop a proposal on its way to execution.
#[derive(Debug, Clone, PartialEq)]
pub enum ControlError {
    /// Rejected by deterministic policy evaluation (stage 1).
    PolicyViolation(String),
    /// Rejected by the safety simulation (stage 2) — possibly even though
    /// policy allowed it; the gates are distinct.
    Unsafe(String),
    /// No `(biome, agent, actuator)` authority grant exists (stage 3).
    NotAuthorized {
        /// Biome the proposal targeted.
        biome_id: String,
        /// Agent that proposed.
        agent_id: String,
        /// Actuator it tried to command.
        actuator_id: String,
    },
    /// The command's signer key is not in the gateway's trusted set.
    UntrustedKey(String),
    /// The ed25519 signature did not verify over the canonical bytes.
    BadSignature,
    /// The command reached the gateway after its expiry.
    Expired {
        /// Command expiry, ns since Unix epoch.
        expires_ns: u64,
        /// Gateway's `now_ns` at validation time.
        now_ns: u64,
    },
    /// The command id is already known to the gateway in **any** phase
    /// (`Executing`, `Executed`, or `Failed`) — replay protection, fail
    /// closed. An `Executing` entry restored from a journal after a crash is
    /// deliberately *not* retried, and a command that failed must be
    /// re-issued under a new command id.
    DuplicateCommand(String),
    /// Gateway validation passed but the local execution closure reported
    /// failure. The command id is recorded as `Failed` and can never be
    /// replayed — recovery requires a new command id.
    ExecutionFailed(String),
    /// Malformed hex / key / signature material.
    BadEncoding(String),
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlError::PolicyViolation(m) => write!(f, "policy violation: {m}"),
            ControlError::Unsafe(m) => write!(f, "unsafe: {m}"),
            ControlError::NotAuthorized {
                biome_id,
                agent_id,
                actuator_id,
            } => write!(
                f,
                "not authorized: agent {agent_id} has no grant for actuator {actuator_id} in biome {biome_id}"
            ),
            ControlError::UntrustedKey(k) => write!(f, "untrusted signer key: {k}"),
            ControlError::BadSignature => write!(f, "signature verification failed"),
            ControlError::Expired {
                expires_ns,
                now_ns,
            } => write!(f, "command expired: expires_ns={expires_ns}, now_ns={now_ns}"),
            ControlError::DuplicateCommand(id) => {
                write!(f, "duplicate command {id}: already in a recorded phase")
            }
            ControlError::ExecutionFailed(m) => write!(f, "execution failed: {m}"),
            ControlError::BadEncoding(m) => write!(f, "bad encoding: {m}"),
        }
    }
}

impl std::error::Error for ControlError {}

#[cfg(test)]
mod tests {
    use super::*;
    use rucelium_core::GeoPoint;

    const SEED: &[u8; 32] = b"rucelium-test-seed-32-bytes-ok!!";
    const OTHER_SEED: &[u8; 32] = b"rucelium-EVIL-seed-32-bytes-ok!!";
    const GATEWAY_SEED: &[u8; 32] = b"rucelium-gate-seed-32-bytes-ok!!";

    fn actuator_proposal_with_id(proposal_id: &str, magnitude: f64) -> AgentProposal {
        AgentProposal {
            proposal_id: proposal_id.into(),
            agent_id: "agent/flood".into(),
            biome_id: "biome/thames-estuary".into(),
            kind: ProposalKind::ActuatorCommand {
                actuator_id: "sluice-7".into(),
                action: "open".into(),
                magnitude,
            },
            justification: "water level rising across 3 nodes".into(),
            proposed_ns: 1_000,
        }
    }

    fn actuator_proposal(magnitude: f64) -> AgentProposal {
        actuator_proposal_with_id("p-1", magnitude)
    }

    fn permissive_policy() -> PolicyEngine {
        let mut config = PolicyConfig::default();
        config.allowed_actuators.insert("sluice-7".into());
        PolicyEngine::new(config)
    }

    /// Run the whole pipeline from fresh state; returns the receipt and trail.
    fn run_happy_path() -> (ExecutionReceipt, AuditTrail) {
        let mut audit = AuditTrail::new();
        let engine = permissive_policy();
        let mut sim = SafetySimulator::new(SafetyConfig::default());
        let mut registry = AuthorityRegistry::new();
        registry.grant("biome/thames-estuary", "agent/flood", "sluice-7");
        let signer = CommandSigner::from_seed(SEED);
        let mut gateway = GatewayValidator::new(vec![signer.public_hex()], GATEWAY_SEED);

        let evaluated = engine
            .evaluate(actuator_proposal(0.5), 2_000, &mut audit)
            .unwrap();
        let simulated = sim.simulate(evaluated, 3_000, &mut audit).unwrap();
        let authorized = registry.authorize(simulated, 4_000, &mut audit).unwrap();
        let cmd = signer.sign(authorized, 5_000, 60_000_000_000, &mut audit);
        let receipt = gateway
            .validate_and_execute(
                &cmd,
                6_000,
                |kind| Ok(format!("executed {kind:?}")),
                &mut audit,
            )
            .unwrap();
        // The budget is charged only now, on confirmed execution.
        sim.record_execution("sluice-7");
        (receipt, audit)
    }

    #[test]
    fn full_happy_path_yields_receipt_and_seven_audit_stages() {
        let (receipt, audit) = run_happy_path();
        assert_eq!(receipt.command_id, "cmd-p-1");
        assert_eq!(receipt.executed_ns, 6_000);
        assert!(receipt.gateway_receipt_hash.starts_with("sha256:"));
        assert!(!receipt.gateway_pubkey_hex.is_empty());
        assert!(verify_receipt(&receipt));

        let stages: Vec<&str> = audit.entries().iter().map(|e| e.stage).collect();
        assert_eq!(
            stages,
            [
                "proposed",
                "policy_evaluated",
                "safety_simulated",
                "authorized",
                "signed",
                "gateway_validated",
                "executed",
            ]
        );
        assert_eq!(audit.for_proposal("p-1").len(), 7);
        assert!(audit.for_proposal("nope").is_empty());
    }

    #[test]
    fn receipt_hash_is_deterministic_across_identical_runs() {
        let (a, _) = run_happy_path();
        let (b, _) = run_happy_path();
        assert_eq!(a, b);
        assert_eq!(a.gateway_receipt_hash, b.gateway_receipt_hash);
    }

    #[test]
    fn sampling_interval_below_min_is_policy_violation_and_audited() {
        let mut audit = AuditTrail::new();
        let engine = PolicyEngine::default();
        let proposal = AgentProposal {
            proposal_id: "p-2".into(),
            agent_id: "agent/dq".into(),
            biome_id: "biome/x".into(),
            kind: ProposalKind::SetSamplingRate {
                node_id: 9,
                interval_s: 5,
            },
            justification: "denser sampling".into(),
            proposed_ns: 0,
        };
        let err = engine.evaluate(proposal, 10, &mut audit).unwrap_err();
        assert!(matches!(err, ControlError::PolicyViolation(_)));
        let last = audit.entries().last().unwrap();
        assert_eq!(last.stage, "policy_evaluated");
        assert!(last.verdict.starts_with("rejected:"), "{}", last.verdict);
    }

    #[test]
    fn actuator_not_in_allowed_set_is_policy_violation() {
        let mut audit = AuditTrail::new();
        // Default policy: allowed_actuators is empty.
        let engine = PolicyEngine::default();
        let err = engine
            .evaluate(actuator_proposal(0.1), 10, &mut audit)
            .unwrap_err();
        assert!(matches!(err, ControlError::PolicyViolation(_)));
    }

    #[test]
    fn policy_and_safety_are_distinct_gates() {
        let mut audit = AuditTrail::new();
        let engine = permissive_policy();
        let mut sim = SafetySimulator::new(SafetyConfig::default());
        // Magnitude 0.9: within the policy maximum (1.0)…
        let evaluated = engine
            .evaluate(actuator_proposal(0.9), 10, &mut audit)
            .unwrap();
        // …but beyond the safety envelope (0.8).
        let err = sim.simulate(evaluated, 20, &mut audit).unwrap_err();
        assert!(matches!(err, ControlError::Unsafe(_)));
        let last = audit.entries().last().unwrap();
        assert_eq!(last.stage, "safety_simulated");
        assert!(last.verdict.starts_with("rejected:"));
    }

    #[test]
    fn actuator_command_budget_binds_only_on_recorded_executions() {
        let mut audit = AuditTrail::new();
        let engine = permissive_policy();
        let mut sim = SafetySimulator::new(SafetyConfig {
            safe_magnitude: 0.8,
            max_commands_per_actuator: 2,
        });
        // Simulation alone never consumes the budget, no matter how often.
        for _ in 0..20 {
            let evaluated = engine
                .evaluate(actuator_proposal(0.1), 10, &mut audit)
                .unwrap();
            sim.simulate(evaluated, 20, &mut audit).unwrap();
        }
        // Two confirmed executions exhaust the budget of 2…
        sim.record_execution("sluice-7");
        sim.record_execution("sluice-7");
        let evaluated = engine
            .evaluate(actuator_proposal(0.1), 10, &mut audit)
            .unwrap();
        // …and only then does the check bind.
        let err = sim.simulate(evaluated, 20, &mut audit).unwrap_err();
        assert!(matches!(err, ControlError::Unsafe(_)));
    }

    #[test]
    fn unauthorized_replays_do_not_consume_safety_budget() {
        let mut audit = AuditTrail::new();
        let engine = permissive_policy();
        let mut sim = SafetySimulator::new(SafetyConfig {
            safe_magnitude: 0.8,
            max_commands_per_actuator: 2,
        });
        let mut registry = AuthorityRegistry::new(); // rogue agent: no grant
        for _ in 0..10 {
            let evaluated = engine
                .evaluate(actuator_proposal(0.1), 10, &mut audit)
                .unwrap();
            let simulated = sim.simulate(evaluated, 20, &mut audit).unwrap();
            let err = registry.authorize(simulated, 30, &mut audit).unwrap_err();
            assert!(matches!(err, ControlError::NotAuthorized { .. }));
        }
        // A legitimately authorized proposal afterwards still executes: the
        // rogue replays consumed none of sluice-7's budget.
        registry.grant("biome/thames-estuary", "agent/flood", "sluice-7");
        let signer = CommandSigner::from_seed(SEED);
        let mut gateway = GatewayValidator::new(vec![signer.public_hex()], GATEWAY_SEED);
        let evaluated = engine
            .evaluate(actuator_proposal(0.1), 10, &mut audit)
            .unwrap();
        let simulated = sim.simulate(evaluated, 20, &mut audit).unwrap();
        let authorized = registry.authorize(simulated, 30, &mut audit).unwrap();
        let cmd = signer.sign(authorized, 40, 1_000_000, &mut audit);
        let receipt = gateway
            .validate_and_execute(&cmd, 50, |_| Ok("opened".into()), &mut audit)
            .unwrap();
        sim.record_execution("sluice-7");
        assert_eq!(receipt.outcome, "opened");
    }

    #[test]
    fn missing_grant_is_not_authorized() {
        let mut audit = AuditTrail::new();
        let engine = permissive_policy();
        let mut sim = SafetySimulator::default();
        let registry = AuthorityRegistry::new(); // no grants
        let evaluated = engine
            .evaluate(actuator_proposal(0.5), 10, &mut audit)
            .unwrap();
        let simulated = sim.simulate(evaluated, 20, &mut audit).unwrap();
        let err = registry.authorize(simulated, 30, &mut audit).unwrap_err();
        assert_eq!(
            err,
            ControlError::NotAuthorized {
                biome_id: "biome/thames-estuary".into(),
                agent_id: "agent/flood".into(),
                actuator_id: "sluice-7".into(),
            }
        );
    }

    #[test]
    fn non_actuator_kinds_are_auto_authorized() {
        let mut audit = AuditTrail::new();
        let engine = PolicyEngine::default();
        let mut sim = SafetySimulator::default();
        let registry = AuthorityRegistry::new(); // no grants needed
        let proposal = AgentProposal {
            proposal_id: "p-3".into(),
            agent_id: "agent/deploy".into(),
            biome_id: "biome/x".into(),
            kind: ProposalKind::RepositionSensor {
                node_id: 4,
                to: GeoPoint::new(514_000_000, 500_000, 0).unwrap(),
            },
            justification: "shade moved".into(),
            proposed_ns: 0,
        };
        let evaluated = engine.evaluate(proposal, 10, &mut audit).unwrap();
        let simulated = sim.simulate(evaluated, 20, &mut audit).unwrap();
        assert!(registry.authorize(simulated, 30, &mut audit).is_ok());
    }

    #[test]
    fn invalid_reposition_geo_is_policy_violation() {
        let mut audit = AuditTrail::new();
        let engine = PolicyEngine::default();
        let proposal = AgentProposal {
            proposal_id: "p-4".into(),
            agent_id: "agent/deploy".into(),
            biome_id: "biome/x".into(),
            kind: ProposalKind::RepositionSensor {
                node_id: 4,
                to: GeoPoint {
                    latitude_e7: 900_000_001, // out of range
                    longitude_e7: 0,
                    altitude_mm: 0,
                },
            },
            justification: "move north".into(),
            proposed_ns: 0,
        };
        let err = engine.evaluate(proposal, 10, &mut audit).unwrap_err();
        assert!(matches!(err, ControlError::PolicyViolation(_)));
    }

    /// Sign a valid command through the full front half of the pipeline.
    fn signed_command_with_id(
        signer: &CommandSigner,
        proposal_id: &str,
        ttl_ns: u64,
        audit: &mut AuditTrail,
    ) -> SignedCommand {
        let engine = permissive_policy();
        let mut sim = SafetySimulator::default();
        let mut registry = AuthorityRegistry::new();
        registry.grant("biome/thames-estuary", "agent/flood", "sluice-7");
        let evaluated = engine
            .evaluate(actuator_proposal_with_id(proposal_id, 0.5), 10, audit)
            .unwrap();
        let simulated = sim.simulate(evaluated, 20, audit).unwrap();
        let authorized = registry.authorize(simulated, 30, audit).unwrap();
        signer.sign(authorized, 40, ttl_ns, audit)
    }

    fn signed_command(
        signer: &CommandSigner,
        ttl_ns: u64,
        audit: &mut AuditTrail,
    ) -> SignedCommand {
        signed_command_with_id(signer, "p-1", ttl_ns, audit)
    }

    #[test]
    fn expired_command_is_rejected() {
        let mut audit = AuditTrail::new();
        let signer = CommandSigner::from_seed(SEED);
        let cmd = signed_command(&signer, 1_000, &mut audit); // expires_ns = 1_040
        let mut gateway = GatewayValidator::new(vec![signer.public_hex()], GATEWAY_SEED);
        let err = gateway
            .validate_and_execute(&cmd, 1_040, |_| Ok(String::new()), &mut audit)
            .unwrap_err();
        assert_eq!(
            err,
            ControlError::Expired {
                expires_ns: 1_040,
                now_ns: 1_040,
            }
        );
    }

    #[test]
    fn replaying_a_command_is_duplicate() {
        let mut audit = AuditTrail::new();
        let signer = CommandSigner::from_seed(SEED);
        let cmd = signed_command(&signer, 1_000_000, &mut audit);
        let mut gateway = GatewayValidator::new(vec![signer.public_hex()], GATEWAY_SEED);
        gateway
            .validate_and_execute(&cmd, 50, |_| Ok("ok".into()), &mut audit)
            .unwrap();
        let err = gateway
            .validate_and_execute(&cmd, 60, |_| Ok("ok".into()), &mut audit)
            .unwrap_err();
        assert_eq!(err, ControlError::DuplicateCommand("cmd-p-1".into()));
        // The replay is audited as a duplicate rejection at the gateway.
        let last = audit.entries().last().unwrap();
        assert_eq!(last.stage, "gateway_validated");
        assert!(
            last.verdict.starts_with("duplicate_rejected:"),
            "{}",
            last.verdict
        );
    }

    #[test]
    fn tampered_payload_fails_signature() {
        let mut audit = AuditTrail::new();
        let signer = CommandSigner::from_seed(SEED);
        let cmd = signed_command(&signer, 1_000_000, &mut audit);
        // Serde round-trip mutation: bump the magnitude after signing.
        let mut v: serde_json::Value = serde_json::to_value(&cmd).unwrap();
        v["payload"]["kind"]["ActuatorCommand"]["magnitude"] = serde_json::json!(0.95);
        let forged: SignedCommand = serde_json::from_value(v).unwrap();
        assert_ne!(forged, cmd);
        let mut gateway = GatewayValidator::new(vec![signer.public_hex()], GATEWAY_SEED);
        let err = gateway
            .validate_and_execute(&forged, 50, |_| Ok(String::new()), &mut audit)
            .unwrap_err();
        assert_eq!(err, ControlError::BadSignature);
    }

    #[test]
    fn untrusted_key_is_rejected() {
        let mut audit = AuditTrail::new();
        let rogue = CommandSigner::from_seed(OTHER_SEED);
        let cmd = signed_command(&rogue, 1_000_000, &mut audit);
        // Gateway trusts only the legitimate key.
        let trusted = CommandSigner::from_seed(SEED);
        let mut gateway = GatewayValidator::new(vec![trusted.public_hex()], GATEWAY_SEED);
        let err = gateway
            .validate_and_execute(&cmd, 50, |_| Ok(String::new()), &mut audit)
            .unwrap_err();
        assert_eq!(err, ControlError::UntrustedKey(rogue.public_hex()));
    }

    #[test]
    fn signed_command_survives_serde_round_trip() {
        let mut audit = AuditTrail::new();
        let signer = CommandSigner::from_seed(SEED);
        let cmd = signed_command(&signer, 1_000_000, &mut audit);
        let json = serde_json::to_string(&cmd).unwrap();
        let back: SignedCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cmd);
        // …and still validates after the round trip.
        let mut gateway = GatewayValidator::new(vec![signer.public_hex()], GATEWAY_SEED);
        assert!(gateway
            .validate_and_execute(&back, 50, |_| Ok("ok".into()), &mut audit)
            .is_ok());
    }

    #[test]
    fn gateway_executed_command_cap_binds_on_real_executions() {
        let mut audit = AuditTrail::new();
        let signer = CommandSigner::from_seed(SEED);
        let mut gateway = GatewayValidator::new(vec![signer.public_hex()], GATEWAY_SEED)
            .with_max_commands_per_actuator(2);
        for id in ["p-a", "p-b"] {
            let cmd = signed_command_with_id(&signer, id, 1_000_000, &mut audit);
            gateway
                .validate_and_execute(&cmd, 50, |_| Ok("ok".into()), &mut audit)
                .unwrap();
        }
        let cmd = signed_command_with_id(&signer, "p-c", 1_000_000, &mut audit);
        let err = gateway
            .validate_and_execute(&cmd, 50, |_| Ok("ok".into()), &mut audit)
            .unwrap_err();
        assert!(matches!(err, ControlError::Unsafe(_)), "{err}");
    }

    #[test]
    fn gateway_cap_is_not_consumed_by_failed_executions() {
        let mut audit = AuditTrail::new();
        let signer = CommandSigner::from_seed(SEED);
        let mut gateway = GatewayValidator::new(vec![signer.public_hex()], GATEWAY_SEED)
            .with_max_commands_per_actuator(1);
        let failing = signed_command_with_id(&signer, "p-fail", 1_000_000, &mut audit);
        let err = gateway
            .validate_and_execute(&failing, 50, |_| Err("valve jammed".into()), &mut audit)
            .unwrap_err();
        assert_eq!(err, ControlError::ExecutionFailed("valve jammed".into()));
        // The failure did not consume the executed-command cap of 1.
        let cmd = signed_command_with_id(&signer, "p-good", 1_000_000, &mut audit);
        assert!(gateway
            .validate_and_execute(&cmd, 60, |_| Ok("ok".into()), &mut audit)
            .is_ok());
    }

    #[test]
    fn failed_execution_is_audited_and_never_retryable_under_same_id() {
        let mut audit = AuditTrail::new();
        let signer = CommandSigner::from_seed(SEED);
        let cmd = signed_command(&signer, 1_000_000, &mut audit);
        let mut gateway = GatewayValidator::new(vec![signer.public_hex()], GATEWAY_SEED);
        let err = gateway
            .validate_and_execute(&cmd, 50, |_| Err("valve jammed".into()), &mut audit)
            .unwrap_err();
        assert_eq!(err, ControlError::ExecutionFailed("valve jammed".into()));
        let last = audit.entries().last().unwrap();
        assert_eq!(last.stage, "executed");
        assert_eq!(last.verdict, "execution_failed: valve jammed");
        // The command id is burned: replaying it — even with a now-working
        // closure — is a duplicate. Recovery needs a new command id.
        let err = gateway
            .validate_and_execute(&cmd, 60, |_| Ok("ok".into()), &mut audit)
            .unwrap_err();
        assert_eq!(err, ControlError::DuplicateCommand("cmd-p-1".into()));
        assert_eq!(
            gateway.export_phases(),
            vec![("cmd-p-1".to_string(), "failed".to_string())]
        );
    }

    #[test]
    fn restored_executing_phase_is_fail_closed_and_unknown_phases_skipped() {
        let mut audit = AuditTrail::new();
        let signer = CommandSigner::from_seed(SEED);

        // First gateway life: one success, one failure, then "crash".
        let mut gateway = GatewayValidator::new(vec![signer.public_hex()], GATEWAY_SEED);
        let done = signed_command_with_id(&signer, "p-done", 1_000_000, &mut audit);
        gateway
            .validate_and_execute(&done, 50, |_| Ok("ok".into()), &mut audit)
            .unwrap();
        let broke = signed_command_with_id(&signer, "p-broke", 1_000_000, &mut audit);
        let _ = gateway.validate_and_execute(&broke, 50, |_| Err("boom".into()), &mut audit);
        let mut journal = gateway.export_phases();
        assert_eq!(
            journal,
            vec![
                ("cmd-p-broke".to_string(), "failed".to_string()),
                ("cmd-p-done".to_string(), "executed".to_string()),
            ]
        );
        // Simulate a crash mid-execution of a third command: the daemon's
        // journal holds an Executing entry, plus a corrupt line.
        journal.push(("cmd-p-crashed".to_string(), "executing".to_string()));
        journal.push(("cmd-p-corrupt".to_string(), "banana".to_string()));

        // Restarted gateway restores the journal.
        let mut restarted = GatewayValidator::new(vec![signer.public_hex()], GATEWAY_SEED);
        restarted.restore_phases(journal);

        // Fail closed: every journaled phase — including Executing — rejects.
        for id in ["p-done", "p-broke", "p-crashed"] {
            let cmd = signed_command_with_id(&signer, id, 1_000_000, &mut audit);
            let err = restarted
                .validate_and_execute(&cmd, 60, |_| Ok("ok".into()), &mut audit)
                .unwrap_err();
            assert_eq!(err, ControlError::DuplicateCommand(format!("cmd-{id}")));
        }
        // The unknown phase string was skipped, so that id still executes.
        let cmd = signed_command_with_id(&signer, "p-corrupt", 1_000_000, &mut audit);
        assert!(restarted
            .validate_and_execute(&cmd, 60, |_| Ok("ok".into()), &mut audit)
            .is_ok());
    }

    #[test]
    fn receipt_attestation_verifies_and_tampering_breaks_it() {
        let (receipt, _) = run_happy_path();
        assert_eq!(receipt.gateway_pubkey_hex.len(), 64);
        assert_eq!(receipt.signature_hex.len(), 128);
        assert!(verify_receipt(&receipt));

        let mut tampered = receipt.clone();
        tampered.outcome = "did something else entirely".into();
        assert!(!verify_receipt(&tampered));

        let mut tampered = receipt.clone();
        tampered.command_id = "cmd-p-666".into();
        assert!(!verify_receipt(&tampered));

        let mut tampered = receipt.clone();
        tampered.executed_ns += 1;
        assert!(!verify_receipt(&tampered));

        let mut tampered = receipt.clone();
        tampered.signature_hex = "not-hex".into();
        assert!(!verify_receipt(&tampered));

        // A different gateway identity cannot pass off the same receipt body.
        let mut tampered = receipt;
        tampered.gateway_pubkey_hex =
            GatewayValidator::new(vec![], OTHER_SEED).gateway_pubkey_hex();
        assert!(!verify_receipt(&tampered));
    }
}
