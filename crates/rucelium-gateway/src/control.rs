//! The daemon's end of the governed control path (ADR-264 §9).
//!
//! The policy crate enforces stage *ordering* with type privacy — there is no
//! way to obtain an `AuthorizedProposal` without passing policy and safety
//! first. What the daemon owns is everything the library deliberately does
//! not: the wall clock, the local execution effect, the durable command
//! journal, and the budget bookkeeping that must only be charged once a
//! command actually ran.
//!
//! ```text
//! AgentProposal → PolicyEngine → SafetySimulator → AuthorityRegistry
//!               → CommandSigner → GatewayValidator → execute → receipt
//! ```
//!
//! Ordering of the post-execution steps matters:
//!
//! 1. `validate_and_execute` records `Executing` before the closure runs and
//!    `Executed`/`Failed` after it;
//! 2. the journal is rewritten **after every attempt** — success or failure —
//!    so a crash can never leave an executed command absent from disk;
//! 3. only then is the safety budget charged (`record_execution`), because a
//!    budget is spent by execution, not by proposing.

use crate::state::Inner;
use rucelium_policy::{AgentProposal, ControlError, ExecutionReceipt, ProposalKind, SignedCommand};

/// How long a signed command stays valid (1 hour) — long enough for a slow
/// local link, short enough that a captured command is not replayable forever.
pub const COMMAND_TTL_NS: u64 = 3_600 * 1_000_000_000;

/// Build the actuator proposal the admin endpoint drives.
#[must_use]
pub fn actuator_proposal(
    biome_id: &str,
    proposal_id: &str,
    agent_id: &str,
    actuator_id: &str,
    action: &str,
    magnitude: f64,
    now_ns: u64,
) -> AgentProposal {
    AgentProposal {
        proposal_id: proposal_id.to_string(),
        agent_id: agent_id.to_string(),
        biome_id: biome_id.to_string(),
        kind: ProposalKind::ActuatorCommand {
            actuator_id: actuator_id.to_string(),
            action: action.to_string(),
            magnitude,
        },
        justification: format!("admin control request for {actuator_id}"),
        proposed_ns: now_ns,
    }
}

/// Run one proposal through **every** stage of the governed path and, on
/// success, record the signed receipt.
///
/// Returns the gateway's signed [`ExecutionReceipt`] or the first
/// [`ControlError`] that stopped the proposal. Either way the command journal
/// is rewritten before returning, and the control-path counters are updated.
pub fn run_proposal(
    inner: &mut Inner,
    proposal: AgentProposal,
    now_ns: u64,
) -> Result<ExecutionReceipt, ControlError> {
    let outcome = drive(inner, proposal, now_ns);

    // Journal after every attempt (including rejections: `validate_and_execute`
    // may have recorded a phase before failing inside the closure).
    if let Err(e) = inner.journal_command_phases() {
        eprintln!("gateway: command journal write failed: {e}");
    }

    match &outcome {
        Ok(receipt) => {
            inner.control.commands_executed += 1;
            inner.receipts.push(receipt.clone());
            inner.control.receipts = inner.receipts.len() as u64;
        }
        Err(_) => inner.control.proposals_rejected += 1,
    }
    outcome
}

/// The stage pipeline itself, factored out so [`run_proposal`] can journal and
/// count around it on every path.
fn drive(
    inner: &mut Inner,
    proposal: AgentProposal,
    now_ns: u64,
) -> Result<ExecutionReceipt, ControlError> {
    // Split borrows: every stage needs a different field of `Inner` plus the
    // shared audit trail.
    let Inner {
        policy,
        safety,
        authority,
        command_signer,
        gateway,
        audit,
        ..
    } = inner;

    let evaluated = policy.evaluate(proposal, now_ns, audit)?;
    let simulated = safety.simulate(evaluated, now_ns, audit)?;
    let authorized = authority.authorize(simulated, now_ns, audit)?;
    let command: SignedCommand = command_signer.sign(authorized, now_ns, COMMAND_TTL_NS, audit);

    let receipt = gateway.validate_and_execute(&command, now_ns, execute_locally, audit)?;

    // Charged only now: the command really ran (ADR-264 §9 "checked at
    // safety, charged at execution").
    if let ProposalKind::ActuatorCommand { actuator_id, .. } = &command.payload.kind {
        safety.record_execution(actuator_id);
    }
    Ok(receipt)
}

/// The local execution effect. v0.1 has no physical actuator wired up, so
/// this is an honest description of what *would* be driven — it never claims
/// a physical effect it cannot produce (ADR-264 §12).
fn execute_locally(kind: &ProposalKind) -> Result<String, String> {
    match kind {
        ProposalKind::ActuatorCommand {
            actuator_id,
            action,
            magnitude,
        } => Ok(format!("{actuator_id}: {action}={magnitude}")),
        ProposalKind::SetSamplingRate {
            node_id,
            interval_s,
        } => Ok(format!("node {node_id}: sampling interval {interval_s}s")),
        ProposalKind::DeployModel { model_id, .. } => Ok(format!("model {model_id} staged")),
        ProposalKind::RepositionSensor { node_id, .. } => {
            Ok(format!("node {node_id}: reposition scheduled"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::testutil::test_inner;
    use crate::state::GRANTED_AGENT_ID;
    use rucelium_policy::verify_receipt;

    const NOW: u64 = 1_754_000_000_000_000_000;
    const ACTUATOR: &str = "sluice-gate-1";

    fn proposal(inner: &Inner, id: &str, agent: &str, magnitude: f64) -> AgentProposal {
        let biome_id = inner.biome.config().biome_id.clone();
        actuator_proposal(
            &biome_id,
            id,
            agent,
            ACTUATOR,
            "open_fraction",
            magnitude,
            NOW,
        )
    }

    #[test]
    fn authorized_proposal_executes_once_and_yields_a_verifiable_receipt() {
        let mut inner = test_inner("control-ok");
        let p = proposal(&inner, "42", GRANTED_AGENT_ID, 0.5);
        let receipt = run_proposal(&mut inner, p, NOW).expect("authorized command executes");

        assert_eq!(receipt.command_id, "cmd-42");
        assert!(
            verify_receipt(&receipt),
            "receipts are gateway attestations"
        );
        assert_eq!(
            receipt.gateway_pubkey_hex,
            inner.gateway.gateway_pubkey_hex()
        );
        assert_eq!(inner.control.commands_executed, 1);
        assert_eq!(inner.control.receipts, 1);

        // The journal recorded the executed phase durably.
        assert_eq!(
            crate::journal::load(&inner.command_journal).unwrap(),
            vec![("cmd-42".to_string(), "executed".to_string())]
        );

        // A replay of the same command id is rejected, and no second receipt
        // is produced.
        let again = proposal(&inner, "42", GRANTED_AGENT_ID, 0.5);
        assert!(matches!(
            run_proposal(&mut inner, again, NOW),
            Err(ControlError::DuplicateCommand(id)) if id == "cmd-42"
        ));
        assert_eq!(inner.receipts.len(), 1);
        assert_eq!(inner.control.proposals_rejected, 1);
    }

    #[test]
    fn unauthorized_agent_never_reaches_signing() {
        let mut inner = test_inner("control-unauthorized");
        let p = proposal(&inner, "rogue-1", "agent/unknown", 0.5);
        assert!(matches!(
            run_proposal(&mut inner, p, NOW),
            Err(ControlError::NotAuthorized { .. })
        ));
        assert_eq!(inner.control.commands_executed, 0);
        assert!(inner.receipts.is_empty());
        // Nothing was ever executed, so the journal stays empty.
        assert!(crate::journal::load(&inner.command_journal)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn unsafe_magnitude_is_stopped_by_the_safety_gate() {
        let mut inner = test_inner("control-unsafe");
        // Policy allows up to 1.0; the safety envelope stops at 0.8.
        let p = proposal(&inner, "hot-1", GRANTED_AGENT_ID, 0.95);
        assert!(matches!(
            run_proposal(&mut inner, p, NOW),
            Err(ControlError::Unsafe(_))
        ));
        assert_eq!(inner.control.proposals_rejected, 1);
    }

    #[test]
    fn unknown_actuator_is_stopped_by_policy() {
        let mut inner = test_inner("control-unknown-actuator");
        let biome_id = inner.biome.config().biome_id.clone();
        let p = actuator_proposal(
            &biome_id,
            "other-1",
            GRANTED_AGENT_ID,
            "not-configured",
            "open_fraction",
            0.5,
            NOW,
        );
        assert!(matches!(
            run_proposal(&mut inner, p, NOW),
            Err(ControlError::PolicyViolation(_))
        ));
    }

    #[test]
    fn safety_budget_is_charged_only_by_execution() {
        let mut inner = test_inner("control-budget");
        // 10 successful executions exhaust `SafetyConfig::max_commands_per_actuator`.
        for i in 0..10 {
            let p = proposal(&inner, &format!("b-{i}"), GRANTED_AGENT_ID, 0.5);
            run_proposal(&mut inner, p, NOW).expect("within budget");
        }
        let p = proposal(&inner, "b-over", GRANTED_AGENT_ID, 0.5);
        assert!(matches!(
            run_proposal(&mut inner, p, NOW),
            Err(ControlError::Unsafe(_))
        ));
        assert_eq!(inner.control.commands_executed, 10);
        // All ten phases are journaled.
        assert_eq!(
            crate::journal::load(&inner.command_journal).unwrap().len(),
            10
        );
    }
}
