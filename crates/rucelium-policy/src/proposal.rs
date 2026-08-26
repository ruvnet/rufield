//! Agent proposal types — the **only** types agents ever construct
//! (ADR-264 §9).
//!
//! An agent's entire vocabulary is [`AgentProposal`] + [`ProposalKind`]. Every
//! other type in this crate is a stage output with private fields and no
//! public constructor, so an agent physically cannot fabricate something the
//! gateway would execute.

use rucelium_core::GeoPoint;
use serde::{Deserialize, Serialize};

/// What an agent is asking the fabric to do.
///
/// Agents may propose new sampling rates, model deployments, sensor
/// repositioning, or actuator commands — and nothing else. They never
/// directly control physical systems (ADR-264 §9).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ProposalKind {
    /// Change the sampling interval of a spore node.
    SetSamplingRate {
        /// Target node.
        node_id: u64,
        /// Proposed sampling interval in seconds.
        interval_s: u32,
    },
    /// Deploy a model to a rhizome gateway.
    DeployModel {
        /// Model identifier.
        model_id: String,
        /// Gateway that should receive the model.
        target_gateway: String,
    },
    /// Physically reposition a sensor node.
    RepositionSensor {
        /// Node to move.
        node_id: u64,
        /// Proposed new location.
        to: GeoPoint,
    },
    /// Drive an actuator (valve, gate, pump, …). The most dangerous kind:
    /// it must clear the policy gate, the safety envelope, **and** an exact
    /// per-actuator authority grant before it can be signed.
    ActuatorCommand {
        /// Target actuator.
        actuator_id: String,
        /// Named action, e.g. `"open"`.
        action: String,
        /// Signed magnitude of the action, in actuator-native units.
        magnitude: f64,
    },
}

/// A raw, unevaluated proposal from an agent. All fields are public: agents
/// construct these freely. Constructing one grants **no** power — a proposal
/// only reaches execution by moving through every stage of the governed
/// control path, each of which returns a privately-constructed witness type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentProposal {
    /// Unique proposal id (deterministic in the simulator).
    pub proposal_id: String,
    /// Proposing agent.
    pub agent_id: String,
    /// Biome the proposal targets. Actuator authority never leaves the biome
    /// owner (ADR-264 §6).
    pub biome_id: String,
    /// What is being proposed.
    pub kind: ProposalKind,
    /// Human-readable justification. Required — an empty justification is a
    /// policy violation.
    pub justification: String,
    /// When the agent made the proposal, ns since Unix epoch.
    pub proposed_ns: u64,
}
