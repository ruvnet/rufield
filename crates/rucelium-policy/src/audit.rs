//! Append-only audit trail for the governed control path (ADR-264 §9).
//!
//! Every stage of the pipeline appends an [`AuditEntry`] — acceptances **and**
//! rejections — so a completed happy path leaves exactly seven entries:
//! `"proposed"`, `"policy_evaluated"`, `"safety_simulated"`, `"authorized"`,
//! `"signed"`, `"gateway_validated"`, `"executed"`.
//!
//! Gateway failure outcomes are recorded too: a replayed command id leaves a
//! `"gateway_validated"` entry with verdict `"duplicate_rejected: …"`, and a
//! failed execution closure leaves an `"executed"` entry with verdict
//! `"execution_failed: …"`.

use serde::Serialize;

/// One audit record: which stage saw which proposal, when, with what verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEntry {
    /// Stage name (one of the seven fixed stage strings).
    pub stage: &'static str,
    /// Proposal this entry concerns.
    pub proposal_id: String,
    /// When the stage ran, ns since Unix epoch (caller-supplied — no clocks).
    pub at_ns: u64,
    /// Human-readable verdict, e.g. `"accepted"` or `"rejected: …"`.
    pub verdict: String,
}

/// Append-only trail threaded through every stage of the pipeline. Only this
/// crate's stage implementations can append (the recording method is
/// `pub(crate)`); callers get read-only access.
#[derive(Debug, Default)]
pub struct AuditTrail {
    entries: Vec<AuditEntry>,
}

impl AuditTrail {
    /// New, empty trail.
    #[must_use]
    pub fn new() -> Self {
        AuditTrail::default()
    }

    /// Append an entry. Crate-private: only pipeline stages write the trail.
    pub(crate) fn record(
        &mut self,
        stage: &'static str,
        proposal_id: &str,
        at_ns: u64,
        verdict: impl Into<String>,
    ) {
        self.entries.push(AuditEntry {
            stage,
            proposal_id: proposal_id.to_string(),
            at_ns,
            verdict: verdict.into(),
        });
    }

    /// All entries, in append order.
    #[must_use]
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Entries for one proposal, in append order.
    #[must_use]
    pub fn for_proposal(&self, proposal_id: &str) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.proposal_id == proposal_id)
            .collect()
    }
}
