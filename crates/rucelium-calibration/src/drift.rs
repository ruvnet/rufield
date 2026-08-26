//! EWMA drift detection against reference anchors, with sticky sensor
//! quarantine (ADR-264 §12 items 2, 5, 6).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Quarantine state of a node in the drift monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineState {
    /// EWMA residual within the drift threshold.
    Healthy,
    /// EWMA residual over threshold, but not yet confirmed.
    Suspect,
    /// Drift confirmed. **Sticky**: a quarantined node never self-heals —
    /// silent correction is forbidden (ADR-264 §12 item 6); the only way back
    /// is an explicit recalibration via [`DriftDetector::reinstate`].
    Quarantined,
}

/// Configuration for the EWMA drift monitor.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DriftConfig {
    /// EWMA weight for the newest residual (`0.0..=1.0`).
    pub alpha: f64,
    /// Absolute EWMA residual above which a node becomes
    /// [`QuarantineState::Suspect`].
    pub threshold: f64,
    /// Consecutive over-threshold observations required to confirm drift and
    /// move a node from `Suspect` to `Quarantined`.
    pub confirm_count: u32,
}

impl Default for DriftConfig {
    /// Reference defaults: `alpha = 0.2`, `threshold = 1.0`,
    /// `confirm_count = 3`.
    fn default() -> Self {
        DriftConfig {
            alpha: 0.2,
            threshold: 1.0,
            confirm_count: 3,
        }
    }
}

/// Per-node monitor state.
#[derive(Debug, Clone, Copy, PartialEq)]
struct NodeDrift {
    /// EWMA of the residuals observed so far (seeded with the first).
    ewma: f64,
    /// Consecutive over-threshold observations.
    over_count: u32,
    /// Current state.
    state: QuarantineState,
}

/// EWMA residual monitor versus co-located reference anchors
/// (ADR-264 §12 items 2 and 5).
///
/// The caller computes each residual as *node value minus co-located anchor
/// value* and feeds it to [`DriftDetector::observe`]; the detector maintains
/// a per-node EWMA and a three-state machine
/// `Healthy → Suspect → Quarantined`. Dropping back under the threshold
/// resets `Suspect` to `Healthy`, but `Quarantined` is sticky — recovery is
/// only ever explicit, through [`DriftDetector::reinstate`] with a new
/// calibration id (§12 item 6).
///
/// Fully deterministic: identical residual streams always produce identical
/// states.
#[derive(Debug, Clone, Default)]
pub struct DriftDetector {
    config: DriftConfig,
    nodes: BTreeMap<u64, NodeDrift>,
}

impl DriftDetector {
    /// Create a detector with the given configuration.
    #[must_use]
    pub fn new(config: DriftConfig) -> Self {
        DriftDetector {
            config,
            nodes: BTreeMap::new(),
        }
    }

    /// Feed one residual (node value minus co-located anchor value) for
    /// `node_id` and return the node's resulting state.
    pub fn observe(&mut self, node_id: u64, residual: f64) -> QuarantineState {
        let node = self
            .nodes
            .entry(node_id)
            .and_modify(|n| {
                n.ewma = self.config.alpha * residual + (1.0 - self.config.alpha) * n.ewma;
            })
            .or_insert(NodeDrift {
                ewma: residual,
                over_count: 0,
                state: QuarantineState::Healthy,
            });
        // Sticky: once quarantined, no residual stream can heal the node.
        if node.state == QuarantineState::Quarantined {
            return QuarantineState::Quarantined;
        }
        if node.ewma.abs() > self.config.threshold {
            node.over_count += 1;
            node.state = if node.over_count >= self.config.confirm_count {
                QuarantineState::Quarantined
            } else {
                QuarantineState::Suspect
            };
        } else {
            node.over_count = 0;
            node.state = QuarantineState::Healthy;
        }
        node.state
    }

    /// Current state of `node_id` (`Healthy` for never-observed nodes).
    #[must_use]
    pub fn state(&self, node_id: u64) -> QuarantineState {
        self.nodes
            .get(&node_id)
            .map_or(QuarantineState::Healthy, |n| n.state)
    }

    /// Whether `node_id` is quarantined.
    #[must_use]
    pub fn is_quarantined(&self, node_id: u64) -> bool {
        self.state(node_id) == QuarantineState::Quarantined
    }

    /// Explicitly reinstate a quarantined node after recalibration — the only
    /// path out of quarantine (ADR-264 §12 item 6). Clears the node's monitor
    /// state only if it is currently quarantined **and** a real calibration id
    /// is supplied (`new_calibration_id != 0`; 0 is reserved for
    /// "uncalibrated" and cannot reinstate anything). Returns whether the
    /// node was quarantined and has now been cleared.
    pub fn reinstate(&mut self, node_id: u64, new_calibration_id: u32) -> bool {
        if new_calibration_id == 0 || !self.is_quarantined(node_id) {
            return false;
        }
        self.nodes.remove(&node_id);
        true
    }

    /// All quarantined node ids, sorted ascending.
    #[must_use]
    pub fn quarantined(&self) -> Vec<u64> {
        self.nodes
            .iter()
            .filter(|(_, n)| n.state == QuarantineState::Quarantined)
            .map(|(&id, _)| id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> DriftConfig {
        DriftConfig {
            alpha: 0.2,
            threshold: 0.5,
            confirm_count: 3,
        }
    }

    #[test]
    fn steady_drift_becomes_suspect_then_quarantined_and_is_sticky() {
        let mut d = DriftDetector::new(config());
        assert_eq!(d.observe(7, 1.0), QuarantineState::Suspect);
        assert_eq!(d.observe(7, 1.1), QuarantineState::Suspect);
        assert_eq!(d.observe(7, 1.2), QuarantineState::Quarantined);
        // Residuals returning to zero do NOT heal the node (§12 item 6).
        for _ in 0..50 {
            assert_eq!(d.observe(7, 0.0), QuarantineState::Quarantined);
        }
        assert!(d.is_quarantined(7));
        assert_eq!(d.quarantined(), vec![7]);
    }

    #[test]
    fn healthy_node_never_leaves_healthy() {
        let mut d = DriftDetector::new(config());
        for i in 0..100 {
            let residual = if i % 2 == 0 { 0.05 } else { -0.05 };
            assert_eq!(d.observe(9, residual), QuarantineState::Healthy);
        }
        assert_eq!(d.state(9), QuarantineState::Healthy);
        assert!(!d.is_quarantined(9));
        assert!(d.quarantined().is_empty());
    }

    #[test]
    fn dip_below_threshold_resets_suspect_to_healthy() {
        let mut d = DriftDetector::new(config());
        assert_eq!(d.observe(3, 1.0), QuarantineState::Suspect);
        assert_eq!(d.observe(3, 1.0), QuarantineState::Suspect);
        // A strong opposite residual pulls the EWMA back under threshold:
        // 0.2 * (-4.0) + 0.8 * 1.0 = 0.0.
        assert_eq!(d.observe(3, -4.0), QuarantineState::Healthy);
        // The confirmation counter restarts from scratch.
        assert_eq!(d.observe(3, 5.0), QuarantineState::Suspect);
    }

    #[test]
    fn unknown_nodes_are_healthy() {
        let d = DriftDetector::new(config());
        assert_eq!(d.state(12345), QuarantineState::Healthy);
        assert!(!d.is_quarantined(12345));
    }

    #[test]
    fn reinstate_clears_only_quarantined_nodes_with_a_real_calibration() {
        let mut d = DriftDetector::new(config());
        // Node 1: quarantined.
        for _ in 0..3 {
            d.observe(1, 2.0);
        }
        // Node 2: merely suspect.
        d.observe(2, 2.0);
        assert_eq!(d.state(1), QuarantineState::Quarantined);
        assert_eq!(d.state(2), QuarantineState::Suspect);

        // calibration_id 0 is reserved for "uncalibrated": no reinstatement.
        assert!(!d.reinstate(1, 0));
        assert!(d.is_quarantined(1));
        // Suspect and unknown nodes are not cleared.
        assert!(!d.reinstate(2, 42));
        assert_eq!(d.state(2), QuarantineState::Suspect);
        assert!(!d.reinstate(999, 42));
        // A real recalibration clears the quarantined node.
        assert!(d.reinstate(1, 42));
        assert_eq!(d.state(1), QuarantineState::Healthy);
        assert!(d.quarantined().is_empty());
    }

    #[test]
    fn quarantined_list_is_sorted() {
        let mut d = DriftDetector::new(config());
        for id in [30_u64, 10, 20] {
            for _ in 0..3 {
                d.observe(id, 2.0);
            }
        }
        assert_eq!(d.quarantined(), vec![10, 20, 30]);
    }

    #[test]
    fn identical_streams_produce_identical_states() {
        let residuals: Vec<f64> = (0..40).map(|i| f64::from(i) * 0.031 - 0.3).collect();
        let mut a = DriftDetector::new(config());
        let mut b = DriftDetector::new(config());
        for r in &residuals {
            let sa = a.observe(5, *r);
            let sb = b.observe(5, *r);
            assert_eq!(sa, sb);
        }
        assert_eq!(a.state(5), b.state(5));
        assert_eq!(a.quarantined(), b.quarantined());
    }

    #[test]
    fn defaults_and_serde() {
        let c = DriftConfig::default();
        assert_eq!(c.alpha, 0.2);
        assert_eq!(c.threshold, 1.0);
        assert_eq!(c.confirm_count, 3);
        let d = DriftDetector::default();
        assert_eq!(d.config, DriftConfig::default());
        assert_eq!(
            serde_json::to_string(&QuarantineState::Quarantined).unwrap(),
            "\"quarantined\""
        );
        let back: QuarantineState = serde_json::from_str("\"suspect\"").unwrap();
        assert_eq!(back, QuarantineState::Suspect);
    }
}
