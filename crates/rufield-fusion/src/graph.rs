//! Fusion graph (ADR-260 §12). A lightweight typed node/edge store recording
//! which events were observed, which derived into features, and which fused
//! into inferences. v0.1 uses it for provenance tracking + introspection.

use std::collections::BTreeMap;

/// Node kinds (ADR-260 §12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeKind {
    /// A physical sensor.
    Sensor,
    /// A field event.
    Event,
    /// A field tensor.
    FieldTensor,
    /// A derived feature.
    Feature,
    /// A detected object.
    Object,
    /// A spatial zone.
    Zone,
    /// A room state.
    State,
    /// A fused inference.
    Inference,
    /// A provenance receipt.
    Receipt,
}

/// Edge kinds (ADR-260 §12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    /// event observed_by sensor.
    ObservedBy,
    /// feature derived_from event.
    DerivedFrom,
    /// event calibrated_by receipt.
    CalibratedBy,
    /// event supports inference.
    Supports,
    /// event contradicts inference.
    Contradicts,
    /// event fused_into inference.
    FusedInto,
    /// inference expires_at time.
    ExpiresAt,
    /// inference requires_consent.
    RequiresConsent,
}

/// A node with a stable string id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Stable id.
    pub id: String,
    /// Node kind.
    pub kind: NodeKind,
}

/// A directed typed edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    /// Source node id.
    pub from: String,
    /// Destination node id.
    pub to: String,
    /// Edge kind.
    pub kind: EdgeKind,
}

/// The fusion graph.
#[derive(Debug, Clone, Default)]
pub struct FusionGraph {
    nodes: BTreeMap<String, Node>,
    edges: Vec<Edge>,
}

impl FusionGraph {
    /// Empty graph.
    #[must_use]
    pub fn new() -> Self {
        FusionGraph::default()
    }

    /// Insert (or replace) a node.
    pub fn add_node(&mut self, id: impl Into<String>, kind: NodeKind) {
        let id = id.into();
        self.nodes.insert(id.clone(), Node { id, kind });
    }

    /// Add a directed edge (idempotent on exact duplicates).
    pub fn add_edge(&mut self, from: impl Into<String>, to: impl Into<String>, kind: EdgeKind) {
        let e = Edge {
            from: from.into(),
            to: to.into(),
            kind,
        };
        if !self.edges.contains(&e) {
            self.edges.push(e);
        }
    }

    /// Node count.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Edge count.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Count nodes of a kind.
    #[must_use]
    pub fn count_kind(&self, kind: NodeKind) -> usize {
        self.nodes.values().filter(|n| n.kind == kind).count()
    }

    /// Edges of a given kind.
    #[must_use]
    pub fn edges_of(&self, kind: EdgeKind) -> Vec<&Edge> {
        self.edges.iter().filter(|e| e.kind == kind).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_records_nodes_and_edges() {
        let mut g = FusionGraph::new();
        g.add_node("sensor_1", NodeKind::Sensor);
        g.add_node("ev_1", NodeKind::Event);
        g.add_node("inf_1", NodeKind::Inference);
        g.add_edge("ev_1", "sensor_1", EdgeKind::ObservedBy);
        g.add_edge("ev_1", "inf_1", EdgeKind::FusedInto);
        assert_eq!(g.node_count(), 3);
        assert_eq!(g.edge_count(), 2);
        assert_eq!(g.count_kind(NodeKind::Event), 1);
        assert_eq!(g.edges_of(EdgeKind::FusedInto).len(), 1);
    }

    #[test]
    fn duplicate_edges_deduped() {
        let mut g = FusionGraph::new();
        g.add_edge("a", "b", EdgeKind::Supports);
        g.add_edge("a", "b", EdgeKind::Supports);
        assert_eq!(g.edge_count(), 1);
    }
}
