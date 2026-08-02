//! The environmental WorldGraph (ADR-264 §5.2): typed nodes, geospatial
//! registration, typed evidence edges, contradiction tracking, and JSON
//! persistence (ADR-139 heritage).

use rucelium_core::{EnvSample, GeoPoint, SensorModality};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Mean Earth radius in metres, used by [`haversine_m`].
pub const EARTH_RADIUS_M: f64 = 6_371_000.0;

/// Errors from WorldGraph operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    /// An edge endpoint referenced a node key that does not exist.
    UnknownNode(String),
    /// JSON persistence (serialize / deserialize) failed.
    Persist(String),
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GraphError::UnknownNode(key) => write!(f, "unknown graph node: {key}"),
            GraphError::Persist(msg) => write!(f, "worldgraph persistence error: {msg}"),
        }
    }
}

impl std::error::Error for GraphError {}

/// A typed WorldGraph node (ADR-264 §5.2). Extends the ADR-139 node set with
/// the environmental kinds of the fabric.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphNode {
    /// A physical (or RF-context) sensor registered in the graph.
    Sensor {
        /// Producing device identity (0 for string-identified RF devices).
        node_id: u64,
        /// Sensor modality.
        modality: SensorModality,
        /// Geospatial registration of the sensor.
        geo: GeoPoint,
        /// Placement hint (e.g. `riverbank_post`, `auto_registered`).
        placement: String,
    },
    /// A named ecosystem feature (a wetland, a stand of oaks, a river reach).
    Ecosystem {
        /// Human-readable name.
        name: String,
        /// Ecosystem kind (e.g. `wetland`, `forest_stand`).
        kind: String,
        /// Geospatial registration.
        geo: GeoPoint,
    },
    /// A biome-scale region grouping sensors and ecosystems.
    Region {
        /// Owning biome id (e.g. `biome/thames-estuary`).
        biome_id: String,
        /// Human-readable region name.
        name: String,
    },
    /// A reference-grade calibration anchor station (ADR-264 §12).
    Anchor {
        /// Anchor station identifier.
        station_id: String,
        /// Modality the anchor references.
        modality: SensorModality,
        /// Geospatial registration.
        geo: GeoPoint,
    },
}

/// Typed edge kinds between WorldGraph nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Evidence from `from` supports the state of `to`.
    Supports,
    /// Evidence from `from` contradicts the state of `to` (tracked, never
    /// silently resolved).
    Contradicts,
    /// The two nodes are physically co-located.
    Colocated,
    /// `from` lies within region `to`.
    WithinRegion,
    /// `from` was derived from `to`.
    DerivedFrom,
}

/// A directed, typed, weighted evidence edge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    /// Source node key.
    pub from: String,
    /// Destination node key.
    pub to: String,
    /// Edge kind.
    pub kind: EdgeKind,
    /// Evidence weight, clamped to `0.0..=1.0`.
    pub weight: f32,
    /// Free-text annotation (e.g. a contradiction reason).
    pub note: String,
}

/// The environmental WorldGraph: typed nodes keyed by stable string keys,
/// adjacency-listed typed edges, and a contradiction counter.
///
/// All maps are [`BTreeMap`]s so iteration (and therefore serialization and
/// every derived listing) is deterministic.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WorldGraph {
    /// Nodes by stable string key (e.g. `sensor/7`, `region/thames`).
    nodes: BTreeMap<String, GraphNode>,
    /// Outgoing edges by source node key.
    edges: BTreeMap<String, Vec<Edge>>,
    /// Number of contradictions recorded since the graph was created.
    contradiction_count: u64,
}

impl WorldGraph {
    /// Empty graph.
    #[must_use]
    pub fn new() -> Self {
        WorldGraph::default()
    }

    /// Insert a node under `key`. Returns `false` (without overwriting) if a
    /// node already exists under that key — registered topology is never
    /// silently replaced.
    pub fn add_node(&mut self, key: impl Into<String>, node: GraphNode) -> bool {
        let key = key.into();
        if self.nodes.contains_key(&key) {
            return false;
        }
        self.nodes.insert(key, node);
        true
    }

    /// Look up a node by key.
    #[must_use]
    pub fn node(&self, key: &str) -> Option<&GraphNode> {
        self.nodes.get(key)
    }

    /// Number of nodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// True if the graph has no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Add a directed typed edge. Both endpoints must already exist;
    /// `weight` is clamped to `0.0..=1.0` (non-finite weights clamp to 0).
    pub fn add_edge(
        &mut self,
        from: &str,
        to: &str,
        kind: EdgeKind,
        weight: f32,
        note: impl Into<String>,
    ) -> Result<(), GraphError> {
        if !self.nodes.contains_key(from) {
            return Err(GraphError::UnknownNode(from.to_string()));
        }
        if !self.nodes.contains_key(to) {
            return Err(GraphError::UnknownNode(to.to_string()));
        }
        let weight = if weight.is_finite() {
            weight.clamp(0.0, 1.0)
        } else {
            0.0
        };
        self.edges.entry(from.to_string()).or_default().push(Edge {
            from: from.to_string(),
            to: to.to_string(),
            kind,
            weight,
            note: note.into(),
        });
        Ok(())
    }

    /// Outgoing edges of a node (empty slice for unknown keys).
    #[must_use]
    pub fn edges_from(&self, key: &str) -> &[Edge] {
        self.edges.get(key).map_or(&[], Vec::as_slice)
    }

    /// All edges, in deterministic (source-key, insertion) order.
    pub fn edges(&self) -> impl Iterator<Item = &Edge> {
        self.edges.values().flatten()
    }

    /// Register an accepted observation into the graph, ensuring a `Sensor`
    /// node exists at key `sensor/{node_id}` (created from the sample's
    /// modality and geo with placement `"auto_registered"` if absent), and
    /// return that key.
    ///
    /// This is what makes every accepted observation mappable into the graph
    /// (ADR-264 §14 acceptance criterion 6) — registration is idempotent and
    /// never overwrites an existing sensor node.
    pub fn register_observation(&mut self, sample: &EnvSample) -> String {
        let key = format!("sensor/{}", sample.node_id);
        if !self.nodes.contains_key(&key) {
            self.nodes.insert(
                key.clone(),
                GraphNode::Sensor {
                    node_id: sample.node_id,
                    modality: sample.modality,
                    geo: sample.geo,
                    placement: "auto_registered".to_string(),
                },
            );
        }
        key
    }

    /// Record a contradiction between two nodes: adds a `Contradicts` edge
    /// (weight 1.0) annotated with `reason` and increments the contradiction
    /// counter. Contradictions are tracked, never silently resolved.
    pub fn record_contradiction(
        &mut self,
        a_key: &str,
        b_key: &str,
        reason: impl Into<String>,
    ) -> Result<(), GraphError> {
        self.add_edge(a_key, b_key, EdgeKind::Contradicts, 1.0, reason)?;
        self.contradiction_count += 1;
        Ok(())
    }

    /// All `Contradicts` edges, in deterministic order.
    #[must_use]
    pub fn contradictions(&self) -> Vec<&Edge> {
        self.edges()
            .filter(|e| e.kind == EdgeKind::Contradicts)
            .collect()
    }

    /// Number of contradictions recorded via [`WorldGraph::record_contradiction`]
    /// (and the RF bridge's contradiction path) since the graph was created.
    #[must_use]
    pub fn contradiction_count(&self) -> u64 {
        self.contradiction_count
    }

    /// All `Sensor` nodes within `radius_m` metres of `center` (haversine
    /// great-circle distance), as `(node key, node_id)` pairs sorted by key
    /// for determinism.
    #[must_use]
    pub fn sensors_within_m(&self, center: GeoPoint, radius_m: f64) -> Vec<(String, u64)> {
        // BTreeMap iteration is already key-sorted, so the result is too.
        self.nodes
            .iter()
            .filter_map(|(key, node)| match node {
                GraphNode::Sensor { node_id, geo, .. } if haversine_m(center, *geo) <= radius_m => {
                    Some((key.clone(), *node_id))
                }
                _ => None,
            })
            .collect()
    }

    /// Convenience: link a sensor into a region with a `WithinRegion` edge
    /// (weight 1.0). Both nodes must already exist.
    pub fn link_within_region(
        &mut self,
        sensor_key: &str,
        region_key: &str,
    ) -> Result<(), GraphError> {
        self.add_edge(sensor_key, region_key, EdgeKind::WithinRegion, 1.0, "")
    }

    /// Serialize the full graph (persisted topology, ADR-139 heritage) to
    /// JSON. Deterministic: `BTreeMap`s serialize in key order.
    #[must_use]
    pub fn to_json(&self) -> String {
        // Serialization of this type cannot fail: all map keys are strings
        // and all floats are finite by construction (weights are clamped).
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Restore a graph from its [`WorldGraph::to_json`] form.
    pub fn from_json(json: &str) -> Result<WorldGraph, GraphError> {
        serde_json::from_str(json).map_err(|e| GraphError::Persist(e.to_string()))
    }
}

/// Great-circle (haversine) distance between two points in metres, using a
/// mean Earth radius of [`EARTH_RADIUS_M`] (6 371 000 m). Altitude is ignored.
#[must_use]
pub fn haversine_m(a: GeoPoint, b: GeoPoint) -> f64 {
    let lat_a = a.latitude_deg().to_radians();
    let lat_b = b.latitude_deg().to_radians();
    let d_lat = (b.latitude_deg() - a.latitude_deg()).to_radians();
    let d_lon = (b.longitude_deg() - a.longitude_deg()).to_radians();
    let h = (d_lat / 2.0).sin().powi(2) + lat_a.cos() * lat_b.cos() * (d_lon / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS_M * h.sqrt().min(1.0).asin()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rucelium_core::{SampleProvenance, Uncertainty};

    pub(crate) fn sample(node_id: u64) -> EnvSample {
        EnvSample {
            node_id,
            sequence: 1,
            measured_ns: 1_000,
            received_ns: 2_000,
            geo: GeoPoint::new(514_778_216, -14_767, 46_000).unwrap(),
            modality: SensorModality::Weather,
            observed_property: "air_temperature".into(),
            unit: "Cel".into(),
            value: 21.5,
            quality: 0.98,
            uncertainty: Uncertainty::symmetric(21.5, 0.3),
            calibration_id: 3,
            flags: 0,
            battery_mv: 3600,
            provenance: SampleProvenance {
                firmware_hash: "sha256:abc".into(),
                signer_pubkey_hex: "00ff".into(),
                verified: true,
                lineage: vec!["cal:3".into()],
            },
        }
    }

    fn region() -> GraphNode {
        GraphNode::Region {
            biome_id: "biome/thames-estuary".into(),
            name: "Thames Estuary".into(),
        }
    }

    #[test]
    fn register_observation_is_idempotent_with_stable_key() {
        let mut g = WorldGraph::new();
        let s = sample(7);
        let key = g.register_observation(&s);
        assert_eq!(key, "sensor/7");
        assert_eq!(g.len(), 1);

        // Re-registering the same node is idempotent and never overwrites.
        let key2 = g.register_observation(&s);
        assert_eq!(key2, "sensor/7");
        assert_eq!(g.len(), 1);
        match g.node("sensor/7").unwrap() {
            GraphNode::Sensor {
                node_id, placement, ..
            } => {
                assert_eq!(*node_id, 7);
                assert_eq!(placement, "auto_registered");
            }
            other => panic!("expected sensor node, got {other:?}"),
        }
    }

    #[test]
    fn add_node_refuses_overwrite() {
        let mut g = WorldGraph::new();
        assert!(g.add_node("region/thames", region()));
        assert!(!g.add_node("region/thames", region()));
        assert_eq!(g.len(), 1);
        assert!(!g.is_empty());
    }

    #[test]
    fn add_edge_unknown_node_fails_and_weights_clamp() {
        let mut g = WorldGraph::new();
        g.register_observation(&sample(1));
        g.add_node("region/thames", region());

        assert_eq!(
            g.add_edge("sensor/1", "region/nowhere", EdgeKind::Supports, 0.5, ""),
            Err(GraphError::UnknownNode("region/nowhere".into()))
        );
        assert_eq!(
            g.add_edge("sensor/99", "region/thames", EdgeKind::Supports, 0.5, ""),
            Err(GraphError::UnknownNode("sensor/99".into()))
        );

        g.add_edge("sensor/1", "region/thames", EdgeKind::Supports, 3.5, "hi")
            .unwrap();
        g.add_edge("sensor/1", "region/thames", EdgeKind::Supports, -1.0, "lo")
            .unwrap();
        let weights: Vec<f32> = g.edges_from("sensor/1").iter().map(|e| e.weight).collect();
        assert_eq!(weights, vec![1.0, 0.0]);
        assert_eq!(g.edges().count(), 2);
        assert!(g.edges_from("sensor/none").is_empty());
    }

    #[test]
    fn haversine_one_degree_latitude() {
        let a = GeoPoint::new(0, 0, 0).unwrap();
        let b = GeoPoint::new(10_000_000, 0, 0).unwrap(); // +1 degree latitude
        let d = haversine_m(a, b);
        let expected = 111_190.0;
        assert!(
            (d - expected).abs() / expected < 0.01,
            "expected ~{expected} m, got {d} m"
        );
        // Symmetric and zero at identity.
        assert!((haversine_m(b, a) - d).abs() < 1e-6);
        assert_eq!(haversine_m(a, a), 0.0);
    }

    #[test]
    fn sensors_within_m_filters_and_sorts() {
        let mut g = WorldGraph::new();
        let center = GeoPoint::new(514_778_216, -14_767, 0).unwrap();

        let mut near_1 = sample(3);
        near_1.geo = center;
        let mut near_2 = sample(1);
        near_2.geo = GeoPoint::new(514_779_000, -14_000, 0).unwrap(); // ~ 10s of m
        let mut far = sample(2);
        far.geo = GeoPoint::new(524_778_216, -14_767, 0).unwrap(); // ~111 km north

        g.register_observation(&near_1);
        g.register_observation(&near_2);
        g.register_observation(&far);
        // Non-sensor nodes are never returned.
        g.add_node("region/thames", region());

        let hits = g.sensors_within_m(center, 500.0);
        assert_eq!(
            hits,
            vec![("sensor/1".to_string(), 1), ("sensor/3".to_string(), 3)]
        );
    }

    #[test]
    fn contradiction_tracking() {
        let mut g = WorldGraph::new();
        g.register_observation(&sample(1));
        g.register_observation(&sample(2));
        assert!(g.contradictions().is_empty());
        assert_eq!(g.contradiction_count(), 0);

        g.record_contradiction("sensor/1", "sensor/2", "disagreeing water level")
            .unwrap();
        let c = g.contradictions();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].kind, EdgeKind::Contradicts);
        assert_eq!(c[0].weight, 1.0);
        assert_eq!(c[0].note, "disagreeing water level");
        assert_eq!(g.contradiction_count(), 1);

        assert_eq!(
            g.record_contradiction("sensor/1", "sensor/9", "x"),
            Err(GraphError::UnknownNode("sensor/9".into()))
        );
        assert_eq!(g.contradiction_count(), 1);
    }

    #[test]
    fn json_round_trip() {
        let mut g = WorldGraph::new();
        g.register_observation(&sample(1));
        g.register_observation(&sample(2));
        g.add_node("region/thames", region());
        g.add_node(
            "anchor/met-01",
            GraphNode::Anchor {
                station_id: "met-01".into(),
                modality: SensorModality::Weather,
                geo: GeoPoint::new(514_000_000, 0, 0).unwrap(),
            },
        );
        g.add_node(
            "eco/reedbed",
            GraphNode::Ecosystem {
                name: "North Reedbed".into(),
                kind: "wetland".into(),
                geo: GeoPoint::new(514_500_000, 100_000, 0).unwrap(),
            },
        );
        g.link_within_region("sensor/1", "region/thames").unwrap();
        g.add_edge("sensor/1", "eco/reedbed", EdgeKind::Colocated, 0.9, "")
            .unwrap();
        g.record_contradiction("sensor/1", "sensor/2", "drift")
            .unwrap();

        let json = g.to_json();
        let back = WorldGraph::from_json(&json).unwrap();
        assert_eq!(g, back);
        assert_eq!(back.contradiction_count(), 1);

        assert!(matches!(
            WorldGraph::from_json("not json"),
            Err(GraphError::Persist(_))
        ));
    }
}
