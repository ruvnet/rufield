//! # rucelium-worldgraph
//!
//! The RuCelium environmental **WorldGraph** (ADR-264 §5.2) and the RuView
//! RF-context bridge (ADR-264 §8).
//!
//! The WorldGraph extends the ADR-139 concept — typed nodes, geospatial
//! registration, typed evidence edges, contradiction tracking — with the
//! environmental node kinds of the fabric: sensors, ecosystems, regions, and
//! calibration anchors. Every accepted observation must be mappable into the
//! graph (ADR-264 §14 acceptance criterion 6); [`WorldGraph::register_observation`]
//! guarantees that by auto-registering a sensor node for any accepted
//! [`rucelium_core::EnvSample`].
//!
//! The [`rf`] module bridges RuField MFS [`rufield_core::FieldEvent`]s
//! (WiFi-CSI RF observations) into the graph under the §8 normative rule:
//!
//! > RuView outputs are supporting evidence. They may raise or lower
//! > confidence and create contradiction edges. They may **never** be the
//! > sole basis for an event above `Advisory` severity, and they are never
//! > ground truth.

#![doc(html_root_url = "https://docs.rs/rucelium-worldgraph/0.1.0")]

pub mod graph;
pub mod rf;

pub use graph::{haversine_m, Edge, EdgeKind, GraphError, GraphNode, WorldGraph};
pub use rf::{
    assess_plausibility, fuse_rf_context, rf_only_severity_cap, Plausibility, RfContext,
    RF_MAX_EVIDENCE_WEIGHT,
};
