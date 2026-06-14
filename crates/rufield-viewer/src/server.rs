//! The Axum web server (ADR-260 §14 Layer 7). Read-only: it drives the
//! deterministic synthetic pipeline and serves it to a single-page dashboard.
//!
//! Routes:
//! - `GET /`          → the dashboard HTML page.
//! - `GET /app.js`    → the vanilla-JS dashboard logic.
//! - `GET /health`    → `{"status":"ok",...}` liveness.
//! - `GET /api/run`   → the full deterministic run as JSON (non-streaming).
//! - `GET /events`    → Server-Sent Events: each tick frame, paced for viewing.
//!
//! There is **no hardware** and **no live sensor**: everything streamed here is
//! the `SyntheticSim` demo replayed at a watchable cadence.

use axum::{
    extract::{Query, State},
    response::{
        sse::{Event, KeepAlive, Sse},
        Html, IntoResponse,
    },
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::StreamExt;

use crate::runtime::{build_run, RunData};

/// Static dashboard HTML (no build step, no npm).
const INDEX_HTML: &str = include_str!("../static/index.html");
/// Static dashboard JS (vanilla, no framework).
const APP_JS: &str = include_str!("../static/app.js");

/// Default demo seed (matches the ADR-260 §31 acceptance seed).
pub const DEFAULT_SEED: u64 = 2026;
/// Default per-tick stream cadence in milliseconds.
pub const DEFAULT_TICK_MS: u64 = 300;

/// Shared, immutable server configuration.
#[derive(Debug, Clone)]
pub struct ViewerConfig {
    /// Demo seed (determinism anchor).
    pub seed: u64,
    /// Per-tick stream cadence in ms.
    pub tick_ms: u64,
    /// Whether the SSE stream loops when it reaches the end.
    pub loop_stream: bool,
}

impl Default for ViewerConfig {
    fn default() -> Self {
        ViewerConfig {
            seed: DEFAULT_SEED,
            tick_ms: DEFAULT_TICK_MS,
            loop_stream: true,
        }
    }
}

/// Build the Axum router for the dashboard.
pub fn app(config: ViewerConfig) -> Router {
    let state = Arc::new(config);
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/health", get(health))
        .route("/api/run", get(api_run))
        .route("/events", get(events))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn app_js() -> impl IntoResponse {
    ([(axum::http::header::CONTENT_TYPE, "application/javascript")], APP_JS)
}

async fn health(State(cfg): State<Arc<ViewerConfig>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "spec_version": rufield_core::SPEC_VERSION,
        "synthetic": true,
        "seed": cfg.seed,
        "tick_ms": cfg.tick_ms,
    }))
}

/// Query parameters accepted by `/api/run` and `/events`.
#[derive(Debug, Deserialize)]
pub struct RunParams {
    /// Override the demo seed.
    pub seed: Option<u64>,
    /// Override the per-tick cadence (ms), for `/events` only.
    pub tick_ms: Option<u64>,
}

async fn api_run(
    State(cfg): State<Arc<ViewerConfig>>,
    Query(params): Query<RunParams>,
) -> Json<RunData> {
    let seed = params.seed.unwrap_or(cfg.seed);
    Json(build_run(seed))
}

/// Stream each tick frame as an SSE event, paced at `tick_ms`. On completion,
/// emits a terminal `done` event; if `loop_stream` is set, it restarts.
async fn events(
    State(cfg): State<Arc<ViewerConfig>>,
    Query(params): Query<RunParams>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let seed = params.seed.unwrap_or(cfg.seed);
    let tick_ms = params.tick_ms.unwrap_or(cfg.tick_ms).max(1);
    let loop_stream = cfg.loop_stream;

    // Build the full run once; replay its frames at a watchable cadence. The
    // frame order is fully deterministic for a fixed seed. SSE payloads are
    // pre-rendered as `(event_name, data_json)` pairs so they can be cheaply
    // re-emitted (axum's `Event` is not `Clone`).
    let run = build_run(seed);
    let payloads = render_payloads(&run);

    let throttle = Duration::from_millis(tick_ms);
    let stream: std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<Event, Infallible>> + Send>,
    > = if loop_stream {
        Box::pin(payload_stream(payloads, true).throttle(throttle))
    } else {
        Box::pin(payload_stream(payloads, false).throttle(throttle))
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// A pre-rendered SSE payload: the event name and its JSON `data`.
#[derive(Clone)]
struct Payload {
    name: &'static str,
    data: String,
}

impl Payload {
    fn to_event(&self) -> Event {
        Event::default().event(self.name).data(self.data.clone())
    }
}

/// Render the full SSE sequence: `meta` → one `frame` per tick → `done`.
fn render_payloads(run: &RunData) -> Vec<Payload> {
    let mut out = Vec::with_capacity(run.frames.len() + 2);
    let meta = serde_json::json!({
        "spec_version": run.spec_version,
        "synthetic": run.synthetic,
        "seed": run.seed,
        "events_total": run.events_total,
        "modalities": run.modalities,
        "distinct_inferences": run.distinct_inferences,
        "privacy_violations": run.privacy_violations,
        "provenance_coverage_pct": run.provenance_coverage_pct,
        "total_frames": run.frames.len(),
    });
    out.push(Payload { name: "meta", data: meta.to_string() });
    for f in &run.frames {
        out.push(Payload {
            name: "frame",
            data: serde_json::to_string(f).unwrap_or_default(),
        });
    }
    out.push(Payload { name: "done", data: "{}".to_string() });
    out
}

/// Turn pre-rendered payloads into an SSE stream. When `repeat` is true the
/// sequence loops indefinitely; otherwise it ends after `done`.
fn payload_stream(
    payloads: Vec<Payload>,
    repeat: bool,
) -> impl tokio_stream::Stream<Item = Result<Event, Infallible>> {
    PayloadStream { payloads, idx: 0, repeat }
}

struct PayloadStream {
    payloads: Vec<Payload>,
    idx: usize,
    repeat: bool,
}

impl tokio_stream::Stream for PayloadStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        if self.payloads.is_empty() {
            return std::task::Poll::Ready(None);
        }
        if self.idx >= self.payloads.len() {
            if self.repeat {
                self.idx = 0;
            } else {
                return std::task::Poll::Ready(None);
            }
        }
        let ev = self.payloads[self.idx].to_event();
        self.idx += 1;
        std::task::Poll::Ready(Some(Ok(ev)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_are_sane() {
        let c = ViewerConfig::default();
        assert_eq!(c.seed, 2026);
        assert!(c.tick_ms >= 1);
        assert!(c.loop_stream);
    }
}
