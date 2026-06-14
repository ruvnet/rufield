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
use tokio::sync::broadcast;
use tokio_stream::StreamExt;

use crate::live::LiveFrame;
use crate::runtime::{build_run, RunData};
use crate::source::{
    banner_for, spawn_ingest, BannerState, LiveState, SourceMode, DEFAULT_POLL_MS,
};

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
    /// Demo seed (determinism anchor) — synthetic mode only.
    pub seed: u64,
    /// Per-tick stream cadence in ms — synthetic mode only.
    pub tick_ms: u64,
    /// Whether the SSE stream loops when it reaches the end — synthetic only.
    pub loop_stream: bool,
    /// Where the viewer sources its events (synthetic vs live upstream).
    pub source: SourceMode,
    /// Upstream poll interval (ms) for the `/api/field` fallback — live only.
    pub poll_ms: u64,
}

impl Default for ViewerConfig {
    fn default() -> Self {
        ViewerConfig {
            seed: DEFAULT_SEED,
            tick_ms: DEFAULT_TICK_MS,
            loop_stream: true,
            // Default stays SYNTHETIC — never live by default.
            source: SourceMode::Synthetic,
            poll_ms: DEFAULT_POLL_MS,
        }
    }
}

/// Runtime state shared by all handlers: the config plus, in live mode, the
/// observable live-connection state and the broadcast channel of ingested
/// [`LiveFrame`]s. In synthetic mode `live`/`live_tx` are `None`.
pub struct AppState {
    /// Immutable server configuration.
    pub config: ViewerConfig,
    /// Live connection state (banner truth), present only in live mode.
    pub live: Option<Arc<LiveState>>,
    /// Broadcast of ingested live frames, present only in live mode.
    pub live_tx: Option<broadcast::Sender<LiveFrame>>,
}

impl AppState {
    /// The banner state actually displayed — derived solely from the source
    /// mode and (for live) the live connection state. Single source of truth.
    fn banner(&self) -> BannerState {
        banner_for(&self.config.source, self.live.as_deref())
    }
}

/// Build the Axum router for the dashboard.
///
/// In [`SourceMode::Live`] this also spawns the background ingest task (it must
/// therefore be called from within a Tokio runtime, which the binary and the
/// `#[tokio::test]` harness both provide).
pub fn app(config: ViewerConfig) -> Router {
    let (live, live_tx) = match &config.source {
        SourceMode::Synthetic => (None, None),
        SourceMode::Live { upstream } => {
            let state = Arc::new(LiveState::new(upstream.clone()));
            let tx = spawn_ingest(state.clone(), config.poll_ms);
            (Some(state), Some(tx))
        }
    };
    let state = Arc::new(AppState { config, live, live_tx });
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/health", get(health))
        .route("/api/source", get(api_source))
        .route("/api/run", get(api_run))
        .route("/events", get(events))
        .with_state(state)
}

/// Build the router **without** spawning any background task. Used by the
/// live-mode tests so they can assert config/banner state synchronously without
/// requiring a reachable upstream.
pub fn app_no_ingest(config: ViewerConfig) -> Router {
    let live = match &config.source {
        SourceMode::Synthetic => None,
        SourceMode::Live { upstream } => Some(Arc::new(LiveState::new(upstream.clone()))),
    };
    let state = Arc::new(AppState { config, live, live_tx: None });
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/health", get(health))
        .route("/api/source", get(api_source))
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

async fn health(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let banner = st.banner();
    Json(serde_json::json!({
        "status": "ok",
        "spec_version": rufield_core::SPEC_VERSION,
        // `synthetic` is true ONLY when actually serving synthetic data.
        "synthetic": st.config.source.is_synthetic(),
        "source": st.config.source.code(),
        "upstream": st.config.source.upstream(),
        "banner": banner,
        "banner_label": banner.label(),
        "seed": st.config.seed,
        "tick_ms": st.config.tick_ms,
    }))
}

/// `GET /api/source` — the data-source selector + banner state. The dashboard
/// reads this once on load to render the correct (SYNTHETIC / LIVE /
/// DISCONNECTED) banner; it is the single source of truth for banner honesty.
async fn api_source(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let banner = st.banner();
    Json(serde_json::json!({
        "source": st.config.source.code(),
        "upstream": st.config.source.upstream(),
        "synthetic": st.config.source.is_synthetic(),
        "banner": banner,
        "banner_label": banner.label(),
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
    State(st): State<Arc<AppState>>,
    Query(params): Query<RunParams>,
) -> axum::response::Response {
    // `/api/run` is the deterministic synthetic run — meaningless in live mode,
    // where there is no fixed seed and events arrive from an upstream. Return an
    // honest note rather than fabricating a synthetic run under a live viewer.
    if st.config.source.is_live() {
        return (
            axum::http::StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "not_available_in_live_mode",
                "source": "live",
                "upstream": st.config.source.upstream(),
                "hint": "use GET /events for the live FieldEvent stream",
            })),
        )
            .into_response();
    }
    let seed = params.seed.unwrap_or(st.config.seed);
    Json(build_run(seed)).into_response()
}

/// Stream tick frames as SSE events.
///
/// - **Synthetic** mode: replay the deterministic synthetic run, paced at
///   `tick_ms`, emitting `meta` → `frame`* → `done` (looping unless `--no-loop`).
/// - **Live** mode: emit a `meta` frame announcing the LIVE/DISCONNECTED banner,
///   then forward each ingested upstream [`LiveFrame`] as a `frame` event as it
///   arrives. There is no `done` (a live feed does not end).
async fn events(
    State(st): State<Arc<AppState>>,
    Query(params): Query<RunParams>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    match (&st.config.source, st.live_tx.clone()) {
        (SourceMode::Live { .. }, Some(tx)) => {
            let stream: std::pin::Pin<
                Box<dyn tokio_stream::Stream<Item = Result<Event, Infallible>> + Send>,
            > = Box::pin(live_event_stream(st.clone(), tx));
            Sse::new(stream).keep_alive(KeepAlive::default())
        }
        _ => {
            let seed = params.seed.unwrap_or(st.config.seed);
            let tick_ms = params.tick_ms.unwrap_or(st.config.tick_ms).max(1);
            let loop_stream = st.config.loop_stream;

            // Build the full run once; replay its frames at a watchable cadence.
            let run = build_run(seed);
            let payloads = render_payloads(&run);

            let throttle = Duration::from_millis(tick_ms);
            let stream: std::pin::Pin<
                Box<dyn tokio_stream::Stream<Item = Result<Event, Infallible>> + Send>,
            > = Box::pin(payload_stream(payloads, loop_stream).throttle(throttle));
            Sse::new(stream).keep_alive(KeepAlive::default())
        }
    }
}

/// The live SSE stream: a leading `meta` event (carrying the honest banner +
/// source), then one `frame` per ingested [`LiveFrame`] forwarded from the
/// broadcast channel. Lagged frames (a slow client) are skipped, not fatal.
fn live_event_stream(
    st: Arc<AppState>,
    tx: broadcast::Sender<LiveFrame>,
) -> impl tokio_stream::Stream<Item = Result<Event, Infallible>> {
    use tokio_stream::wrappers::BroadcastStream;

    let banner = st.banner();
    let meta = serde_json::json!({
        "source": "live",
        "upstream": st.config.source.upstream(),
        "synthetic": false,
        "banner": banner,
        "banner_label": banner.label(),
        "spec_version": rufield_core::SPEC_VERSION,
    });
    let meta_stream =
        tokio_stream::iter(vec![Ok(Event::default().event("meta").data(meta.to_string()))]);

    let frames = BroadcastStream::new(tx.subscribe()).filter_map(|res| match res {
        Ok(frame) => {
            let data = serde_json::to_string(&frame).unwrap_or_default();
            Some(Ok(Event::default().event("frame").data(data)))
        }
        // Lagged (slow client) — skip, do not terminate the stream.
        Err(_) => None,
    });

    meta_stream.chain(frames)
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
