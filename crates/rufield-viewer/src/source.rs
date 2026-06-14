//! The viewer's **data source selector** and the live-ingest runtime
//! (ADR-260 §27.9 + ADR-262 P3).
//!
//! The viewer can be driven from one of two sources:
//!
//! - [`SourceMode::Synthetic`] — the default. Replays the deterministic
//!   `SyntheticSim → RuFieldFusion` pipeline. Banner: `SYNTHETIC`.
//! - [`SourceMode::Live`] — consumes **real** `rufield_core::FieldEvent`s from
//!   an external upstream (RuView's `/ws/field` / `/api/field`, ADR-262 P3),
//!   verifies each event's provenance receipt on ingest, and feeds the verified
//!   events through the *same* fusion/inference display path. Banner: `LIVE`
//!   when connected, `DISCONNECTED` when the upstream is unreachable.
//!
//! ## Banner honesty (the whole point)
//!
//! The banner state is derived **only** from what is actually being displayed:
//!
//! | mode                | reachable | banner state                  |
//! |---------------------|-----------|-------------------------------|
//! | `Synthetic`         | —         | `SYNTHETIC`                   |
//! | `Live`              | yes       | `LIVE — <upstream>`           |
//! | `Live`              | no        | `DISCONNECTED — <upstream>`   |
//!
//! Live mode **never** falls back to synthetic data: if the upstream is
//! unreachable the viewer shows an explicit `DISCONNECTED` state rather than
//! silently mislabeling simulated data as live. Synthetic mode never shows a
//! LIVE banner. The two are mutually exclusive by construction.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::broadcast;

use crate::live::{frame_from_api_payload, frame_from_ws_event, LiveFrame};

/// Default upstream poll interval (ms) when subscribing the `/api/field` ring.
pub const DEFAULT_POLL_MS: u64 = 500;

/// How the viewer sources its events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceMode {
    /// Replay the built-in deterministic synthetic simulator (default).
    Synthetic,
    /// Ingest live `FieldEvent`s from an external RuField upstream.
    Live {
        /// Base URL of the upstream, e.g. `http://127.0.0.1:8080`.
        upstream: String,
    },
}

impl SourceMode {
    /// `true` for [`SourceMode::Synthetic`].
    #[must_use]
    pub fn is_synthetic(&self) -> bool {
        matches!(self, SourceMode::Synthetic)
    }

    /// `true` for [`SourceMode::Live`].
    #[must_use]
    pub fn is_live(&self) -> bool {
        matches!(self, SourceMode::Live { .. })
    }

    /// The upstream URL, if live.
    #[must_use]
    pub fn upstream(&self) -> Option<&str> {
        match self {
            SourceMode::Synthetic => None,
            SourceMode::Live { upstream } => Some(upstream.as_str()),
        }
    }

    /// Short source code used in the wire `meta`/`/api/source` payloads.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            SourceMode::Synthetic => "synthetic",
            SourceMode::Live { .. } => "live",
        }
    }
}

/// The banner state actually displayed — derived from the source mode *and*
/// (for live) the live connection state. This is the single source of truth the
/// UI reads, so mislabeling is impossible: there is exactly one way to compute it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BannerState {
    /// `SYNTHETIC — simulated sensors, no hardware`.
    Synthetic,
    /// `LIVE — <upstream>` (real upstream events, receipt-verified).
    Live {
        /// The upstream base URL.
        upstream: String,
    },
    /// `DISCONNECTED — <upstream> unreachable` (live, but no upstream reach).
    Disconnected {
        /// The upstream base URL.
        upstream: String,
    },
}

impl BannerState {
    /// The banner label text shown verbatim in the UI.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            BannerState::Synthetic => {
                "SYNTHETIC — simulated sensors, no hardware".to_string()
            }
            BannerState::Live { upstream } => format!("LIVE — {upstream}"),
            BannerState::Disconnected { upstream } => {
                format!("DISCONNECTED — {upstream} unreachable")
            }
        }
    }
}

/// Shared, observable live-connection state. The ingest task flips `connected`;
/// the HTTP handlers read it to compute the [`BannerState`] for live mode.
#[derive(Debug)]
pub struct LiveState {
    /// The upstream this viewer is bound to.
    pub upstream: String,
    connected: AtomicBool,
}

impl LiveState {
    /// New live state for `upstream`, initially disconnected (we have not yet
    /// reached the upstream, so the honest initial banner is DISCONNECTED).
    #[must_use]
    pub fn new(upstream: impl Into<String>) -> Self {
        LiveState {
            upstream: upstream.into(),
            connected: AtomicBool::new(false),
        }
    }

    /// Whether the most recent upstream interaction succeeded.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    fn set_connected(&self, v: bool) {
        self.connected.store(v, Ordering::Relaxed);
    }

    /// Compute the banner state for this live source from current connectivity.
    #[must_use]
    pub fn banner(&self) -> BannerState {
        if self.is_connected() {
            BannerState::Live { upstream: self.upstream.clone() }
        } else {
            BannerState::Disconnected { upstream: self.upstream.clone() }
        }
    }
}

/// Compute the banner state for an arbitrary source mode. For synthetic this is
/// unconditional; for live it consults `live` (which may be `None` before the
/// ingest task has started, yielding the honest DISCONNECTED state).
#[must_use]
pub fn banner_for(mode: &SourceMode, live: Option<&LiveState>) -> BannerState {
    match mode {
        SourceMode::Synthetic => BannerState::Synthetic,
        SourceMode::Live { upstream } => match live {
            Some(state) => state.banner(),
            None => BannerState::Disconnected { upstream: upstream.clone() },
        },
    }
}

/// Spawn the background live-ingest task. It tries the `/ws/field` SSE stream
/// first (preferred — one event per cycle, push); if that cannot be opened it
/// falls back to polling `/api/field` on [`DEFAULT_POLL_MS`]. Each decoded batch
/// becomes a [`LiveFrame`] (with on-ingest receipt verification) and is
/// broadcast to all connected dashboards. Connectivity is reflected into
/// `state` so the banner can show LIVE vs DISCONNECTED honestly.
///
/// Returns the broadcast receiver factory (via the returned `Sender`).
pub fn spawn_ingest(
    state: Arc<LiveState>,
    poll_ms: u64,
) -> broadcast::Sender<LiveFrame> {
    let (tx, _rx) = broadcast::channel::<LiveFrame>(256);
    let tx_task = tx.clone();
    tokio::spawn(async move {
        ingest_loop(state, poll_ms.max(1), tx_task).await;
    });
    tx
}

/// The ingest loop: prefer `/ws/field` SSE, fall back to `/api/field` polling,
/// retrying forever with a short backoff and keeping `state.connected` honest.
async fn ingest_loop(
    state: Arc<LiveState>,
    poll_ms: u64,
    tx: broadcast::Sender<LiveFrame>,
) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    let ws_url = format!("{}/ws/field", state.upstream.trim_end_matches('/'));
    let api_url = format!("{}/api/field", state.upstream.trim_end_matches('/'));
    let mut tick: usize = 0;

    loop {
        // Prefer the push stream. If it opens, consume it until it ends/errors.
        match stream_ws(&client, &ws_url, &state, &tx, &mut tick).await {
            Ok(consumed) if consumed > 0 => {
                // Stream ended after delivering frames; loop and reconnect.
                continue;
            }
            _ => {
                // SSE not available — fall back to polling the ring once.
                if poll_api_once(&client, &api_url, &state, &tx, &mut tick).await {
                    // Connected via poll; pace before the next poll.
                } else {
                    state.set_connected(false);
                }
                tokio::time::sleep(Duration::from_millis(poll_ms)).await;
            }
        }
    }
}

/// Consume the upstream `/ws/field` SSE stream, emitting one [`LiveFrame`] per
/// `data:` line. Returns the number of frames delivered (0 if the stream could
/// not be opened, so the caller falls back to polling).
async fn stream_ws(
    client: &reqwest::Client,
    url: &str,
    state: &LiveState,
    tx: &broadcast::Sender<LiveFrame>,
    tick: &mut usize,
) -> Result<usize, ()> {
    use futures_util::StreamExt;

    let resp = match client.get(url).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return Err(()),
    };
    state.set_connected(true);

    let mut delivered = 0usize;
    let mut buf = String::new();
    let mut body = resp.bytes_stream();
    while let Some(chunk) = body.next().await {
        let bytes = match chunk {
            Ok(b) => b,
            Err(_) => break,
        };
        buf.push_str(&String::from_utf8_lossy(&bytes));
        // SSE frames are separated by a blank line; each has `data:` lines.
        while let Some(pos) = buf.find("\n\n") {
            let raw = buf[..pos].to_string();
            buf.drain(..pos + 2);
            if let Some(data) = parse_sse_data(&raw) {
                if let Ok(frame) = frame_from_ws_event(*tick, &data) {
                    *tick += 1;
                    delivered += 1;
                    let _ = tx.send(frame);
                }
            }
        }
    }
    state.set_connected(false);
    Ok(delivered)
}

/// Extract the concatenated `data:` payload from one raw SSE frame, ignoring
/// comment/`event:`/`id:` lines. Returns `None` for keep-alive/empty frames.
fn parse_sse_data(raw: &str) -> Option<String> {
    let mut data = String::new();
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest.trim_start());
        }
    }
    if data.is_empty() {
        None
    } else {
        Some(data)
    }
}

/// Poll the upstream `/api/field` ring once and broadcast the resulting frame.
/// Returns `true` if the upstream was reachable and a frame was produced.
async fn poll_api_once(
    client: &reqwest::Client,
    url: &str,
    state: &LiveState,
    tx: &broadcast::Sender<LiveFrame>,
    tick: &mut usize,
) -> bool {
    let body = match client.get(url).send().await {
        Ok(r) if r.status().is_success() => match r.text().await {
            Ok(t) => t,
            Err(_) => return false,
        },
        _ => return false,
    };
    match frame_from_api_payload(*tick, &body) {
        Ok(frame) => {
            *tick += 1;
            state.set_connected(true);
            let _ = tx.send(frame);
            true
        }
        Err(_) => {
            // Reached the upstream but its payload was malformed: that is still
            // "connected" (we got bytes) but we have nothing valid to render.
            state.set_connected(true);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_banner_is_always_synthetic() {
        let b = banner_for(&SourceMode::Synthetic, None);
        assert_eq!(b, BannerState::Synthetic);
        assert_eq!(b.label(), "SYNTHETIC — simulated sensors, no hardware");
    }

    #[test]
    fn live_disconnected_before_ingest_connects() {
        let mode = SourceMode::Live { upstream: "http://127.0.0.1:8080".into() };
        // No live state yet ⇒ honest DISCONNECTED, NOT synthetic, NOT live.
        let b = banner_for(&mode, None);
        assert!(matches!(b, BannerState::Disconnected { .. }));
        assert!(b.label().starts_with("DISCONNECTED — http://127.0.0.1:8080"));
        assert_ne!(b, BannerState::Synthetic);
    }

    #[test]
    fn live_state_flips_banner_on_connectivity() {
        let st = LiveState::new("http://127.0.0.1:8080");
        // Initial: not yet reached ⇒ DISCONNECTED.
        assert!(matches!(st.banner(), BannerState::Disconnected { .. }));
        st.set_connected(true);
        match st.banner() {
            BannerState::Live { upstream } => assert_eq!(upstream, "http://127.0.0.1:8080"),
            other => panic!("expected LIVE, got {other:?}"),
        }
        // And it can be lost again — never silently becoming synthetic.
        st.set_connected(false);
        assert!(matches!(st.banner(), BannerState::Disconnected { .. }));
    }

    #[test]
    fn source_mode_accessors() {
        let s = SourceMode::Synthetic;
        assert!(s.is_synthetic() && !s.is_live() && s.upstream().is_none());
        let l = SourceMode::Live { upstream: "http://x".into() };
        assert!(l.is_live() && !l.is_synthetic());
        assert_eq!(l.upstream(), Some("http://x"));
        assert_eq!(l.code(), "live");
    }

    #[test]
    fn sse_data_parsing() {
        assert_eq!(parse_sse_data("event: field\ndata: {\"a\":1}"), Some("{\"a\":1}".to_string()));
        assert_eq!(
            parse_sse_data("data: line1\ndata: line2"),
            Some("line1\nline2".to_string())
        );
        assert_eq!(parse_sse_data(": keep-alive comment"), None);
        assert_eq!(parse_sse_data(""), None);
    }
}
