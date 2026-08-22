//! # rufield-viewer
//!
//! A lightweight, **read-only** web dashboard for the RuField MFS v0.1
//! reference stack (ADR-260 §14 Layer 7, §27.9). It runs the deterministic
//! `SyntheticSim` → `RuFieldFusion` pipeline and streams it to a single-page
//! dashboard (vanilla HTML + CSS + JS, no build step, no npm) so you can
//! *watch* the §19 camera-free room-intelligence demo:
//!
//! enter → sit → breathe → sleep → scratch → bed-exit → leave.
//!
//! ## Honesty (non-negotiable)
//!
//! Synthetic mode is the default and is always visibly labeled. Live mode is
//! fail closed: it requires an independently injected sensor-key registry and
//! a production or captured-replay trust policy before its ingest task starts.
//! Live mode never falls back to simulation.
//!
//! ## What it serves
//!
//! - `GET /`         — the dashboard page.
//! - `GET /app.js`   — the vanilla-JS dashboard logic.
//! - `GET /health`   — liveness JSON.
//! - `GET /api/run`  — the full deterministic run as JSON (non-streaming).
//! - `GET /events`   — Server-Sent Events. Synthetic frames retain demo
//!   receipts. Live frames are a privacy-guarded public projection with stable
//!   trust diagnostics and no upstream direct identifiers or receipt material.
//!
//! ## Run it
//!
//! ```no_run
//! # async fn run() {
//! use rufield_viewer::{app, ViewerConfig};
//! let router = app(ViewerConfig::default()).unwrap();
//! let listener = tokio::net::TcpListener::bind("127.0.0.1:8088").await.unwrap();
//! axum::serve(listener, router).await.unwrap();
//! # }
//! ```

#![doc(html_root_url = "https://docs.rs/rufield-viewer/0.1.0")]

pub mod live;
pub mod runtime;
pub mod server;
pub mod source;

pub use live::{
    frame_from_api_payload, frame_from_events, frame_from_ws_event, ApiFieldPayload,
    LiveEventDetails, LiveEventView, LiveFrame, LiveInferenceView, LivePrivacyDisposition,
    LiveProcessor, LiveTickFrame, LiveTrustConfig, LiveTrustDecisionView, LiveTrustRejectionCode,
};
pub use runtime::{
    build_run, EventView, InferenceView, PrivacyBadge, ReceiptView, RunData, TickFrame,
};
pub use server::{
    app, app_no_ingest, AppState, ViewerConfig, ViewerConfigError, DEFAULT_SEED, DEFAULT_TICK_MS,
};
pub use source::{banner_for, BannerState, LiveState, SourceMode, DEFAULT_POLL_MS};
