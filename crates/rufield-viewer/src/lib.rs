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
//! Everything this viewer shows is **SYNTHETIC** — produced by a deterministic
//! simulator. There is **no hardware**, no live sensor, and no live camera.
//! This is a *demo viewer*, not a device-management console: in v0.1 there are
//! no real devices to manage. Fleet / real-adapter integration is a separate,
//! later milestone. The dashboard renders a persistent
//! `SYNTHETIC — simulated sensors, no hardware` banner that cannot be dismissed.
//!
//! ## What it serves
//!
//! - `GET /`         — the dashboard page.
//! - `GET /app.js`   — the vanilla-JS dashboard logic.
//! - `GET /health`   — liveness JSON.
//! - `GET /api/run`  — the full deterministic run as JSON (non-streaming).
//! - `GET /events`   — Server-Sent Events: each tick frame + its inferences,
//!   paced at a watchable cadence; loops or stops cleanly.
//!
//! ## Run it
//!
//! ```no_run
//! # async fn run() {
//! use rufield_viewer::{app, ViewerConfig};
//! let router = app(ViewerConfig::default());
//! let listener = tokio::net::TcpListener::bind("127.0.0.1:8088").await.unwrap();
//! axum::serve(listener, router).await.unwrap();
//! # }
//! ```

#![doc(html_root_url = "https://docs.rs/rufield-viewer/0.1.0")]

pub mod live;
pub mod runtime;
pub mod server;
pub mod source;

pub use live::{frame_from_api_payload, frame_from_events, frame_from_ws_event, ApiFieldPayload, LiveFrame};
pub use runtime::{
    build_run, EventView, InferenceView, PrivacyBadge, ReceiptView, RunData, TickFrame,
};
pub use server::{app, app_no_ingest, AppState, ViewerConfig, DEFAULT_SEED, DEFAULT_TICK_MS};
pub use source::{
    banner_for, BannerState, LiveState, SourceMode, DEFAULT_POLL_MS,
};
