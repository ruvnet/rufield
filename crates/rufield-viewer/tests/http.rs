//! HTTP-level integration tests for the read-only RuField MFS viewer.
//!
//! Uses `tower::ServiceExt::oneshot` to drive the Axum router in-process (no
//! TCP bind needed), mirroring the ADR-260 §31 acceptance assertions at the
//! transport layer.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use rufield_viewer::{app, ViewerConfig};
use tower::ServiceExt;

async fn get(path: &str) -> (StatusCode, String) {
    let router = app(ViewerConfig::default());
    let resp = router
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
async fn index_returns_200_with_synthetic_banner() {
    let (status, body) = get("/").await;
    assert_eq!(status, StatusCode::OK);
    // The persistent, unmissable honesty banner must be present in the HTML.
    assert!(
        body.contains("SYNTHETIC — simulated sensors, no hardware"),
        "dashboard HTML must carry the SYNTHETIC banner text"
    );
    // It must serve the dashboard, not imply live hardware.
    assert!(body.contains("Camera-Free Room Intelligence"));
}

#[tokio::test]
async fn app_js_is_served() {
    let (status, body) = get("/app.js").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("EventSource"), "app.js wires the SSE stream");
}

#[tokio::test]
async fn health_is_ok_and_synthetic() {
    let (status, body) = get("/health").await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "ok");
    assert_eq!(v["synthetic"], true);
}

#[tokio::test]
async fn api_run_is_deterministic_and_meets_section31() {
    // Two requests at the same seed must produce byte-identical JSON.
    let (s1, b1) = get("/api/run?seed=2026").await;
    let (s2, b2) = get("/api/run?seed=2026").await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(b1, b2, "/api/run must be deterministic for a fixed seed");

    let run: serde_json::Value = serde_json::from_str(&b1).unwrap();

    // (1) synthetic flag present and true.
    assert_eq!(run["synthetic"], true);

    // (2) >= 1 event per modality across 3 modalities.
    let mods = run["modalities"].as_array().unwrap();
    assert_eq!(mods.len(), 3, "expected 3 modalities");

    // Walk frames: every event carries a privacy_class + a provenance receipt.
    let frames = run["frames"].as_array().unwrap();
    let mut seen_mods = std::collections::BTreeSet::new();
    let mut total_events = 0usize;
    for f in frames {
        for ev in f["events"].as_array().unwrap() {
            total_events += 1;
            seen_mods.insert(ev["modality"].as_str().unwrap().to_string());
            // privacy class badge
            let pc = ev["privacy"]["class"].as_str().unwrap();
            assert!(pc.starts_with('P'), "event must carry a P0..P5 badge");
            // provenance receipt
            let r = &ev["receipt"];
            assert!(r["raw_hash"].as_str().unwrap().starts_with("sha256:"));
            assert!(r["signature_hex"].as_str().is_some(), "event must be signed");
            assert_eq!(r["verified"], true, "signature must verify");
            assert_eq!(r["fusable"], true, "event must be §11-fusable");
        }
    }
    assert_eq!(seen_mods.len(), 3, "events must cover all 3 modalities");
    assert!(total_events >= 3);

    // (3) >= 5 distinct room-state inferences (mirrors §31).
    let distinct = run["distinct_inferences"].as_array().unwrap();
    assert!(
        distinct.len() >= 5,
        "expected >=5 room-state inferences, got {}",
        distinct.len()
    );

    // (4) privacy + provenance invariants.
    assert_eq!(run["privacy_violations"], 0);
    assert!((run["provenance_coverage_pct"].as_f64().unwrap() - 100.0).abs() < 1e-9);
}

#[tokio::test]
async fn events_stream_emits_meta_then_frames_in_order() {
    // Stop at end-of-demo so the stream terminates and we can read it fully.
    let router = app(ViewerConfig { tick_ms: 1, loop_stream: false, ..ViewerConfig::default() });
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/events?seed=2026&tick_ms=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&bytes);

    // Deterministic SSE ordering: a single `meta`, then `frame`s, then `done`.
    let meta_pos = text.find("event: meta").expect("meta event present");
    let first_frame = text.find("event: frame").expect("frame events present");
    let done_pos = text.find("event: done").expect("done event present");
    assert!(meta_pos < first_frame, "meta precedes frames");
    assert!(first_frame < done_pos, "frames precede done");

    // Determinism: a second identical stream is byte-identical.
    let router2 = app(ViewerConfig { tick_ms: 1, loop_stream: false, ..ViewerConfig::default() });
    let resp2 = router2
        .oneshot(
            Request::builder()
                .uri("/events?seed=2026&tick_ms=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes2 = resp2.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(bytes, bytes2, "SSE stream must be deterministic for a fixed seed");
}
