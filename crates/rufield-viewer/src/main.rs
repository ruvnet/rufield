//! `rufield-viewer` binary — serves the read-only RuField MFS dashboard.
//!
//! Usage:
//!   cargo run -p rufield-viewer                  # 127.0.0.1:8088, seed 2026
//!   cargo run -p rufield-viewer -- --port 9090   # custom port
//!   cargo run -p rufield-viewer -- --seed 7 --tick-ms 200
//!   cargo run -p rufield-viewer -- --no-loop     # stop stream at end of demo
//!
//! Env overrides: `RUFIELD_VIEWER_PORT`, `RUFIELD_VIEWER_SEED`,
//! `RUFIELD_VIEWER_TICK_MS`.
//!
//! Everything served is SYNTHETIC — there is no hardware.

use rufield_viewer::{app, ViewerConfig, DEFAULT_SEED, DEFAULT_TICK_MS};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let port = arg_value(&args, "--port")
        .or_else(|| std::env::var("RUFIELD_VIEWER_PORT").ok())
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(8088);
    let seed = arg_value(&args, "--seed")
        .or_else(|| std::env::var("RUFIELD_VIEWER_SEED").ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SEED);
    let tick_ms = arg_value(&args, "--tick-ms")
        .or_else(|| std::env::var("RUFIELD_VIEWER_TICK_MS").ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TICK_MS);
    let loop_stream = !args.iter().any(|a| a == "--no-loop");

    let config = ViewerConfig { seed, tick_ms, loop_stream };
    let router = app(config);

    let addr = format!("127.0.0.1:{port}");
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind {addr}: {e}");
            std::process::exit(1);
        }
    };

    println!("RuField MFS viewer (SYNTHETIC — simulated sensors, no hardware)");
    println!("  seed={seed}  tick_ms={tick_ms}  loop={loop_stream}");
    println!("  dashboard:  http://{addr}/");
    println!("  run json:   http://{addr}/api/run");
    println!("  sse stream: http://{addr}/events");

    if let Err(e) = axum::serve(listener, router).await {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}

/// Read `--flag value` from a flat arg list.
fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}
