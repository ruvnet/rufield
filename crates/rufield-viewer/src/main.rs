//! `rufield-viewer` binary — serves the read-only RuField MFS dashboard.
//!
//! Usage (synthetic, the default):
//!   cargo run -p rufield-viewer                  # 127.0.0.1:8088, seed 2026
//!   cargo run -p rufield-viewer -- --port 9090   # custom port
//!   cargo run -p rufield-viewer -- --seed 7 --tick-ms 200
//!   cargo run -p rufield-viewer -- --no-loop     # stop stream at end of demo
//!
//! Usage (live — consume a real RuField upstream, ADR-262 P3):
//!   cargo run -p rufield-viewer -- --source live --upstream http://127.0.0.1:8080
//!
//! Env overrides: `RUFIELD_VIEWER_PORT`, `RUFIELD_VIEWER_SEED`,
//! `RUFIELD_VIEWER_TICK_MS`, `RUFIELD_VIEWER_SOURCE` (`synthetic`|`live`),
//! `RUFIELD_VIEWER_UPSTREAM`, `RUFIELD_VIEWER_POLL_MS`.
//!
//! In SYNTHETIC mode everything served is simulated — there is no hardware. In
//! LIVE mode the viewer renders ONLY receipt-verified events from the upstream;
//! if the upstream is unreachable it shows DISCONNECTED, never synthetic data.

use rufield_viewer::{
    app, SourceMode, ViewerConfig, DEFAULT_POLL_MS, DEFAULT_SEED, DEFAULT_TICK_MS,
};

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
    let poll_ms = arg_value(&args, "--poll-ms")
        .or_else(|| std::env::var("RUFIELD_VIEWER_POLL_MS").ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_POLL_MS);

    // Source selector. Default stays SYNTHETIC.
    let source_sel = arg_value(&args, "--source")
        .or_else(|| std::env::var("RUFIELD_VIEWER_SOURCE").ok())
        .unwrap_or_else(|| "synthetic".to_string());
    let upstream = arg_value(&args, "--upstream")
        .or_else(|| std::env::var("RUFIELD_VIEWER_UPSTREAM").ok());

    let source = match source_sel.as_str() {
        "live" => match upstream {
            Some(u) if !u.is_empty() => SourceMode::Live { upstream: u },
            _ => {
                eprintln!(
                    "--source live requires --upstream <URL> (or RUFIELD_VIEWER_UPSTREAM)"
                );
                std::process::exit(2);
            }
        },
        "synthetic" => SourceMode::Synthetic,
        other => {
            eprintln!("unknown --source '{other}' (expected 'synthetic' or 'live')");
            std::process::exit(2);
        }
    };

    let config = ViewerConfig { seed, tick_ms, loop_stream, source: source.clone(), poll_ms };
    let router = app(config);

    let addr = format!("127.0.0.1:{port}");
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind {addr}: {e}");
            std::process::exit(1);
        }
    };

    match &source {
        SourceMode::Synthetic => {
            println!("RuField MFS viewer (SYNTHETIC — simulated sensors, no hardware)");
            println!("  seed={seed}  tick_ms={tick_ms}  loop={loop_stream}");
        }
        SourceMode::Live { upstream } => {
            println!("RuField MFS viewer (LIVE — ingesting {upstream}, ADR-262 P3)");
            println!("  upstream={upstream}  poll_ms={poll_ms}");
            println!("  receipts verified on ingest; unreachable ⇒ DISCONNECTED (no synthetic fallback)");
        }
    }
    println!("  dashboard:  http://{addr}/");
    println!("  source:     http://{addr}/api/source");
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
