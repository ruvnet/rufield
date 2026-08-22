//! `rufield-viewer` binary — serves the read-only RuField MFS dashboard.
//!
//! Usage (synthetic, the default):
//!   cargo run -p rufield-viewer                  # 127.0.0.1:8088, seed 2026
//!   cargo run -p rufield-viewer -- --port 9090   # custom port
//!   cargo run -p rufield-viewer -- --seed 7 --tick-ms 200
//!   cargo run -p rufield-viewer -- --no-loop     # stop stream at end of demo
//!
//! Usage (live — ADR-261 trust over the ADR-262 P3 transport):
//!   cargo run -p rufield-viewer -- --source live --upstream http://127.0.0.1:8080 \
//!     --sensor-key sensor_room_01=<ed25519-public-key-hex>
//!
//! Env overrides: `RUFIELD_VIEWER_PORT`, `RUFIELD_VIEWER_SEED`,
//! `RUFIELD_VIEWER_TICK_MS`, `RUFIELD_VIEWER_SOURCE` (`synthetic`|`live`),
//! `RUFIELD_VIEWER_UPSTREAM`, `RUFIELD_VIEWER_POLL_MS`,
//! `RUFIELD_VIEWER_SENSOR_KEYS` (comma-separated `sensor=key` bindings), and
//! `RUFIELD_VIEWER_TRUST_MODE` (`production`|`captured_replay`).
//!
//! In SYNTHETIC mode everything served is simulated — there is no hardware. In
//! LIVE mode fuses ONLY events accepted by the enrolled sensor trust policy;
//! if the upstream is unreachable it shows DISCONNECTED, never synthetic data.

use rufield_provenance::{
    TrustPolicy, TrustedKeyRegistry, DEFAULT_MAX_EVENT_AGE_NS, DEFAULT_MAX_FUTURE_SKEW_NS,
};
use rufield_viewer::{
    app, LiveTrustConfig, SourceMode, ViewerConfig, DEFAULT_POLL_MS, DEFAULT_SEED, DEFAULT_TICK_MS,
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
    let upstream =
        arg_value(&args, "--upstream").or_else(|| std::env::var("RUFIELD_VIEWER_UPSTREAM").ok());

    let source = match source_sel.as_str() {
        "live" => match upstream {
            Some(u) if !u.is_empty() => SourceMode::Live { upstream: u },
            _ => {
                eprintln!("--source live requires --upstream <URL> (or RUFIELD_VIEWER_UPSTREAM)");
                std::process::exit(2);
            }
        },
        "synthetic" => SourceMode::Synthetic,
        other => {
            eprintln!("unknown --source '{other}' (expected 'synthetic' or 'live')");
            std::process::exit(2);
        }
    };

    let live_trust = if source.is_live() {
        match live_trust_config(&args) {
            Ok(config) => Some(config),
            Err(error) => {
                eprintln!("invalid live trust configuration: {error}");
                std::process::exit(2);
            }
        }
    } else {
        None
    };

    let config = ViewerConfig {
        seed,
        tick_ms,
        loop_stream,
        source: source.clone(),
        poll_ms,
        live_trust,
    };
    let router = match app(config) {
        Ok(router) => router,
        Err(error) => {
            eprintln!("viewer configuration rejected: {error}");
            std::process::exit(2);
        }
    };

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
            println!(
                "RuField MFS viewer (LIVE — ingesting {upstream}, ADR-262 P3 transport; ADR-261 trust)"
            );
            println!("  upstream={upstream}  poll_ms={poll_ms}");
            println!(
                "  enrolled sensor trust enforced; unreachable ⇒ DISCONNECTED (no synthetic fallback)"
            );
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

fn arg_values(args: &[String], flag: &str) -> Vec<String> {
    args.iter()
        .enumerate()
        .filter_map(|(index, value)| {
            if value == flag {
                args.get(index + 1).cloned()
            } else {
                None
            }
        })
        .collect()
}

fn live_trust_config(args: &[String]) -> Result<LiveTrustConfig, String> {
    let mode = arg_value(args, "--trust-mode")
        .or_else(|| std::env::var("RUFIELD_VIEWER_TRUST_MODE").ok())
        .unwrap_or_else(|| "production".into());

    let mut bindings = arg_values(args, "--sensor-key");
    if let Ok(encoded) = std::env::var("RUFIELD_VIEWER_SENSOR_KEYS") {
        bindings.extend(
            encoded
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
        );
    }
    if bindings.is_empty() {
        return Err(
            "at least one --sensor-key sensor_id=public_key_hex binding is required".into(),
        );
    }

    let mut registry = TrustedKeyRegistry::new();
    for binding in bindings {
        let (sensor, key) = binding.split_once('=').ok_or_else(|| {
            format!("invalid sensor-key binding {binding:?}; expected sensor=key")
        })?;
        registry
            .enroll_sensor_key(sensor, key)
            .map_err(|error| error.to_string())?;
    }

    let policy = match mode.as_str() {
        "production" => {
            let max_age_ns = duration_override_ns(
                args,
                "--max-event-age-ms",
                "RUFIELD_VIEWER_MAX_EVENT_AGE_MS",
                DEFAULT_MAX_EVENT_AGE_NS,
            )?;
            let future_skew_ns = duration_override_ns(
                args,
                "--max-future-skew-ms",
                "RUFIELD_VIEWER_MAX_FUTURE_SKEW_MS",
                DEFAULT_MAX_FUTURE_SKEW_NS,
            )?;
            TrustPolicy::production_with_window(max_age_ns, future_skew_ns)
        }
        "captured_replay" => TrustPolicy::captured_replay(),
        "simulation" => {
            return Err("simulation trust mode is forbidden for a live source".into());
        }
        other => {
            return Err(format!(
                "unknown trust mode {other:?}; expected production or captured_replay"
            ));
        }
    };

    Ok(LiveTrustConfig {
        policy,
        registry,
        replay_state: None,
    })
}

fn duration_override_ns(
    args: &[String],
    flag: &str,
    environment: &str,
    default_ns: u64,
) -> Result<u64, String> {
    let Some(value) = arg_value(args, flag).or_else(|| std::env::var(environment).ok()) else {
        return Ok(default_ns);
    };
    let milliseconds = value
        .parse::<u64>()
        .map_err(|_| format!("{flag} must be an unsigned integer"))?;
    milliseconds
        .checked_mul(1_000_000)
        .ok_or_else(|| format!("{flag} is too large"))
}
