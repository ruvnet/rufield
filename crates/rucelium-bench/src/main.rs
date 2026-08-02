//! `rucelium-bench` binary — runs the deterministic ADR-264 §14 biome
//! acceptance benchmark and prints the human table plus JSON.
//!
//! Usage:
//!   cargo run -p rucelium-bench            # default seed
//!   cargo run -p rucelium-bench -- 2026    # custom seed
//!   cargo run -p rucelium-bench -- 2026 --json   # JSON only

use rucelium_bench::{run, SimConfig, DEFAULT_SEED};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let seed: u64 = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SEED);
    let json_only = args.iter().any(|a| a == "--json");

    let report = run(SimConfig {
        seed,
        ..SimConfig::default()
    });

    if json_only {
        println!("{}", report.to_json());
    } else {
        print!("{}", report.to_table());
        println!("\n--- JSON ---\n{}", report.to_json());
    }

    if !report.accepted_all() {
        std::process::exit(1);
    }
}
