//! `rufield-bench` binary — runs the deterministic RuField MFS v0.1 benchmark
//! and prints the human table plus JSON.
//!
//! Usage:
//!   cargo run -p rufield-bench            # default seed
//!   cargo run -p rufield-bench -- 2026    # custom seed
//!   cargo run -p rufield-bench -- 2026 --json   # JSON only

use rufield_bench::run;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let seed: u64 = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(rufield_adapters_default_seed());
    let json_only = args.iter().any(|a| a == "--json");

    let report = run(seed);

    if json_only {
        println!("{}", report.to_json());
    } else {
        print!("{}", report.to_table());
        println!("\n--- JSON ---\n{}", report.to_json());
    }
}

fn rufield_adapters_default_seed() -> u64 {
    rufield_adapters::DEFAULT_SEED
}
