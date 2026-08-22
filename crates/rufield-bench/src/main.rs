//! `rufield-bench` binary — runs the deterministic RuField MFS v0.1 benchmark
//! and prints the human table plus JSON.
//!
//! Usage:
//!   cargo run -p rufield-bench            # default seed
//!   cargo run -p rufield-bench -- 2026    # custom seed
//!   cargo run -p rufield-bench -- 2026 --json   # JSON only

use rufield_bench::{
    evaluate_promotion_with_artifacts, run, verify_local_artifacts, EvidenceManifest,
    PromotionPolicy,
};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "evidence-gate") {
        run_evidence_gate(&args[1..]);
        return;
    }
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

fn run_evidence_gate(args: &[String]) {
    let Some(path) = args.first().filter(|argument| !argument.starts_with("--")) else {
        eprintln!(
            "usage: rufield-bench evidence-gate <manifest.json> --evidence-bundle <local-path> --evaluated-model <local-path> --authority-registry <local-path> (--split-artifact <local-path> | --model-lineage <local-path>) [--json]"
        );
        std::process::exit(2);
    };
    let manifest = match EvidenceManifest::from_path(path) {
        Ok(manifest) => manifest,
        Err(error) => {
            eprintln!("invalid evidence manifest: {error}");
            std::process::exit(2);
        }
    };
    let Some(bundle_path) = flag_value(args, "--evidence-bundle") else {
        eprintln!("--evidence-bundle is required; remote artifacts must be materialized locally");
        std::process::exit(2);
    };
    let split_path = flag_value(args, "--split-artifact").map(std::path::Path::new);
    let lineage_path = flag_value(args, "--model-lineage").map(std::path::Path::new);
    let Some(authority_registry) = flag_value(args, "--authority-registry") else {
        eprintln!(
            "--authority-registry is required; evidence artifacts cannot supply their own trust anchor"
        );
        std::process::exit(2);
    };
    let Some(evaluated_model) = flag_value(args, "--evaluated-model") else {
        eprintln!("--evaluated-model is required so model_digest is verified against local bytes");
        std::process::exit(2);
    };
    let artifacts = match verify_local_artifacts(
        &manifest,
        bundle_path,
        split_path,
        lineage_path,
        evaluated_model,
        authority_registry,
    ) {
        Ok(artifacts) => artifacts,
        Err(error) => {
            eprintln!("artifact verification failed: {error}");
            std::process::exit(2);
        }
    };
    let decision =
        evaluate_promotion_with_artifacts(&manifest, &PromotionPolicy::default(), &artifacts);
    println!("{}", decision.to_json());
    if !decision.promotable {
        std::process::exit(1);
    }
}

fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|argument| argument == flag)
        .and_then(|index| args.get(index + 1))
        .filter(|value| !value.starts_with("--"))
        .map(String::as_str)
}

fn rufield_adapters_default_seed() -> u64 {
    rufield_adapters::DEFAULT_SEED
}
