//! `rucelium-gateway` binary: parse CLI args, print the startup banner,
//! start the full stack, and run until Ctrl-C (ADR-265 §4).

use rucelium_gateway::{spawn_gateway, GatewayConfig};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = match GatewayConfig::from_args(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("rucelium-gateway: {e}");
            eprintln!(
                "usage: rucelium-gateway [--biome-id <s>] [--udp <port>] [--http <port>] \
                 [--data-dir <path>] [--peer <url>]... [--simulate <n>] [--seed <u64>] \
                 [--sim-interval-ms <u64>] [--retention-check-secs <u64>] \
                 [--federation-poll-ms <u64>] [--actuator <id>] [--fsync <bool>]"
            );
            std::process::exit(2);
        }
    };

    println!("rucelium-gateway (ADR-265 rhizome daemon)");
    println!("  biome:      {}", config.biome_id);
    println!("  udp:        {}", config.udp_port);
    println!("  http:       {}", config.http_port);
    println!("  data dir:   {}", config.data_dir.display());
    println!("  fsync:      {}", config.fsync);
    println!("  actuator:   {}", config.actuator_id);
    println!("  simulate:   {} synthetic node(s)", config.simulate);
    if config.peers.is_empty() {
        println!("  peers:      none");
    } else {
        for peer in &config.peers {
            println!("  peer:       {peer}");
        }
    }
    println!("  WARNING: admin endpoints are UNAUTHENTICATED in v0.1 — bind");
    println!("           the http port to localhost or firewall it.");

    let handle = match spawn_gateway(config).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("rucelium-gateway: startup failed: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "  listening:  udp 0.0.0.0:{}  http http://0.0.0.0:{}",
        handle.udp_port, handle.http_port
    );

    if let Err(e) = tokio::signal::ctrl_c().await {
        eprintln!("rucelium-gateway: signal wait failed: {e}");
    }
    println!("rucelium-gateway: shutting down");
    for task in handle.tasks {
        task.abort();
    }
}
