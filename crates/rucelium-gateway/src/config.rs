//! Gateway configuration: defaults plus a hand-rolled, unit-testable CLI
//! argument parser (no `clap` — zero new dependencies, ADR-265 §4).

use std::path::PathBuf;

/// Default biome identity.
pub const DEFAULT_BIOME_ID: &str = "biome/dev";
/// Default UDP ingest port (ADR-265 §4).
pub const DEFAULT_UDP_PORT: u16 = 7464;
/// Default HTTP API port (ADR-265 §4).
pub const DEFAULT_HTTP_PORT: u16 = 7465;
/// Default on-disk data directory.
pub const DEFAULT_DATA_DIR: &str = "./rucelium-data";
/// Default deterministic seed (biome identity + synthetic node keys).
pub const DEFAULT_SEED: u64 = 2026;
/// Default synthetic-node emission interval in milliseconds.
pub const DEFAULT_SIM_INTERVAL_MS: u64 = 1000;
/// Default retention-enforcement check interval in seconds.
pub const DEFAULT_RETENTION_CHECK_SECS: u64 = 3600;
/// Default peer federation poll interval in milliseconds.
pub const DEFAULT_FEDERATION_POLL_MS: u64 = 30_000;
/// Default actuator the biome owner exposes to the governed control path.
pub const DEFAULT_ACTUATOR_ID: &str = "sluice-gate-1";
/// Default durability mode for the durable stores: the daemon fsyncs every
/// accepted append, so an accepted record survives power loss.
pub const DEFAULT_FSYNC: bool = true;

/// Runtime configuration of one gateway daemon instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayConfig {
    /// Biome identity (e.g. `biome/thames-estuary`). Also seeds the biome's
    /// deterministic signing key (see `GatewayState::open`).
    pub biome_id: String,
    /// UDP ingest port (`0` = ephemeral, useful for tests).
    pub udp_port: u16,
    /// HTTP API port (`0` = ephemeral, useful for tests).
    pub http_port: u16,
    /// Data directory; observation and event segments live in `obs/` and
    /// `events/` beneath it.
    pub data_dir: PathBuf,
    /// Peer gateway base URLs to federate with (repeatable `--peer`).
    pub peers: Vec<String>,
    /// Number of SYNTHETIC spore nodes to simulate (`0` = none).
    pub simulate: u32,
    /// Deterministic seed for the biome key and synthetic node keys.
    pub seed: u64,
    /// Synthetic-node emission interval in milliseconds.
    pub sim_interval_ms: u64,
    /// Retention-enforcement check interval in seconds.
    pub retention_check_secs: u64,
    /// Peer federation poll interval in milliseconds (short in tests).
    pub federation_poll_ms: u64,
    /// Interval of the **mandatory** `sync_since` backfill backstop, in
    /// milliseconds (ADR-269 §3). `None` inherits [`Self::federation_poll_ms`],
    /// so the ADR-265 §4 behaviour is the default; set it explicitly to slow
    /// the backstop down once push is carrying the latency-critical traffic.
    pub federation_backfill_ms: Option<u64>,
    /// The actuator id the biome owner grants `agent/flood` authority over
    /// (ADR-264 §6: actuator authority never leaves the biome owner).
    pub actuator_id: String,
    /// Durability mode for `ObservationStore` / `EventStore`: `true` fsyncs
    /// every accepted append before it is acknowledged.
    pub fsync: bool,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        GatewayConfig {
            biome_id: DEFAULT_BIOME_ID.to_string(),
            udp_port: DEFAULT_UDP_PORT,
            http_port: DEFAULT_HTTP_PORT,
            data_dir: PathBuf::from(DEFAULT_DATA_DIR),
            peers: Vec::new(),
            simulate: 0,
            seed: DEFAULT_SEED,
            sim_interval_ms: DEFAULT_SIM_INTERVAL_MS,
            retention_check_secs: DEFAULT_RETENTION_CHECK_SECS,
            federation_poll_ms: DEFAULT_FEDERATION_POLL_MS,
            federation_backfill_ms: None,
            actuator_id: DEFAULT_ACTUATOR_ID.to_string(),
            fsync: DEFAULT_FSYNC,
        }
    }
}

impl GatewayConfig {
    /// Interval of the ADR-269 §3 backfill backstop, in milliseconds:
    /// [`Self::federation_backfill_ms`] when set, otherwise the ADR-265 §4
    /// [`Self::federation_poll_ms`].
    #[must_use]
    pub fn federation_backfill_ms(&self) -> u64 {
        self.federation_backfill_ms
            .unwrap_or(self.federation_poll_ms)
    }

    /// Parse CLI arguments (without the program name). Unknown flags and
    /// malformed values are hard errors — the daemon never guesses.
    pub fn from_args(args: Vec<String>) -> Result<Self, String> {
        let mut config = GatewayConfig::default();
        let mut it = args.into_iter();
        while let Some(flag) = it.next() {
            let mut value =
                |flag: &str| it.next().ok_or_else(|| format!("missing value for {flag}"));
            match flag.as_str() {
                "--biome-id" => config.biome_id = value("--biome-id")?,
                "--udp" => config.udp_port = parse_num(&value("--udp")?, "--udp")?,
                "--http" => config.http_port = parse_num(&value("--http")?, "--http")?,
                "--data-dir" => config.data_dir = PathBuf::from(value("--data-dir")?),
                "--peer" => config.peers.push(value("--peer")?),
                "--simulate" => config.simulate = parse_num(&value("--simulate")?, "--simulate")?,
                "--seed" => config.seed = parse_num(&value("--seed")?, "--seed")?,
                "--sim-interval-ms" => {
                    config.sim_interval_ms =
                        parse_num(&value("--sim-interval-ms")?, "--sim-interval-ms")?;
                }
                "--retention-check-secs" => {
                    config.retention_check_secs =
                        parse_num(&value("--retention-check-secs")?, "--retention-check-secs")?;
                }
                "--federation-poll-ms" => {
                    config.federation_poll_ms =
                        parse_num(&value("--federation-poll-ms")?, "--federation-poll-ms")?;
                }
                "--federation-backfill-ms" => {
                    config.federation_backfill_ms = Some(parse_num(
                        &value("--federation-backfill-ms")?,
                        "--federation-backfill-ms",
                    )?);
                }
                "--actuator" => config.actuator_id = value("--actuator")?,
                "--fsync" => config.fsync = parse_num(&value("--fsync")?, "--fsync")?,
                unknown => return Err(format!("unknown flag {unknown}")),
            }
        }
        Ok(config)
    }
}

/// Parse a numeric flag value with a diagnostic naming the flag.
fn parse_num<T: std::str::FromStr>(raw: &str, flag: &str) -> Result<T, String> {
    raw.parse::<T>()
        .map_err(|_| format!("invalid value {raw:?} for {flag}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn defaults_match_adr_265() {
        let c = GatewayConfig::from_args(Vec::new()).unwrap();
        assert_eq!(c, GatewayConfig::default());
        assert_eq!(c.biome_id, "biome/dev");
        assert_eq!(c.udp_port, 7464);
        assert_eq!(c.http_port, 7465);
        assert_eq!(c.data_dir, PathBuf::from("./rucelium-data"));
        assert!(c.peers.is_empty());
        assert_eq!(c.simulate, 0);
        assert_eq!(c.seed, 2026);
        assert_eq!(c.sim_interval_ms, 1000);
        assert_eq!(c.retention_check_secs, 3600);
        assert_eq!(c.federation_poll_ms, 30_000);
        // ADR-269 §3: the backstop defaults to the ADR-265 §4 poll interval.
        assert_eq!(c.federation_backfill_ms, None);
        assert_eq!(c.federation_backfill_ms(), 30_000);
        assert_eq!(c.actuator_id, "sluice-gate-1");
        assert!(c.fsync, "the daemon fsyncs accepted appends by default");
    }

    #[test]
    fn backfill_interval_overrides_the_poll_interval_when_set() {
        let c = GatewayConfig::from_args(args(&[
            "--federation-poll-ms",
            "200",
            "--federation-backfill-ms",
            "60000",
        ]))
        .unwrap();
        assert_eq!(c.federation_poll_ms, 200);
        assert_eq!(c.federation_backfill_ms, Some(60_000));
        assert_eq!(c.federation_backfill_ms(), 60_000);
    }

    #[test]
    fn all_flags_parse() {
        let c = GatewayConfig::from_args(args(&[
            "--biome-id",
            "biome/x",
            "--udp",
            "1111",
            "--http",
            "2222",
            "--data-dir",
            "/tmp/gw",
            "--simulate",
            "8",
            "--seed",
            "42",
            "--sim-interval-ms",
            "250",
            "--retention-check-secs",
            "60",
            "--federation-poll-ms",
            "200",
            "--actuator",
            "weir-3",
            "--fsync",
            "false",
        ]))
        .unwrap();
        assert_eq!(c.biome_id, "biome/x");
        assert_eq!(c.udp_port, 1111);
        assert_eq!(c.http_port, 2222);
        assert_eq!(c.data_dir, PathBuf::from("/tmp/gw"));
        assert_eq!(c.simulate, 8);
        assert_eq!(c.seed, 42);
        assert_eq!(c.sim_interval_ms, 250);
        assert_eq!(c.retention_check_secs, 60);
        assert_eq!(c.federation_poll_ms, 200);
        assert_eq!(c.actuator_id, "weir-3");
        assert!(!c.fsync);
    }

    #[test]
    fn peer_is_repeatable_in_order() {
        let c = GatewayConfig::from_args(args(&[
            "--peer",
            "http://a:7465",
            "--peer",
            "http://b:7465",
        ]))
        .unwrap();
        assert_eq!(c.peers, vec!["http://a:7465", "http://b:7465"]);
    }

    #[test]
    fn unknown_flag_is_an_error() {
        let err = GatewayConfig::from_args(args(&["--nope"])).unwrap_err();
        assert!(err.contains("--nope"), "{err}");
    }

    #[test]
    fn missing_and_malformed_values_are_errors() {
        let err = GatewayConfig::from_args(args(&["--udp"])).unwrap_err();
        assert!(err.contains("--udp"), "{err}");
        let err = GatewayConfig::from_args(args(&["--udp", "not-a-port"])).unwrap_err();
        assert!(err.contains("not-a-port"), "{err}");
        let err = GatewayConfig::from_args(args(&["--seed", "-3"])).unwrap_err();
        assert!(err.contains("--seed"), "{err}");
    }
}
