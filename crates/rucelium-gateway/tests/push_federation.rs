//! ADR-269 §3 acceptance: push federation over the default (HTTP) path.
//!
//! Everything here is transport-agnostic and runs with the `quic` feature
//! **off**, which is the point of ADR-269 §5's additive constraint. The
//! properties under test:
//!
//! 1. **push on revocation reaches a peer and is applied** without waiting
//!    for a poll — the receiving gateway has no backstop running at all, so
//!    a pass can only come from the push;
//! 2. a pushed artifact with a **bad signature** is rejected 4xx and not
//!    applied;
//! 3. a pushed artifact whose **signer is not the claimed biome's registered
//!    key** is rejected — the identity-binding path — even though its
//!    signature is perfectly valid;
//! 4. a **duplicate** pushed event is applied exactly once;
//! 5. **backfill converges** a peer that never received a push, with the
//!    push path unavailable — the ADR-269 §3 backstop doing its job;
//! 6. the `/api/stats` push counters move the way they claim to.

use rucelium_abi::{NodeSigner, RvEnvSampleV1, RV_ENV_SCHEMA_V1};
use rucelium_core::EnvironmentalEvent;
use rucelium_federation::{Biome, BiomeConfig};
use rucelium_gateway::federation::register_peer_identity;
use rucelium_gateway::state::biome_seed;
use rucelium_gateway::{spawn_gateway_with_state, GatewayConfig, GatewayHandle, GatewayState};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Device provisioning seed shared by both gateways in a test.
const SEED: &[u8; 32] = b"rucelium-push-provision-seed-32!";
/// The one device these tests revoke.
const NODE: u64 = 0x5CF0_0000_0000_0001;
/// A backstop interval far enough away that it cannot fire during a test
/// after the initial tick, so a pass can only come from the push path.
const NEVER_MS: u64 = 3_600_000;
/// A brisk backstop interval for the convergence test.
const FAST_MS: u64 = 100;

/// Wall-clock nanoseconds.
fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos() as u64
}

/// A unique temp data dir.
fn temp_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "rucelium-gw-push-{tag}-{}-{}",
        std::process::id(),
        now_ns()
    ))
}

/// The biome public key a gateway with this id (and the default seed) will
/// have. Biome identity is deterministic in `(biome_id, seed)`, so a peer's
/// federation key can be registered before that peer ever runs — which is
/// how these tests bind identity without a bootstrap poll.
fn biome_key_hex(biome_id: &str) -> String {
    Biome::new(
        BiomeConfig::new(biome_id),
        &biome_seed(biome_id, GatewayConfig::default().seed),
    )
    .public_key_hex()
}

/// A genuine signed v1 envelope from `NODE`.
fn envelope(sequence: u32) -> Vec<u8> {
    let wire = RvEnvSampleV1 {
        schema_version: RV_ENV_SCHEMA_V1,
        sensor_type: 5, // weather
        flags: 0,
        node_id: NODE,
        timestamp_ns: now_ns(),
        sequence,
        latitude_e7: 514_778_216,
        longitude_e7: -14_767,
        altitude_mm: 46_000,
        value_q16: 16 * 65_536,
        quality_q15: 0x7000,
        battery_mv: 3_600,
        calibration_id: 0,
    };
    NodeSigner::for_node(SEED, NODE).sign_sample(&wire).encode()
}

/// A running test gateway.
struct Gw {
    /// Tasks and ports.
    handle: GatewayHandle,
    /// Base HTTP URL.
    http: String,
    /// Data directory, removed by [`Gw::shutdown`].
    dir: PathBuf,
}

impl Gw {
    /// Spawn a gateway with `NODE` provisioned, plus any peer federation
    /// identities pre-registered, before any task can race them.
    async fn spawn(
        tag: &str,
        biome_id: &str,
        peers: Vec<String>,
        backfill_ms: u64,
        known: &[(&str, &str)],
    ) -> Self {
        let dir = temp_dir(tag);
        let config = GatewayConfig {
            biome_id: biome_id.into(),
            udp_port: 0,
            http_port: 0,
            data_dir: dir.clone(),
            peers,
            federation_poll_ms: backfill_ms,
            federation_backfill_ms: Some(backfill_ms),
            ..GatewayConfig::default()
        };
        let state = GatewayState::open(&config).expect("open state");
        {
            let mut inner = state.inner.lock().await;
            inner.ingest.registry_mut().register(
                NODE,
                NodeSigner::for_node(SEED, NODE).public_key(),
                "sha256:push-fw".into(),
            );
            for (peer_biome, url) in known {
                register_peer_identity(&mut inner, peer_biome, &biome_key_hex(peer_biome), url);
            }
        }
        let handle = spawn_gateway_with_state(state, config)
            .await
            .expect("spawn gateway");
        let http = format!("http://127.0.0.1:{}", handle.http_port);
        Gw { handle, http, dir }
    }

    /// Stop every task and remove the data directory.
    fn shutdown(self) {
        for task in self.handle.tasks {
            task.abort();
        }
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

/// Fetch a JSON body.
async fn get_json(client: &reqwest::Client, url: &str) -> Value {
    client
        .get(url)
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {url}: {e}"))
        .json()
        .await
        .unwrap_or_else(|e| panic!("decode {url}: {e}"))
}

/// Poll `url` until `pred` holds, panicking after `timeout`.
async fn wait_for_json<F>(client: &reqwest::Client, url: &str, timeout: Duration, pred: F) -> Value
where
    F: Fn(&Value) -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        let v = get_json(client, url).await;
        if pred(&v) {
            return v;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting on {url}; last body: {v}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// `POST {http}/api/federation/announce`, returning status and body.
async fn announce(
    client: &reqwest::Client,
    http: &str,
    artifact: &Value,
) -> (reqwest::StatusCode, Value) {
    let response = client
        .post(format!("{http}/api/federation/announce"))
        .json(artifact)
        .send()
        .await
        .expect("announce request");
    let status = response.status();
    let body = response.json().await.unwrap_or(Value::Null);
    (status, body)
}

/// Wrap an event as the body `POST /api/federation/announce` accepts.
fn event_artifact(event: &EnvironmentalEvent) -> Value {
    let mut value = serde_json::to_value(event).expect("event serializes");
    value["artifact"] = json!("event");
    value
}

/// Revoke `NODE` on a gateway and return the response body.
async fn revoke(client: &reqwest::Client, http: &str) -> Value {
    client
        .post(format!("{http}/api/admin/revoke/{NODE}"))
        .send()
        .await
        .expect("revoke request")
        .json()
        .await
        .expect("revoke body")
}

/// (1), (4) and (6): a revocation on A reaches B by push. B runs **no**
/// federation task at all — it has no peers — so nothing but the push can
/// possibly deliver it.
#[tokio::test(flavor = "multi_thread")]
async fn push_on_revocation_reaches_a_peer_without_waiting_for_a_poll() {
    let client = reqwest::Client::new();

    // B: no peers, therefore no poller and no backstop. It knows A's
    // federation key (registered up front, as a real deployment would from
    // a first contact) so it can identity-bind what A pushes.
    let b = Gw::spawn(
        "recv-b",
        "biome/push-b",
        Vec::new(),
        NEVER_MS,
        &[("biome/push-a", "http://a.invalid")],
    )
    .await;

    // A: peers with B, backstop parked an hour out.
    let a = Gw::spawn(
        "send-a",
        "biome/push-a",
        vec![b.http.clone()],
        NEVER_MS,
        &[],
    )
    .await;

    let before = get_json(&client, &format!("{}/api/stats", b.http)).await;
    assert_eq!(before["applied_peer_revocations"], 0);
    assert_eq!(before["pushes_received"], 0);

    let pushed_at = Instant::now();
    let response = revoke(&client, &a.http).await;
    assert_eq!(
        response["pushed"], true,
        "revoke must queue an immediate push: {response}"
    );

    // B applies it. There is no timer on B that could have done this.
    let b_stats = wait_for_json(
        &client,
        &format!("{}/api/stats", b.http),
        Duration::from_secs(10),
        |v| v["applied_peer_revocations"] == 1,
    )
    .await;
    assert!(
        pushed_at.elapsed() < Duration::from_secs(10),
        "push latency is link speed, not poll speed"
    );
    assert_eq!(b_stats["pushes_received"], 1);
    assert_eq!(b_stats["backfills"], 0, "B has no peers to back off");

    // (6) A counted the push it sent, and nothing failed.
    let a_stats = wait_for_json(
        &client,
        &format!("{}/api/stats", a.http),
        Duration::from_secs(10),
        |v| v["pushes_sent"] == 1,
    )
    .await;
    assert_eq!(a_stats["push_failures"], 0);
    assert_eq!(a_stats["push"]["pushes_sent"], 1);

    // (4) Re-pushing the identical event is verified, accepted, applied
    // once: `202 Accepted`, `applied: false`.
    let event: EnvironmentalEvent =
        serde_json::from_value(response["event"].clone()).expect("event decodes");
    let (status, body) = announce(&client, &b.http, &event_artifact(&event)).await;
    assert_eq!(status, reqwest::StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["applied"], false);
    let after = get_json(&client, &format!("{}/api/stats", b.http)).await;
    assert_eq!(after["applied_peer_revocations"], 1, "applied exactly once");
    assert_eq!(after["pushes_received"], 1, "a no-op is not a delivery");

    // The revocation is real: B's registry rejects the node's traffic now.
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind sender");
    sender
        .send_to(&envelope(1), ("127.0.0.1", b.handle.udp_port))
        .await
        .expect("send envelope");
    wait_for_json(
        &client,
        &format!("{}/api/stats", b.http),
        Duration::from_secs(5),
        |v| v["ingest"]["revoked_device"] == 1,
    )
    .await;

    a.shutdown();
    b.shutdown();
}

/// (2) and (3): a pushed artifact that does not verify — tampered, or signed
/// by a key that is not the claimed biome's registered key — gets a 4xx and
/// changes nothing. Being *pushed* buys an artifact no trust (ADR-269 §4).
#[tokio::test(flavor = "multi_thread")]
async fn pushed_artifacts_that_do_not_verify_are_refused_and_never_applied() {
    let client = reqwest::Client::new();
    let a = Gw::spawn("bad-a", "biome/bad-a", Vec::new(), NEVER_MS, &[]).await;
    let b = Gw::spawn(
        "bad-b",
        "biome/bad-b",
        Vec::new(),
        NEVER_MS,
        &[("biome/bad-a", "http://a.invalid")],
    )
    .await;

    // A genuine revocation from A, which B *would* accept.
    let response = revoke(&client, &a.http).await;
    let good: EnvironmentalEvent =
        serde_json::from_value(response["event"].clone()).expect("event decodes");

    // (2) Bad signature: one character added after signing. 400, not
    // applied.
    let mut tampered = good.clone();
    tampered.message.push('!');
    let (status, body) = announce(&client, &b.http, &event_artifact(&tampered)).await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["applied"], false);

    // (3) Identity mismatch: a *validly signed* revocation claiming A's
    // biome id, signed by a key that is not A's registered key. 403, not
    // applied — a valid signature is not an identity.
    let mut impostor = Biome::new(
        BiomeConfig::new("biome/bad-a"),
        b"rucelium-impostor-seed-32-bytes!",
    );
    let forged = impostor.revoke_device(NODE, now_ns(), "forged");
    assert!(rucelium_federation::verify_event(&forged));
    assert_ne!(forged.signer_pubkey_hex, good.signer_pubkey_hex);
    let (status, body) = announce(&client, &b.http, &event_artifact(&forged)).await;
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["error"].as_str().unwrap_or_default().contains("bad-a"),
        "identity-binding failure must name the biome: {body}"
    );

    // An artifact from an entirely unknown biome cannot be identity-bound
    // at all, so it is refused too.
    let mut stranger = Biome::new(
        BiomeConfig::new("biome/stranger"),
        b"rucelium-stranger-seed-32-bytes!",
    );
    let strange = stranger.revoke_device(NODE, now_ns(), "who?");
    let (status, _) = announce(&client, &b.http, &event_artifact(&strange)).await;
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN);

    // Nothing landed.
    let stats = get_json(&client, &format!("{}/api/stats", b.http)).await;
    assert_eq!(stats["applied_peer_revocations"], 0);
    assert_eq!(stats["pushes_received"], 0);

    // ...and the genuine one still works, proving the refusals were about
    // the artifacts rather than a broken endpoint.
    let (status, body) = announce(&client, &b.http, &event_artifact(&good)).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert_eq!(body["applied"], true);
    let stats = get_json(&client, &format!("{}/api/stats", b.http)).await;
    assert_eq!(stats["applied_peer_revocations"], 1);
    assert_eq!(stats["pushes_received"], 1);

    a.shutdown();
    b.shutdown();
}

/// (5): the mandatory backstop. A revokes while it has no peers at all, so
/// no `announce` is ever attempted; B still converges from `sync_since`
/// alone (ADR-269 §3: "a peer that missed a pushed event must still
/// converge").
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_missed_the_push_converges_through_backfill() {
    let client = reqwest::Client::new();

    // A federates with nobody: the revocation exists only in its own store.
    let a = Gw::spawn("back-a", "biome/back-a", Vec::new(), NEVER_MS, &[]).await;
    let response = revoke(&client, &a.http).await;
    assert_eq!(response["pushed"], false, "A has no peers to push to");
    let a_stats = get_json(&client, &format!("{}/api/stats", a.http)).await;
    assert_eq!(a_stats["pushes_sent"], 0);

    // B polls A on a brisk backstop and converges with no push involved.
    let b = Gw::spawn("back-b", "biome/back-b", vec![a.http.clone()], FAST_MS, &[]).await;
    let b_stats = wait_for_json(
        &client,
        &format!("{}/api/stats", b.http),
        Duration::from_secs(10),
        |v| v["applied_peer_revocations"] == 1,
    )
    .await;
    assert_eq!(
        b_stats["pushes_received"], 0,
        "convergence here is backfill, not push"
    );
    assert!(b_stats["backfills"].as_u64().unwrap_or(0) >= 1);
    // Identity was learned from A itself, over the same backfill pass.
    assert_eq!(b_stats["known_peers"], 1);
    // ...which also carried A's signed summary.
    wait_for_json(
        &client,
        &format!("{}/api/stats", b.http),
        Duration::from_secs(10),
        |v| v["peer_summaries"] == 1,
    )
    .await;

    a.shutdown();
    b.shutdown();
}

/// A push aimed at a peer that is not there is counted as a failure and is
/// never fatal — the gateway keeps federating (ADR-265 §4, ADR-269 §3).
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_push_is_counted_and_never_fatal() {
    let client = reqwest::Client::new();
    // Port 1 on loopback: nothing listens there, ever.
    let a = Gw::spawn(
        "dead-peer",
        "biome/dead-peer",
        vec!["http://127.0.0.1:1".into()],
        FAST_MS,
        &[],
    )
    .await;

    revoke(&client, &a.http).await;

    let stats = wait_for_json(
        &client,
        &format!("{}/api/stats", a.http),
        Duration::from_secs(10),
        |v| v["push_failures"].as_u64().unwrap_or(0) >= 1,
    )
    .await;
    assert_eq!(stats["pushes_sent"], 0);
    // Still alive and serving.
    let health = get_json(&client, &format!("{}/health", a.http)).await;
    assert_eq!(health["ok"], true);

    a.shutdown();
}
