//! End-to-end test of the running daemon stack (ADR-265 §4): two gateways
//! on ephemeral ports, real UDP envelopes, the real HTTP API, and network
//! federation of a device revocation from gateway A to gateway B.

use rucelium_abi::{NodeSigner, RvEnvSampleV1, RV_ENV_SCHEMA_V1};
use rucelium_gateway::{spawn_gateway_with_state, GatewayConfig, GatewayState};
use serde_json::Value;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;

const SEED: &[u8; 32] = b"rucelium-e2e-provision-seed-32b!";
const NODE: u64 = 0x5CE2_0000_0000_0001;

/// Unique temp data dir per gateway under the system temp dir.
fn temp_dir(tag: &str) -> PathBuf {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("rucelium-gw-e2e-{tag}-{}-{t}", std::process::id()))
}

/// A genuine signed v1 envelope from `NODE` with the given sequence.
fn envelope(sequence: u32) -> Vec<u8> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos() as u64;
    let wire = RvEnvSampleV1 {
        schema_version: RV_ENV_SCHEMA_V1,
        sensor_type: 5, // weather
        flags: 0,
        node_id: NODE,
        timestamp_ns: ts,
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
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn full_stack_ingest_api_and_peer_revocation_federation() {
    let client = reqwest::Client::new();
    let signer = NodeSigner::for_node(SEED, NODE);
    let sender = UdpSocket::bind("127.0.0.1:0").await.expect("bind sender");

    // --- Gateway A: full stack on ephemeral ports, node provisioned before
    // any traffic can race the registration. ---
    let dir_a = temp_dir("a");
    let cfg_a = GatewayConfig {
        biome_id: "biome/e2e-a".into(),
        udp_port: 0,
        http_port: 0,
        data_dir: dir_a.clone(),
        federation_poll_ms: 200,
        ..GatewayConfig::default()
    };
    let state_a = GatewayState::open(&cfg_a).expect("open state a");
    state_a.inner.lock().await.ingest.registry_mut().register(
        NODE,
        signer.public_key(),
        "sha256:e2e-fw".into(),
    );
    let a = spawn_gateway_with_state(state_a, cfg_a)
        .await
        .expect("spawn gateway a");
    let a_http = format!("http://127.0.0.1:{}", a.http_port);

    // (1) Health.
    let health = get_json(&client, &format!("{a_http}/health")).await;
    assert_eq!(health["ok"], true);
    assert_eq!(health["biome_id"], "biome/e2e-a");

    // (2) A genuine signed envelope over real UDP is accepted end to end.
    sender
        .send_to(&envelope(1), ("127.0.0.1", a.udp_port))
        .await
        .expect("send envelope to a");
    let stats = wait_for_json(
        &client,
        &format!("{a_http}/api/stats"),
        Duration::from_secs(5),
        |v| v["ingest"]["accepted"] == 1,
    )
    .await;
    assert_eq!(stats["observations"]["records"], 1);
    assert_eq!(stats["biome"]["accepted"], 1);
    assert_eq!(stats["worldgraph"]["nodes"], 1);

    // (3) The SensorThings projection serves the observation.
    let st = get_json(&client, &format!("{a_http}/api/sensorthings/Observations")).await;
    let obs = st["value"].as_array().expect("value array");
    assert_eq!(obs.len(), 1);
    assert_eq!(obs[0]["@iot.id"], format!("obs:{NODE}:1"));
    let things = get_json(&client, &format!("{a_http}/api/sensorthings/Things")).await;
    assert_eq!(things["value"].as_array().expect("things").len(), 1);

    // (4) Admin revocation produces one signed DeviceRevoked event.
    client
        .post(format!("{a_http}/api/admin/revoke/{NODE}"))
        .send()
        .await
        .expect("revoke request")
        .error_for_status()
        .expect("revoke ok");
    let revs = get_json(&client, &format!("{a_http}/api/federation/revocations")).await;
    let revs = revs.as_array().expect("revocations array");
    assert_eq!(revs.len(), 1);
    let event: rucelium_core::EnvironmentalEvent =
        serde_json::from_value(revs[0].clone()).expect("event decodes");
    assert!(
        rucelium_federation::verify_event(&event),
        "served revocation must verify"
    );

    // --- Gateway B: peers with A; the same node is provisioned before the
    // federation task starts, so the peer revocation must land on it. ---
    let dir_b = temp_dir("b");
    let cfg_b = GatewayConfig {
        biome_id: "biome/e2e-b".into(),
        udp_port: 0,
        http_port: 0,
        data_dir: dir_b.clone(),
        peers: vec![a_http.clone()],
        federation_poll_ms: 200,
        ..GatewayConfig::default()
    };
    let state_b = GatewayState::open(&cfg_b).expect("open state b");
    state_b.inner.lock().await.ingest.registry_mut().register(
        NODE,
        signer.public_key(),
        "sha256:e2e-fw".into(),
    );
    let b = spawn_gateway_with_state(state_b, cfg_b)
        .await
        .expect("spawn gateway b");
    let b_http = format!("http://127.0.0.1:{}", b.http_port);

    // (5) B applies A's verified revocation within a few poll ticks.
    let b_stats = wait_for_json(
        &client,
        &format!("{b_http}/api/stats"),
        Duration::from_secs(10),
        |v| v["applied_peer_revocations"] == 1,
    )
    .await;
    assert_eq!(b_stats["applied_peer_revocations"], 1);
    // ...and it verified A's summary too.
    wait_for_json(
        &client,
        &format!("{b_http}/api/stats"),
        Duration::from_secs(10),
        |v| v["peer_summaries"] == 1,
    )
    .await;
    let peers = get_json(&client, &format!("{b_http}/api/federation/peers")).await;
    assert_eq!(peers.as_array().expect("peers array").len(), 1);
    assert_eq!(peers[0]["summary"]["biome_id"], "biome/e2e-a");

    // (6) B's registry now rejects the revoked node's envelopes over UDP.
    sender
        .send_to(&envelope(2), ("127.0.0.1", b.udp_port))
        .await
        .expect("send envelope to b");
    wait_for_json(
        &client,
        &format!("{b_http}/api/stats"),
        Duration::from_secs(5),
        |v| v["ingest"]["revoked_device"] == 1,
    )
    .await;
    let b_final = get_json(&client, &format!("{b_http}/api/stats")).await;
    assert_eq!(b_final["ingest"]["accepted"], 0);
    assert_eq!(b_final["observations"]["records"], 0);

    // Shut both gateways down and clean up.
    for task in a.tasks.into_iter().chain(b.tasks) {
        task.abort();
    }
    std::fs::remove_dir_all(&dir_a).ok();
    std::fs::remove_dir_all(&dir_b).ok();
}
