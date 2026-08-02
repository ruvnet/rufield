//! The security review's restart acceptance test.
//!
//! Everything here is about state that must **outlive the process**. A
//! gateway that forgets its anti-replay windows, its executed-command ids, or
//! its dedup index on restart offers replay protection only for as long as it
//! happens to stay up — which is not protection at all. Each test below kills
//! the in-memory copy of some security state and checks the durable copy
//! still refuses the attack.
//!
//! The seven criteria, in order:
//!
//! 1. a signed packet accepted before a restart is a **replay** after it;
//! 2. a command id executed before a restart is a **duplicate** after it;
//! 3. an observation whose segment retention has deleted is *still* deduped
//!    after a restart (the dedup index outlives the payload);
//! 4. a serialized `EnvSample` claiming `verified: true` cannot enter a biome
//!    — enforced by the type system, not a runtime check;
//! 5. a registered federation key may not publish under another biome's id;
//! 6. a replayed signed regional summary is rejected;
//! 7. a corrupted **complete** store record is an integrity failure, never
//!    silent truncation.

use rucelium_abi::{NodeSigner, RvEnvSampleV1, RV_ENV_SCHEMA_V1};
use rucelium_core::EnvSample;
use rucelium_federation::{
    verify_summary, AcceptOutcome, Biome, BiomeConfig, FederationBus, FederationError,
};
use rucelium_gateway::{spawn_gateway_with_state, GatewayConfig, GatewayState};
use rucelium_ingest::{DeviceRegistry, IngestPipeline, RejectReason};
use rucelium_policy::verify_receipt;
use rucelium_store::{AppendOutcome, ObservationStore, StoreError};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;

/// Device provisioning seed for this test's spore node.
const SEED: &[u8; 32] = b"rucelium-restart-provision-seed!";
/// The one device the restart gateway knows about.
const NODE: u64 = 0x5CDE_0000_0000_0001;
/// Firmware hash registered for `NODE`.
const FW: &str = "sha256:restart-fw";
/// The sequence number criterion 1 replays.
const SEQUENCE: u32 = 100;
/// Agent the gateway grants actuator authority to at startup.
const AGENT: &str = "agent/flood";
/// The default configured actuator.
const ACTUATOR: &str = "sluice-gate-1";

/// Wall-clock nanoseconds.
fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos() as u64
}

/// A unique temp data dir. Each *test* gets its own directory; the two
/// gateway lifetimes inside a test deliberately share one.
fn temp_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "rucelium-gw-restart-{tag}-{}-{}",
        std::process::id(),
        now_ns()
    ))
}

/// The signer for `NODE`.
fn signer() -> NodeSigner {
    NodeSigner::for_node(SEED, NODE)
}

/// A genuine signed v1 envelope from `NODE`. Deterministic in its arguments,
/// so "the exact same packet" really is byte-identical.
fn envelope(sequence: u32, measured_ns: u64) -> Vec<u8> {
    let wire = RvEnvSampleV1 {
        schema_version: RV_ENV_SCHEMA_V1,
        sensor_type: 5, // weather
        flags: 0,
        node_id: NODE,
        timestamp_ns: measured_ns,
        sequence,
        latitude_e7: 514_778_216,
        longitude_e7: -14_767,
        altitude_mm: 46_000,
        value_q16: 16 * 65_536,
        quality_q15: 0x7000,
        battery_mv: 3_600,
        calibration_id: 0, // uncalibrated: no calibration record needed
    };
    signer().sign_sample(&wire).encode()
}

/// A pipeline with `NODE` provisioned under its real key.
fn pipeline() -> IngestPipeline {
    let mut registry = DeviceRegistry::new();
    registry.register(NODE, signer().public_key(), FW.to_string());
    IngestPipeline::new(registry)
}

/// The plain `EnvSample` behind a freshly ingested envelope. Unwrapping the
/// seal is exactly what storage does — see criterion 4.
fn stored_sample(ingest: &mut IngestPipeline, sequence: u32, measured_ns: u64) -> EnvSample {
    ingest
        .ingest(&envelope(sequence, measured_ns), measured_ns + 1_000_000)
        .expect("genuine envelope ingests")
        .into_inner()
}

/// The gateway config for a restart test: ephemeral ports, a fixed data dir,
/// fsync on so an accepted append really is durable.
fn config(dir: &Path) -> GatewayConfig {
    GatewayConfig {
        biome_id: "biome/restart".into(),
        udp_port: 0,
        http_port: 0,
        data_dir: dir.to_path_buf(),
        fsync: true,
        ..GatewayConfig::default()
    }
}

/// Open a gateway on `dir` with `NODE` provisioned before any traffic can
/// race the registration. The device registry is in-memory provisioning
/// state, so it is re-supplied on each boot — unlike the replay and command
/// state, which must come off disk.
async fn boot(dir: &Path) -> rucelium_gateway::GatewayHandle {
    let cfg = config(dir);
    let state = GatewayState::open(&cfg).expect("open gateway state");
    state.inner.lock().await.ingest.registry_mut().register(
        NODE,
        signer().public_key(),
        FW.to_string(),
    );
    spawn_gateway_with_state(state, cfg)
        .await
        .expect("spawn gateway")
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
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// POST the admin command body, returning `(status, json)`.
async fn post_command(
    client: &reqwest::Client,
    base: &str,
    proposal_id: &str,
) -> (reqwest::StatusCode, Value) {
    let resp = client
        .post(format!("{base}/api/admin/command"))
        .json(&json!({
            "proposal_id": proposal_id,
            "agent_id": AGENT,
            "actuator_id": ACTUATOR,
            "action": "open_fraction",
            "magnitude": 0.5,
        }))
        .send()
        .await
        .expect("POST /api/admin/command");
    let status = resp.status();
    let body = resp.json().await.expect("command response decodes");
    (status, body)
}

/// Stop a gateway: abort every background task so its sockets close and its
/// in-memory state becomes unreachable. Only what reached disk survives.
fn shutdown(handle: rucelium_gateway::GatewayHandle) {
    for task in handle.tasks {
        task.abort();
    }
    drop(handle.state);
}

// ---------------------------------------------------------------------------
// Criteria 1 + 2 — replay protection and command dedup survive a restart
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn replay_and_command_dedup_survive_a_gateway_restart() {
    let client = reqwest::Client::new();
    let dir = temp_dir("replay-command");
    let sender = UdpSocket::bind("127.0.0.1:0").await.expect("bind sender");

    // The exact bytes both gateways will see. Measured a second ago so the
    // reception timestamp is always later (`EnvSample` rejects inverted time).
    let packet = envelope(SEQUENCE, now_ns() - 1_000_000_000);

    // --- First boot ---------------------------------------------------
    let first = boot(&dir).await;
    let first_http = format!("http://127.0.0.1:{}", first.http_port);

    // (1a) A genuine signed packet with sequence 100 is accepted.
    sender
        .send_to(&packet, ("127.0.0.1", first.udp_port))
        .await
        .expect("send packet");
    let stats = wait_for_json(
        &client,
        &format!("{first_http}/api/stats"),
        Duration::from_secs(5),
        |v| v["ingest"]["accepted"] == 1,
    )
    .await;
    assert_eq!(stats["observations"]["records"], 1);
    assert_eq!(stats["ingest"]["replay"], 0);
    assert_eq!(
        stats["observations"]["fsync"], true,
        "the daemon must fsync accepted appends"
    );

    // (2a) Command "cmd-42" runs the whole governed path and yields a signed
    // receipt.
    let (status, body) = post_command(&client, &first_http, "42").await;
    assert!(status.is_success(), "command rejected: {body}");
    let receipt: rucelium_policy::ExecutionReceipt =
        serde_json::from_value(body["receipt"].clone()).expect("receipt decodes");
    assert_eq!(receipt.command_id, "cmd-42");
    assert!(
        verify_receipt(&receipt),
        "the receipt is a gateway-signed attestation"
    );
    let stats = get_json(&client, &format!("{first_http}/api/stats")).await;
    assert_eq!(stats["control"]["commands_executed"], 1);
    assert_eq!(stats["control"]["receipts"], 1);

    // --- Restart on the SAME data dir ---------------------------------
    shutdown(first);
    let second = boot(&dir).await;
    let second_http = format!("http://127.0.0.1:{}", second.http_port);

    // The fresh process starts with empty counters: everything asserted from
    // here on is state that came back off disk, not state that never left.
    let fresh = get_json(&client, &format!("{second_http}/api/stats")).await;
    assert_eq!(fresh["ingest"]["accepted"], 0);
    assert_eq!(fresh["ingest"]["replay"], 0);
    assert_eq!(fresh["control"]["commands_executed"], 0);
    assert_eq!(fresh["control"]["receipts"], 0);
    assert_eq!(
        fresh["observations"]["records"], 1,
        "the durable observation survived the restart"
    );

    // (1b) The exact same packet is now REJECTED as a replay: the anti-replay
    // window was primed from the store's durable dedup index.
    sender
        .send_to(&packet, ("127.0.0.1", second.udp_port))
        .await
        .expect("resend packet");
    let stats = wait_for_json(
        &client,
        &format!("{second_http}/api/stats"),
        Duration::from_secs(5),
        |v| v["ingest"]["replay"] == 1,
    )
    .await;
    assert_eq!(
        stats["ingest"]["accepted"], 0,
        "a replayed packet must never be accepted after a restart"
    );
    assert_eq!(
        stats["observations"]["records"], 1,
        "and it must not be stored a second time"
    );

    // (2b) Re-POSTing command id "cmd-42" is rejected as a duplicate: the
    // phase table came back from `commands.jsonl`.
    let (status, body) = post_command(&client, &second_http, "42").await;
    assert_eq!(
        status,
        reqwest::StatusCode::CONFLICT,
        "duplicate command must not be executed: {body}"
    );
    assert_eq!(body["ok"], false);
    assert_eq!(body["stage"], "gateway_duplicate");
    assert!(
        body.get("receipt").is_none(),
        "a duplicate command must produce no receipt: {body}"
    );
    let stats = get_json(&client, &format!("{second_http}/api/stats")).await;
    assert_eq!(
        stats["control"]["receipts"], 0,
        "no second receipt was produced"
    );
    assert_eq!(stats["control"]["commands_executed"], 0);
    assert_eq!(stats["control"]["proposals_rejected"], 1);

    // A *different* command id still works — the gateway is refusing the
    // replay, not wedged shut.
    let (status, body) = post_command(&client, &second_http, "43").await;
    assert!(status.is_success(), "fresh command id rejected: {body}");

    shutdown(second);
    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// Criterion 3 — dedup outlives retention *and* restart
// ---------------------------------------------------------------------------

/// Retention deletes whole segment *files*; the dedup index is deliberately
/// kept forever. So an observation whose payload is long gone is still enough
/// to reject its replayed envelope after a restart.
///
/// Driven directly against `ObservationStore` + `IngestPipeline` because the
/// daemon's segment size (4096 records) makes segment rollover impractical to
/// reach over HTTP — but this is the exact pair of calls `Inner::open` makes.
#[test]
fn retention_deleted_records_are_still_replay_protected_after_restart() {
    let dir = temp_dir("retention");
    let obs_dir = dir.join("obs");
    let base = now_ns() - 10_000_000_000;

    // One record per segment, so the first sample gets its own deletable file.
    let mut ingest = pipeline();
    let mut store = ObservationStore::open(&obs_dir, 1, true).expect("open store");
    let first = stored_sample(&mut ingest, 1, base);
    let second = stored_sample(&mut ingest, 2, base + 1_000_000_000);
    assert_eq!(store.append(&first).unwrap(), AppendOutcome::Appended);
    assert_eq!(store.append(&second).unwrap(), AppendOutcome::Appended);
    assert_eq!(store.segments().len(), 2);

    // Retention with a 1 ns lifespan drops the first segment entirely (the
    // current segment is never deleted).
    let deleted = store
        .enforce_retention(second.measured_ns + 1, 1)
        .expect("retention runs");
    assert_eq!(deleted, 1, "the expired segment was deleted");
    assert_eq!(store.len(), 1, "its payload is gone");
    drop(store);

    // --- Restart: reopen the store and prime a brand-new pipeline. ---
    let reopened = ObservationStore::open(&obs_dir, 1, true).expect("reopen store");
    assert_eq!(
        reopened.len(),
        1,
        "payload stayed deleted across the restart"
    );
    assert!(
        reopened.dedup_keys().contains(&(NODE, 1)),
        "the dedup key outlives the segment that held its payload"
    );

    // Control: without priming, the restarted gateway would re-accept it.
    let mut unprimed = pipeline();
    assert!(
        unprimed.ingest(&envelope(1, base), now_ns()).is_ok(),
        "sanity: an unprimed pipeline has no memory of the packet"
    );

    // With priming — what `Inner::open` actually does — it is a replay.
    let mut primed = pipeline();
    primed.prime_from_dedup(reopened.dedup_keys());
    assert_eq!(
        primed.ingest(&envelope(1, base), now_ns()),
        Err(RejectReason::Replay {
            node_id: NODE,
            sequence: 1
        })
    );
    assert_eq!(primed.stats().accepted, 0);
    assert_eq!(primed.stats().replay, 1);

    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// Criterion 4 — `"verified": true` in JSON is not a way into a biome
// ---------------------------------------------------------------------------

/// A serialized `EnvSample` can claim anything it likes, including
/// `provenance.verified = true`. It still cannot reach `Biome::accept`,
/// because `accept` does not take an `EnvSample` at all — it takes a
/// `rucelium_ingest::VerifiedEnvSample`, which is not `Deserialize` and has no
/// public constructor. The only producers are `IngestPipeline::ingest` and
/// `IngestPipeline::reverify_stored`, both of which run the full registry +
/// signature verification.
///
/// This is enforced at **compile time**, so the negative half of the property
/// cannot be written as a runtime assertion here. It lives as a `compile_fail`
/// doctest on `rucelium_federation::Biome::accept` (and is exercised by
/// `cargo test -p rucelium-federation --doc`); this test pins the positive
/// half: the one honest path in, and the fact that unwrapping for storage
/// really does drop the seal.
#[test]
fn a_deserialized_verified_sample_cannot_enter_the_biome() {
    let mut ingest = pipeline();
    let base = now_ns() - 1_000_000_000;

    // Round-trip a genuine sample through JSON, exactly as an attacker with
    // write access to the store (or a peer feeding us JSON) would have it.
    let genuine = stored_sample(&mut ingest, 7, base);
    let forged_json = serde_json::to_string(&genuine).expect("sample serializes");
    let forged: EnvSample = serde_json::from_str(&forged_json).expect("sample deserializes");
    assert!(
        forged.provenance.verified,
        "the JSON does claim verified = true"
    );

    // `biome.accept(forged)` is a compile error — see the doc comment above.
    let mut biome = Biome::new(
        BiomeConfig::new("biome/restart"),
        b"rucelium-restart-biome-seed-32b!",
    );

    // The only path in: a real signed envelope through a real pipeline.
    let sealed = ingest
        .ingest(&envelope(8, base), now_ns())
        .expect("genuine envelope ingests");
    assert!(sealed.sample().provenance.verified);
    assert_eq!(biome.accept(sealed), AcceptOutcome::Accepted);
    assert_eq!(
        biome.accepted_count(),
        1,
        "exactly the one sample that came through ingest"
    );

    // And restoring a stored sample requires the original envelope bytes: the
    // seal cannot be re-created from the JSON. Re-verifying the envelope of
    // the sample the biome already holds yields a fresh seal — which the
    // biome's dedup index then correctly refuses.
    let restored = ingest
        .reverify_stored(&envelope(8, base), now_ns())
        .expect("stored envelope re-verifies");
    assert_eq!(restored.sample().node_id, forged.node_id);
    assert_eq!(
        biome.accept(restored),
        AcceptOutcome::Duplicate,
        "the biome dedup index recognises it from the live path"
    );

    // Tampering with the stored bytes breaks re-verification outright, so no
    // seal exists to hand to the biome at all.
    let mut tampered = envelope(7, base);
    tampered[3 + 36] ^= 0x01; // value_q16 inside the signed payload
    assert!(
        matches!(
            ingest.reverify_stored(&tampered, now_ns()),
            Err(RejectReason::BadSignature(NODE))
        ),
        "a tampered stored envelope never re-earns the seal"
    );
    assert_eq!(biome.accepted_count(), 1);
}

// ---------------------------------------------------------------------------
// Criteria 5 + 6 — federation identity binding and summary replay
// ---------------------------------------------------------------------------

/// Two honestly registered biomes. Signing a summary that *claims* the other
/// biome's id is an `IdentityMismatch`, even though the signature verifies and
/// the signing key is genuinely registered — just not for that id.
#[test]
fn a_registered_key_cannot_claim_another_biome_identity() {
    let a = Biome::new(
        BiomeConfig::new("biome/a"),
        b"rucelium-restart-biome-a-seed!!!",
    );
    let b = Biome::new(
        BiomeConfig::new("biome/b"),
        b"rucelium-restart-biome-b-seed!!!",
    );
    let mut bus = FederationBus::new();
    bus.register_biome("biome/a", a.public_key_hex(), 1)
        .expect("register a");
    bus.register_biome("biome/b", b.public_key_hex(), 1)
        .expect("register b");

    // A's key signs a summary stamped with B's identity.
    let mut cross = a.summarize(0, 1_000);
    cross.biome_id = "biome/b".into();
    a.sign_summary(&mut cross);
    assert!(
        verify_summary(&cross),
        "the signature itself is perfectly valid"
    );

    assert_eq!(
        bus.publish(cross),
        Err(FederationError::IdentityMismatch {
            biome_id: "biome/b".into()
        })
    );
    assert!(
        bus.summaries().is_empty(),
        "nothing was published under the stolen identity"
    );
}

/// A signed regional summary is accepted once per `(biome, window)`. Replays
/// — byte-identical or freshly re-signed — are `DuplicateSummary`.
#[test]
fn a_duplicated_signed_summary_is_rejected() {
    let a = Biome::new(
        BiomeConfig::new("biome/a"),
        b"rucelium-restart-biome-a-seed!!!",
    );
    let mut bus = FederationBus::new();
    bus.register_biome("biome/a", a.public_key_hex(), 1)
        .expect("register a");

    let summary = a.summarize(0, 1_000);
    bus.publish(summary.clone()).expect("first publish");

    assert_eq!(
        bus.publish(summary),
        Err(FederationError::DuplicateSummary),
        "an exact replay is refused"
    );
    let mut resigned = a.summarize(0, 1_000);
    a.sign_summary(&mut resigned);
    assert_eq!(
        bus.publish(resigned),
        Err(FederationError::DuplicateSummary),
        "re-signing the same window does not launder the replay"
    );

    // A genuinely new window still publishes.
    bus.publish(a.summarize(1_000, 2_000))
        .expect("new window publishes");
    assert_eq!(bus.summaries().len(), 2);
}

// ---------------------------------------------------------------------------
// Criterion 7 — corruption is an error, not a silent truncation
// ---------------------------------------------------------------------------

/// Torn-tail repair exists for a crash mid-write: a *final*, unterminated,
/// undecodable line. A **complete** record — newline-terminated, well-formed
/// framing — that no longer matches its CRC is corruption, and the store must
/// say so rather than quietly dropping it and everything after it.
#[test]
fn a_corrupted_complete_record_is_an_integrity_error_not_truncation() {
    let dir = temp_dir("corrupt");
    let obs_dir = dir.join("obs");
    let base = now_ns() - 10_000_000_000;

    let mut ingest = pipeline();
    let mut store = ObservationStore::open(&obs_dir, 100, true).expect("open store");
    store
        .append(&stored_sample(&mut ingest, 1, base))
        .expect("append first");
    store
        .append(&stored_sample(&mut ingest, 2, base + 1_000_000_000))
        .expect("append second");
    assert_eq!(store.len(), 2);
    drop(store);

    // Flip a byte in the MIDDLE of the file: inside the first record, which
    // is complete and newline-terminated, with a valid record after it. The
    // edit keeps the JSON parseable and the same length, so the only thing
    // that gives it away is the CRC.
    let path = obs_dir.join("obs-000000.jsonl");
    let text = std::fs::read_to_string(&path).expect("read segment");
    let newline = text.find('\n').expect("two records means a newline");
    assert!(
        newline + 1 < text.len(),
        "the corrupted record must not be the final line"
    );
    let (first_line, rest) = text.split_at(newline);
    assert!(
        first_line.contains("air_temperature"),
        "expected the observed property in the record"
    );
    let tampered = format!(
        "{}{rest}",
        first_line.replace("air_temperature", "air_temperaturx")
    );
    assert_eq!(
        tampered.len(),
        text.len(),
        "same length: only the content changed"
    );
    std::fs::write(&path, &tampered).expect("write tampered segment");

    // Reopening reports the integrity failure, naming the segment and line.
    match ObservationStore::open(&obs_dir, 100, true) {
        Err(StoreError::Corrupt {
            segment,
            line,
            reason,
        }) => {
            assert_eq!(segment, "obs-000000.jsonl");
            assert_eq!(line, 1);
            assert_eq!(reason, "crc mismatch");
        }
        Err(other) => panic!("expected a Corrupt error, got {other:?}"),
        Ok(_) => panic!("a corrupted complete record must not open successfully"),
    }

    // And nothing was truncated away in the attempt.
    assert_eq!(
        std::fs::read(&path).expect("re-read segment").len(),
        tampered.len(),
        "the failed open must not have rewritten the segment"
    );

    std::fs::remove_dir_all(&dir).ok();
}
