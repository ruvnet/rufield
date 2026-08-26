//! ADR-269 §4 acceptance for the optional QUIC transport (`--features quic`).
//!
//! The important test in this file is the second one. QUIC's job here is
//! defence in depth — connection migration, loss recovery, and closing the
//! alert-*timing* side channel — and the ADR is normative that it must never
//! become the trust boundary. So the properties are:
//!
//! 1. the biome's ed25519 identity really is the TLS identity, and an
//!    announce round-trips and then **verifies through the same gate** as
//!    anything polled over HTTP;
//! 2. **a peer whose TLS identity is not its registered federation key is
//!    refused** — no connection, no artifact, and a precise
//!    `IdentityRefused` naming both keys;
//! 3. summaries and events occupy independent streams, so a large summary
//!    cannot stall a revocation (§4.3);
//! 4. `sync_since` backfills over QUIC as it does over HTTP (§3).

#![cfg(feature = "quic")]

use rucelium_abi::NodeSigner;
use rucelium_federation::ModalityStats;
use rucelium_federation::{Biome, BiomeConfig};
use rucelium_gateway::federation::{accept_artifact, register_peer_identity, ArtifactEffect};
use rucelium_gateway::transport::{
    FederationArtifact, FederationTransport, PeerRef, StreamClass, TransportError,
};
use rucelium_gateway::transport_quic::{BackfillSource, QuicTransport};
use rucelium_gateway::{GatewayConfig, Inner};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Biome signing seeds. Distinct seeds ⇒ distinct federation keys ⇒
/// distinct pinned TLS identities.
const SEED_A: &[u8; 32] = b"rucelium-quic-biome-a-seed-32b!!";
const SEED_B: &[u8; 32] = b"rucelium-quic-biome-b-seed-32b!!";
const SEED_C: &[u8; 32] = b"rucelium-quic-biome-c-seed-32b!!";
/// Device provisioning seed.
const NODE_SEED: &[u8; 32] = b"rucelium-quic-node-seed-32-byte!";
/// The device the revocation targets.
const NODE: u64 = 0x5CFC_0000_0000_0001;

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
        "rucelium-gw-quic-{tag}-{}-{}",
        std::process::id(),
        now_ns()
    ))
}

/// A local QUIC endpoint whose TLS identity is `biome_id`'s ed25519 key.
fn endpoint(biome_id: &str, seed: &[u8; 32], backfill: Option<BackfillSource>) -> QuicTransport {
    QuicTransport::bind(
        "127.0.0.1:0".parse().expect("loopback address"),
        biome_id,
        seed,
        backfill,
    )
    .expect("quic endpoint binds")
}

/// A fresh gateway state with `NODE` provisioned and `peer`'s federation
/// identity registered, so a received revocation can actually apply.
fn inner_knowing(tag: &str, peer_biome: &str, peer_key: &str) -> Inner {
    let config = GatewayConfig {
        data_dir: temp_dir(tag),
        ..GatewayConfig::default()
    };
    let mut inner = Inner::open(&config).expect("inner opens");
    inner.ingest.registry_mut().register(
        NODE,
        NodeSigner::for_node(NODE_SEED, NODE).public_key(),
        "sha256:quic-fw".into(),
    );
    register_peer_identity(&mut inner, peer_biome, peer_key, "quic://peer");
    inner
}

/// Drain `transport` until it has yielded `n` artifacts, or panic.
async fn collect(
    transport: &QuicTransport,
    peer: &PeerRef,
    n: usize,
    timeout: Duration,
) -> Vec<FederationArtifact> {
    let deadline = Instant::now() + timeout;
    let mut out = Vec::new();
    while out.len() < n {
        out.extend(transport.subscribe(peer).await.expect("subscribe"));
        if out.len() >= n {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "timed out with {} of {n} artifacts",
            out.len()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    out
}

/// A deliberately bulky signed summary: ~6000 modality buckets, several
/// hundred kilobytes on the wire.
fn bulky_summary(biome: &Biome) -> FederationArtifact {
    let mut stats = BTreeMap::new();
    for i in 0..6_000u32 {
        stats.insert(
            format!("synthetic-modality-{i:05}"),
            ModalityStats {
                count: u64::from(i),
                mean: f64::from(i),
                min: 0.0,
                max: f64::from(i),
                mean_quality: 0.875,
            },
        );
    }
    let mut summary = rucelium_federation::RegionalSummary {
        spec_version: rucelium_core::SPEC_VERSION.into(),
        biome_id: biome.config().biome_id.clone(),
        window_start_ns: 0,
        window_end_ns: 1_000,
        stats,
        signature_hex: None,
        signer_pubkey_hex: None,
    };
    biome.sign_summary(&mut summary);
    FederationArtifact::Summary(summary)
}

/// (1) The QUIC TLS identity *is* the biome signing identity, an announce
/// round-trips, and what arrives is verified by the ordinary gate.
#[tokio::test(flavor = "multi_thread")]
async fn quic_announce_round_trips_and_the_artifact_still_has_to_verify() {
    let a = endpoint("biome/quic-a", SEED_A, None);
    let b = endpoint("biome/quic-b", SEED_B, None);

    // The endpoint's advertised key is exactly the biome's signing key —
    // one key, not two provisioned together (ADR-269 §4).
    let biome_a = Biome::new(BiomeConfig::new("biome/quic-a"), SEED_A);
    assert_eq!(
        a.local_identity().pubkey_hex,
        biome_a.public_key_hex(),
        "the QUIC identity must be the biome's ed25519 federation key"
    );
    assert_eq!(a.name(), "quic");

    let peer_b = b.peer_ref().expect("b advertises itself");
    let mut signer = Biome::new(BiomeConfig::new("biome/quic-a"), SEED_A);
    let event = signer.revoke_device(NODE, now_ns(), "compromised");
    let artifact = FederationArtifact::Event(event.clone());

    a.announce(&peer_b, &artifact)
        .await
        .expect("announce over quic");

    let received = collect(&b, &peer_b, 1, Duration::from_secs(10)).await;
    assert_eq!(received[0], artifact, "the artifact survives the wire");

    // ADR-269 §4, normative: arriving over QUIC changes nothing about
    // verification. It goes through the same gate as an HTTP poll.
    let mut inner = inner_knowing("verify", "biome/quic-a", &biome_a.public_key_hex());
    assert_eq!(
        accept_artifact(&mut inner, &received[0]),
        Ok(ArtifactEffect::RevocationApplied)
    );
    assert!(inner.ingest.registry().is_revoked(NODE));

    // ...and a tampered copy that took the very same QUIC path is refused.
    let mut tampered = event;
    tampered.message.push('!');
    assert!(accept_artifact(&mut inner, &FederationArtifact::Event(tampered)).is_err());
}

/// **(2) The one that matters.** A peer's TLS identity must equal its
/// registered federation key or the connection is refused (ADR-269 §4,
/// normative). Here A dials B while pinning *C's* key: the handshake must
/// fail, the error must name both keys, and nothing may cross.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_presenting_the_wrong_key_is_refused_and_delivers_nothing() {
    let a = endpoint("biome/quic-a", SEED_A, None);
    let b = endpoint("biome/quic-b", SEED_B, None);
    let c_key = Biome::new(BiomeConfig::new("biome/quic-c"), SEED_C).public_key_hex();
    let b_key = b.local_identity().pubkey_hex.clone();
    assert_ne!(b_key, c_key);

    // B's address, C's key. This is the impersonation the pin exists for:
    // an attacker who controls the address but not the biome key.
    let honest_b = b.peer_ref().expect("b advertises itself");
    let impersonated = PeerRef::with_identity(&honest_b.url, "biome/quic-c", &c_key);

    let mut signer = Biome::new(BiomeConfig::new("biome/quic-a"), SEED_A);
    let artifact = FederationArtifact::Event(signer.revoke_device(NODE, now_ns(), "compromised"));

    let err = a
        .announce(&impersonated, &artifact)
        .await
        .expect_err("a mismatched TLS identity must refuse the connection");
    match err {
        TransportError::IdentityRefused { expected, got } => {
            assert_eq!(expected, c_key, "expected key must be the pinned one");
            assert_eq!(got, b_key, "reported key must be what the peer presented");
        }
        other => panic!("expected IdentityRefused, got {other}"),
    }

    // Nothing crossed, and no stream was left open to the refused peer.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        b.subscribe(&honest_b).await.expect("subscribe").is_empty(),
        "a refused connection must not deliver artifacts"
    );
    assert!(a.open_stream_classes(&impersonated).await.is_empty());

    // The same endpoint, dialled with the *correct* key, works — proving
    // the refusal was the pin and not a broken endpoint.
    a.announce(&honest_b, &artifact)
        .await
        .expect("the honest pin connects");
    let received = collect(&b, &honest_b, 1, Duration::from_secs(10)).await;
    assert_eq!(received[0], artifact);
}

/// (3) ADR-269 §4.3: separate streams per artifact class, so a stalled or
/// bulky summary cannot block a revocation. The structural assertion (two
/// distinct streams, each with its own lock) is deterministic; the latency
/// bound is deliberately loose.
#[tokio::test(flavor = "multi_thread")]
async fn summaries_and_revocations_travel_on_independent_streams() {
    let a = endpoint("biome/quic-a", SEED_A, None);
    let b = endpoint("biome/quic-b", SEED_B, None);
    let peer_b = Arc::new(b.peer_ref().expect("b advertises itself"));

    let biome_a = Biome::new(BiomeConfig::new("biome/quic-a"), SEED_A);
    let summary = bulky_summary(&biome_a);
    let mut signer = Biome::new(BiomeConfig::new("biome/quic-a"), SEED_A);
    let revocation = FederationArtifact::Event(signer.revoke_device(NODE, now_ns(), "urgent"));

    // The bulky summary goes first and keeps its own stream busy...
    let summary_send = a.announce(&peer_b, &summary);
    // ...while the revocation is announced on the event stream. If the two
    // classes shared a stream (or a lock), this would have to wait.
    let started = Instant::now();
    let (summary_result, revocation_result) =
        tokio::join!(summary_send, a.announce(&peer_b, &revocation));
    summary_result.expect("summary announced");
    revocation_result.expect("revocation announced");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "revocation announce must not wait on the bulky summary"
    );

    // Structural: two open streams, one per class.
    let mut classes = a.open_stream_classes(&peer_b).await;
    classes.sort();
    assert_eq!(classes, vec![StreamClass::Summary, StreamClass::Event]);

    // Both arrive, and the revocation is not held hostage by the summary.
    let received = collect(&b, &peer_b, 2, Duration::from_secs(20)).await;
    assert!(received.contains(&revocation), "revocation must arrive");
    assert!(received.contains(&summary), "summary must arrive");
}

/// (4) ADR-269 §3: the mandatory backstop works over QUIC too — a fresh
/// bidirectional stream carries the peer's cursor and comes back with the
/// artifacts, which then face the same verification as everything else.
#[tokio::test(flavor = "multi_thread")]
async fn quic_backfill_serves_the_peers_cursor() {
    let mut biome_b = Biome::new(BiomeConfig::new("biome/quic-b"), SEED_B);
    let event = biome_b.revoke_device(NODE, now_ns(), "backfilled");
    let served = vec![FederationArtifact::Event(event)];
    let seen_cursor = Arc::new(std::sync::Mutex::new(Vec::<u64>::new()));

    let recorder = seen_cursor.clone();
    let answers = served.clone();
    let source: BackfillSource = Arc::new(move |since_ns| {
        recorder.lock().expect("cursor lock").push(since_ns);
        answers.clone()
    });

    let a = endpoint("biome/quic-a", SEED_A, None);
    let b = endpoint("biome/quic-b", SEED_B, Some(source));
    let peer_b = b.peer_ref().expect("b advertises itself");

    let got = a
        .sync_since(&peer_b, 1_234_567_890)
        .await
        .expect("backfill over quic");
    assert_eq!(got, served);
    assert_eq!(
        seen_cursor.lock().expect("cursor lock").as_slice(),
        &[1_234_567_890]
    );

    // Verified like anything else.
    let mut inner = inner_knowing("backfill", "biome/quic-b", &b.local_identity().pubkey_hex);
    assert_eq!(
        accept_artifact(&mut inner, &got[0]),
        Ok(ArtifactEffect::RevocationApplied)
    );

    // An endpoint with no backfill source answers empty rather than lying.
    let c = endpoint("biome/quic-c", SEED_C, None);
    let peer_c = c.peer_ref().expect("c advertises itself");
    assert!(a
        .sync_since(&peer_c, 0)
        .await
        .expect("empty backfill")
        .is_empty());
}

/// A QUIC peer with no pinned federation key cannot be dialled at all —
/// there is no "connect first, decide later" path (ADR-269 §4).
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_without_a_pinned_key_is_never_dialled() {
    let a = endpoint("biome/quic-a", SEED_A, None);
    let b = endpoint("biome/quic-b", SEED_B, None);
    let unpinned = PeerRef::new(b.peer_ref().expect("b advertises itself").url);

    let mut signer = Biome::new(BiomeConfig::new("biome/quic-a"), SEED_A);
    let artifact = FederationArtifact::Event(signer.revoke_device(NODE, now_ns(), "x"));
    let err = a
        .announce(&unpinned, &artifact)
        .await
        .expect_err("an unpinned peer cannot be dialled");
    assert!(
        matches!(err, TransportError::Protocol(_)),
        "unexpected error: {err}"
    );
    assert!(a.identity(&unpinned).await.is_err());
}
