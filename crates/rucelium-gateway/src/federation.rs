//! Transport-driven, push-first biome federation (ADR-269 §3).
//!
//! Federation used to be a 30 s poller (ADR-265 §4). ADR-269 §3 calls that
//! out as a *security* problem before a performance one: polling caps
//! revocation latency at the polling interval, so a revoked device stayed
//! valid at peer gateways for up to 30 s after its owner revoked it. The
//! task below is therefore **push first, transport second**:
//!
//! * a locally minted artifact (today: a `DeviceRevoked` event from
//!   `POST /api/admin/revoke/{node_id}`) is
//!   [`announce`](crate::transport::FederationTransport::announce)d to every
//!   peer the instant it exists — no waiting for a tick;
//! * [`subscribe`](crate::transport::FederationTransport::subscribe) drains
//!   whatever a peer streamed at us;
//! * **the polling backstop is mandatory** (ADR-269 §3):
//!   [`sync_since`](crate::transport::FederationTransport::sync_since) still
//!   runs at startup, on reconnect, and on a slow timer, so a peer that
//!   missed a push still converges.
//!
//! # Verification is transport-independent (ADR-269 §4, normative)
//!
//! **Everything received — over any transport, pushed or polled — goes
//! through exactly the same verification.** [`accept_artifact`] is the one
//! gate: the artifact's claimed `biome_id` must resolve to a federation key
//! this gateway learned from the peer itself, the artifact's signer key must
//! *be* that key, the ed25519 signature must verify over the canonical
//! bytes, and revocations are idempotent by `event_id`. A QUIC session, an
//! authenticated HTTP connection, or any other channel property is **never**
//! the reason an artifact is trusted; if it ever becomes one, that is a
//! regression. Unverifiable data is skipped and logged — never applied,
//! never repaired (ADR-264 §12).

use crate::state::{now_ns, GatewayState, Inner, KnownPeer, PeerSummary};
use crate::transport::{FederationArtifact, FederationTransport, PeerRef, TransportError};
use rucelium_core::{EnvironmentalEvent, EventKind};
use rucelium_federation::{verify_event, verify_summary};
use std::sync::Arc;
use std::time::Duration;

/// How often `subscribe` is drained. Only transports with real server push
/// (QUIC) return anything; for HTTP this is a no-op timer with no I/O.
const SUBSCRIBE_TICK: Duration = Duration::from_millis(200);
/// Floor on the backfill interval, so a misconfigured `0` cannot spin.
const MIN_BACKFILL_MS: u64 = 50;

/// Why a received artifact was refused. Every variant means **not applied**
/// and, at the `POST /api/federation/announce` endpoint, a 4xx.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactRejection {
    /// The artifact carried no signer key at all.
    Unsigned,
    /// The claimed `biome_id` is not a peer whose federation key this
    /// gateway has learned. An unknown biome cannot be identity-bound, so it
    /// cannot be trusted (ADR-269 §4).
    UnknownBiome(String),
    /// The signer key is not the key registered for the claimed `biome_id` —
    /// a valid signature from some *other* key is still refused, because
    /// peers may only speak on their own authority.
    IdentityMismatch {
        /// The biome identity the artifact claimed.
        biome_id: String,
    },
    /// The ed25519 signature did not verify over the canonical bytes.
    BadSignature,
    /// Verified, but nothing to do: a non-revocation event, a duplicate
    /// `event_id`, or a revocation for a node this gateway has never
    /// provisioned (left unapplied so a later provisioning picks it up).
    NoEffect,
}

impl std::fmt::Display for ArtifactRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactRejection::Unsigned => write!(f, "artifact is unsigned"),
            ArtifactRejection::UnknownBiome(id) => {
                write!(f, "not a known federation peer biome: {id}")
            }
            ArtifactRejection::IdentityMismatch { biome_id } => {
                write!(f, "signer key is not the registered key for {biome_id}")
            }
            ArtifactRejection::BadSignature => write!(f, "signature verification failed"),
            ArtifactRejection::NoEffect => write!(f, "verified, but no state change"),
        }
    }
}

impl std::error::Error for ArtifactRejection {}

/// What a verified artifact did to local state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactEffect {
    /// A verified peer summary was stored.
    SummaryStored,
    /// A verified `DeviceRevoked` event was applied to the local registry.
    RevocationApplied,
}

/// Learn (or refresh) a peer's federation identity — the `biome_id → key`
/// binding [`accept_artifact`] resolves against. The peer's own published
/// key is authoritative for that peer, exactly as in the ADR-265 §4 poller.
pub fn register_peer_identity(inner: &mut Inner, biome_id: &str, pubkey_hex: &str, url: &str) {
    inner.known_peers.insert(
        biome_id.to_string(),
        KnownPeer {
            biome_id: biome_id.to_string(),
            pubkey_hex: pubkey_hex.to_string(),
            url: url.to_string(),
        },
    );
}

/// Apply one peer `DeviceRevoked` event to the local registry. Returns
/// `true` only when the event was **verified and newly applied**:
///
/// 1. `kind == DeviceRevoked`;
/// 2. the event's signer key equals the peer's published key (a valid
///    signature from any *other* key is refused — peers may only revoke on
///    their own authority);
/// 3. the ed25519 signature verifies over the canonical event bytes;
/// 4. the `event_id` was not already applied;
/// 5. the target node is registered locally (otherwise the event is left
///    unapplied so a later provisioning can pick it up on the next poll).
///
/// Factored out of the network task so it is unit-testable without any I/O.
///
/// **Normative (ADR-269 §4)**: this function is transport-independent and is
/// the *only* way a peer revocation reaches the registry. A revocation that
/// arrived over QUIC, over an HTTP push, or over an HTTP backfill runs these
/// same five checks; no transport property substitutes for any of them.
pub fn apply_peer_revocation(
    inner: &mut Inner,
    event: &EnvironmentalEvent,
    peer_pubkey_hex: &str,
) -> bool {
    if event.kind != EventKind::DeviceRevoked {
        return false;
    }
    if event.signer_pubkey_hex.as_deref() != Some(peer_pubkey_hex) {
        return false;
    }
    if !verify_event(event) {
        return false;
    }
    let Some(evidence) = event.evidence.first() else {
        return false;
    };
    if inner.applied_revocation_ids.contains(&event.event_id) {
        return false;
    }
    if inner.ingest.registry().get(evidence.node_id).is_none() {
        return false;
    }
    inner.ingest.registry_mut().revoke(evidence.node_id);
    inner.applied_revocation_ids.insert(event.event_id.clone());
    inner.applied_peer_revocations += 1;
    true
}

/// **The one verification gate** every federation artifact passes through,
/// whatever transport delivered it and whether it was pushed or polled
/// (ADR-269 §4, normative).
///
/// In order:
///
/// 1. the artifact must carry a signer key ([`ArtifactRejection::Unsigned`]);
/// 2. its claimed `biome_id` must be a peer whose key this gateway learned
///    from that peer ([`ArtifactRejection::UnknownBiome`]);
/// 3. its signer key must be *that* key
///    ([`ArtifactRejection::IdentityMismatch`] — a registered key claiming
///    another biome's identity is refused);
/// 4. the ed25519 signature must verify over the canonical bytes
///    ([`ArtifactRejection::BadSignature`]);
/// 5. summaries replace the stored summary for that biome; revocations go
///    through [`apply_peer_revocation`], which dedups by `event_id`.
pub fn accept_artifact(
    inner: &mut Inner,
    artifact: &FederationArtifact,
) -> Result<ArtifactEffect, ArtifactRejection> {
    let Some(signer) = artifact.signer_pubkey_hex() else {
        return Err(ArtifactRejection::Unsigned);
    };
    let biome_id = artifact.biome_id().to_string();
    let Some(known) = inner.known_peers.get(&biome_id) else {
        return Err(ArtifactRejection::UnknownBiome(biome_id));
    };
    if known.pubkey_hex != signer {
        return Err(ArtifactRejection::IdentityMismatch { biome_id });
    }
    let peer_key = known.pubkey_hex.clone();
    let peer_url = known.url.clone();

    match artifact {
        FederationArtifact::Summary(summary) => {
            if !verify_summary(summary) {
                return Err(ArtifactRejection::BadSignature);
            }
            inner
                .peer_summaries
                .retain(|p| p.summary.biome_id != summary.biome_id);
            inner.peer_summaries.push(PeerSummary {
                peer: peer_url,
                summary: summary.clone(),
                fetched_ns: now_ns(),
            });
            Ok(ArtifactEffect::SummaryStored)
        }
        FederationArtifact::Event(event) => {
            if !verify_event(event) {
                return Err(ArtifactRejection::BadSignature);
            }
            if apply_peer_revocation(inner, event, &peer_key) {
                Ok(ArtifactEffect::RevocationApplied)
            } else {
                Err(ArtifactRejection::NoEffect)
            }
        }
    }
}

/// Run the transport-driven federation task forever (ADR-269 §3).
///
/// Three things happen concurrently, and none can starve the others:
///
/// * **push out** — every artifact published on [`GatewayState::push_tx`] is
///   announced to every peer immediately;
/// * **push in** — `subscribe` is drained on a fast tick (a no-op for
///   transports without server push);
/// * **backstop** — `sync_since` runs on `backfill_ms`, starting
///   immediately, so identities are learned at startup and a peer that
///   missed a push converges anyway.
///
/// Peer failures are logged and never fatal: a dead peer must not stop the
/// others (or the gateway).
pub async fn run_federation(
    state: GatewayState,
    transport: Arc<dyn FederationTransport>,
    peers: Vec<String>,
    backfill_ms: u64,
) {
    let mut push_rx = state.push_tx.subscribe();
    run_federation_with_receiver(state, transport, peers, backfill_ms, &mut push_rx).await;
}

/// [`run_federation`] over a receiver the caller subscribed *before*
/// spawning, so an artifact minted between spawn and first poll is not lost.
pub async fn run_federation_with_receiver(
    state: GatewayState,
    transport: Arc<dyn FederationTransport>,
    peers: Vec<String>,
    backfill_ms: u64,
    push_rx: &mut tokio::sync::broadcast::Receiver<FederationArtifact>,
) {
    /// Per-peer backfill cursor alongside the peer reference.
    struct Tracked {
        /// Address and (once learned) identity.
        peer: PeerRef,
        /// `sync_since` cursor: ns of the last successful backfill.
        last_sync_ns: u64,
    }

    let mut tracked: Vec<Tracked> = peers
        .into_iter()
        .map(|url| Tracked {
            peer: PeerRef::new(url),
            last_sync_ns: 0,
        })
        .collect();

    let mut backfill_tick =
        tokio::time::interval(Duration::from_millis(backfill_ms.max(MIN_BACKFILL_MS)));
    let mut subscribe_tick = tokio::time::interval(SUBSCRIBE_TICK);

    loop {
        tokio::select! {
            // Push out: an artifact this gateway just minted.
            received = push_rx.recv() => match received {
                Ok(artifact) => {
                    for t in &tracked {
                        announce_to_peer(&state, transport.as_ref(), &t.peer, &artifact).await;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    eprintln!("gateway: federation push queue lagged, {n} artifact(s) dropped; the sync_since backstop will converge peers");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            },

            // Push in: drain anything a peer streamed at us.
            _ = subscribe_tick.tick() => {
                for t in &tracked {
                    drain_subscription(&state, transport.as_ref(), &t.peer).await;
                }
            }

            // The mandatory backstop (ADR-269 §3).
            _ = backfill_tick.tick() => {
                for t in &mut tracked {
                    let now = now_ns();
                    match backfill_peer(&state, transport.as_ref(), &mut t.peer, t.last_sync_ns).await {
                        Ok(()) => t.last_sync_ns = now,
                        Err(e) => eprintln!(
                            "gateway: federation backfill of peer {} over {}: {e}",
                            t.peer.url,
                            transport.name()
                        ),
                    }
                }
            }
        }
    }
}

/// Push one artifact to one peer, counting the outcome. A failed push is
/// logged and counted, never retried inline: [`backfill_peer`] is the
/// convergence path (ADR-269 §3).
async fn announce_to_peer(
    state: &GatewayState,
    transport: &dyn FederationTransport,
    peer: &PeerRef,
    artifact: &FederationArtifact,
) {
    match transport.announce(peer, artifact).await {
        Ok(()) => state.inner.lock().await.push.pushes_sent += 1,
        Err(e) => {
            state.inner.lock().await.push.push_failures += 1;
            eprintln!(
                "gateway: federation push to peer {} over {}: {e}",
                peer.url,
                transport.name()
            );
        }
    }
}

/// Drain whatever the peer streamed at us and run every artifact through
/// [`accept_artifact`] — same verification as the polled path.
async fn drain_subscription(
    state: &GatewayState,
    transport: &dyn FederationTransport,
    peer: &PeerRef,
) {
    let artifacts = match transport.subscribe(peer).await {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "gateway: federation subscribe to peer {} over {}: {e}",
                peer.url,
                transport.name()
            );
            return;
        }
    };
    if artifacts.is_empty() {
        return;
    }
    let mut inner = state.inner.lock().await;
    for artifact in &artifacts {
        match accept_artifact(&mut inner, artifact) {
            Ok(effect) => {
                inner.push.pushes_received += 1;
                eprintln!(
                    "gateway: streamed artifact from peer {}: {effect:?}",
                    peer.url
                );
            }
            Err(ArtifactRejection::NoEffect) => {}
            Err(e) => eprintln!(
                "gateway: rejecting streamed artifact from peer {}: {e}",
                peer.url
            ),
        }
    }
}

/// One backfill pass against one peer (ADR-269 §3): learn/refresh identity,
/// then `sync_since`, then verify and apply everything it returned.
async fn backfill_peer(
    state: &GatewayState,
    transport: &dyn FederationTransport,
    peer: &mut PeerRef,
    since_ns: u64,
) -> Result<(), TransportError> {
    if let Some(identity) = transport.identity(peer).await? {
        peer.biome_id = Some(identity.biome_id.clone());
        peer.pubkey_hex = Some(identity.pubkey_hex.clone());
        let mut inner = state.inner.lock().await;
        register_peer_identity(
            &mut inner,
            &identity.biome_id,
            &identity.pubkey_hex,
            &peer.url,
        );
    }

    let artifacts = transport.sync_since(peer, since_ns).await?;
    let mut inner = state.inner.lock().await;
    for artifact in &artifacts {
        match accept_artifact(&mut inner, artifact) {
            Ok(ArtifactEffect::RevocationApplied) => eprintln!(
                "gateway: applied revocation from peer {} (backfill)",
                peer.url
            ),
            Ok(ArtifactEffect::SummaryStored) | Err(ArtifactRejection::NoEffect) => {}
            Err(e) => eprintln!(
                "gateway: skipping unverifiable artifact from peer {}: {e}",
                peer.url
            ),
        }
    }
    inner.push.backfills += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::testutil::test_inner;
    use rucelium_abi::{NodeSigner, RvEnvSampleV1, RV_ENV_SCHEMA_V1};
    use rucelium_federation::{Biome, BiomeConfig};
    use rucelium_ingest::RejectReason;

    const PEER_SEED: &[u8; 32] = b"rucelium-peer-biome-seed-32-b!!!";
    const OTHER_SEED: &[u8; 32] = b"rucelium-wrong-key-seed-32-byte!";
    const NODE_SEED: &[u8; 32] = b"rucelium-gateway-test-seed-32b!!";
    const NODE: u64 = 0x5C00_0000_0000_0042;
    const PEER_BIOME: &str = "biome/peer";
    const PEER_URL: &str = "http://peer.invalid:7465";

    /// A valid wire sample from `NODE`.
    fn wire(sequence: u32) -> RvEnvSampleV1 {
        RvEnvSampleV1 {
            schema_version: RV_ENV_SCHEMA_V1,
            sensor_type: 5, // weather
            flags: 0,
            node_id: NODE,
            timestamp_ns: 1_754_000_000_000_000_000,
            sequence,
            latitude_e7: 514_778_216,
            longitude_e7: -14_767,
            altitude_mm: 46_000,
            value_q16: 16 * 65_536,
            quality_q15: 0x7000,
            battery_mv: 3_600,
            calibration_id: 0,
        }
    }

    fn peer_biome() -> Biome {
        Biome::new(BiomeConfig::new(PEER_BIOME), PEER_SEED)
    }

    fn inner_with_registered_node(tag: &str) -> Inner {
        let mut inner = test_inner(tag);
        inner.ingest.registry_mut().register(
            NODE,
            NodeSigner::for_node(NODE_SEED, NODE).public_key(),
            "sha256:fw".into(),
        );
        inner
    }

    /// An inner with `NODE` provisioned and the peer biome's identity known.
    fn inner_knowing_peer(tag: &str, peer: &Biome) -> Inner {
        let mut inner = inner_with_registered_node(tag);
        register_peer_identity(&mut inner, PEER_BIOME, &peer.public_key_hex(), PEER_URL);
        inner
    }

    #[test]
    fn verified_peer_revocation_is_applied_once_and_registry_rejects() {
        let mut inner = inner_with_registered_node("fed-apply");
        let mut peer = peer_biome();
        let event = peer.revoke_device(NODE, 1_000, "compromised");

        assert!(apply_peer_revocation(
            &mut inner,
            &event,
            &peer.public_key_hex()
        ));
        assert!(inner.ingest.registry().is_revoked(NODE));
        assert_eq!(inner.applied_peer_revocations, 1);

        // Idempotent: the same event never counts twice.
        assert!(!apply_peer_revocation(
            &mut inner,
            &event,
            &peer.public_key_hex()
        ));
        assert_eq!(inner.applied_peer_revocations, 1);

        // The revoked node's envelopes are rejected at ingest from now on.
        let env = NodeSigner::for_node(NODE_SEED, NODE)
            .sign_sample(&wire(1))
            .encode();
        assert_eq!(
            inner.ingest.ingest(&env, crate::state::now_ns()),
            Err(RejectReason::RevokedDevice(NODE))
        );
    }

    #[test]
    fn event_signed_by_the_wrong_key_is_not_applied() {
        let mut inner = inner_with_registered_node("fed-wrong-key");
        let peer = peer_biome();
        // A different biome signs a revocation but claims the peer's slot.
        let mut impostor = Biome::new(BiomeConfig::new("biome/impostor"), OTHER_SEED);
        let event = impostor.revoke_device(NODE, 1_000, "forged");

        // The impostor's signature is valid — but not the peer's key.
        assert!(verify_event(&event));
        assert!(!apply_peer_revocation(
            &mut inner,
            &event,
            &peer.public_key_hex()
        ));
        assert!(!inner.ingest.registry().is_revoked(NODE));
        assert_eq!(inner.applied_peer_revocations, 0);
    }

    #[test]
    fn tampered_or_wrong_kind_events_are_not_applied() {
        let mut inner = inner_with_registered_node("fed-tamper");
        let mut peer = peer_biome();
        let event = peer.revoke_device(NODE, 1_000, "compromised");

        let mut tampered = event.clone();
        tampered.message.push('!');
        assert!(!apply_peer_revocation(
            &mut inner,
            &tampered,
            &peer.public_key_hex()
        ));

        let mut wrong_kind = event.clone();
        wrong_kind.kind = EventKind::Anomaly;
        peer.sign_event(&mut wrong_kind);
        assert!(!apply_peer_revocation(
            &mut inner,
            &wrong_kind,
            &peer.public_key_hex()
        ));

        assert!(!inner.ingest.registry().is_revoked(NODE));
        assert_eq!(inner.applied_peer_revocations, 0);
    }

    #[test]
    fn unregistered_node_leaves_event_unapplied_for_retry() {
        let mut inner = test_inner("fed-unregistered");
        let mut peer = peer_biome();
        let event = peer.revoke_device(NODE, 1_000, "compromised");
        assert!(!apply_peer_revocation(
            &mut inner,
            &event,
            &peer.public_key_hex()
        ));
        // After provisioning, the same event applies on the next poll.
        inner
            .ingest
            .registry_mut()
            .register(NODE, [0xAA; 32], "sha256:fw".into());
        assert!(apply_peer_revocation(
            &mut inner,
            &event,
            &peer.public_key_hex()
        ));
        assert!(inner.ingest.registry().is_revoked(NODE));
    }

    // --- ADR-269 §4: the one verification gate, exercised directly. ---

    #[test]
    fn accepted_artifacts_apply_revocations_and_store_summaries() {
        let mut peer = peer_biome();
        let mut inner = inner_knowing_peer("gate-accept", &peer);

        let summary = FederationArtifact::Summary(peer.summarize(0, 5_000));
        assert_eq!(
            accept_artifact(&mut inner, &summary),
            Ok(ArtifactEffect::SummaryStored)
        );
        assert_eq!(inner.peer_summaries.len(), 1);
        assert_eq!(inner.peer_summaries[0].peer, PEER_URL);

        let event = FederationArtifact::Event(peer.revoke_device(NODE, 1_000, "compromised"));
        assert_eq!(
            accept_artifact(&mut inner, &event),
            Ok(ArtifactEffect::RevocationApplied)
        );
        assert!(inner.ingest.registry().is_revoked(NODE));

        // Idempotent: the same pushed event applies exactly once.
        assert_eq!(
            accept_artifact(&mut inner, &event),
            Err(ArtifactRejection::NoEffect)
        );
        assert_eq!(inner.applied_peer_revocations, 1);

        // A second summary for the same biome replaces, never accumulates.
        let again = FederationArtifact::Summary(peer.summarize(5_000, 10_000));
        assert_eq!(
            accept_artifact(&mut inner, &again),
            Ok(ArtifactEffect::SummaryStored)
        );
        assert_eq!(inner.peer_summaries.len(), 1);
    }

    #[test]
    fn unknown_biome_and_unsigned_artifacts_are_refused() {
        let mut peer = peer_biome();
        let mut inner = inner_with_registered_node("gate-unknown");
        let event = FederationArtifact::Event(peer.revoke_device(NODE, 1_000, "compromised"));
        // Nothing learned yet: the biome cannot be identity-bound.
        assert_eq!(
            accept_artifact(&mut inner, &event),
            Err(ArtifactRejection::UnknownBiome(PEER_BIOME.into()))
        );
        assert!(!inner.ingest.registry().is_revoked(NODE));

        register_peer_identity(&mut inner, PEER_BIOME, &peer.public_key_hex(), PEER_URL);
        let FederationArtifact::Event(raw) = event else {
            unreachable!("constructed as an event")
        };
        let mut unsigned = raw;
        unsigned.signature_hex = None;
        unsigned.signer_pubkey_hex = None;
        assert_eq!(
            accept_artifact(&mut inner, &FederationArtifact::Event(unsigned)),
            Err(ArtifactRejection::Unsigned)
        );
        assert!(!inner.ingest.registry().is_revoked(NODE));
    }

    #[test]
    fn pushed_artifact_signed_by_another_key_is_an_identity_mismatch() {
        let peer = peer_biome();
        let mut inner = inner_knowing_peer("gate-identity", &peer);

        // An impostor with a perfectly valid signature claims the peer's
        // biome id. Signature validity is not identity (ADR-269 §4).
        let mut impostor = Biome::new(BiomeConfig::new(PEER_BIOME), OTHER_SEED);
        let forged = impostor.revoke_device(NODE, 1_000, "forged");
        assert!(verify_event(&forged));
        assert_ne!(forged.signer_pubkey_hex, Some(peer.public_key_hex()));
        assert_eq!(forged.biome_id, PEER_BIOME);

        assert_eq!(
            accept_artifact(&mut inner, &FederationArtifact::Event(forged)),
            Err(ArtifactRejection::IdentityMismatch {
                biome_id: PEER_BIOME.into()
            })
        );
        assert!(!inner.ingest.registry().is_revoked(NODE));
        assert_eq!(inner.applied_peer_revocations, 0);
    }

    #[test]
    fn pushed_artifact_with_a_bad_signature_is_refused() {
        let mut peer = peer_biome();
        let mut inner = inner_knowing_peer("gate-badsig", &peer);

        let mut event = peer.revoke_device(NODE, 1_000, "compromised");
        event.message.push('!'); // tamper after signing
        assert_eq!(
            accept_artifact(&mut inner, &FederationArtifact::Event(event)),
            Err(ArtifactRejection::BadSignature)
        );
        assert!(!inner.ingest.registry().is_revoked(NODE));

        let mut summary = peer.summarize(0, 5_000);
        summary.window_end_ns += 1; // tamper after signing
        assert_eq!(
            accept_artifact(&mut inner, &FederationArtifact::Summary(summary)),
            Err(ArtifactRejection::BadSignature)
        );
        assert!(inner.peer_summaries.is_empty());
    }

    #[test]
    fn rejection_reasons_display() {
        assert!(ArtifactRejection::Unsigned.to_string().contains("unsigned"));
        assert!(ArtifactRejection::UnknownBiome("biome/x".into())
            .to_string()
            .contains("biome/x"));
        assert!(ArtifactRejection::IdentityMismatch {
            biome_id: "biome/x".into()
        }
        .to_string()
        .contains("biome/x"));
        assert!(!ArtifactRejection::BadSignature.to_string().is_empty());
        assert!(!ArtifactRejection::NoEffect.to_string().is_empty());
    }
}
