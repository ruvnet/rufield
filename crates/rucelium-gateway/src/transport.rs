//! The federation transport abstraction (ADR-269 §3): **push first,
//! transport second**.
//!
//! ADR-269 §3 replaces the 30 s poller with three verbs carried by a
//! [`FederationTransport`]:
//!
//! * [`announce`](FederationTransport::announce) — push one signed artifact
//!   to one peer, so a revocation propagates at link speed instead of
//!   polling speed;
//! * [`subscribe`](FederationTransport::subscribe) — take whatever a peer
//!   has streamed to us since we last looked;
//! * [`sync_since`](FederationTransport::sync_since) — backfill after a
//!   partition. **Not optional**: a peer that missed a pushed event must
//!   still converge (ADR-269 §3), so the polling backstop runs on reconnect
//!   and on a slow timer regardless of transport.
//!
//! Two implementations ship: [`HttpPollTransport`] here (always available,
//! zero new dependencies, the backfill of record) and
//! `transport_quic::QuicTransport` behind the `quic` feature.
//!
//! # The transport is never the trust boundary (ADR-269 §4, normative)
//!
//! Nothing in this module verifies anything. A transport moves bytes;
//! [`crate::federation::accept_artifact`] is the single gate every artifact
//! passes through — same ed25519 signature check, same `biome_id → key`
//! identity binding, same `event_id` dedup — whether it arrived by HTTP
//! poll, HTTP push, or QUIC. If a session ever becomes the reason a peer is
//! trusted, that is a regression.
//!
//! # No `async-trait`
//!
//! The trait is object-safe by hand: each verb returns a boxed future
//! ([`TransportFuture`]) rather than pulling in a proc-macro dependency, so
//! `Arc<dyn FederationTransport>` works and the crate stays lean.

use rucelium_core::EnvironmentalEvent;
use rucelium_federation::RegionalSummary;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// Per-request HTTP timeout for [`HttpPollTransport`].
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
/// Widest window [`HttpPollTransport::sync_since`] will ask a peer for, in
/// seconds. A `since_ns` older than this is clamped — the peer's summary
/// endpoint aggregates, so an unbounded window is a denial-of-service knob.
const MAX_SUMMARY_WINDOW_S: u64 = 86_400;
/// Window requested when the caller has never synced this peer before.
const DEFAULT_SUMMARY_WINDOW_S: u64 = 3_600;

/// One signed thing that crosses the federation boundary (ADR-264 §6:
/// biomes federate signed events and statistical summaries, never raw
/// measurements).
///
/// `#[serde(tag = "artifact")]` gives the wire form a stable discriminator,
/// so `POST /api/federation/announce` can decode either variant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "artifact", rename_all = "snake_case")]
pub enum FederationArtifact {
    /// A signed regional summary.
    Summary(RegionalSummary),
    /// A signed environmental event (the ADR-269 §3 case that matters:
    /// `DeviceRevoked`).
    Event(EnvironmentalEvent),
}

impl FederationArtifact {
    /// The biome identity the artifact claims. Identity binding resolves the
    /// expected signing key from this, never from the connection.
    #[must_use]
    pub fn biome_id(&self) -> &str {
        match self {
            FederationArtifact::Summary(s) => &s.biome_id,
            FederationArtifact::Event(e) => &e.biome_id,
        }
    }

    /// The hex ed25519 key the artifact says signed it, if any. It is a
    /// *claim*: [`crate::federation::accept_artifact`] checks it against the
    /// registered key for [`Self::biome_id`] and then checks the signature.
    #[must_use]
    pub fn signer_pubkey_hex(&self) -> Option<&str> {
        match self {
            FederationArtifact::Summary(s) => s.signer_pubkey_hex.as_deref(),
            FederationArtifact::Event(e) => e.signer_pubkey_hex.as_deref(),
        }
    }

    /// Which QUIC stream class carries this artifact (ADR-269 §4.3: a
    /// stalled summary stream must not block revocations).
    #[must_use]
    pub fn stream_class(&self) -> StreamClass {
        match self {
            FederationArtifact::Summary(_) => StreamClass::Summary,
            FederationArtifact::Event(_) => StreamClass::Event,
        }
    }
}

/// Artifact classes that get their own independent stream (ADR-269 §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StreamClass {
    /// Regional summaries — bulky, latency-tolerant.
    Summary,
    /// Events, including revocations — small, latency-critical.
    Event,
}

impl StreamClass {
    /// One-byte tag written at the head of a QUIC stream.
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            StreamClass::Summary => 0,
            StreamClass::Event => 1,
        }
    }

    /// Decode a stream tag.
    #[must_use]
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(StreamClass::Summary),
            1 => Some(StreamClass::Event),
            _ => None,
        }
    }
}

/// A federation peer as this gateway currently knows it.
///
/// `biome_id` and `pubkey_hex` start `None` and are learned on first contact
/// (over HTTP, from `GET /api/federation/pubkey`; over QUIC they must be
/// known *before* connecting, because they are the pinned TLS identity).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerRef {
    /// Peer base URL (HTTP) or `host:port` (QUIC).
    pub url: String,
    /// Peer biome identity, once learned.
    pub biome_id: Option<String>,
    /// Peer biome ed25519 public key in hex, once learned.
    pub pubkey_hex: Option<String>,
}

impl PeerRef {
    /// A peer known only by address; identity is learned on first contact.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        PeerRef {
            url: url.into(),
            biome_id: None,
            pubkey_hex: None,
        }
    }

    /// A peer whose federation identity is already known — the form
    /// `transport_quic::QuicTransport` requires, since the key is
    /// the pinned TLS identity (ADR-269 §4).
    #[must_use]
    pub fn with_identity(
        url: impl Into<String>,
        biome_id: impl Into<String>,
        pubkey_hex: impl Into<String>,
    ) -> Self {
        PeerRef {
            url: url.into(),
            biome_id: Some(biome_id.into()),
            pubkey_hex: Some(pubkey_hex.into()),
        }
    }

    /// The peer URL without a trailing slash (HTTP path building).
    #[must_use]
    pub fn base(&self) -> &str {
        self.url.trim_end_matches('/')
    }
}

/// A peer's federation identity as published by the peer itself.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PeerIdentity {
    /// Peer biome identity.
    pub biome_id: String,
    /// Peer biome ed25519 public key, hex.
    pub pubkey_hex: String,
}

/// Why a transport could not move an artifact. Transport failures are never
/// fatal to the gateway: a dead peer must not stop the others (ADR-265 §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The peer could not be reached at all (connect / DNS / timeout).
    Unreachable(String),
    /// The peer answered, but not in a way the protocol allows.
    Protocol(String),
    /// **The peer's transport identity is not its registered federation
    /// key** (ADR-269 §4, normative). The connection is refused; no artifact
    /// crosses.
    IdentityRefused {
        /// The registered federation key we pinned.
        expected: String,
        /// What the peer actually presented (hex, or a diagnostic).
        got: String,
    },
    /// An artifact could not be encoded or decoded.
    Encoding(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Unreachable(m) => write!(f, "peer unreachable: {m}"),
            TransportError::Protocol(m) => write!(f, "protocol error: {m}"),
            TransportError::IdentityRefused { expected, got } => write!(
                f,
                "peer transport identity refused: expected {expected}, got {got}"
            ),
            TransportError::Encoding(m) => write!(f, "encoding error: {m}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// Boxed future returned by every [`FederationTransport`] verb — the
/// `async-trait`-free way to keep the trait object safe.
pub type TransportFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, TransportError>> + Send + 'a>>;

/// A way to move signed federation artifacts between biomes (ADR-269 §3).
///
/// Implementations move bytes and **nothing else**: every artifact they
/// return is unverified until [`crate::federation::accept_artifact`] has run
/// (ADR-269 §4, normative).
pub trait FederationTransport: Send + Sync {
    /// Stable transport name, for logs and `/api/stats`.
    fn name(&self) -> &'static str;

    /// Push one signed artifact to one peer. Best effort by design: a
    /// dropped push is recovered by [`Self::sync_since`] (ADR-269 §3, §5).
    fn announce<'a>(
        &'a self,
        peer: &'a PeerRef,
        artifact: &'a FederationArtifact,
    ) -> TransportFuture<'a, ()>;

    /// Take whatever the peer has streamed to us since the last call.
    /// Transports without server push return an empty vector.
    fn subscribe<'a>(&'a self, peer: &'a PeerRef) -> TransportFuture<'a, Vec<FederationArtifact>>;

    /// Backfill everything the peer has from `since_ns` onwards — the
    /// mandatory convergence path after a partition or a dropped push
    /// (ADR-269 §3).
    fn sync_since<'a>(
        &'a self,
        peer: &'a PeerRef,
        since_ns: u64,
    ) -> TransportFuture<'a, Vec<FederationArtifact>>;

    /// Discover the peer's published federation identity, so `biome_id` and
    /// `pubkey_hex` can be learned on first contact.
    ///
    /// Defaulted to `Ok(None)` ("this transport cannot discover identity —
    /// keep whatever you already had"). HTTP fetches
    /// `GET /api/federation/pubkey`; QUIC returns the identity it already
    /// pinned, because over QUIC the key is a *precondition* of connecting
    /// (ADR-269 §4).
    fn identity<'a>(&'a self, peer: &'a PeerRef) -> TransportFuture<'a, Option<PeerIdentity>> {
        let _ = peer;
        Box::pin(async { Ok(None) })
    }
}

/// The always-available default transport: plain HTTP over the endpoints the
/// gateway already serves (ADR-269 §3 — "the existing behaviour, kept as the
/// always-available default with no new dependencies").
pub struct HttpPollTransport {
    /// One shared `reqwest` client (connection pooling, fixed timeout).
    client: reqwest::Client,
}

impl HttpPollTransport {
    /// Build the HTTP transport. Fails only if the TLS/client stack cannot
    /// be initialised.
    pub fn new() -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        Ok(HttpPollTransport { client })
    }

    /// GET a JSON body, mapping transport and decode failures onto
    /// [`TransportError`].
    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<T, TransportError> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| TransportError::Unreachable(format!("GET {url}: {e}")))?;
        let response = response
            .error_for_status()
            .map_err(|e| TransportError::Protocol(format!("GET {url}: {e}")))?;
        response
            .json::<T>()
            .await
            .map_err(|e| TransportError::Encoding(format!("decode {url}: {e}")))
    }
}

impl std::fmt::Debug for HttpPollTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpPollTransport").finish_non_exhaustive()
    }
}

impl FederationTransport for HttpPollTransport {
    fn name(&self) -> &'static str {
        "http"
    }

    /// `POST {peer}/api/federation/announce` with the artifact as JSON. A
    /// 4xx means the peer refused to verify it — that is the peer doing its
    /// job (ADR-269 §4), so it is reported as [`TransportError::Protocol`]
    /// and never retried blindly; the backstop re-offers it as backfill.
    fn announce<'a>(
        &'a self,
        peer: &'a PeerRef,
        artifact: &'a FederationArtifact,
    ) -> TransportFuture<'a, ()> {
        Box::pin(async move {
            let url = format!("{}/api/federation/announce", peer.base());
            let response = self
                .client
                .post(&url)
                .json(artifact)
                .send()
                .await
                .map_err(|e| TransportError::Unreachable(format!("POST {url}: {e}")))?;
            let status = response.status();
            if status.is_success() {
                return Ok(());
            }
            let body = response.text().await.unwrap_or_default();
            Err(TransportError::Protocol(format!(
                "POST {url}: {status}: {body}"
            )))
        })
    }

    /// **HTTP has no server push here.** There is no long-poll, no SSE and
    /// no websocket on the gateway's federation surface, so there is nothing
    /// for a peer to have streamed at us: this always returns an empty
    /// vector, immediately and without a request.
    ///
    /// That is not a gap in convergence. Over HTTP a peer *pushes to us* by
    /// calling `POST /api/federation/announce` (which lands in
    /// [`crate::api`], not here), and anything that push missed is recovered
    /// by [`Self::sync_since`].
    fn subscribe<'a>(&'a self, peer: &'a PeerRef) -> TransportFuture<'a, Vec<FederationArtifact>> {
        let _ = peer;
        Box::pin(async { Ok(Vec::new()) })
    }

    /// The ADR-265 §4 poll, unchanged in behaviour and now expressed as a
    /// backfill: `GET /api/federation/summary` then
    /// `GET /api/federation/revocations`, returned as artifacts for
    /// [`crate::federation::accept_artifact`] to verify.
    ///
    /// `since_ns` selects the summary window; `0` (never synced) asks for
    /// the default hour, and anything older than a day is clamped (see
    /// [`summary_window_s`]).
    fn sync_since<'a>(
        &'a self,
        peer: &'a PeerRef,
        since_ns: u64,
    ) -> TransportFuture<'a, Vec<FederationArtifact>> {
        Box::pin(async move {
            let base = peer.base();
            let window_s = summary_window_s(since_ns, crate::state::now_ns());
            let summary: RegionalSummary = self
                .get_json(&format!(
                    "{base}/api/federation/summary?window_s={window_s}"
                ))
                .await?;
            let events: Vec<EnvironmentalEvent> = self
                .get_json(&format!("{base}/api/federation/revocations"))
                .await?;
            let mut out = Vec::with_capacity(events.len() + 1);
            out.push(FederationArtifact::Summary(summary));
            out.extend(events.into_iter().map(FederationArtifact::Event));
            Ok(out)
        })
    }

    /// `GET {peer}/api/federation/pubkey` — the peer's own statement of its
    /// federation identity, and the only thing this gateway will accept a
    /// signature from on that peer's behalf.
    fn identity<'a>(&'a self, peer: &'a PeerRef) -> TransportFuture<'a, Option<PeerIdentity>> {
        Box::pin(async move {
            let url = format!("{}/api/federation/pubkey", peer.base());
            let identity: PeerIdentity = self.get_json(&url).await?;
            Ok(Some(identity))
        })
    }
}

/// Summary window in seconds for a backfill that last succeeded at
/// `since_ns`, clamped to `[1, MAX_SUMMARY_WINDOW_S]`. Pure and
/// deterministic in its arguments so it is unit-testable without a clock.
#[must_use]
pub fn summary_window_s(since_ns: u64, now_ns: u64) -> u64 {
    if since_ns == 0 {
        return DEFAULT_SUMMARY_WINDOW_S;
    }
    let elapsed_s = now_ns.saturating_sub(since_ns) / 1_000_000_000;
    elapsed_s.clamp(1, MAX_SUMMARY_WINDOW_S)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rucelium_federation::{Biome, BiomeConfig};

    const SEED: &[u8; 32] = b"rucelium-transport-test-seed-32!";

    fn biome() -> Biome {
        Biome::new(BiomeConfig::new("biome/transport"), SEED)
    }

    #[test]
    fn artifact_round_trips_and_reports_its_identity_claims() {
        let mut b = biome();
        let event = b.revoke_device(7, 1_000, "compromised");
        let artifact = FederationArtifact::Event(event.clone());
        assert_eq!(artifact.biome_id(), "biome/transport");
        assert_eq!(
            artifact.signer_pubkey_hex(),
            Some(b.public_key_hex().as_str())
        );
        assert_eq!(artifact.stream_class(), StreamClass::Event);

        let json = serde_json::to_string(&artifact).expect("artifact serializes");
        assert!(json.contains("\"artifact\":\"event\""), "{json}");
        let back: FederationArtifact = serde_json::from_str(&json).expect("artifact decodes");
        assert_eq!(back, artifact);

        let summary = FederationArtifact::Summary(b.summarize(0, 5_000));
        assert_eq!(summary.stream_class(), StreamClass::Summary);
        assert_eq!(summary.biome_id(), "biome/transport");
        let json = serde_json::to_string(&summary).expect("summary serializes");
        let back: FederationArtifact = serde_json::from_str(&json).expect("summary decodes");
        assert_eq!(back, summary);
    }

    #[test]
    fn stream_classes_are_distinct_and_round_trip() {
        assert_ne!(StreamClass::Summary.tag(), StreamClass::Event.tag());
        assert_eq!(
            StreamClass::from_tag(StreamClass::Summary.tag()),
            Some(StreamClass::Summary)
        );
        assert_eq!(
            StreamClass::from_tag(StreamClass::Event.tag()),
            Some(StreamClass::Event)
        );
        assert_eq!(StreamClass::from_tag(9), None);
    }

    #[test]
    fn peer_ref_trims_and_carries_learned_identity() {
        let bare = PeerRef::new("http://peer:7465/");
        assert_eq!(bare.base(), "http://peer:7465");
        assert!(bare.pubkey_hex.is_none());
        let known = PeerRef::with_identity("127.0.0.1:9", "biome/x", "ab12");
        assert_eq!(known.biome_id.as_deref(), Some("biome/x"));
        assert_eq!(known.pubkey_hex.as_deref(), Some("ab12"));
    }

    #[test]
    fn transport_errors_display_their_cause() {
        assert!(TransportError::Unreachable("down".into())
            .to_string()
            .contains("down"));
        assert!(TransportError::Protocol("418".into())
            .to_string()
            .contains("418"));
        assert!(TransportError::Encoding("bad json".into())
            .to_string()
            .contains("bad json"));
        let refused = TransportError::IdentityRefused {
            expected: "aa".into(),
            got: "bb".into(),
        };
        let text = refused.to_string();
        assert!(text.contains("aa") && text.contains("bb"), "{text}");
    }

    #[test]
    fn summary_window_is_clamped_and_deterministic() {
        // Never synced: the default hour.
        assert_eq!(
            summary_window_s(0, 10_000_000_000),
            DEFAULT_SUMMARY_WINDOW_S
        );
        // 5 s of elapsed time asks for a 5 s window.
        assert_eq!(summary_window_s(5_000_000_000, 10_000_000_000), 5);
        // Sub-second gaps still ask for at least a second.
        assert_eq!(summary_window_s(9_999_999_999, 10_000_000_000), 1);
        // An ancient cursor is clamped, not unbounded.
        assert_eq!(summary_window_s(1, u64::MAX), MAX_SUMMARY_WINDOW_S);
        // Clock going backwards cannot underflow.
        assert_eq!(summary_window_s(10_000_000_000, 1), 1);
    }

    #[tokio::test]
    async fn http_subscribe_is_an_empty_no_op() {
        let t = HttpPollTransport::new().expect("http transport builds");
        assert_eq!(t.name(), "http");
        let peer = PeerRef::new("http://127.0.0.1:1");
        assert_eq!(
            t.subscribe(&peer).await.expect("no-op subscribe"),
            Vec::new()
        );
    }

    #[tokio::test]
    async fn http_transport_reports_unreachable_peers() {
        let t = HttpPollTransport::new().expect("http transport builds");
        // Port 1 on loopback: nothing listens, connection is refused fast.
        let peer = PeerRef::new("http://127.0.0.1:1");
        let err = t.identity(&peer).await.expect_err("must fail");
        assert!(
            matches!(err, TransportError::Unreachable(_)),
            "unexpected error: {err}"
        );
        let mut b = biome();
        let artifact = FederationArtifact::Event(b.revoke_device(1, 1, "x"));
        let err = t
            .announce(&peer, &artifact)
            .await
            .expect_err("announce must fail");
        assert!(
            matches!(err, TransportError::Unreachable(_)),
            "unexpected error: {err}"
        );
    }
}
