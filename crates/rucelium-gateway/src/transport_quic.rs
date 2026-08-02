//! The optional QUIC federation transport (ADR-269 §4), behind the `quic`
//! cargo feature.
//!
//! QUIC earns its place at the *biome-to-biome* hop — never at the sensor
//! boundary (ADR-269 §2) — for four reasons the ADR lists: connection
//! migration across LTE → satellite → wifi, resumption after a partition,
//! **no head-of-line blocking between artifact classes** (§4.3), and
//! channel encryption that closes the alert-*timing* side channel for
//! sensitive-species deployments (ADR-266 §3.1).
//!
//! # Identity: RFC 7250 raw public keys pinned to the biome key
//!
//! ADR-269 §4 is normative: *"TLS identity is the biome's existing ed25519
//! key, carried as a raw public key (RFC 7250) rather than X.509. No
//! certificate authority, no new PKI, no name-based trust … A peer's TLS
//! identity must equal its registered federation key or the connection is
//! refused."*
//!
//! That is implemented literally, not approximated:
//!
//! * **Server side** — the endpoint's TLS credential is the biome's own
//!   ed25519 key. The private key is handed to rustls as a PKCS#8 v1
//!   encoding of the same 32-byte seed [`crate::state::biome_seed`] derives
//!   the [`rucelium_federation::Biome`] identity from, so the QUIC identity
//!   and the signing identity are *the same key*, not two keys that happen
//!   to be provisioned together. The "certificate chain" is a single
//!   [`rustls::pki_types::SubjectPublicKeyInfoDer`] and the resolver is
//!   [`rustls::server::AlwaysResolvesServerRawPublicKeys`], which sets
//!   `server_certificate_type = RawPublicKey` in the handshake. There is no
//!   X.509 anywhere: no self-signed certificate, no subject name, no
//!   validity window, no CA.
//! * **Client side** — [`PinnedBiomeKeyVerifier`] accepts exactly one SPKI:
//!   the one built from the peer's registered federation key. Anything else
//!   fails the handshake, and [`QuicTransport::announce`] reports it as
//!   [`TransportError::IdentityRefused`] carrying both the expected and the
//!   presented key. The verifier also declares
//!   `requires_raw_public_keys() = true`, so rustls negotiates RFC 7250 and
//!   **refuses** a peer that answers with an X.509 chain instead — a
//!   downgrade to name-based trust is not reachable.
//!
//! Installing any custom verifier in rustls requires
//! `ClientConfig::dangerous()`. That call is not a bypass here: the verifier
//! it installs is *stricter* than webpki (one key, exact bytes, no name
//! matching, no CA), and it never returns `Ok` for an unpinned key.
//!
//! ## Honest limitations
//!
//! 1. **The server does not authenticate the client.** TLS client
//!    authentication is not requested, so any host may open a connection and
//!    push artifacts. This is deliberate and safe *only* because ADR-269 §4
//!    makes the session non-load-bearing: every artifact that arrives is
//!    verified by [`crate::federation::accept_artifact`] — signature plus
//!    `biome_id → key` identity binding — exactly as if it had been polled.
//!    An unauthenticated connection can therefore waste our bandwidth; it
//!    cannot revoke a device. Mutual raw-public-key auth would need a
//!    registry of *inbound* peer keys and is honest follow-up work.
//! 2. **`subscribe` is endpoint-wide, not per-peer.** Artifacts pushed to
//!    us over any inbound connection land in one queue;
//!    [`QuicTransport::subscribe`] drains it and ignores its `peer`
//!    argument except for logging. That is sound because the queue's
//!    contents are unverified until the same gate runs on them, but it does
//!    mean the transport cannot attribute an artifact to a connection —
//!    only to the key that signed it, which is the attribution that counts.
//! 3. **0-RTT is not enabled.** Connection migration and loss recovery come
//!    free with QUIC; resumption (ADR-269 §4 item 2) is not wired up.
//! 4. **`sync_since` needs a local source.** Serving backfill requires
//!    reading this gateway's own event store, which the transport does not
//!    own; a [`BackfillSource`] callback supplies it. Without one the
//!    endpoint answers backfill requests with an empty set, and peers fall
//!    back to HTTP for the backfill of record.

use crate::transport::{
    FederationArtifact, FederationTransport, PeerIdentity, PeerRef, StreamClass, TransportError,
    TransportFuture,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{
    alg_id, CertificateDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime,
};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex;

/// ALPN protocol identifier for the RuCelium federation protocol.
const ALPN: &[u8] = b"rucelium-fed/1";
/// Server name presented in the TLS SNI. Unused for trust — the pinned raw
/// public key is the identity — but rustls requires a syntactically valid
/// name.
const SNI: &str = "biome.rucelium.invalid";
/// Largest artifact frame accepted, in bytes.
const MAX_FRAME_BYTES: usize = 1 << 20;
/// Largest backfill response accepted, in bytes.
const MAX_BACKFILL_BYTES: usize = 8 << 20;
/// Bytes of an ed25519 public key.
const ED25519_KEY_BYTES: usize = 32;

/// Supplies this gateway's own artifacts when a peer asks for a backfill
/// over QUIC (`sync_since`). Takes the peer's cursor in ns.
pub type BackfillSource = Arc<dyn Fn(u64) -> Vec<FederationArtifact> + Send + Sync>;

/// Lowercase hex, matching `rucelium_federation`'s key encoding.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Decode lowercase/uppercase hex; `None` on odd length or non-hex bytes.
fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// PKCS#8 v1 wrapper around a raw ed25519 seed (RFC 8410 §7), the form
/// rustls' ring key provider parses. The 16-byte prefix is
/// `SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING {
/// OCTET STRING (32) } }`.
fn ed25519_pkcs8(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ]);
    der.extend_from_slice(seed);
    der
}

/// The SPKI a peer holding `pubkey_hex` must present. Built with rustls'
/// own encoder so it is byte-identical to what a peer's
/// `AlwaysResolvesServerRawPublicKeys` will send.
fn expected_spki(pubkey_hex: &str) -> Result<Vec<u8>, TransportError> {
    let raw = hex_decode(pubkey_hex)
        .ok_or_else(|| TransportError::Encoding(format!("peer key is not hex: {pubkey_hex}")))?;
    if raw.len() != ED25519_KEY_BYTES {
        return Err(TransportError::Encoding(format!(
            "peer key is {} bytes, expected {ED25519_KEY_BYTES}",
            raw.len()
        )));
    }
    Ok(rustls::sign::public_key_to_spki(&alg_id::ED25519, &raw)
        .as_ref()
        .to_vec())
}

/// The ed25519 public key inside an SPKI, hex-encoded — used to report what
/// a peer *actually* presented in [`TransportError::IdentityRefused`].
fn key_hex_from_spki(spki: &[u8]) -> String {
    if spki.len() >= ED25519_KEY_BYTES {
        hex_encode(&spki[spki.len() - ED25519_KEY_BYTES..])
    } else {
        format!("<{} byte credential>", spki.len())
    }
}

/// What the last refused handshake presented, so `announce` can turn a
/// generic TLS failure into a precise [`TransportError::IdentityRefused`].
#[derive(Debug, Default)]
struct PinOutcome {
    /// Hex key the peer presented, set only when the pin check failed.
    refused: StdMutex<Option<String>>,
}

/// **The identity gate for QUIC** (ADR-269 §4): a rustls
/// [`ServerCertVerifier`] that accepts exactly one RFC 7250 raw public key —
/// the peer's registered federation key — and nothing else.
///
/// It performs no name matching, consults no trust anchors, and has no
/// notion of certificate validity, because there is no certificate: the
/// credential *is* the key. A peer presenting any other key, or an X.509
/// chain instead of a raw public key, fails the handshake.
#[derive(Debug)]
pub struct PinnedBiomeKeyVerifier {
    /// DER SPKI of the one key this verifier will accept.
    expected_spki: Vec<u8>,
    /// Hex form of the same key, for diagnostics.
    expected_hex: String,
    /// Records a refusal for the connecting side to report.
    outcome: Arc<PinOutcome>,
    /// Crypto provider supplying the signature verification algorithms.
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinnedBiomeKeyVerifier {
    /// Pin to the ed25519 federation key `pubkey_hex`.
    pub fn new(
        pubkey_hex: &str,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<Self, TransportError> {
        Ok(PinnedBiomeKeyVerifier {
            expected_spki: expected_spki(pubkey_hex)?,
            expected_hex: pubkey_hex.to_string(),
            outcome: Arc::new(PinOutcome::default()),
            provider,
        })
    }

    /// The key this verifier pins, hex-encoded.
    #[must_use]
    pub fn expected_hex(&self) -> &str {
        &self.expected_hex
    }
}

impl ServerCertVerifier for PinnedBiomeKeyVerifier {
    /// With `requires_raw_public_keys() == true`, `end_entity` is the peer's
    /// DER `SubjectPublicKeyInfo`, not a certificate. Accept it only when it
    /// is byte-for-byte the registered federation key.
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !intermediates.is_empty() {
            return Err(rustls::Error::General(
                "raw public key identity must be a single SPKI".into(),
            ));
        }
        if end_entity.as_ref() == self.expected_spki.as_slice() {
            return Ok(ServerCertVerified::assertion());
        }
        if let Ok(mut refused) = self.outcome.refused.lock() {
            *refused = Some(key_hex_from_spki(end_entity.as_ref()));
        }
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ))
    }

    /// QUIC is TLS 1.3 only; a TLS 1.2 handshake signature is unreachable
    /// and is refused rather than silently accepted.
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "TLS 1.2 is not offered for QUIC federation".into(),
        ))
    }

    /// Verify the handshake signature *against the pinned raw key* — the
    /// proof that the peer holds the private half of the biome key, not
    /// merely a copy of its public half.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if cert.as_ref() != self.expected_spki.as_slice() {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    /// Only ed25519 — the biome identity algorithm.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    /// Negotiate RFC 7250 raw public keys; an X.509 answer is refused by
    /// rustls before this verifier is even consulted.
    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// One peer's live QUIC connection and its per-class send streams.
struct PeerConnection {
    /// The QUIC connection (survives IP changes — ADR-269 §4 item 1).
    connection: quinn::Connection,
    /// One long-lived unidirectional stream per artifact class, each behind
    /// its **own** lock so a stalled summary write cannot block a
    /// revocation write (ADR-269 §4.3).
    streams: BTreeMap<StreamClass, Arc<Mutex<quinn::SendStream>>>,
}

/// QUIC federation transport (ADR-269 §4).
///
/// One endpoint serves both roles: it accepts inbound pushes from peers and
/// dials outbound connections, one per peer, each pinned to that peer's
/// registered ed25519 federation key.
pub struct QuicTransport {
    /// The shared quinn endpoint (client + server).
    endpoint: quinn::Endpoint,
    /// This gateway's own federation identity.
    identity: PeerIdentity,
    /// Live outbound connections, keyed by peer address.
    peers: Mutex<BTreeMap<String, PeerConnection>>,
    /// Artifacts peers pushed at us, awaiting `subscribe`.
    inbound: Arc<StdMutex<Vec<FederationArtifact>>>,
    /// The rustls crypto provider (ring) used for every connection.
    provider: Arc<rustls::crypto::CryptoProvider>,
    /// Background accept loop; aborted on drop.
    accept_task: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for QuicTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicTransport")
            .field("biome_id", &self.identity.biome_id)
            .field("pubkey_hex", &self.identity.pubkey_hex)
            .finish_non_exhaustive()
    }
}

impl Drop for QuicTransport {
    fn drop(&mut self) {
        self.accept_task.abort();
        self.endpoint.close(0u32.into(), b"shutdown");
    }
}

impl QuicTransport {
    /// Bind a QUIC endpoint whose TLS identity **is** the biome's ed25519
    /// key (ADR-269 §4): pass the same 32-byte seed
    /// [`crate::state::biome_seed`] gives [`rucelium_federation::Biome`], and
    /// the transport identity and the signing identity are one key.
    ///
    /// `backfill` supplies this gateway's own artifacts when a peer calls
    /// `sync_since`; `None` answers backfill requests with an empty set.
    pub fn bind(
        addr: SocketAddr,
        biome_id: impl Into<String>,
        biome_seed: &[u8; 32],
        backfill: Option<BackfillSource>,
    ) -> Result<Self, TransportError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        // The biome key, as a rustls signing key. Same 32 bytes as the
        // ed25519 identity the biome signs summaries and events with.
        let pkcs8 = PrivatePkcs8KeyDer::from(ed25519_pkcs8(biome_seed));
        let signing_key = rustls::crypto::ring::sign::any_eddsa_type(&pkcs8)
            .map_err(|e| TransportError::Protocol(format!("biome key unusable for TLS: {e}")))?;
        let spki = signing_key
            .public_key()
            .ok_or_else(|| TransportError::Protocol("biome key exposes no SPKI".into()))?;
        let pubkey_hex = key_hex_from_spki(spki.as_ref());
        let certified = rustls::sign::CertifiedKey::new(
            vec![CertificateDer::from(spki.as_ref().to_vec())],
            signing_key,
        );

        let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| TransportError::Protocol(format!("TLS 1.3 unavailable: {e}")))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(
                rustls::server::AlwaysResolvesServerRawPublicKeys::new(Arc::new(certified)),
            ));
        server_crypto.alpn_protocols = vec![ALPN.to_vec()];
        let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| TransportError::Protocol(format!("quic server config: {e}")))?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server));

        let endpoint = quinn::Endpoint::server(server_config, addr)
            .map_err(|e| TransportError::Unreachable(format!("bind quic {addr}: {e}")))?;

        let inbound = Arc::new(StdMutex::new(Vec::new()));
        let accept_task = tokio::spawn(accept_loop(endpoint.clone(), inbound.clone(), backfill));

        Ok(QuicTransport {
            endpoint,
            identity: PeerIdentity {
                biome_id: biome_id.into(),
                pubkey_hex,
            },
            peers: Mutex::new(BTreeMap::new()),
            inbound,
            provider,
            accept_task,
        })
    }

    /// The address the endpoint actually bound (useful with port `0`).
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint
            .local_addr()
            .map_err(|e| TransportError::Unreachable(format!("quic local_addr: {e}")))
    }

    /// This gateway's own federation identity, as peers must pin it.
    ///
    /// Named `local_identity` so it cannot be confused with
    /// [`FederationTransport::identity`], which reports a *peer's*.
    #[must_use]
    pub fn local_identity(&self) -> &PeerIdentity {
        &self.identity
    }

    /// Which artifact classes currently hold an open send stream to `peer`.
    ///
    /// Exposed because it is the observable form of the ADR-269 §4.3
    /// guarantee: summaries and events must occupy *different* streams, so
    /// loss or backpressure on one cannot stall the other.
    pub async fn open_stream_classes(&self, peer: &PeerRef) -> Vec<StreamClass> {
        let peers = self.peers.lock().await;
        peers
            .get(&peer.url)
            .map(|c| c.streams.keys().copied().collect())
            .unwrap_or_default()
    }

    /// A [`PeerRef`] describing this endpoint, ready for another
    /// [`QuicTransport`] to pin and dial.
    pub fn peer_ref(&self) -> Result<PeerRef, TransportError> {
        Ok(PeerRef::with_identity(
            self.local_addr()?.to_string(),
            &self.identity.biome_id,
            &self.identity.pubkey_hex,
        ))
    }

    /// Dial `peer`, pinning its registered federation key as the only
    /// acceptable TLS identity (ADR-269 §4). A mismatch is reported as
    /// [`TransportError::IdentityRefused`], never as a generic failure.
    async fn dial(&self, peer: &PeerRef) -> Result<quinn::Connection, TransportError> {
        let Some(pubkey_hex) = peer.pubkey_hex.as_deref() else {
            return Err(TransportError::Protocol(format!(
                "peer {} has no registered federation key; QUIC requires it before connecting",
                peer.url
            )));
        };
        let addr: SocketAddr = peer
            .url
            .parse()
            .map_err(|e| TransportError::Unreachable(format!("bad quic peer {}: {e}", peer.url)))?;

        let verifier = Arc::new(PinnedBiomeKeyVerifier::new(
            pubkey_hex,
            self.provider.clone(),
        )?);
        let outcome = verifier.outcome.clone();
        let mut crypto = rustls::ClientConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| TransportError::Protocol(format!("TLS 1.3 unavailable: {e}")))?
            // Installing ANY custom verifier requires this call. The
            // verifier installed here is strictly *stronger* than webpki:
            // one pinned key, exact bytes, no CA, no name matching.
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        crypto.alpn_protocols = vec![ALPN.to_vec()];
        let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| TransportError::Protocol(format!("quic client config: {e}")))?;
        let client_config = quinn::ClientConfig::new(Arc::new(quic_client));

        let refuse = |fallback: TransportError| -> TransportError {
            match outcome.refused.lock() {
                Ok(guard) => match guard.as_ref() {
                    Some(got) => TransportError::IdentityRefused {
                        expected: pubkey_hex.to_string(),
                        got: got.clone(),
                    },
                    None => fallback,
                },
                Err(_) => fallback,
            }
        };

        let connecting = self
            .endpoint
            .connect_with(client_config, addr, SNI)
            .map_err(|e| refuse(TransportError::Unreachable(format!("connect {addr}: {e}"))))?;
        connecting.await.map_err(|e| {
            refuse(TransportError::Unreachable(format!(
                "handshake {addr}: {e}"
            )))
        })
    }

    /// The send stream for one artifact class on one peer, opening the
    /// connection and/or the stream on first use.
    ///
    /// Each class gets its own stream and its own lock, which is the whole
    /// point of ADR-269 §4.3: a large summary in flight neither occupies the
    /// revocation stream nor holds a lock a revocation needs.
    async fn class_stream(
        &self,
        peer: &PeerRef,
        class: StreamClass,
    ) -> Result<Arc<Mutex<quinn::SendStream>>, TransportError> {
        let mut peers = self.peers.lock().await;
        // Drop a connection the peer has closed, so the next call redials.
        if let Some(existing) = peers.get(&peer.url) {
            if existing.connection.close_reason().is_some() {
                peers.remove(&peer.url);
            }
        }
        if !peers.contains_key(&peer.url) {
            let connection = self.dial(peer).await?;
            peers.insert(
                peer.url.clone(),
                PeerConnection {
                    connection,
                    streams: BTreeMap::new(),
                },
            );
        }
        let entry = peers
            .get_mut(&peer.url)
            .ok_or_else(|| TransportError::Unreachable(format!("peer {} vanished", peer.url)))?;
        if let Some(stream) = entry.streams.get(&class) {
            return Ok(stream.clone());
        }
        let mut send = entry
            .connection
            .open_uni()
            .await
            .map_err(|e| TransportError::Unreachable(format!("open_uni: {e}")))?;
        send.write_all(&[class.tag()])
            .await
            .map_err(|e| TransportError::Unreachable(format!("write class tag: {e}")))?;
        let stream = Arc::new(Mutex::new(send));
        entry.streams.insert(class, stream.clone());
        Ok(stream)
    }
}

/// Encode one artifact as a length-prefixed JSON frame.
fn encode_frame(artifact: &FederationArtifact) -> Result<Vec<u8>, TransportError> {
    let body = serde_json::to_vec(artifact)
        .map_err(|e| TransportError::Encoding(format!("encode artifact: {e}")))?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(TransportError::Encoding(format!(
            "artifact is {} bytes, over the {MAX_FRAME_BYTES} byte frame limit",
            body.len()
        )));
    }
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

impl FederationTransport for QuicTransport {
    fn name(&self) -> &'static str {
        "quic"
    }

    /// Push one artifact on the stream for its class (ADR-269 §4.3).
    fn announce<'a>(
        &'a self,
        peer: &'a PeerRef,
        artifact: &'a FederationArtifact,
    ) -> TransportFuture<'a, ()> {
        Box::pin(async move {
            let frame = encode_frame(artifact)?;
            let stream = self.class_stream(peer, artifact.stream_class()).await?;
            let mut send = stream.lock().await;
            send.write_all(&frame)
                .await
                .map_err(|e| TransportError::Unreachable(format!("write artifact: {e}")))?;
            Ok(())
        })
    }

    /// Drain everything peers pushed at us since the last call.
    ///
    /// The queue is endpoint-wide (see the module's honest limitations), so
    /// `peer` is not used to filter — attribution comes from the signing key
    /// during verification, not from the connection.
    fn subscribe<'a>(&'a self, peer: &'a PeerRef) -> TransportFuture<'a, Vec<FederationArtifact>> {
        let _ = peer;
        Box::pin(async move {
            let mut queue = self
                .inbound
                .lock()
                .map_err(|_| TransportError::Protocol("inbound queue poisoned".into()))?;
            Ok(std::mem::take(&mut *queue))
        })
    }

    /// Ask the peer for everything from `since_ns` on, over a fresh
    /// bidirectional stream so a backfill never shares fate with the push
    /// streams (ADR-269 §3, §4.3).
    fn sync_since<'a>(
        &'a self,
        peer: &'a PeerRef,
        since_ns: u64,
    ) -> TransportFuture<'a, Vec<FederationArtifact>> {
        Box::pin(async move {
            let connection = {
                let mut peers = self.peers.lock().await;
                if let Some(existing) = peers.get(&peer.url) {
                    if existing.connection.close_reason().is_some() {
                        peers.remove(&peer.url);
                    }
                }
                match peers.get(&peer.url) {
                    Some(existing) => existing.connection.clone(),
                    None => {
                        let connection = self.dial(peer).await?;
                        peers.insert(
                            peer.url.clone(),
                            PeerConnection {
                                connection: connection.clone(),
                                streams: BTreeMap::new(),
                            },
                        );
                        connection
                    }
                }
            };
            let (mut send, mut recv) = connection
                .open_bi()
                .await
                .map_err(|e| TransportError::Unreachable(format!("open_bi: {e}")))?;
            send.write_all(&since_ns.to_be_bytes())
                .await
                .map_err(|e| TransportError::Unreachable(format!("write backfill cursor: {e}")))?;
            send.finish().map_err(|e| {
                TransportError::Unreachable(format!("finish backfill request: {e}"))
            })?;
            let body = recv
                .read_to_end(MAX_BACKFILL_BYTES)
                .await
                .map_err(|e| TransportError::Unreachable(format!("read backfill: {e}")))?;
            if body.is_empty() {
                return Ok(Vec::new());
            }
            serde_json::from_slice(&body)
                .map_err(|e| TransportError::Encoding(format!("decode backfill: {e}")))
        })
    }

    /// Over QUIC the peer's key is a *precondition* of connecting, not
    /// something learned afterwards — the handshake already proved the peer
    /// holds it (ADR-269 §4). Report it back so the gateway can bind
    /// `biome_id → key` exactly as it does for HTTP.
    fn identity<'a>(&'a self, peer: &'a PeerRef) -> TransportFuture<'a, Option<PeerIdentity>> {
        Box::pin(async move {
            match (peer.biome_id.as_deref(), peer.pubkey_hex.as_deref()) {
                (Some(biome_id), Some(pubkey_hex)) => Ok(Some(PeerIdentity {
                    biome_id: biome_id.to_string(),
                    pubkey_hex: pubkey_hex.to_string(),
                })),
                _ => Err(TransportError::Protocol(format!(
                    "peer {} has no pinned federation identity",
                    peer.url
                ))),
            }
        })
    }
}

/// Accept inbound connections forever, servicing each on its own task.
async fn accept_loop(
    endpoint: quinn::Endpoint,
    inbound: Arc<StdMutex<Vec<FederationArtifact>>>,
    backfill: Option<BackfillSource>,
) {
    while let Some(incoming) = endpoint.accept().await {
        let inbound = inbound.clone();
        let backfill = backfill.clone();
        tokio::spawn(async move {
            let connection = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    // A refused pin shows up here as a handshake failure.
                    eprintln!("gateway: quic inbound handshake failed: {e}");
                    return;
                }
            };
            serve_connection(connection, inbound, backfill).await;
        });
    }
}

/// Service one inbound connection: every stream on its own task, so a
/// stalled summary stream cannot delay a revocation stream (ADR-269 §4.3).
async fn serve_connection(
    connection: quinn::Connection,
    inbound: Arc<StdMutex<Vec<FederationArtifact>>>,
    backfill: Option<BackfillSource>,
) {
    loop {
        tokio::select! {
            uni = connection.accept_uni() => match uni {
                Ok(recv) => {
                    let inbound = inbound.clone();
                    tokio::spawn(async move { read_class_stream(recv, inbound).await; });
                }
                Err(_) => return,
            },
            bi = connection.accept_bi() => match bi {
                Ok((send, recv)) => {
                    let backfill = backfill.clone();
                    tokio::spawn(async move { serve_backfill(send, recv, backfill).await; });
                }
                Err(_) => return,
            },
        }
    }
}

/// Read length-prefixed artifact frames off one class stream until it ends.
async fn read_class_stream(
    mut recv: quinn::RecvStream,
    inbound: Arc<StdMutex<Vec<FederationArtifact>>>,
) {
    let mut tag = [0u8; 1];
    if recv.read_exact(&mut tag).await.is_err() {
        return;
    }
    if StreamClass::from_tag(tag[0]).is_none() {
        eprintln!(
            "gateway: quic peer opened a stream with unknown class {}",
            tag[0]
        );
        return;
    }
    loop {
        let mut len = [0u8; 4];
        if recv.read_exact(&mut len).await.is_err() {
            return; // stream ended (or the peer went away)
        }
        let len = u32::from_be_bytes(len) as usize;
        if len > MAX_FRAME_BYTES {
            eprintln!("gateway: quic frame of {len} bytes exceeds the limit; dropping stream");
            return;
        }
        let mut body = vec![0u8; len];
        if recv.read_exact(&mut body).await.is_err() {
            return;
        }
        match serde_json::from_slice::<FederationArtifact>(&body) {
            Ok(artifact) => {
                if let Ok(mut queue) = inbound.lock() {
                    queue.push(artifact);
                }
            }
            Err(e) => eprintln!("gateway: undecodable quic artifact: {e}"),
        }
    }
}

/// Answer one backfill request from the local [`BackfillSource`].
async fn serve_backfill(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    backfill: Option<BackfillSource>,
) {
    let mut cursor = [0u8; 8];
    if recv.read_exact(&mut cursor).await.is_err() {
        return;
    }
    let since_ns = u64::from_be_bytes(cursor);
    let artifacts = backfill.map(|source| source(since_ns)).unwrap_or_default();
    let body = match serde_json::to_vec(&artifacts) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("gateway: encoding quic backfill failed: {e}");
            return;
        }
    };
    if send.write_all(&body).await.is_err() {
        return;
    }
    let _ = send.finish();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs8_wrapper_is_the_rfc_8410_encoding_and_round_trips_through_ring() {
        let seed = [7u8; 32];
        let der = ed25519_pkcs8(&seed);
        assert_eq!(der.len(), 48);
        assert_eq!(&der[..2], &[0x30, 0x2e]);
        assert_eq!(&der[der.len() - 32..], &seed);
        // ring accepts it, and the derived SPKI holds a 32-byte key.
        let key = rustls::crypto::ring::sign::any_eddsa_type(&PrivatePkcs8KeyDer::from(der))
            .expect("ring parses the biome key");
        let spki = key.public_key().expect("ed25519 exposes an SPKI");
        assert_eq!(spki.as_ref().len(), 44);
        assert_eq!(key_hex_from_spki(spki.as_ref()).len(), 64);
    }

    #[test]
    fn expected_spki_matches_what_a_server_would_present() {
        let seed = [3u8; 32];
        let key = rustls::crypto::ring::sign::any_eddsa_type(&PrivatePkcs8KeyDer::from(
            ed25519_pkcs8(&seed),
        ))
        .expect("ring parses the biome key");
        let served = key.public_key().expect("spki").as_ref().to_vec();
        let pinned = expected_spki(&key_hex_from_spki(&served)).expect("pin builds");
        assert_eq!(
            pinned, served,
            "the pinned SPKI must be byte-identical to the served one"
        );
    }

    #[test]
    fn malformed_peer_keys_are_encoding_errors_not_silent_accepts() {
        assert!(matches!(
            expected_spki("nothex!"),
            Err(TransportError::Encoding(_))
        ));
        assert!(matches!(
            expected_spki("aabb"),
            Err(TransportError::Encoding(_))
        ));
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("zz"), None);
        assert_eq!(hex_decode("00ff"), Some(vec![0x00, 0xff]));
    }

    #[test]
    fn hex_round_trips() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        assert_eq!(hex_decode(&hex_encode(&bytes)), Some(bytes));
    }
}
