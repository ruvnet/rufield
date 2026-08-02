# ADR 269: Push Federation and the QUIC Question

Status: Accepted — transport-agnostic push, QUIC as an optional transport

Date: 2026 08 02

Deciders: rUv

Tags: rucelium, federation, quic, transport, revocation, push, sovereignty, lorawan

## 1. Context

Two questions arrived together: *should the gateway use QUIC instead of UDP?*
and *should federation stay a poller?* They have different answers, and
conflating them would produce the wrong design.

There is no `@ruvector/quic`: RuVector is a vector database and format family
(`ruvector`, `@ruvector/rvf`, `@ruvector/core`, `@ruvector/gnn`,
`@ruvector/graph-node`, WASM/napi bindings). It is a **memory** substrate
(ADR-268 §2.1), not a transport. So the transport question is plain QUIC.

RuCelium has three network hops with genuinely different requirements, and the
current implementation gets one of them wrong.

## 2. Decision — the sensor boundary keeps datagrams. Not QUIC.

The gateway's UDP socket is **scaffolding standing in for a radio**. Real
spore transports are LoRaWAN, BLE, 802.15.4, RS-485, and SDI-12 — mostly not
IP at all. QUIC is a category error there:

1. **The handshake dwarfs the payload.** RFC 9000 §14.1 requires a client
   Initial packet be padded to **≥1200 bytes** for path validation. Our whole
   envelope is 114 bytes (ADR-265 §2) and LoRaWAN DR0 MTU is 51. The handshake
   alone is ~24× the message.
2. **Connection state versus sleep.** A node waking every 30 minutes to send
   48 bytes cannot amortize connection establishment and will have lost the
   connection between wakeups regardless. Per-connection state × thousands of
   nodes is a gateway memory problem for no gain.
3. **Duty cycle.** Under EU868's 1% budget, handshake round-trips are often
   not merely expensive but unaffordable.
4. **Decisive: we do not need what it provides.** The envelope is
   *object-secured* — ed25519 over the exact 48 payload bytes, with the
   anti-replay window above it. Authenticity, integrity, and replay protection
   travel **with the data, not the pipe**. That is what lets an untrusted
   store-and-forward relay — precisely what a LoRaWAN network server is — sit
   in the path harmlessly. Channel security would add cost without adding the
   property the design depends on.

The real work at this hop is a LoRaWAN network-server adapter, not a
transport swap.

## 3. Decision — federation moves from poll to push (transport-agnostic)

This is the weaker link, and it is a *security* problem before it is a
performance one. Federation currently polls each peer every 30 s
(ADR-265 §4). That means a revoked device stays valid at peer gateways for up
to a full polling interval after the biome owner revokes it. Revocation
latency is a security property; polling caps it at the interval.

Therefore: **push first, transport second.** A `FederationTransport` trait
carries three verbs — `announce` (a signed summary or event), `subscribe`
(receive a peer's stream), and `sync_since` (backfill after a partition) —
with two implementations:

- `HttpPollTransport` — the existing behaviour, kept as the always-available
  default with no new dependencies. Backfill and correctness live here.
- `QuicTransport` — optional, behind the `quic` cargo feature.

Push changes the revocation story from "within 30 s" to "as fast as the link
allows, with polling as the backstop". The backstop is not optional: a peer
that missed a pushed event must still converge, so `sync_since` runs on
reconnect and on a slow timer regardless of transport.

## 4. Decision — QUIC is the optional transport, and never the trust boundary

Where QUIC earns its place is exactly ADR-264 §1's founding premise —
unreliable connectivity:

1. **Connection migration.** A watershed gateway failing over LTE → satellite
   → wifi keeps its connection across IP changes. TCP breaks; QUIC survives.
2. **0-RTT resumption** after a partition — reconnect and drain backlog
   without a full handshake.
3. **No head-of-line blocking.** A lost packet in the summary stream must not
   stall the revocation stream. Separate QUIC streams per artifact class.
4. **Loss recovery** on satellite and rural cellular links.
5. **Traffic-analysis resistance.** This matters more than it sounds for the
   biodiversity wedge (ADR-266 §3.1): alert *timing* leaks information about a
   sensitive location even when the payload is signed and the coordinates are
   coarsened. Channel encryption hides the pattern; disclosure policy alone
   does not.

Two constraints, both normative:

- **QUIC is defence in depth, never the trust boundary.** Summaries and events
  are already ed25519-signed and identity-bound (`biome_id → key + epoch`,
  ADR-268-era hardening). If a QUIC session ever becomes the reason a peer is
  trusted, that is a regression. Everything received over QUIC goes through
  exactly the same verification as everything received over HTTP.
- **TLS identity is the biome's existing ed25519 key**, carried as a raw
  public key (RFC 7250) rather than X.509. No certificate authority, no new
  PKI, no name-based trust — the sovereignty model already says the biome owns
  its key, and this makes the transport agree with it. A peer's TLS identity
  must equal its registered federation key or the connection is refused.

## 5. Consequences

Positive: revocation propagates at link speed instead of polling speed;
federation survives IP changes and partitions; the alert-timing side channel
closes for sensitive-species deployments; the transport becomes swappable, so
the ThreeFold Mycelium overlay (ADR-264 §9) or anything else can be added
later without touching federation logic.

Negative / accepted: `quinn` + `rustls` is a substantial dependency tree for a
deliberately lean workspace — hence the feature flag, default off. Push adds a
delivery-state concern (what if a push is dropped?) answered by keeping
`sync_since` mandatory. Raw-public-key TLS is less widely supported than
X.509; the HTTP transport remains the interoperable path.

**Additive constraint (inherited from ADR-268 §3, restated as normative):**
the ADR-264 §14 acceptance path and the ADR-265 restart-attack tests must both
continue to pass with the `quic` feature **disabled**.

## Implementation status

| # | Item | Status |
|---|---|---|
| 1 | `FederationTransport` trait (announce / subscribe / sync_since) | shipped |
| 2 | `HttpPollTransport` — default, dependency-free, backfill of record | shipped |
| 3 | Push-on-revocation with polling backstop | shipped |
| 4 | `QuicTransport` behind the `quic` feature, raw-public-key identity bound to the biome key | shipped |
| 5 | Peer TLS identity ≠ registered federation key ⇒ connection refused | shipped |
| 6 | LoRaWAN network-server adapter (the actual sensor-boundary work) | honest follow-up |
