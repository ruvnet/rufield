# ADR 265: RuCelium Runtime — Gateway Daemon, Constrained Transport, Durable Store

Status: Accepted — v0.1 runtime layer

Date: 2026 08 02

Deciders: rUv

Tags: rucelium, gateway, daemon, lorawan, fragmentation, storage, retention, federation, no_std

## 1. Context

ADR-264 shipped the RuCelium data model, trust machinery, and a deterministic
64-node acceptance benchmark. What it deliberately did not ship is a runtime:
the crates were libraries, the federation bus was in-process, storage was an
in-memory buffer, and the signed envelope had never met a real radio budget.

Auditing the gap surfaced one hard fact: the v1 envelope
(`[payload 48 B, pubkey 32 B, signature 64 B]` in CBOR ≈ **150 bytes**) does
not fit LoRaWAN DR0's ~51-byte application payload cap — and LoRaWAN 1.0.4 is
the ADR-264 primary spore transport. The transport problem is therefore not
hypothetical; it gates any real deployment.

## 2. Decision — constrained transport (`rucelium-transport`)

Two composable mechanisms:

1. **Compact envelope v2, pubkey by reference.** The gateway already holds the
   device registry keyed by the `node_id` inside the payload, so the envelope
   does not need to carry the public key. v2 is a packed frame:
   `magic 0xC2, version 2, payload[48], signature[64]` = **114 bytes** —
   24 % smaller than v1, with identical cryptographic strength (the gateway
   verifies against the registered key; a forged node_id simply selects a key
   the signature cannot match). `to_v1()` rehydrates a v1 record so the
   ingest pipeline is unchanged downstream and re-verifies as before.
2. **MTU fragmentation.** A 6-byte header (`magic 0xF7, version, msg_id u16,
   frag_idx, frag_count`) splits any message into ≤255 chunks of `mtu − 6`
   bytes. At `LORAWAN_DR0_MTU = 51`, a compact envelope is exactly
   **3 datagrams**. The `Reassembler` is keyed by `(sender, msg_id)`,
   tolerates loss (caller-driven timeout eviction), duplication, and
   reordering, and caps pending messages so lost fragments cannot leak memory.

Rejected alternatives: truncated signatures (breaks ed25519), MAC-only links
with periodic signed checkpoints (weakens the per-observation provenance
requirement of ADR-264 §7.1 — may be revisited as an *addition* for
ultra-constrained duty cycles, never a replacement).

## 3. Decision — durable store (`rucelium-store`)

ADR-264 §13 named "SQLite or RVF buffering". v0.1 chooses an RVF-style
**append-only segmented JSONL log** over SQLite: zero new dependencies, no C
build, human-inspectable segments, and deletion-by-segment matches the
retention model (whole expired segments are unlinked; no rewrite, no vacuum).

Properties:

- **Dedup index** on `(node_id, sequence)` (observations) / `event_id`
  (events), rebuilt by scanning segments at open — restart-safe.
- **Crash recovery**: a torn tail line (crash mid-write) is truncated on open;
  corruption anywhere else is a hard, named error — never silently skipped.
- **Deterministic replay**: iteration is append order, always.
- **Retention enforcement** (`enforce_retention(now_ns, retention_ns)`)
  deletes whole expired segments, never the active one, implementing the
  ADR-264 §10 per-class lifespans (raw: days; derived: months; events: years).
- Dedup keys are retained after segment deletion (bytes are freed, keys are
  tiny); documented trade-off.

## 4. Decision — gateway daemon (`rucelium-gateway`)

A single tokio/axum binary that composes the existing library crates into the
ADR-264 Layer-2 rhizome:

```text
UDP :7464  ──► envelope detect (v1 CBOR / v2 compact / fragments)
           ──► reassemble ──► registry + signature + anti-replay (ingest)
           ──► calibration + drift quarantine
           ──► ObservationStore (disk) + WorldGraph + local alert rules
           ──► EventStore + biome-signed events
HTTP :7465 ──► /health /api/stats /api/observations/recent /api/events
           ──► /api/sensorthings/{Things,Datastreams,Observations}
           ──► /api/federation/{pubkey,summary,revocations,peers}
```

- **Federation over the network**: a background task polls each configured
  peer's `/api/federation/summary` and `/revocations`, verifies the ed25519
  signatures with the peer's published biome key, stores verified summaries,
  and applies verified `DeviceRevoked` events to the local registry. Biome
  sovereignty is preserved: only signed summaries and events cross the wire,
  exactly as ADR-264 §6 requires.
- **`--simulate N`**: the daemon can spawn N synthetic spore nodes that sign
  real envelopes and send them over the loopback UDP socket — the full
  pipeline demonstrable with zero hardware, honestly labelled SYNTHETIC.
- Retention enforcement runs on a timer with the ADR-264 §10 defaults.

## 5. Decision — `no_std` ABI surface

`rucelium-abi` gains a `std` default feature. With
`--no-default-features --features alloc`, the crate exposes the wire format
(`RvEnvSampleV1` parse/encode/validate) and deterministic CBOR — the exact
surface a Rust-based spore node (RP2040/ESP32 class) needs to produce
envelopes. Signing (`sign` module) and domain conversion (`to_env_sample`,
which requires `rucelium-core`) remain std-only in v0.1.

## 6. Consequences

Positive: the platform now *runs* — one command starts a gateway that ingests,
verifies, calibrates, stores, alerts, serves SensorThings, and federates
revocations with a peer. The LoRaWAN fit problem is solved at the framing
layer where it belongs.

Negative / accepted: JSONL segments are larger than a binary store (revisit
with RVF proper); federation polling is pull-based (push/webhooks later);
retention deletes at segment granularity; `no_std` is compile-checked, not
yet CI-checked on an embedded target.

## Implementation status (v0.1 runtime)

| # | Item | Status |
|---|---|---|
| 1 | Compact envelope v2 + DR0 fragmentation | shipped — `rucelium-transport` |
| 2 | Durable segmented store + retention | shipped — `rucelium-store` |
| 3 | Gateway daemon (UDP ingest, HTTP/SensorThings API, simulate mode) | shipped — `rucelium-gateway` |
| 4 | Peer federation sync (summaries + revocations, verified) | shipped — `rucelium-gateway::federation` |
| 5 | `no_std` ABI feature | shipped — `rucelium-abi` |
| 6 | Reference C firmware, real LoRaWAN stack, secure time, key rotation, RVF binary store, embedded-target CI | honest follow-up |
