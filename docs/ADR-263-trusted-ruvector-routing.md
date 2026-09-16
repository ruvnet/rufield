# ADR 263: Trusted local RuVector routing handoff

Status: proposed. Companion implementation: RuVector PR 986, revision
`a55d429117c040adcdc5d17a814230f98ffbd8e2`.

## Problem

The routing consumer accepts a caller supplied verification flag. Passing that
flag directly from an event or remote request could bypass the SDK trust registry.
Serializing an entire sensor tensor for a router also wastes work and exposes
fields that routing does not need.

## Decision

Extend the existing `rufield-ruvector` boundary with `prepare_routing_event`.
The caller owns a production `TrustVerifier` and persists its replay state.
Preparation validates privacy, SDK evidence and routing scalars, then verifies
the original signature, sensor binding, freshness and replay watermark. The
result is an immutable, non-deserializable `PreparedRoutingEvent` with a compact
local routing payload. No boolean verification input exists on preparation.

Only tensor and observation classes P1/P2 are accepted. Identity evidence is
rejected even if incorrectly labeled. Only event ID, integer timestamp, sensor
ID, zone/cell, confidence and presence/motion/transient features are forwarded.
The adapter does not infer geographic positions from CSI peaks.

The closure seam follows the existing SDK policy of not pinning an unpublished
RuVector package. Use with RuVector's Rust SDK:

```rust,ignore
let prepared = prepare_routing_event(&event, &mut verifier, now_ns)?;
let update = prepared.deliver(now_ns, |json, verified, now| {
    router.ingest_json(json, verified, now)
})??;
```

The backend remains responsible for zone bindings, route cost policy, TTL,
source aggregation and idempotence. Call `expire(now_ns)` on the router regularly.
Prepared delivery uses borrowed bytes and performs no serialization or allocation.
The original full event must still be canonicalized for signature verification.

## Failure and deployment semantics

Invalid projections never advance replay state. Successful preparation does,
regardless of subsequent delivery. Retain the prepared object to retry a failed
local mapping/backend operation. Delivery rechecks the original production time
window; downstream TTL may be stricter. Do not rewind replay state on sink errors.
Persist SDK replay state across restart as required by the deployment.

This is an in-process authorization result, not a network credential. The compact
payload has no valid original signature. Verify the original event again at every
remote trust boundary. A prepared object snapshots trust at preparation time:
a key revocation requires discarding queued objects from that sensor. Keep queues
short and governed by the host. No untrusted JSON parsing endpoint is added.

All times remain u64. JavaScript Number cannot represent Unix epoch nanoseconds
exactly. This upstream adapter targets the Rust SDK; an external JS bridge must
use a lossless BigInt or decimal string contract, not a Number conversion.

## Validation and measurements

`cargo test --workspace` covers the SDK and added security regressions.
`python3 harness/routing/run.py` retrieves SHA256 pinned routing source from the
companion revision and compiles it with the real upstream SDK in isolation. The
contract signs a RuView fixture, enrolls its sensor key, closes the preferred
route, checks retry idempotence, expires risk and restores original route cost.
It is not a build of the full RuVector workspace.

`cargo run --release -p rufield-ruvector --example routing_bench` runs 100 warmup
and 1,000 measured events with a deterministic 4,096 value tensor. Signing is
outside the timer. On the development runner, full payload was 21,726 bytes and
routing projection was 268 bytes, a 98.77% reduction. Verification plus preparation
p50 was 155.195 microseconds and p95 172.250 microseconds. Full event serialization
alone was 80.201 microseconds median. No-op prepared delivery was 20 nanoseconds;
that measures adapter overhead only and excludes route updates, IPC and networking.
These are generated SDK workloads, not captured RF performance or SOTA claims.
