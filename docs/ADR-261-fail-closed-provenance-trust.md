# ADR 261: Fail Closed Provenance Trust and Replay Defense

Status: Accepted

Date: 2026 08 21

Deciders: rUv, RuField maintainers

Tags: provenance, trust, sensor identity, replay, STRIDE, production

## 1. Context

The original RuField MFS version 0.1 fusability rule accepted an event when it
was marked synthetic or when its detached Ed25519 signature verified against
the public key carried inside that same event.

That rule is useful for deterministic simulation and integrity checks, but it
does not authenticate a sensor. Any producer can create a key pair, sign its
own event and provide the corresponding public key. Any producer can also set
the unsigned synthetic flag. The stateless rule has no replay protection.

Production fusion therefore needs an authorization decision above signature
verification. The decision must be deterministic under test, persist across a
restart and reject before the graph or inference window changes.

## 2. Decision

Introduce a stateful `TrustVerifier` in `rufield-provenance` and make
`RuFieldFusion` own one verifier.

The verifier has three explicit modes.

| Mode | Synthetic evidence | Independent key enrollment | Freshness | Replay watermark |
| --- | --- | --- | --- | --- |
| `Simulation` | Allowed | Not required | Not checked | Enforced |
| `CapturedReplay` | Rejected | Required | Historical time allowed | Enforced |
| `Production` | Rejected | Required | Required | Enforced |

`Simulation` is the only compatibility boundary for the original
`is_fusable` behavior. `is_fusable` remains public for existing benchmark and
simulator callers, but its documentation forbids using it as a production
authorization decision.

`CapturedReplay` exists for real, signed recordings whose timestamps are
necessarily outside a live freshness window. It is not a way to admit
synthetic events or unknown keys.

`Production` defaults to a maximum event age of five minutes and maximum future
clock skew of five seconds. A caller may configure stricter values.

## 3. Trust Anchors and Binding

`TrustedKeyRegistry` is configured independently from event input. It maps a
stable sensor id to a normalized Ed25519 public key and carries a revocation
set.

The event-carried public key is treated only as a claimed identifier. A live
event is accepted only when all of these predicates are true.

1. The event and sensor ids are nonempty.
2. The event is not synthetic.
3. The carried key is valid Ed25519 material.
4. The key appears in the independent registry.
5. The key is not revoked.
6. The sensor id is enrolled.
7. The sensor id is bound to that exact key.
8. The signature verifies over the canonical event.
9. The timestamp is inside the configured live window.
10. The event timestamp strictly advances its sensor watermark.

All checks precede replay watermark mutation. Only a fully accepted event can
advance state. Fusion then records the sensor and event nodes and adds the
event to its temporal window.

## 4. Replay State

Versioned `ReplayState` stores one `ReplayWatermark` per sensor. A watermark
contains the last timestamp, event id and optional signer key.

The state has strict JSON serialization and restoration. Restoration rejects
unknown fields, unsupported schema versions, empty sensor ids, empty event ids,
malformed signer keys, removed existing watermarks and timestamp rollback.

The storage system must write this state atomically after accepted batches and
integrity protect it. The library deliberately does not choose a database or
key management service.

## 5. STRIDE Analysis

| Threat | Existing exposure | Control in this decision | Residual risk |
| --- | --- | --- | --- |
| Spoofing | Attacker self signs with an event-carried key or exploits noncanonical registry material | Validated normalized registry deserialization, independent key enrollment and sensor binding | Enrollment control plane compromise |
| Tampering | Field values or synthetic flag modified after signing | Canonical signature covers event contents | Compromised sensor signing key |
| Repudiation | No durable acceptance position | Persistable per-sensor watermark and signer identity | External audit receipt not yet implemented |
| Information disclosure | Full accepted or rejected events and detailed trust errors can reveal device/zone ids, labels, hashes, signer material and enrollment status | The live viewer broadcasts a default-policy public projection with no direct identifiers, raw labels, receipt material, signatures or provenance edges; rejection diagnostics are closed stable enums without attacker-controlled text | Aggregate reason counts may still reveal fleet posture and require endpoint access control |
| Denial of service | Invalid signatures consume verification work | Unknown and revoked keys reject before signature verification | Known-key signature flooding still consumes CPU |
| Elevation of privilege | Synthetic flag bypasses all verification | Synthetic evidence is rejected outside simulation | A caller can still deliberately construct a simulation engine |

## 6. API and Compatibility

`RuFieldFusion::new` and `RuFieldFusion::with_rules` remain deterministic
simulation constructors so existing benchmarks do not silently change.

Live callers use `RuFieldFusion::production(registry)` or pass a verifier to
`RuFieldFusion::with_trust_verifier`. Deterministic production tests use
`ingest_at(event, now_ns)`. The trait `ingest` path uses system wall clock and
still invokes the owned verifier.

No event wire fields change in this decision. This keeps MFS version 0.1 input
compatible and avoids modifying `rufield-core` during the security fix.

## 7. Migration

1. Inventory every caller of `is_fusable` and classify it as simulation,
   captured replay or live production.
2. Keep simulator and synthetic benchmark callers on `Simulation`.
3. Provision a sensor-to-key registry from an authenticated control plane.
4. Change historical real-data jobs to `CapturedReplay`.
5. Change live services to `RuFieldFusion::production`.
6. Persist `ReplayState` atomically and restore it before opening ingestion.
7. Alert on unknown key, revocation, binding, freshness and replay rejection
   counters without exposing enrollment details to untrusted clients.
8. Remove direct live uses of `is_fusable` after downstream migration.

The RuField viewer now implements steps 4, 5 and 8 at its ingest boundary. A
single `LiveProcessor` retains the production or captured-replay verifier
across upstream batches and reconnects. Live viewer startup requires explicit
registry injection and rejects simulation mode.

The viewer also applies `DefaultPrivacyGuard` before constructing its live
broadcast projection. Raw `FieldEvent`s never enter the broadcast channel.
P1/P2 output is restricted to whitelisted modality metadata and confidence;
P0/P3/P4/P5 details are withheld without additional authorization. Direct
identifiers, raw labels, hashes, signer keys, signatures, model/calibration ids
and provenance edges are never members of the public live frame type. Trust
failures are exposed only as stable enumerated reason codes.

## 8. Rollback

Operational rollback must fail closed.

If trust configuration or replay storage fails, stop live fusion and retain
the input for quarantine where privacy policy permits. Do not switch live
traffic to `Simulation` and do not clear replay watermarks.

The code can be rolled back only after disabling the live ingest endpoint. A
rollback that restores the original production use of `is_fusable` reopens the
self-signed and synthetic bypasses and is not an acceptable degraded mode.

## 9. Consequences

Benefits:

1. A valid signature now proves both event integrity and an enrolled sensor
   identity in captured replay and production.
2. Replay rejection survives process restart when state is persisted.
3. Simulation remains deterministic and backwards compatible.
4. Typed rejection reasons support governance metrics and incident response.

Costs:

1. Production deployment now requires key enrollment, revocation distribution
   and durable replay state.
2. Every accepted event incurs one Ed25519 verification and one ordered-map
   watermark lookup. At room-scale rates this should remain submillisecond, but
   it requires a benchmark on target hardware.
3. Operators must manage clock synchronization within the configured skew.

## 10. Residual Risks and Follow Up

The current event schema lacks a signed issuer key id, audience, stream epoch,
explicit sequence number, nonce and attestation claims. Timestamp monotonicity
is therefore the version 0.1 replay primitive. MFS version 0.2 should add these
protected claims and define a COSE Sign1 profile aligned with RFC 9052 and an
Entity Attestation Token profile aligned with RFC 9711.

The trust registry and replay JSON are only as strong as their storage. A
production adapter should bind them to hardware-backed keys or an equivalent
managed key service and emit an append-only transparency receipt. SCITT, RFC
9943, is a candidate interoperability profile.

`RuFieldFusion::new` remains intentionally simulation scoped for compatibility.
Repository policy should eventually lint any use of that constructor under a
live feature or binary.

The viewer accepts programmatically restored replay state, but its reference
binary does not yet atomically export and persist updated watermarks. Replay
defense therefore survives upstream reconnects within one process, but viewer
restart protection requires a host storage adapter. Until that adapter exists,
production operators must checkpoint `ReplayState` in an integrity-protected
store or treat restart as a controlled trust-boundary reset.

## 11. Acceptance Test

Enroll one sensor key and submit one correctly signed fresh event. Confirm the
event creates graph state. Then submit empty-identity, synthetic, flag-flipped,
unknown self-signed, binding-mismatched, revoked, stale, future,
malformed-signature, duplicate and nonmonotonic events. Confirm every case is
rejected and neither the graph nor replay state changes. Deserialize an
uppercase form of an enrolled key into the revocation set and confirm
revocation still wins. Serialize the accepted watermark, restore it into a new
process and confirm the original event is still rejected as a duplicate.

Submit non-ASCII public-key and signature strings whose UTF-8 byte lengths are
even and confirm both return `BadEncoding` without panicking. Feed accepted and
rejected events containing sentinel device/zone ids, labels, hashes, signer
material and signatures through the live viewer. Confirm its public frame and
HTTP SSE contain none of the sentinels or sensitive field names while retaining
the acceptance flag, stable rejection code, privacy disposition and aggregate
counters.
