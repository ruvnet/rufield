# ADR-267: Composite FieldEvent Privacy Authorization

Status: Proposed

Date: 2026-08-24

Issue: #6

## Context

RuField MFS v0.1 classifies both `FieldTensor` and `Observation` independently. The default privacy guard authorizes one `PrivacyClass` at a time. A complete `FieldEvent` can therefore contain components with different policy requirements.

The reference simulator demonstrates the case directly: raw sensor tensors are P0 while derived occupancy and motion observations can be P1 or P2. A caller that checks only `event.observation.privacy_class` can obtain `Allow` for network export while serializing a P0 tensor in the same object.

This is a library boundary problem even where a current integration is safe. RuView ADR-262 currently exports derived feature tensors stamped with the same egress class as their observations, so the live RuView `/api/field` and `/ws/field` bridge does not reproduce the P0 plus P2 mismatch. Other adapters, including captured CSI replay, can.

External direction reinforces object-boundary authorization. ETSI GR ISC 007 covers security, privacy, resilience and trustworthiness for ISAC. ETSI GR ISC 008 explicitly covers sensing data acquisition, processing, fusion, compression, model lifecycle and secure, robust and accurate sensing results. Privacy-preserving ISAC research is also moving policy into measurement configuration rather than treating privacy as a presentation-only concern.

Relevant sources:

https://portal.etsi.org/webapp/workProgram/Report_WorkItem.asp?wki_id=77924

https://portal.etsi.org/webapp/WorkProgram/Report_WorkItem.asp?SearchPage=TRUE&WKI_ID=77922

https://arxiv.org/abs/2608.21064

## Problem

`PrivacyGuard::authorize(class, ...)` is necessary but insufficient to answer whether a complete `FieldEvent` may cross a trust boundary.

A scalar reduction is also unsafe. P0 through P5 are ordered for existing API compatibility, but they do not form a simple monotonic sensitivity lattice. P0 has a special raw-waveform network prohibition. P4 requires consent. P5 requires identity binding and audit. Taking `min` or `max` can erase one of those independent restrictions.

## Constraints

1. Preserve the v0.1 wire format.
2. Preserve source compatibility for existing `PrivacyGuard` implementations.
3. Add no dependency.
4. Keep the decision deterministic and fail closed.
5. Do not infer consent or identity binding from event content.
6. A valid signature proves integrity, not authorization.
7. Do not change sensing accuracy claims or evidence levels.

## Options considered

### Option A: Use the observation class only

Rejected. This is the current caller pattern that can ignore a more restrictive tensor.

### Option B: Use `max(tensor_class, observation_class)`

Rejected. P0 is raw and has a special prohibition while P4 and P5 use different authorization conditions. Numeric ordering cannot represent the conjunction.

### Option C: Introduce a new multidimensional privacy lattice in the wire format

Deferred. This is architecturally cleaner for a future MFS version, but it creates a wire migration and is unnecessary to close the current authorization gap.

### Option D: Authorize every classified component and compose decisions

Accepted. It is additive, explicit and preserves the current contract.

## Decision

Add `DefaultPrivacyGuard::authorize_event`.

For each complete `FieldEvent`, authorize the tensor and observation independently under the same destination and caller supplied consent and identity context.

Decision precedence is:

1. Any `Deny` produces `Deny`.
2. Otherwise any `RequiresConsent` produces `RequiresConsent`.
3. Only two `Allow` decisions produce `Allow`.

The returned reason identifies the component that blocked authorization.

## Architecture

```text
FieldEvent
  tensor privacy class       -> authorize component
  observation privacy class  -> authorize component
                               -> fail closed composition
                               -> event decision
```

This is intentionally an object-boundary API. Component authorization remains available for projections that truly serialize only one component.

## Interfaces

```rust
pub fn authorize_event(
    &self,
    event: &FieldEvent,
    destination: Destination,
    consent: bool,
    identity_bound: bool,
) -> PrivacyDecision;
```

## Data flow

A network surface that serializes a whole `FieldEvent` must call `authorize_event` immediately before serialization. A surface that creates an explicitly derived projection may authorize the fields present in that projection, but must not use an observation decision as authorization for data it did not classify.

## Security considerations

The change closes a confused-deputy style authorization gap where the caller selects the least restrictive component class.

It does not authenticate the caller, establish consent, verify retention policy, or prove that a claimed class is correctly assigned. Those remain separate controls.

No unsafe Rust is introduced. No parsing or network input surface is added.

## Privacy considerations

The event is exportable only when every included classified component is exportable. This prevents P0 raw CSI or radar data from piggybacking on a P1 or P2 semantic observation authorization.

Future MFS work should consider multidimensional privacy attributes rather than overloading one ordered enum for rawness, aggregation, biometric sensitivity and identity linkage.

## Performance implications

Two small enum policy evaluations replace one when authorizing a complete event. Expected added latency is below measurement noise and allocation cost is limited to denial or consent reason strings.

## Hardware implications

None.

## Compatibility

No wire change. No change to `PrivacyGuard`. Existing scalar callers continue to compile.

Network surfaces that serialize complete events should migrate to `authorize_event`.

## Migration

1. Add the composite API.
2. Add regression tests.
3. Audit complete-event network surfaces.
4. Migrate complete-event callers incrementally.
5. Keep component-specific authorization only for explicitly projected payloads.

## Alternatives rejected

Scalar max classification, wire-version rewrite, and implicit authorization based on provenance were rejected because they either lose policy semantics, create unnecessary migration cost, or confuse integrity with authorization.

## Risks

The main residual risk is incorrect component classification. Composite authorization cannot detect a tensor falsely labeled P1 when it actually contains raw P0 data. Adapter conformance tests and provenance receipts remain necessary.

## Open questions

1. Should MFS v0.2 replace P0 through P5 with orthogonal dimensions such as rawness, identifiability, health sensitivity and aggregation?
2. Should `FieldEvent` carry an explicit export projection so raw tensors can remain edge-local while observations cross the network without duplicating event types?
3. Should authorization context become a typed capability rather than booleans for consent and identity binding?

## Benchmark plan

Security property baseline:

Before: `authorize(P2, Network, false, false) == Allow` even when the same serialized event contains a P0 tensor.

After: `authorize_event(P0 tensor + P2 observation, Network, false, false) == Deny` with a tensor-specific reason.

Regression matrix:

1. P1 tensor plus P2 observation: Allow.
2. P0 tensor plus P2 observation: Deny on network.
3. P1 tensor plus P4 observation without consent: RequiresConsent.
4. The same P4 event with consent: Allow.
5. P1 tensor plus P5 observation without identity binding: Deny.
6. P0 tensor plus P2 observation at `EdgeLocal`: Allow subject to retention controls outside this API.

## Acceptance criteria

1. All composite policy tests pass.
2. P0 plus P2 network transport is structurally denied.
3. Existing scalar policy tests remain green.
4. No dependency or wire-format change.
5. Workspace clippy and tests pass.
6. The PR documents that RuView's current live bridge uses same-class derived tensors and therefore does not claim a previously observed live leak.

## Rollback strategy

Revert the additive method, tests and ADR. No stored data or wire migration is affected.
