# ADR 271: Evidence Freshness and Cohort Timing

Status: Proposed

Date: 2026-08-31

Issue: #12

## Context

RuField already models capture timestamps, inference production and expiry, calibrated uncertainty, provenance, privacy, and abstention. Those fields do not answer a different question: how old was the supporting sensor evidence when a result was evaluated, and did the contributing observations belong to one temporally coherent sensing cohort?

This distinction matters in distributed RF sensing, semantic communication, tracking, and active sensing. A valid model output can still be operationally unsafe when its source observations are stale or temporally inconsistent.

SafeStep, arXiv 2608.27688, demonstrates a live semantic communication system where Age of Information is an explicit control variable and where downstream task degradation becomes observable as evidence age changes. This is not direct evidence for a universal RuField threshold. It is evidence that evidence age belongs in the contract rather than remaining an implicit application assumption.

RuView issue 1726 independently exposed the same systems concern from multistatic sensing. Slow but live nodes can contribute frames outside the fuser coherence guard. RuView now selects a coherent cohort before governed fusion. RuField needs a modality neutral representation for downstream consumers to assess the timing quality of supporting evidence.

The authenticated BLE and Channel Sounding path also exposed an adversarial timestamp hazard. A hostile far future timestamp must be rejected before it can influence shared freshness or replay state.

## Problem

`FieldInference::expires_ns` defines how long a produced inference remains valid. It does not encode source evidence age, evidence span, or future clock skew.

Using only the inference expiry can therefore hide three distinct failure modes:

1. Old evidence may be wrapped in a newly produced inference.
2. Individually recent observations may span too wide a capture interval to be fused coherently.
3. A future timestamp may appear fresh under saturating age arithmetic unless future skew is checked explicitly.

## Constraints

1. Existing `FieldEvent` and `FieldInference` wire forms must not change.
2. Existing public struct literals must remain source compatible.
3. The core assessment must be deterministic and replayable.
4. The core must not read the wall clock.
5. The core must not mutate trust, replay, or watermark state.
6. Timing thresholds are task specific and must not be globally hard coded.
7. Empty evidence must never be interpreted as fresh evidence.
8. Arithmetic must remain defined at `u64` boundaries.

## Options considered

### Option 1: Reuse inference expiry

Rejected. Production lifetime and source evidence age are different quantities.

### Option 2: Add freshness fields directly to `FieldInference`

Rejected for this release. Adding required public fields would break external Rust struct literals and would change the serialized shape of the established inference type.

### Option 3: Add an additive assessment primitive

Chosen. A pure helper computes an explicit `FreshnessAssessment` from supporting evidence timestamps, caller supplied evaluation time, and task supplied policy.

### Option 4: Put one global age threshold in RuField

Rejected. Presence, collision avoidance, occupancy analytics, semantic communication, and archival analysis have materially different age budgets.

## Prior art

1. SafeStep, arXiv 2608.27688, treats Age of Information as a first class semantic communication variable and reports downstream task degradation across communication conditions.
2. IEEE 802.11bf defines WLAN sensing procedures where measurement timing is part of the sensing process, but it does not supply one application level freshness threshold for RuField consumers.
3. ETSI GR ISC 003 separates sensing task coordination, measurement configuration, processing, storage, and result exposure, which supports task scoped timing policy rather than a global limit.
4. 3GPP Release 20 ISAC work separates sensing functions, sensing tasks, measurements, results, and exposure. Draft details remain subject to change, so RuField keeps the primitive modality and standards neutral.
5. RuView issue 1726 enforces a hard multistatic capture guard before fusion, demonstrating the need to distinguish node liveness from cohort coherence.

## Decision

Add the following additive public API to `rufield-core`:

`FreshnessPolicy`

`FreshnessDisposition`

`FreshnessAssessment`

`assess_evidence_freshness`

The helper performs one pass over a timestamp slice and returns no assessment for empty input.

Disposition precedence is deterministic and fail closed:

1. `FutureSkew`
2. `IncoherentCohort`
3. `StaleEvidence`
4. `Fresh`

Limits are inclusive. A value exactly on a configured boundary remains acceptable.

## Architecture

Input:

Supporting evidence capture timestamps

Caller supplied evaluation timestamp

Task supplied freshness policy

Output:

Oldest and newest source timestamps

Oldest and newest evidence age

Cohort capture span

Evidence count

Deterministic disposition

No model confidence is modified by this helper. No privacy decision is modified by this helper.

## Interfaces

```rust
let policy = FreshnessPolicy {
    maximum_age_ns: 100_000_000,
    maximum_cohort_span_ns: 60_000_000,
    maximum_future_skew_ns: 5_000_000,
};

let assessment = assess_evidence_freshness(
    &[1_000_000_000, 1_020_000_000],
    1_050_000_000,
    policy,
).expect("supporting evidence");

if !assessment.is_fresh() {
    // Caller chooses abstention, resensing, or a lower capability tier.
}
```

## Data flow

Sensor evidence enters through an existing adapter.

Trusted evidence timestamps remain attached to events.

A fusion or application layer selects supporting evidence.

The application supplies its evaluation time and freshness policy.

The core helper produces an auditable timing assessment.

The caller decides whether to abstain, request new sensing, or continue.

## Security considerations

1. Future timestamp skew is checked before evidence can be classified fresh.
2. The helper is pure and cannot advance a watermark or mutate replay state.
3. Saturating arithmetic prevents integer underflow and overflow from becoming freshness bypasses.
4. Empty evidence returns `None` rather than a default `Fresh` value.
5. Caller supplied timestamps must still originate from the existing trust and provenance pipeline. Freshness assessment does not authenticate evidence.
6. A malicious caller can choose an unsafe policy. Policy authorization belongs in the sensing task or capability layer and is not weakened here.

## Privacy considerations

The assessment exposes timing metadata and aggregate timing properties. It does not authorize transmission, lower a privacy class, reveal raw waveform data, or establish identity.

Applications should still consider timing information sensitive where it can reveal presence patterns or operational schedules.

## Performance implications

The implementation performs one pass over supporting timestamps and creates no intermediate collection. Time complexity is O(n) in supporting evidence count. Additional memory is O(1).

No wall clock performance claim is made until a reproducible benchmark is added.

## Hardware implications

None in the core crate.

Hardware integrations should provide trustworthy capture timestamps and clock quality. The assessment cannot repair an unknown clock domain or missing synchronization.

## Compatibility

Existing wire structures are unchanged.

Existing `FieldEvent`, `FieldInference`, `CalibratedInference`, and `UncertaintyEnvelope` JSON remain unchanged.

The new types are additive exports.

## Migration

No migration is required.

Consumers opt in when they have supporting evidence timestamps and a task specific timing policy.

## Alternatives rejected

A single global freshness limit is rejected because it confuses application semantics.

Automatic confidence decay is rejected because calibrated probability and data age are not interchangeable.

Treating future timestamps as age zero without an explicit skew classification is rejected because it creates a security bypass.

## Risks

1. Consumers may choose thresholds without field evidence.
2. Clock domains may be incomparable even when numeric timestamps appear close.
3. A fresh evidence cohort may still be wrong, poisoned, or out of distribution.
4. Applications may incorrectly treat `Fresh` as a full trust decision.

## Open questions

1. Should a future RuField sensing task schema carry mandatory freshness policy?
2. Should `UncertaintyEnvelope` eventually reference a separate freshness receipt without changing the legacy inference wire type?
3. Which thresholds are justified for presence, localization, tracking, vital signs, and semantic communication on real hardware?
4. Should clock quality and synchronization uncertainty be composed into the policy rather than represented separately?

## Benchmark plan

Phase 1 validates deterministic classification and boundary behavior.

Phase 2 benchmarks the helper on representative evidence counts and records hardware, compiler, run count, mean, p95, and variance.

Phase 3 replays real RuView multistatic traces with controlled packet delay and loss to measure how freshness gating affects false continuity, localization error, and sensing availability.

No synthetic result may be presented as field accuracy.

## Acceptance criteria

1. Exact policy boundaries remain fresh.
2. Empty evidence produces no assessment.
3. Excess future skew produces `FutureSkew`.
4. Excess capture span produces `IncoherentCohort`.
5. Excess oldest evidence age produces `StaleEvidence`.
6. Input ordering does not affect the result.
7. JSON round trip is deterministic.
8. Existing core wire tests remain unchanged.
9. Workspace tests pass.
10. Strict clippy passes.

## Rollback strategy

Delete `freshness.rs` and remove its module and reexports from `rufield-core::lib`.

No wire rollback, data migration, or persistent state repair is required.

## Relevant research and standards

SafeStep: https://arxiv.org/abs/2608.27688

IEEE 802.11bf working group material: https://www.ieee802.org/11/Reports/tgbf_update.htm

ETSI ISAC: https://www.etsi.org/technical-groups/isac/

3GPP TR 38.765: https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=4357
