# ADR 271: Bounded ISAC standards references in interoperability envelopes

Status: Proposed

Date: 2026-09-07

Issue: #14

## Context

RuField normalizes sensing evidence before projecting it into external interoperability envelopes. ADR 268 added deterministic CloudEvents 1.0 and SOSA JSON LD projections and intentionally treats IEEE 802.11bf and Bluetooth Channel Sounding as source identifiers rather than protocol or certification claims.

The service and application layers around integrated sensing and communications are moving independently of radio acquisition formats. During the week ending 2026-09-07, 3GPP TS 23.138, Use of sensing results for Vertical Applications, advanced to draft 0.2.0 on 2026-09-02; 3GPP TS 29.545, Sensing Function Services Stage 3, advanced to draft 0.2.0 on 2026-09-04; and ETSI GR ISC 009, Demonstrability, Adoption, and Technology Evolution for ISAC, advanced to early draft 0.0.3 on 2026-09-02.

These documents may inform a RuField integration even when the underlying measurement comes from native WiFi CSI, IEEE 802.11bf, Bluetooth Channel Sounding, UWB, radar, ultrasonic, or another modality.

## Problem

Encoding every moving draft as a `SourceProfile` would collapse two independent facts:

1. how the measurement was acquired
2. which external service, exposure, evaluation, security, or compute document informed an integration

It would also make it too easy for a string such as `3gpp.ts.29.545` to be mistaken for a compliance claim.

RuField needs a way to cite evolving standards without changing native `FieldEvent` semantics, breaking current golden fixtures, or implying that RuField implements or is certified against the referenced document.

## Constraints

* Native `FieldEvent` provenance remains authoritative and unchanged.
* Existing `SourceProfile` identifiers remain byte stable.
* Existing CloudEvents and SOSA golden fixtures remain byte identical when no standards references are attached.
* External metadata is untrusted and bounded before it is accepted.
* No input can manufacture a compliance or certification state.
* Serialization remains deterministic for the same typed value.
* The change introduces no new dependency.

## Options considered

### Extend `SourceProfile` for each 3GPP and ETSI document

Rejected. Service, exposure, and evaluation documents are not acquisition profiles. Draft versions also move more quickly than the measurement contract.

### Add standards fields to native `FieldEvent`

Rejected for now. This would put external interoperability metadata into the core sensing wire model and create unnecessary migration pressure.

### Free form metadata map on each envelope

Rejected. It is difficult to bound, validate, fuzz, and reason about security properties of arbitrary keys and values. It would also weaken deterministic semantics.

### Add a typed, bounded `StandardsReference` list to interop envelopes

Selected. Acquisition provenance remains in `SourceProfile`; other standards relationships are expressed separately and explicitly.

## Prior art and standards

* IEEE 802.11bf 2025 WLAN sensing is already represented by an acquisition source identifier under ADR 268.
* Bluetooth Core 6.0 Channel Sounding is already represented by an acquisition source identifier under ADR 268.
* 3GPP TS 23.138 Release 20 draft describes use of sensing results for vertical applications.
* 3GPP TS 29.545 Release 20 draft describes Sensing Function Services Stage 3.
* ETSI GR ISC 009 addresses demonstrability, adoption, evaluation, and use of existing infrastructure for ISAC.
* ETSI GR ISC 003 separates sensing service control, measurement coordination, processing, storage, and result exposure in its architecture.

The referenced drafts are inputs to interoperability design, not normative claims by RuField.

## Decision

Add a typed `StandardsReference` to `rufield-interop` with:

* organization
* document identifier
* exact version
* optional release or stage
* reference date
* architectural role
* `compliance_claim`, which must remain false

Add optional lists to `CloudEvent` and `SosaObservation`. Both lists use `serde(default)` plus `skip_serializing_if = Vec::is_empty`, so old serialized outputs remain byte identical when no reference is present.

Add `to_cloud_event_with_references` and `to_sosa_observation_with_references` rather than changing the existing constructors.

## Architecture

```text
native FieldEvent
      |
      | acquisition provenance
      v
SourceProfile
      |
      +--------------------------+
      |                          |
      v                          v
CloudEvents 1.0             SOSA JSON LD
      |                          |
      +---- StandardsReference --+
              metadata only
```

`StandardsReference` is not part of `FieldEvent` and cannot modify tensor, observation, privacy, calibration, or provenance state.

## Interfaces

`StandardsReference::new` validates a reference before it can be emitted through the explicit constructors.

Inbound CloudEvents and SOSA projections validate every attached reference before returning the native event.

The implementation bounds the list to 16 references, document identifiers to 96 bytes, versions to 32 bytes, and release or stage descriptions to 48 bytes. It rejects empty strings, leading or trailing whitespace, control characters, malformed dates, and any `compliance_claim = true`.

## Data flow

1. A sensing adapter produces a native `FieldEvent` under its actual acquisition profile.
2. An integration chooses zero or more external standards references relevant to its service or exposure behavior.
3. `rufield-interop` validates the bounded references.
4. The typed references are serialized alongside the unchanged native event.
5. An inbound envelope is rejected if a reference violates bounds or asserts compliance.
6. A valid envelope returns the unchanged native `FieldEvent`.

## Security considerations

External standards metadata is attacker controlled at trust boundaries.

The implementation therefore:

* bounds list size and string length before accepting the metadata semantically
* rejects control characters that could corrupt logs or downstream text protocols
* rejects unknown enum values through Serde
* rejects malformed date shapes
* refuses compliance claims on both emit and ingest paths
* preserves native event provenance independently of the reference metadata

Future signed interop envelopes should include standards references in the signed bytes. This ADR does not introduce a new signature layer.

## Privacy considerations

A standards reference contains no sensor payload, identity, location, or biometric data by design. It does not lower the privacy class of the enclosed event. Existing RuField privacy authorization applies to the native payload independently.

## Performance implications

The no reference path adds an empty `Vec` field in memory but emits no additional wire bytes because it is omitted by Serde. The referenced path adds bounded validation linear in at most 16 references and wire bytes proportional to explicitly supplied metadata.

A measured release benchmark is still required before any latency number is claimed.

## Hardware implications

None. This change is confined to the Rust interoperability layer.

## Compatibility

Backward compatible at the serialized fixture level when no references are attached. Existing constructors and `SourceProfile` identifiers are unchanged.

The Rust public `CloudEvent` and `SosaObservation` structs gain additive fields, so downstream code using exhaustive struct literals may need to add the new field. This is a source compatibility consideration and must be called out in the PR.

## Migration

No stored native event migration is required.

Applications deserializing old interop envelopes receive an empty reference list through `serde(default)`. New envelopes without references remain byte identical to old golden fixtures.

## Alternatives rejected

* moving draft identifiers into the acquisition profile
* changing the native RuField wire version
* adding arbitrary metadata maps
* introducing a dedicated 3GPP or ETSI protocol dependency before a concrete protocol implementation exists

## Risks

* Consumers may still visually interpret a standards reference as compliance despite the typed invariant. Documentation and UI must use wording such as `reference`, not `compliant`.
* A future standards document may require fields not represented here. Add typed roles or fields only when concrete interoperability work demands them.
* Calendar date validation is intentionally structural and bounds month and day but is not a full Gregorian calendar implementation. It introduces no date parsing dependency.

## Open questions

* Should a future signed CloudEvent wrapper bind the reference list into an external detached signature in addition to the native event receipt?
* Should finalized standards versions receive convenience constructors after their semantics stabilize?
* Is a separate service profile projection needed once TS 29.545 interfaces mature beyond draft status?

## Benchmark plan

Against current main:

* serialize the existing CloudEvent and SOSA golden fixtures and require byte equality
* serialize and deserialize envelopes with one, three, and sixteen standards references
* report encoded byte delta
* run at least three release benchmark repetitions for encode and decode latency
* fuzz malformed external JSON where the repository fuzz infrastructure permits

No performance improvement is claimed by this ADR. The success condition is bounded interoperability metadata with no measurable regression on the default path.

## Acceptance criteria

* Existing no reference golden fixtures remain byte identical.
* TS 23.138 0.2.0, TS 29.545 0.2.0, and ETSI GR ISC 009 0.0.3 can be represented as metadata.
* `compliance_claim = true` is rejected.
* Oversized and control character inputs are rejected.
* More than 16 references are rejected.
* Native `FieldEvent` round trips unchanged.
* Workspace tests, fmt, and clippy pass.
* PR documents the exact source compatibility effect of the two additive struct fields.

## Rollback strategy

Remove the optional reference fields and explicit reference constructors. Native events and acquisition profiles require no rollback or migration.

## References

* https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=5529
* https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=5533
* https://portal.etsi.org/Portal_WI/Form1.asp?NbToDisplay=30&PersonId=0&SubTB=&SupCrit=F5G+++++++++++++++++++++++4678284&TabId=&TbId=0&WIcritID=18
* ETSI GR ISC 003, Integrated Sensing And Communications, System and RAN Architectures
* ADR 268, Standards Projections
