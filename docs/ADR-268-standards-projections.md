# ADR 268: Deterministic CloudEvents and SOSA projections

Status: Accepted

Date: 2026-08-21

## Context

RuField needs standard integration surfaces without claiming to implement radio protocols or replacing its lossless native event. IEEE 802.11bf and Bluetooth Channel Sounding define sensing capabilities below RuField. CloudEvents defines a transport neutral event envelope. W3C SOSA defines semantic observations and sensors.

## Decision

Add `rufield-interop` with deterministic, lossless projections to CloudEvents 1.0 and SOSA JSON LD. The complete native `FieldEvent` remains the payload so round trips preserve tensor, observation, privacy, and provenance fields.

Use `ieee.802.11bf.2025` and `bluetooth.core.6.0.channel_sounding` only as source profile identifiers. No radio frame parsing, ranging algorithm, certification, or standards compliance claim is introduced.

References:

1. CloudEvents: https://cloudevents.io/
2. W3C SOSA and SSN: https://www.w3.org/TR/vocab-ssn-2023/
3. IEEE 802.11bf: https://standards.ieee.org/ieee/802.11bf/11574/
4. Bluetooth Channel Sounding: https://www.bluetooth.com/learn-about-bluetooth/feature-enhancements/channel-sounding/

## Inputs

1. A validated native `FieldEvent`.
2. A declared acquisition source profile.

## Outputs

1. A CloudEvents 1.0 structured event with nanosecond capture time and lossless data.
2. A SOSA observation with stable observation, sensor, and modality IRIs represented as JSON LD `@id` nodes plus the lossless native event.
3. Deterministic JSON suitable for golden fixture comparison.

## Assumptions

1. Device and event identifiers are stable within their trust domain.
2. A transport layer handles authorization and delivery guarantees.
3. Projection validation detects disagreement between envelope attributes and the native payload.

## Alternatives considered

1. Replace `FieldEvent` with SOSA or SensorThings. Rejected because generic semantic schemas do not preserve every RuField tensor and privacy invariant.
2. Claim native IEEE or Bluetooth implementations. Rejected because a source identifier is not protocol conformance.
3. Map only selected fields. Rejected because lossy round trips weaken provenance and replay.

## Migration

Interop is an optional workspace crate. Existing producers and consumers remain unchanged. Connectors project events only at integration boundaries.

## Rollback

Disable or remove the optional crate. Native event processing is unaffected.

## Acceptance

The WiFi CSI golden event must project deterministically to the checked in CloudEvents and SOSA fixtures and recover a native event equal to the original. Envelope fields that disagree with the payload must be rejected.
