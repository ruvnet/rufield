# ADR 261: BLE Identity Evidence and Channel Sounding

Status: Accepted

Date: 2026 08 23

Deciders: rUv

Tags: BLE, identity evidence, channel sounding, ESP32, CSI, privacy, provenance, fusion

## 1. Context

RuField needs two different Bluetooth inputs that are easy to conflate.

BLE advertisements provide received signal strength and an application payload. They can support short-lived proximity and identity evidence when the payload is authenticated and enrolled. They do not provide coherent carrier phase, exact range, or proof that the associated person is carrying the transmitter.

Bluetooth Channel Sounding provides calibrated phase and round-trip timing primitives across multiple frequencies on capable Bluetooth radios. Those measurements can feed ranging and micromotion feature extraction. They are not available by treating normal advertisements or RSSI samples as phase measurements.

The ESP32-S3 can collect WiFi CSI and ordinary BLE advertisements, but its radio does not implement Bluetooth Channel Sounding. This ADR therefore defines a host adapter boundary. A future supported Channel Sounding radio can feed the same contract without changing fusion.

Normal iPhone background advertisements are not accepted as durable identity. Apple rotates and abstracts identifiers, and an arbitrary background advertisement is not an authenticated enrollment credential for a RuField subject.

## 2. Decision

Add two separate RuField modalities and adapters.

1. `ble_advertisement_rssi`, registry code 16, carries RSSI and short-lived pseudonymous track evidence.
2. `ble_channel_sounding`, existing registry code 5, carries calibrated coherent phase measurements and derived respiration features.

Append code 16 without renumbering existing modalities.

Represent an anonymous spatial tracker identifier in `Observation.track_id`.

Represent identity association in `Observation.identity_evidence`. Evidence contains only a deployment-scoped pseudonym, track, confidence, observed time, hard expiry, enrollment receipt, issuer, source sequence, token epoch, and evidence kind.

Identity evidence is P5. A Channel Sounding respiration observation is P4. Raw Channel Sounding phase remains P0 and stays at the governed edge unless a separate policy explicitly permits release.

The fusion engine continues to read only established scalar features from `Observation.features`. Channel Sounding emits `breathing_band` and `coherent_phase_quality`. It preserves RTT as a typed measurement primitive but does not emit `range_m`: the Bluetooth specification does not define a distance algorithm. RSSI evidence emits `identity_anchor_confidence` and `rssi_proximity`. RSSI never emits `breathing_band`, phase, or RTT features.

Fusion windows are partitioned by `Observation.track_id` and modality. Weighted Bayes and temporal rules cannot combine events from different known tracks. Legacy events without a track remain in one anonymous room-level partition. `FieldInference.track_id` records the partition, while `InferenceQuery.track_id` can scope a query to one track.

Production fusion uses a fail-closed BLE trust policy. Synthetic BLE is rejected. A non-synthetic BLE event is accepted only when its exact `SensorDescriptor.device_id` and Ed25519 signer key pair appears in the configured allowlist. `BleTrustPolicy::synthetic_test_only()` is an explicit test policy and is not a production fallback.

## 3. Firmware to Host Mapping

The RuView ESP32 telemetry version 1 record provides an authenticated eight-byte ephemeral identifier, RSSI, TTL, confidence, node identifier, sequence, and token epoch. The record is accepted only after the host verifies the outer `RuView/GW/v1` gateway envelope, its enrolled node and key, boot nonce, sequence, receive time, and timing uncertainty. A UDP source address, inner authenticated flag, or caller supplied boolean is insufficient.

For advertisement evidence, the RuField host boundary maps the gateway node identifier into `SensorDescriptor.device_id`. It consumes the eight-byte ephemeral identifier only in memory and derives the 32-byte wire pseudonym as:

```text
P = HMAC-SHA-256(
  deployment_key,
  "rufield.ble.identity.v1\0" || ephemeral_id_8 || little_endian_u64(token_epoch)
)
```

The event serializes `blep:` followed by the lowercase hex representation of `P`. It never serializes the ephemeral identifier or a BLE MAC address. The deployment key is never placed in a `FieldEvent` or loggable adapter structure.

The provenance raw hash is computed over a keyed digest of the transient firmware fields. This avoids turning the provenance hash into an offline enumerable durable form of the 64-bit ephemeral token.
The raw-record digest uses a separate `rufield.ble.raw.v1\0` domain, so it cannot be confused with pseudonym derivation even though both operations use the deployment pseudonym key.

`BleAnchorTrust::Enrolled` means the firmware record authentication and enrollment receipt were verified before promotion. Unverified background advertisements and revoked credentials produce an abstention, not identity evidence.

The external Channel Sounding record remains a separate inner contract. Each
authenticated companion step becomes one `BleChannelSoundingSample`. The sample
preserves nonzero `source_id`, `source_session_id`, and `procedure_id`, declared
step count, step index, frequency channel, companion key and sequence, sample
age, companion timing uncertainty, phase, RTT, frequency offset, and quality.
It also preserves the independently authenticated gateway envelope node, key,
boot nonce, sequence, receive time, and timing uncertainty.

An authenticated host decoder upstream of the adapter verifies the companion
HMAC and exact enrolled source id and keys replay state by source session; only
then may it construct a `BleChannelSoundingSample`. The adapter independently
groups steps by `(source_id, source_session_id, procedure_id)`. Promotion
requires exactly the declared set of ascending step indices and between four
and seventy-nine unique frequency channels, each in the Bluetooth RF channel
range 0 through 78. Duplicate step
indices, channels, companion sequences, or gateway sequences; mixed companion
keys; mixed gateway node/key/boot contexts; and incomplete procedures fail
closed. The bounded adapter retains at most 128 incomplete procedures.

One admitted group becomes one `FieldEvent`. Its sensor id is
`ble-cs-companion:` plus the eight-digit lowercase hexadecimal `source_id`.
`Observation.channel_sounding_provenance` retains the complete typed procedure
and each forwarding envelope. The event firmware hash is the attested companion
firmware hash. The ESP32 node remains forwarding provenance only; neither the
sensor descriptor nor the firmware provenance implies that ESP32 generated
Channel Sounding measurements.

## 4. Evidence Invariants

An identity event is valid only when all rules hold.

1. Tensor modality is `ble_advertisement_rssi`.
2. Sensor modality matches tensor modality.
3. Tensor and observation privacy classes are P5.
4. Pseudonym has exactly a 32-byte digest in the `blep:` representation.
5. Track, issuer, and binding receipt are present.
6. Confidence is finite and at least 0.60.
7. TTL is greater than zero and no more than five seconds.
8. Evidence is not expired at the current stream watermark.
9. Sequence moves forward within a pseudonym and token epoch.
10. A live pseudonym cannot claim two tracks.
11. A track cannot hold two live enrollment bindings.
12. Identity evidence issuer exactly matches the sensor device identifier.
13. Firmware hash is an attested SHA-256 reference, model identity is present, and sensor calibration is present.
14. Enrollment receipt and sensor calibration receipt are distinct.
15. Production provenance signature matches the device and signer allowlist.
16. Synthetic BLE is accepted only under the explicit synthetic test policy.

Token epoch rotation may replace a live pseudonym on the same track only when the governed binding receipt is unchanged.

The identity adapter retains at most 1024 simultaneously live bindings. Expired binding
and replay entries are removed at the monotonic stream watermark before a new
token is admitted. A new token is rejected with an explicit capacity
abstention when that table is full. Advertisement capability reports estimate
sample rate from distinct supplied timestamps. Channel Sounding capability
reports use only timestamps of complete coherent procedures, never raw step
arrival rate. Both report zero when timing evidence is insufficient; neither
claims a fixed 50 Hz rate.

The fusion boundary rechecks trust, timestamp, modality, privacy, pseudonym, track, issuer, provenance separation, and expiry before adding graph nodes. A valid signature proves origin and integrity. It does not make an unknown signer or semantically invalid evidence acceptable.

`BleAdapterConfig` keeps firmware attestation, identity model, Channel Sounding model, RSSI calibration, and enrollment as distinct values. The adapter never hashes the vendor label as a firmware identity and never reuses enrollment as calibration. Deterministic keys and metadata exist only through `BleAdapterConfig::synthetic_fixture()`. Setting that fixture material to production mode fails validation.
Signing and pseudonym derivation keys must also be nonzero and distinct.

## 5. Deterministic Simulation

The reference scenario contains two anonymous CSI tracks moving through the same spatial cell and then separating. Each track receives enrolled BLE RSSI evidence and coherent Channel Sounding respiration features.

The scenario injects two failures.

1. A simultaneous cloned or mis-associated pseudonym claims the other live track. The identity adapter records `ConflictingTrack` and emits no event.
2. An old firmware record arrives after its TTL. The adapter records `Expired` and emits no event.

The validated stream contains ten CSI events, ten BLE advertisement evidence events, and ten Channel Sounding events. Given identical configuration, the serialized event bytes and abstention sequence are identical.

Simulation validates contracts and failure policy only. It does not establish radio accuracy, medical accuracy, or ESP32 Channel Sounding capability.

## 6. Threat Model

| Threat | Impact | Control |
| --- | --- | --- |
| Raw MAC or platform identifier leakage | Durable tracking | No MAC field, host pseudonym derivation, P5 policy |
| Ephemeral token replay | False association | Token epoch, monotonic sequence, TTL, stream watermark |
| Token clone on another track | Identity swap | Conflicting track and occupied track abstention |
| Unauthenticated phone advertisement | False identity | Unverified advertisements never promote |
| RSSI multipath or phone left on a table | Wrong person association | Confidence threshold, short TTL, CSI spatial consistency, abstention |
| Gateway event tampering | False evidence | Signed provenance and fusion verification |
| Gateway UDP replay or spoofing | False evidence | Outer HMAC, enrolled node and key, random boot nonce, sequence guard, persistent replay checkpoint |
| Companion reboot or recorded phase replay | Stale biological evidence | Authenticated source session, procedure grouping, sequence guard, sample age |
| Missing, duplicated, or mixed Channel Sounding steps | Fabricated coherent feature | Exact 4..=79-step completion, unique channels and sequences, common companion key and gateway boot context |
| ESP32 forwarding mistaken for radio capability | False capability and provenance claim | Companion source is sensor identity; gateway node/key/boot remains typed transport provenance |
| LAN observation of pseudonyms or phase | Biometric disclosure | Encrypted transport when required; outer HMAC provides no confidentiality |
| Self-signed unknown BLE node | Unauthorized evidence | Exact device and signer allowlist |
| Synthetic fixture reaches production | False trust | Production policy rejects synthetic BLE and fixture configuration |
| Cross-track feature fusion | Vital signs assigned to the wrong person | Track-partitioned windows, queries, and inferences |
| Vendor label used as firmware identity | False provenance | Required attested firmware hash and distinct model identifiers |
| Deployment key compromise | Cross-event linkability and impersonation | KMS or secure element storage, per-deployment keys, rotation, audit |
| Calibration drift in coherent phase | False respiration feature | Calibration receipt, quality feature, expiry, hardware validation |
| Raw phase disclosure | Biometric leakage | P0 edge retention and P4 consent gate for derived health output |

The largest remaining security uncertainty is the trust boundary that marks an advertisement record as authenticated and enrolled. Production deployment must connect `BleAnchorTrust::Enrolled` to cryptographic firmware verification and a governed enrollment receipt. A caller supplied boolean is insufficient.

## 7. Exclusions

This decision does not claim any of the following.

1. BLE RSSI provides centimetre range or coherent micromotion.
2. ESP32-S3 supports Bluetooth Channel Sounding or raw CTE IQ capture.
3. An iPhone background advertisement is a stable identity credential.
4. A phone is physically attached to the person whose CSI track is nearby.
5. Channel Sounding respiration is clinical grade.
6. Channel Sounding is diagnostic ECG or reliable heartbeat reconstruction.
7. RuField stores a real name, raw MAC, Apple identifier, or long-term device identifier.
8. Fusion may infer identity from ground-truth labels.

## 8. Deployment

1. Keep WiFi CSI collection on ESP32-S3 for anonymous motion and track observations.
2. Enable the authenticated BLE telemetry version 1 record for RSSI evidence and verify the independent gateway envelope before adapter ingestion.
3. Provision a unique pseudonym key and signing key for each deployment.
4. Provision the attested firmware hash, immutable model identifiers, and sensor calibration receipts independently from subject enrollment.
5. Configure production fusion with exact BLE device and signer allowlist pairs.
6. Resolve enrollment receipts inside the governed host boundary.
7. Route only derived P2 CSI observations by default.
8. Require identity binding, audit, and applicable consent before releasing P5 evidence.
9. Add a Channel Sounding capable companion radio when coherent phase is required, enroll its exact source id, and preserve source session, procedure, step, companion, gateway, and timing metadata while grouping steps.
10. Calibrate each radio pair and retain raw P0 phase locally.
11. Enable a breathing fusion rule only after labeled reference testing.
12. Monitor abstention rates, replay attempts, identity conflicts, and calibration age.

## 9. Migration

The event schema change is additive. Observation identity fields plus inference and query `track_id` fields use serde defaults, so existing events continue to deserialize and remain in the anonymous partition.

Registry code 16 is appended. Producers must negotiate consumer support before sending it because older enum decoders may reject an unknown modality.

Existing fusion rules remain unchanged. Channel Sounding participates only when a rule lists `ble_channel_sounding` and requests an established feature such as `breathing_band`.

Deployment migration requires unique keys, firmware attestation, model identities, sensor calibration, an enrollment receipt resolver, a BLE signer allowlist, and a P5 audit path. Until these are configured, production BLE must fail closed.

## 10. Rollback

Disable both BLE adapters at the gateway and stop routing modality codes 5 and 16 into new rules.

Existing identity evidence expires within five seconds without a cleanup migration. Purge active in-memory bindings, revoke the deployment pseudonym key, and remove any P5 cache entries according to retention policy.

CSI, radar, thermal, and existing room-state fusion continue unchanged because BLE uses additive modalities and existing feature contracts.

## 11. Consequences

Positive consequences are explicit signal semantics, fail-closed identity handling, bounded evidence lifetime, deterministic regression coverage, and firmware compatibility without making ESP32-S3 capability claims it cannot satisfy.

Negative consequences are P5 governance overhead, deployment key management, an external enrollment dependency, and no guaranteed identity when users do not carry a provisioned beacon.

## 12. Acceptance Test

Run the deterministic crossing scenario twice. Require byte-identical event output, two stable pseudonym-to-track bindings, explicit spoof and expiry abstentions, zero invalid identity events in the fusion graph, P5 classification for identity evidence, P4 classification for Channel Sounding respiration, and exactly one track per breathing inference and its cited events. For every Channel Sounding event, require one external-companion sensor id, complete typed source/session/procedure metadata, 4..=79 ordered unique steps and channels, and preserved companion plus gateway timing provenance. Prove incomplete, duplicate, mixed-context, and over-limit groups emit no event and never enter fusion. Replacing the companion sensor id with the ESP32 gateway id must also fail before a fusion graph node is created. Then prove default fusion rejects both synthetic BLE modalities, the explicit test policy accepts them, an allowlisted production companion device and signer pair succeeds, and production fixture configuration fails.

## 13. Primary References

1. [Bluetooth SIG Channel Sounding overview](https://www.bluetooth.com/learn-about-bluetooth/feature-enhancements/channel-sounding/) defines cooperative phase based ranging and round trip timing and states that the specification does not provide a distance algorithm.
2. [Bluetooth Core 6.0 feature overview](https://www.bluetooth.com/core-specification-6-feature-overview/) separates Channel Sounding from advertisement RSSI path loss ranging.
3. [Bluetooth LE primer](https://www.bluetooth.com/bluetooth-le-primer/) explains that controller support does not guarantee an application API for a radio feature.
4. [Espressif ESP32 S3 BLE feature support status](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-guides/ble/ble-feature-support-status.html) is the capability source of record for Direction Finding and Channel Sounding support.
5. [Espressif ESP32 S3 BLE device discovery](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-guides/ble/get-started/ble-device-discovery.html) documents supported advertisement and scan operation.
