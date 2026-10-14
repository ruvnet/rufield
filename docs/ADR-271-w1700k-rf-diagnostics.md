# ADR: W1700K RF diagnostics stay outside spatial inference

Status: implemented advisory boundary. Hardware validation pending.

## Decision
The W1700K bridge emits `ruview.rf_diagnostics.v1`. RuField consumes this
through `rufield_adapters::rf_spectrum_quality::RfDiagnosticReader`.
Registry code 18 (`rf_spectrum_quality`) denotes scalar receiver diagnostics.
It does not mean a power spectrum, CSI, calibrated RF power, pose or presence.

The adapter accepts at most 4096 bytes per JSONL record, rejects unknown fields,
unsupported schema, invalid ranges and any v1 attempt to set `valid` or
`config_verified` true. A parsing error permanently closes that reader.
Memory is bounded per record; callers control total file/time quotas.

Input source kind is retained honestly. Synthetic input produces a synthetic
provenance marker. Live and captured replay inputs remain non-synthetic,
unsigned and unauthenticated. No demo signing key is used.
The SHA256 `raw_hash` covers the canonical diagnostic record, NOT original IQ.
No firmware or calibration attestation is fabricated.

Raw IQ is P0 and remains at the receiver boundary; this parser does not accept
IQ, packet payloads, MAC addresses or arbitrary extra fields. Output is P1
scalar diagnostics with no identity or spatial features.

## Time and quality
The bridge monotonic clock cannot establish Unix capture time or cross-host
freshness. Output event timestamp is explicitly local receipt time, with the
original monotonic reading preserved in `source_record`. Replay is not refreshed
hardware evidence. The producer's 1000 ms TTL is retained as source metadata,
not interpreted as trusted capture freshness. Every v1 record stays advisory
and invalid because configuration is unverified. Frequency may be absent and
sample rate zero means unknown. RMS is relative to the upstream 8192 scale,
so sign-extended or malformed full int16 inputs can exceed 0 dBFS.
Silent signal can have null RMS with zero rail fraction.

RuFieldFusion rejects code 18 before trust verification or graph mutation,
including synthetic or subsequently signed diagnostics. No diagnostics can
raise occupancy confidence, enter inference windows or create spatial tracks.
This implementation does not yet automatically suppress other sensors based on
RF metrics: association, synchronization and a validated policy are prerequisites.

## Run
From the RuField checkout:

```sh
cargo run -p rufield-adapters --bin rf-diagnostics-replay \
  < diagnostics.jsonl > diagnostic-events.jsonl
cargo test -p rufield-adapters --test rf_spectrum_quality
```

The input is produced by the RuView W1700K companion bridge. Invalid input exits
nonzero; previously emitted records remain advisory. Use a temporary output file
and rename it only after successful exit when atomic file import is required.

## Acceptance and limits
Tests cover schema/range failures, unknown-field IQ rejection, bounded record
size, sticky failure, nonfinite values, exact metadata, honest source mode,
unknown rates, silent signal and denial by spatial fusion.
No physical W1700K, calibrated capture, presence accuracy or false-alert
improvement is claimed. CSI extraction, FFT bins, authenticated configuration,
cross-sensor time mapping and field evaluation are subsequent work.

## Numeric wire bounds
The current fixed-slice producer contract admits sample count 0 or 2048,
missing samples in multiples of 2048, and rates 0 (unknown), 40, 80, 160 or
320 MHz. Center frequency is null or 2 through 8 GHz. RMS is null or finite
in [-200, 16] dBFS; rail fraction is null or finite in [0, 1]. A present RMS
requires a present rail fraction. Reasons are unique and drawn from
configuration_unverified, lost, event, overrun, stale, tag_mismatch, run_change.
The configuration_unverified reason is mandatory. Sample start remains null:
this ABI does not establish an exact sample clock across events.
