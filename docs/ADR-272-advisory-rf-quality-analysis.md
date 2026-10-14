# ADR-272: Advisory RF power change and receiver quality analysis

Status: implemented. Hardware validation and calibrated interpretation remain open.

## Decision
Add `RfQualityAnalyzer` and `rf-diagnostics-analyze` on top of the bounded
`ruview.rf_diagnostics.v1` reader. Reports use
`rufield.rf_quality_analysis.v1`; they are not FieldEvents and are not fed into
spatial fusion. Output is always `valid:false`, `confidence:0`,
`trust:unverified_advisory`, `cause:unknown`. Source kind is preserved.
No report asserts interference, occupancy, human motion, or a better channel.

Each stream has a key containing source id, source kind, run, sample rate and
center frequency. Interleaved source kinds never share baselines. Changes to
run, sample rate or frequency discard that stream's baseline and abstain for
that record. Returning to an older configuration starts over.

Warmup uses 16 eligible power windows. Their median is frozen until reset.
A later power increase of at least 6 dB emits `power_rise:true` with the delta.
This threshold is an engineering diagnostic, not a calibrated detector.
Median resists a minority of outliers; sustained network traffic during warmup
can contaminate the reference. The windows have no guaranteed physical duration.
Choosing a representative baseline requires field measurements.

## Abstention and reset
Any producer quality reason other than configuration_unverified, nonzero
missing samples, events, overruns or rail fraction clears the baseline and
abstains. This includes stale/tag mismatch/run change reports.
Absent frequency, unknown sample rate, no power or zero sample count abstains.

Nonincreasing producer timestamps, a gap above one second, nonincreasing
slot numbers or a zero timestamp clear the baseline. These checks establish
stream ordering only; producer monotonic time cannot prove wallclock capture
freshness. The next eligible sample starts fresh warmup; `reset()` clears all
streams. Start a new CLI process at recording boundaries.

Up to 32 stream states are retained, each with at most 16 f64 reference values.
The strict schema currently admits three source kinds and one source id, so
actual occupancy is at most three. At capacity, new streams abstain without
allocating. Input retains the 4096 byte record limit. No IQ is accepted.

## Use
From a RuField checkout:

```sh
cargo run -p rufield-adapters --bin rf-diagnostics-analyze \
  < diagnostics.jsonl > quality.jsonl
cargo test -p rufield-adapters --test rf_quality_analysis
```

Feed the companion bridge's diagnostic output directly to this command.
Configure the bridge's advisory center frequency to obtain a channel baseline;
with absent frequency the analyzer reports unknown configuration.
Frequency remains an unverified operator claim. This software neither
retunes the receiver nor suppresses other sensing automatically.

One JSON report is emitted per valid input record. Malformed input terminates
nonzero; previous output remains advisory. Use temporary output plus rename on
successful completion for atomic file import.

## Acceptance
Deterministic tests cover median outlier resistance, frozen baselines, inclusive
6 dB threshold, every quality issue reset, configuration isolation, reordered
timestamps, pauses, sequence regression, unknown configuration, source-mode
separation, explicit reset, 10,000-record bounded state, failed input preserving
state, CLI output and malformed-input failure. Existing diagnostics tests verify
exclusion from spatial fusion. These are software tests, not field accuracy,
detection sensitivity, or false-alert reduction measurements.
