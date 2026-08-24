# RuField MFS

**The open specification for camera-free field intelligence.**

[![CI](https://img.shields.io/github/actions/workflow/status/ruvnet/rufield/ci.yml?branch=main&label=CI)](https://github.com/ruvnet/rufield/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Rust edition](https://img.shields.io/badge/rust-edition%202021-orange.svg)](https://www.rust-lang.org)
[![spec](https://img.shields.io/badge/spec-rufield.mfs.v0.1-purple.svg)](./docs/ADR-260-rufield-mfs.md)
[![status](https://img.shields.io/badge/status-v0.1%20reference%20stack-success.svg)](#user-guide)
[![camera-free](https://img.shields.io/badge/camera--free-yes-green.svg)](#what-it-is)
[![privacy](https://img.shields.io/badge/privacy-P0--P5-informational.svg)](#privacy--provenance)

> **Honesty note up front:** the v0.1 benchmark numbers are produced by a
> deterministic **synthetic** simulator and are labelled **SYNTHETIC** — they
> prove the pipeline scores correctly against known ground truth; they are
> **not** field-validated accuracy.
>
> One adapter now ingests **real** signal: [`CsiReplayAdapter`](#real-csi-replay)
> replays **real captured WiFi CSI** from a `.csi.jsonl` recording. Be explicit
> about what that is and is not: it is **replay from a file, not live
> hardware**; the recordings are **unlabeled**, so its motion/presence output is
> a **physically-grounded CSI-variance proxy, NOT validated accuracy** (no pose,
> no accuracy numbers). The other modalities (mmWave, thermal IR) remain
> synthetic. Live-hardware streaming and labeled-accuracy validation remain
> documented roadmap items.

---

## What it is

RuField MFS (Multimodal Field Sensing Specification) is the missing **sensing
layer that sits above** WiFi, radar, ultrasound, infrared, and quantum
sensors. Each modality has its own sampling, calibration, confidence, privacy,
and provenance semantics — which makes reliable fusion hard and governance
weak. RuField normalizes **every** modality into one common grammar:

```text
WiFi CSI            ┐
WiFi CIR            │
WiFi BFLD           │
UWB                 │
Bluetooth Sounding  │
mmWave radar        ├─ all emit ─▶  RuField Field Event
Ultrasonic          │               RuField Field Tensor
Subsonic            │               RuField Fusion Graph
Infrared            │               RuField Privacy Class
Quantum magnetic    │               RuField Provenance Receipt
Quantum inertial    ┘
```

RuField does **not** replace IEEE 802.11bf, Bluetooth Channel Sounding, UWB,
Matter, or any radar protocol. It sits above them. It is the open,
privacy-aware, provenance-rich, fusion-ready event model for camera-free
ambient sensing.

The full specification of record is
[ADR-260](./docs/ADR-260-rufield-mfs.md).

## Crates

| Crate | Description |
|-------|-------------|
| [`rufield-core`](crates/rufield-core) | Data model + traits: `Modality` (15), `FieldAxis`, `FieldTensor`, `PrivacyClass` (P0–P5), `FieldEvent`, `Observation`, `CalibrationReceipt`, `FieldInference`, and the `FieldAdapter`/`FieldEncoder`/`FusionEngine`/`PrivacyGuard` traits. |
| [`rufield-provenance`](crates/rufield-provenance) | Real `sha256` content hashing + `ed25519` sign/verify. ADR-261 adds explicit simulation, captured-replay, and production trust policies, an independently enrolled sensor-key registry, revocation, freshness checks, and persistent replay watermarks. The legacy `is_fusable` helper is simulation-only. |
| [`rufield-privacy`](crates/rufield-privacy) | `PrivacyClass` policy + `DefaultPrivacyGuard`: P0 edge-only, network ≤ P2, P4 consent gate, P5 identity binding. |
| [`rufield-adapters`](crates/rufield-adapters) | Deterministic seeded `SyntheticSim` adapter (camera-free room-intelligence demo across 3 modalities) **plus `CsiReplayAdapter`** — the first real (non-synthetic) adapter, replaying real captured WiFi CSI from a `.csi.jsonl` recording (replay, unlabeled). |
| [`rufield-fusion`](crates/rufield-fusion) | `FusionGraph` + `RuFieldFusion` engine with TOML rules (weighted-Bayes / temporal-window), confidence + expiry. |
| [`rufield-bench`](crates/rufield-bench) | Deterministic benchmark runner: F1 per task (SYNTHETIC), p95 latency, provenance coverage, privacy violations, and the ADR-260 §31 acceptance test. |
| [`rufield-viewer`](crates/rufield-viewer) | Read-only web dashboard (Axum + vanilla JS, no build step): room state, event log with privacy badges, fusion graph, and a synthetic-mode signed-receipt viewer. **Two sources** — `--source synthetic` (default) replays `SyntheticSim → RuFieldFusion`; `--source live --upstream <URL>` ingests **real** `FieldEvent`s over the RuView `/ws/field` / `/api/field` transport (ADR-262 P3). Live startup requires an independently enrolled sensor-key registry and an ADR-261 production or captured-replay policy. Live SSE uses a fail-closed public projection with stable trust diagnostics and no event/device/zone ids, raw labels, hashes, signer keys, signatures, model ids, or provenance edges. Honest, mutually-exclusive `SYNTHETIC` / `LIVE` / `DISCONNECTED` banner. Not a device-management console. |

## Install / Quickstart

This repository is a standalone Cargo workspace. The fastest way to see it
work end-to-end is to run the benchmark:

```bash
git clone https://github.com/ruvnet/rufield
cd rufield
cargo run -p rufield-bench            # default seed
cargo run -p rufield-bench -- 2026    # custom seed
cargo run -p rufield-bench -- 2026 --json   # JSON only
```

## Dashboard / demo

To *watch* the camera-free room-intelligence demo (ADR-260 §19) instead of
reading benchmark numbers, run the read-only web viewer:

```bash
cargo run -p rufield-viewer            # serves http://127.0.0.1:8088/
cargo run -p rufield-viewer -- --port 9090 --seed 7 --tick-ms 200
```

Then open **http://localhost:8088/**. The dashboard drives the same
`SyntheticSim → RuFieldFusion` pipeline the benchmark uses and replays it tick
by tick, showing:

- **Live room state** — fused inferences (`person_present`, `sitting`,
  `sleeping`, `breathing`, `bed_exit`, …) with confidence, updating as the
  enter → sit → breathe → sleep → scratch → bed-exit → leave sequence plays.
- **Event stream** — every `FieldEvent` tagged with its modality
  (`wifi_csi` / `mmwave_radar` / `infrared_thermal`) and a colour-coded
  **privacy-class badge (P0–P5)**.
- **Fusion graph** — the supporting / contradicting events feeding each
  inference (ADR-260 §12).
- **Provenance receipts** — click an event to inspect its signed receipt
  (`sha256` hashes + ed25519 signer + verified ✓/✗).

Endpoints: `GET /` (page), `GET /events` (Server-Sent Events stream),
`GET /api/run` (full deterministic run as JSON), `GET /api/source` (the
data-source selector + banner state), `GET /health`.

### Live mode — ADR-261 trust over the ADR-262 P3 transport

The same dashboard can display **real** `FieldEvent`s streamed from an external
upstream (RuView's `wifi-densepose-sensing-server`, which exposes `GET /api/field`
and `GET /ws/field` per ADR-262 P3) instead of the built-in synthetic simulator:

```bash
# Default: SYNTHETIC (simulator replay)
cargo run -p rufield-viewer -- --source synthetic

# LIVE: replace SENSOR_PUBLIC_KEY_HEX with the independently enrolled key
cargo run -p rufield-viewer -- --source live \
  --upstream http://127.0.0.1:8080 \
  --sensor-key sensor_room_01=SENSOR_PUBLIC_KEY_HEX
```

Env equivalents: `RUFIELD_VIEWER_SOURCE` (`synthetic`|`live`),
`RUFIELD_VIEWER_UPSTREAM`, `RUFIELD_VIEWER_POLL_MS`,
`RUFIELD_VIEWER_SENSOR_KEYS` (comma-separated `sensor=key` bindings), and
`RUFIELD_VIEWER_TRUST_MODE` (`production` by default, or `captured_replay`).
Production freshness can be tightened with `RUFIELD_VIEWER_MAX_EVENT_AGE_MS`
and `RUFIELD_VIEWER_MAX_FUTURE_SKEW_MS`. **The source default stays
SYNTHETIC.**

In live mode the viewer subscribes to the upstream's `/ws/field` SSE stream
(falling back to polling `/api/field`) and authorizes every event through a
persistent `TrustVerifier` before fusion state can change. The trust registry
must be provisioned independently from the event stream. Production and
captured-replay modes both reject synthetic events, unknown self-signed keys,
revoked keys, sensor/key binding mismatches, malformed signatures, and replay;
production additionally enforces stale/future timestamp bounds. Rejected
events are flagged and never fused. The same `LiveProcessor` and replay
watermarks survive upstream batches and reconnects within the running process.

Before a live frame enters the broadcast channel, the default network privacy
guard builds a redacted public projection. It never emits upstream event,
device, or zone identifiers; observation labels; receipt hashes; signer keys;
signatures; model or calibration identifiers; or supporting-event edges.
Rejected events remain operationally visible through stable, non-identifying
reason codes such as `unknown_key` or `signature_verification_failed`. P0, P3,
P4, and P5 details are withheld by default; P4 requires consent and P5 requires
identity binding before any future policy could release them.

The reference viewer binary can accept restored replay state programmatically,
but it does not yet atomically persist updated watermarks. A process restart
therefore requires an operator-provided integrity-protected persistence adapter
to retain replay rejection across restarts.

> **Banner honesty (non-negotiable):** the banner reflects *exactly* what is being
> shown, and the three states are mutually exclusive and visually distinct:
>
> - **`SYNTHETIC — simulated sensors, no hardware`** (amber) — synthetic mode.
> - **`LIVE — <upstream>`** (green) — live mode, actually receiving
>   policy-authorized upstream events.
> - **`DISCONNECTED — <upstream> unreachable`** (red) — live mode selected but the
>   upstream cannot be reached. The viewer shows this explicitly and **never**
>   falls back to synthetic data under a LIVE banner (or vice versa).
>
> Synthetic mode is still a **read-only demo** — no hardware, no live camera, no
> real devices, not a fleet/device-management console.

To depend on the crates from your own project (once published / vendored):

```toml
[dependencies]
rufield-core       = "0.1"
rufield-adapters   = "0.1"
rufield-fusion     = "0.1"
rufield-privacy    = "0.1"
rufield-provenance = "0.1"
```

## Usage

Stream synthetic field events, fuse them into room-state inferences, and apply
the privacy guard. This is the real API — it compiles against the published
crates (see [`crates/rufield-bench/examples/room_intelligence.rs`](crates/rufield-bench/examples/room_intelligence.rs)).

```rust
use rufield_adapters::{run_demo, SimConfig};
use rufield_core::{Destination, FusionEngine, InferenceQuery, PrivacyDecision, PrivacyGuard, PrivacyClass};
use rufield_fusion::RuFieldFusion;
use rufield_privacy::DefaultPrivacyGuard;
use rufield_provenance::is_fusable;

// 1. Build a deterministic synthetic stream (3 modalities, signed events).
let config = SimConfig { seed: 2026, ..SimConfig::default() };
let events = run_demo(&config);

// 2. This deterministic demo deliberately uses the simulation-only policy.
let mut engine = RuFieldFusion::new();
for se in &events {
    assert!(is_fusable(&se.event)); // compatibility helper: simulation only
    engine.ingest(se.event.clone()).unwrap();
}

// 3. Read out the fused room-state inferences (with privacy class + provenance).
for inf in engine.infer(&InferenceQuery::all()).unwrap() {
    println!(
        "{:<18} conf={:.2} privacy={:?} model={} supported_by={} events",
        inf.label,
        inf.confidence,
        inf.privacy_class,
        inf.model_id,
        inf.supporting_events.len(),
    );
}

// 4. The privacy guard: P0 raw frames cannot leave the device by default...
let guard = DefaultPrivacyGuard::default();
let p0 = guard.authorize(PrivacyClass::P0, Destination::Network, false, false);
assert!(matches!(p0, PrivacyDecision::Deny(_)));

// ...and P4 biometric inference (e.g. breathing) is gated on consent.
let p4_no_consent = guard.authorize(PrivacyClass::P4, Destination::Network, false, false);
assert!(matches!(p4_no_consent, PrivacyDecision::RequiresConsent(_)));
let p4_consent = guard.authorize(PrivacyClass::P4, Destination::Network, true, false);
assert!(matches!(p4_consent, PrivacyDecision::Allow));
```

### Real CSI replay

`CsiReplayAdapter` is the **first adapter driven by real captured WiFi CSI**
rather than the synthetic simulator. It reads a `.csi.jsonl` recording (one JSON
object per line: `{"timestamp": <seconds>, "subcarriers": [<amplitude>...]}`),
establishes an empty-room baseline via per-subcarrier Welford statistics, and
emits a signed `FieldEvent` per frame — which feeds the same `RuFieldFusion`
engine as the synthetic stream.

```rust
use rufield_adapters::{CsiReplayAdapter, REPLAY_SIGNER_SEED};
use rufield_core::{FieldAdapter, FusionEngine, InferenceQuery};
use rufield_fusion::RuFieldFusion;
use rufield_provenance::{Signer, TrustPolicy, TrustVerifier, TrustedKeyRegistry};

// Real captured WiFi CSI, replayed from a recording file (not live hardware).
let jsonl = std::fs::read_to_string("recording.csi.jsonl")?;
let mut adapter = CsiReplayAdapter::from_jsonl(&jsonl)?;

// Calibrate an empty-room baseline (per-subcarrier mean + variance).
let receipt = adapter.calibrate("living_room")?;
println!("calibration: {} ({})", receipt.calibration_id, receipt.data_hash);

// Configure captured-replay trust independently from incoming events. This
// fixture key is deterministic; production deployments provision keys through
// an authenticated control plane instead.
let signer = Signer::from_seed(&REPLAY_SIGNER_SEED);
let mut registry = TrustedKeyRegistry::new();
registry.enroll_sensor_key("csi_replay_node_01", &signer.public_hex())?;
let trust = TrustVerifier::new(TrustPolicy::captured_replay(), registry);
let mut engine = RuFieldFusion::with_trust_verifier(trust);
while let Some(event) = adapter.next_event()? {
    engine.ingest(event)?;
    for inf in engine.infer(&InferenceQuery::all())? {
        println!("{} conf={:.2} privacy={:?}", inf.label, inf.confidence, inf.privacy_class);
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

> **Honest caveats (read these).** This is **replay from a file, not live
> hardware**. The recording is **unlabeled**, so the `motion_proxy` /
> `presence_proxy` labels and the `presence` / `motion_energy` / `breathing_band`
> features are a **standard CSI-variance heuristic — a physically-grounded
> proxy, NOT validated-accuracy detection.** No pose, no accuracy numbers are
> claimed. The win is simply: *RuField now ingests real WiFi CSI and produces
> fused events from it.* Over the staged 199-frame real-CSI fixture this yields
> presence/breathing inferences from real signal; live-hardware streaming and
> labeled-accuracy validation remain roadmap.

## User guide

### Run the camera-free room-intelligence demo

The `SyntheticSim` adapter walks the ADR-260 §19 sequence deterministically:

```text
enter → sit → breathing → sleep → scratch → bed-exit → leave
```

across WiFi CSI, mmWave radar, and thermal IR. Every event carries a real
`FieldTensor`, a P2 occupancy observation, ground-truth labels (used **only**
by the benchmark, never by the fusion engine), and a synthetic-signed
provenance receipt. Same `seed` ⇒ byte-identical event stream.

### Run the benchmark

```bash
cargo run -p rufield-bench -- 2026
```

### Read the deterministic report

```text
TASK (SYNTHETIC)       METRIC      VALUE     TARGET    MEETS
presence                   f1      1.000      0.900      yes
breathing                  f1      1.000      0.800      yes
nocturnal_scratch          f1      0.923      0.750      yes
bed_exit                   f1      1.000      0.900      yes
room_transition            f1      1.000      0.850      yes
-----------------------------------------------------------------------------------
p50 latency:          0.0097 ms
p95 latency:          0.0123 ms   (target < 100 ms: PASS)
provenance coverage:  100.0 %      (target 100%: PASS)
privacy violations:   0          (target 0: PASS)
```

How to read it:

- **F1 per task** — scored against the simulator's own ground-truth labels.
  These are **SYNTHETIC**: they show the pipeline recovers known truth, not
  field accuracy. Targets are ADR-260 §18.
- **p95 latency** — per-event pipeline latency. It is sub-millisecond because
  fusion runs in-process; the §27.5 target is < 100 ms.
- **provenance coverage** — fraction of events that pass the §11 fusability
  check (verifiable receipt or synthetic flag). Target 100%.
- **privacy violations** — events transmitted above the default P2 network
  ceiling. Target 0.

### ADR-260 §27 acceptance criteria

The §31 acceptance test (`cargo test -p rufield-bench`) asserts: 3 modalities
present, every event has a privacy class + verifiable receipt, ≥ 5 distinct
inferences, p95 < 100 ms, all default-transmitted events ≤ P2, and a
deterministic report across two runs. See
[ADR-260 "Implementation Status"](./docs/ADR-260-rufield-mfs.md) for the full
§27 scorecard. Criterion 9 (live dashboard) is deferred to a follow-up; all
other v0.1 criteria pass.

## Firmware

**v0.1 ships synthetic adapters only — no hardware adapter is validated.** The
3 modalities in the demo are simulated. This section describes how real edge
hardware connects, as the documented follow-up.

A firmware integrator implements the `FieldAdapter` trait from `rufield-core`:

```rust,ignore
pub trait FieldAdapter {
    type Error: std::error::Error;
    fn modality(&self) -> Modality;
    fn capabilities(&self) -> AdapterCapabilities;
    fn next_event(&mut self) -> Result<Option<FieldEvent>, Self::Error>;
}
```

Planned real sources:

| Modality | Hardware | Notes |
|----------|----------|-------|
| WiFi CSI | ESP32-C6 / ESP32-S3 | Use the RuView [`esp32-csi-node`](https://github.com/ruvnet/RuView) firmware as the CSI source; normalize CSI amplitude/phase into a `FieldTensor`. |
| mmWave | Seeed MR60BHA2 (60 GHz FMCW) or similar cheap module | Range-Doppler bins → `FieldTensor` with `Range`/`Velocity` axes. |
| Thermal IR | Low-res thermal array (e.g. AMG8833/MLX90640) | Temperature grid → `FieldTensor` with `Temperature` axis. |

**Privacy default for real adapters:** raw frames are **P0 and stay
on-device** (the guard denies P0 network transmission by default); only
derived observations at **P2 or below** cross the network without an explicit
consent / identity gate. No hardware adapter has been built or validated in
v0.1 — these are honest follow-ups, not shipped features.

## Privacy & provenance

### Privacy classes (ADR-260 §10)

| Class | Description | Example |
|-------|-------------|---------|
| P0 | Raw waveform / raw sensor frame | raw CSI, raw radar cube |
| P1 | Derived non-identity features | Doppler peak, thermal blob |
| P2 | Occupancy and motion only | person present, bed exit |
| P3 | Anonymous aggregate state | room count, zone activity |
| P4 | Biometric / health inference | breathing, gait, sleep, scratch |
| P5 | Identity-linked inference | named person state |

Default policy: P0 stays on the edge; network transmission defaults to **P2 or
lower**; **P4 requires explicit consent**; **P5 requires identity binding +
audit log**.

### Provenance invariant (ADR-260 §11)

> **No fused inference is valid unless every contributing event has a
> provenance receipt or is explicitly marked synthetic.**

`rufield-provenance` enforces integrity with real `sha256` content hashing and
`ed25519` signatures. The compatibility helper `is_fusable(&event)` implements
the original rule only for simulation: it accepts an explicitly synthetic
event or a signature that verifies against the event-carried key.

Captured replay and production use the ADR-261 stateful `TrustVerifier`
instead. Those modes reject synthetic evidence and require a key enrolled and
bound to the sensor independently of the event. They also enforce revocation
and monotonic replay watermarks; production adds stale/future time bounds. All
checks pass before either replay or fusion state is mutated.

## BLE evidence and Channel Sounding

ADR 261 adds separate adapters for coherent Bluetooth Channel Sounding and
BLE advertisement RSSI identity evidence. The identity path consumes an
authenticated eight-byte ephemeral firmware token at the host boundary,
derives a deployment-scoped HMAC-SHA-256 pseudonym, and emits only short-lived
P5 evidence. Raw BLE MAC addresses are never identity. RSSI is never treated
as coherent phase or exact range. The included two-person crossing scenario is
deterministic and exercises spoof and expiry abstention. It is simulation, not
radio or clinical validation.

Live RuView input is admitted only after verification of the independent
gateway envelope, enrolled node and key, boot session, receive time, and replay
sequence. Channel Sounding additionally requires the exact enrolled companion,
an authenticated source session, and a complete coherent procedure with four
through seventy-nine unique RF channels drawn from channel indices 0 through 78.
Its sensor id and firmware provenance identify the external companion. The
ESP32 node, key, boot,
sequence, receive time, and timing uncertainty remain typed forwarding
provenance and never imply ESP32 Channel Sounding capability. The gateway HMAC
authenticates integrity but does not encrypt UDP; deployments add a confidential
transport when P5 pseudonyms or P0 phase primitives must not be observable on
the LAN.

Production fusion rejects synthetic BLE and requires an exact sensor-device
and Ed25519 signer allowlist pair. Fusion windows are partitioned by anonymous
track, so known tracks never share weighted or temporal evidence. Deterministic
credentials and provenance metadata are available only through the explicit
`BleAdapterConfig::synthetic_fixture()` constructor and fail validation when
marked as production.

## Spec / ADR

The specification of record is [ADR-260](./docs/ADR-260-rufield-mfs.md). It
defines the Field Event, Field Tensor, modality registry, privacy classes,
provenance receipts, fusion rules, benchmark suite, and acceptance criteria.
The BLE evidence extension is [ADR-261](./docs/ADR-261-ble-evidence-and-channel-sounding.md).

## License

[MIT](./LICENSE).

## Contributing

Issues and PRs welcome. Keep crates pure-Rust and `cargo test --workspace`
green; new adapters implement `FieldAdapter` and must respect the P0-edge-only
privacy default. All benchmark numbers must remain honestly labelled SYNTHETIC
until a real hardware adapter is validated.
