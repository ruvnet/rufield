# ADR 264: RuCelium Federated Environmental Intelligence Fabric

Status: Accepted — v0.1 reference stack

Date: 2026 08 02

Deciders: rUv

Tags: environmental sensing, federation, biome, sovereignty, calibration, lorawan, cbor, cose, sensorthings, worldgraph, ruview, rufield, mycelium

## 1. Context

RuField MFS (ADR-260) normalized camera-free ambient sensing into one privacy
aware, provenance rich event model. RuView proved a safe architecture for
hostile hardware boundaries: ADR 096 confines vendor and firmware complexity
to a narrow, allocation free, bounds checked C boundary while keeping
validation, DSP, events, runtime composition, and memory integration in safe
Rust. ADR 139 defined WorldGraph — an environmental digital twin with typed
Rust graph nodes, geospatial registration, sensor placement, typed evidence
edges, contradiction tracking, privacy constraints, and persisted topology.

The next opportunity is planetary-scale environmental intelligence: soil,
water, air, acoustic biodiversity, bioelectric, and RF-contextual sensing
across forests, watersheds, cities, farms, coastlines, and protected areas.

A flat global peer mesh is the obvious design and the wrong one. It fails on:

1. **Battery life** — battery nodes cannot participate in chatty mesh routing.
2. **Bandwidth** — raw RF/acoustic streams cannot cross constrained uplinks
   (§10 quantifies this: one CSI link ≈ 2.2 GB/day).
3. **Routing** — global DHT-style routing over LoRaWAN-class links is fantasy.
4. **Calibration** — a measurement without calibration lineage is scientifically
   worthless at aggregation time; a flat mesh has no calibration authority.
5. **Sovereignty** — a forest, a farm, and a city have different owners,
   retention duties, and disclosure obligations. A flat mesh has one namespace.
6. **Compromised nodes** — a flat mesh gives one compromised node global blast
   radius; revocation must be containable.

The largest failure mode is not networking. It is **scientifically invalid
data** caused by sensor drift, inconsistent calibration, undocumented
placement, and model domain shift.

## 2. Decision

Create **RuCelium**, a federated environmental intelligence fabric — not a
global peer mesh. Four layers, each with a sovereignty boundary:

```text
Layer 4  Planetary federation   discovery + aggregate intelligence, no ownership
Layer 3  Biome regions          sovereign owners of data, models, actuators
Layer 2  Rhizome gateways       Rust: verify, normalize, fuse, buffer, govern
Layer 1  Spore nodes            C: sense, calibrate (fixed point), sign, transmit
```

Language split follows ADR 096: **C at the sensor boundary only** (drivers,
interrupts, fixed point calibration, deterministic DSP, serialization,
transport). **Rust everywhere above it** (validation, ingestion, fusion,
WorldGraph, storage, policy, federation, agents). No policy engine, graph
logic, or large model executes on a spore node.

RuView RF sensing joins as a **contextual environmental modality** — supporting
evidence, never ground truth (§8). Mycelium-style multi-agent coordination
sits **above** the biome layer behind a mandatory governed control path (§9).

## 3. Name

Mycelium: the underground fungal network that connects a forest — decentralized,
regional, resilient, and symbiotic rather than centrally owned. Spores (sensor
nodes) seed it; rhizomes (gateways) root it; biomes own it; the planetary layer
merely lets biomes find each other.

## 4. Layer 1 — Spore nodes (C)

Small environmental sensor nodes written primarily in C.

Responsibilities (exhaustive — nothing else runs here):

1. Sensor drivers and interrupt handling
2. Fixed point calibration
3. Basic filtering
4. Local anomaly thresholds
5. Offline ring buffer
6. Device signing
7. Transport: LoRaWAN 1.0.4, BLE, WiFi, 802.15.4, RS485, or SDI-12

Modalities (the v0.1 registry, §7.1): temperature/humidity, CO₂ and volatile
compounds, PM1/PM2.5/PM10, soil moisture and conductivity, water level and
flow, acoustic biodiversity, mycelial bioelectric potential, light/UV/IR,
leaf wetness and rainfall, and RuView-compatible RF observations.

LoRaWAN 1.0.4 is appropriate for battery powered nodes with small periodic
payloads. It is **not** appropriate for raw RF or acoustic streams — those stay
on-gateway (§10).

## 5. Layer 2 — Rhizome gateways (Rust)

Rust services on CognitumWRT, Linux gateways, Raspberry Pi, industrial ARM, or
partner routers.

Responsibilities:

1. Decode all sensor protocols
2. Verify signatures and sequence numbers
3. Normalize observations
4. Run RuView DSP and local models
5. Fuse environmental and RF evidence
6. Maintain local WorldGraph state
7. Store data during network outages
8. Publish signed regional summaries
9. Execute governed actuator commands

### 5.1 Crate map

The specified crate family and where v0.1 implements each concern:

| Specified crate | v0.1 home | Notes |
|---|---|---|
| `rucelium-core` | `rucelium-core` | domain model: `EnvSample`, `EnvFrame`, `CalibrationRecord`, `EnvironmentalEvent`, `SensorModality`, `GeoPoint`, `DataClass` |
| `rucelium-c-ffi` | `rucelium-abi` | versioned C ABI (`rv_env_sample_v1`), bounds-checked alloc-free parse, deterministic CBOR, signed record envelope, shipped C header |
| `rucelium-ingest` | `rucelium-ingest` | gateway pipeline: parse → verify → replay-window → normalize |
| `rucelium-calibration` | `rucelium-calibration` | lineage chains, drift detection, quarantine (never silent correction) |
| `rucelium-ruview` | `rucelium-worldgraph::rf` | RuField `FieldEvent` → contextual evidence bridge |
| `rucelium-fusion` | `rucelium-worldgraph` | evidence edges, plausibility checks, contradiction tracking |
| `rucelium-worldgraph` | `rucelium-worldgraph` | typed nodes, geospatial registration, evidence/contradiction edges |
| `rucelium-store` | `rucelium-federation::buffer` | outage buffer with deterministic duplicate-free replay |
| `rucelium-policy` | `rucelium-policy` | governed control path (§9), typed so steps cannot be skipped |
| `rucelium-federation` | `rucelium-federation` | biome sovereignty, signed summaries, revocation, SensorThings projection |
| `rucelium-agent` | `rucelium-policy::agent` | agent proposal types; agents never touch actuators directly |
| `rucelium-cli` | `rucelium-bench` (bin) | v0.1 CLI is the deterministic biome benchmark runner |

Consolidation is deliberate: v0.1 keeps the crate count at the scale of the
existing workspace and splits later along the seams the table already draws.

### 5.2 WorldGraph reuse

ADR 139's WorldGraph is directly reusable. v0.1 **extends its sensor
modalities rather than creating a second graph**:

```rust
pub enum SensorModality {
    WifiCsi,
    AirQuality,
    SoilMoisture,
    WaterQuality,
    Acoustic,
    Weather,
    Bioelectric,
    Radiation,
    Optical,
    Chemical,
}
```

## 6. Layer 3 — Biome regions

Each forest, watershed, city, farm, coastline, or protected area is a
**sovereign biome**. A biome owns:

1. Its raw observations
2. Its calibration records
3. Its WorldGraphs
4. Its local models
5. Its retention policy
6. Its disclosure policy
7. Its actuator authority

Biomes exchange **signed events, statistical summaries, model updates, and
cross-boundary alerts**. They do not continuously replicate raw measurements.

Sensitive biodiversity locations support coordinate coarsening, delayed
disclosure, and access-controlled raw data. Actuator permissions never leave
the biome owner.

## 7. Layer 4 — Planetary federation

The global layer provides **discovery and aggregate intelligence, not
centralized ownership**. It exposes:

1. OGC SensorThings API 1.1 (Things, Sensors, Locations, Datastreams,
   Observations, ObservedProperties, FeaturesOfInterest) for external
   interoperability
2. Geospatial tiles
3. Regional event feeds
4. Environmental model registry
5. RuVector similarity search
6. WorldGraph query federation
7. Public research datasets
8. Sovereign private namespaces

v0.1 implements the SensorThings **projection** (biome → SensorThings JSON
entities) in `rucelium-federation::sensorthings`; serving it over HTTP is a
follow-up.

**Do not start with the global layer.** §13 requires one biome to prove 30
days of operation without internet before the planetary service is designed.

### 7.1 Observation requirements

Every observation carries all twelve:

1. Device identity
2. Sequence number
3. Measurement time
4. Reception time
5. Geospatial reference
6. Unit and observed property
7. Calibration identifier
8. Quality score
9. Uncertainty interval
10. Firmware measurement implementation
11. Signature
12. Derivation lineage

An observation missing any of these is rejected at ingest, not repaired.

## 8. RuView's contribution — RF as context, never ground truth

RuView does not pretend RF replaces physical environmental sensors. RF becomes
a **contextual environmental modality** contributing:

1. Movement of people and animals around protected areas
2. Canopy and vegetation motion signatures
3. Water surface and flood boundary changes
4. Precipitation related channel changes
5. Soil and vegetation moisture related RF features
6. Structural movement around cliffs, trees, bridges, and buildings
7. Detection of sensor displacement or tampering
8. Spatial localization of events reported by other sensors
9. Validation that an observation is physically plausible

Current ISAC research covers environmental sensing through CSI, Doppler, and
signal statistics (rainfall, soil moisture, flood dynamics, water level), but
the **generalization problem remains unresolved**. Therefore, normatively:

> RuView outputs are supporting evidence. They may raise or lower confidence
> and create contradiction edges. They may never be the sole basis for an
> environmental fact, an alert above advisory severity, or an actuator command.

The bridge (`rucelium-worldgraph::rf`) ingests RuField `FieldEvent`s (which
already carry privacy class + provenance per ADR-260) and emits
`Supports` / `Contradicts` evidence edges against environmental observations.

## 9. Mycelium agent layer and the governed control path

Mycelium IO is a multi-agent coordination and persistent memory layer, not a
constrained sensor protocol. It sits **above** the biome layer. Agents include
calibration, sensor health, wildfire risk, flood, biodiversity, pollution
source, deployment optimization, data quality, scientific hypothesis, and
governance agents.

Agents can propose new sampling rates, model deployments, sensor
repositioning, or actuator commands. **They never directly control physical
systems.** The only path to execution:

```text
Agent proposal
→ deterministic policy evaluation
→ safety simulation
→ authority check
→ signed command
→ gateway validation
→ local execution
→ execution receipt
```

v0.1 enforces this **by construction**: `rucelium-policy` types each stage's
output as the only valid input to the next stage, so a proposal cannot reach
execution without passing every gate, and every stage appends to a signed audit
trail.

The ThreeFold "Mycelium" project (an encrypted IPv6 overlay in Rust) is a
different technology. It may optionally connect gateways across unreliable
networks; it is not required by sensor nodes and is not embedded in the data
model.

## 10. Data economics

Raw RuView data cannot leave every site. One CSI link at 100 frames/s ×
64 complex subcarriers × 4 bytes ≈ 25,600 B/s ≈ **2.2 GB/day per RF link**;
one million links ≈ 2.2 EB/day before metadata or replication. A normal
environmental node sending a 64-byte observation once per minute produces
≈ 92 KB/day; one million nodes ≈ 92 GB/day — manageable.

Therefore three data classes with distinct residency and retention:

| Class | Content | Residency | Retention |
|---|---|---|---|
| `RawSignal` | raw CSI/acoustic/waveform | gateway only | hours–days |
| `DerivedFeature` | DSP features, model outputs | biome | weeks–months |
| `FederatedEvent` | signed events + aggregates | global | years |

Target latencies:

1. Local safety event: **< 250 ms**
2. Gateway fusion: **< 2 s**
3. Biome alert: **< 30 s**
4. Global propagation: **< 5 min**
5. Scientific aggregate: hourly or daily

## 11. The C ↔ Rust contract

A versioned C ABI at ingestion, then deterministic CBOR above it.

### 11.1 Wire struct (v1, little-endian, 48 bytes, no padding)

```c
typedef struct {
    uint8_t  schema_version;   /* == 1 */
    uint8_t  sensor_type;      /* SensorModality code */
    uint16_t flags;
    uint64_t node_id;
    uint64_t timestamp_ns;
    uint32_t sequence;
    int32_t  latitude_e7;      /* degrees × 1e7 */
    int32_t  longitude_e7;     /* degrees × 1e7 */
    int32_t  altitude_mm;
    int32_t  value_q16;        /* Q16.16 fixed point */
    uint16_t quality_q15;      /* Q0.15: 0x0000..0x8000 → 0.0..1.0 */
    uint16_t battery_mv;
    uint32_t calibration_id;
} rv_env_sample_v1;
```

The Rust mirror is `#[repr(C)]` and **every field is validated before
conversion into the domain model**. Because the workspace forbids `unsafe`,
the parser never transmutes: it performs bounds-checked little-endian field
reads over the byte slice — allocation free, panic free, exactly the ADR-096
posture. The header of record is
[`crates/rucelium-abi/include/rucelium_env.h`](../crates/rucelium-abi/include/rucelium_env.h).

### 11.2 Serialization and signing

- **CBOR** (RFC 8949) for everything above the fixed struct, chosen for small
  code and message sizes. v0.1 ships a dependency-free deterministic encoder:
  definite lengths, fixed field order, shortest-form integers — same sample ⇒
  byte-identical encoding.
- **Signing**: ed25519 detached signatures over the exact wire payload, carried
  in a COSE_Sign1-inspired deterministic CBOR envelope
  (`[payload bstr, pubkey bstr, signature bstr]`). Honest label: this is
  COSE-*inspired* deterministic framing, not a full RFC 9052 implementation —
  upgrading the envelope to real COSE/CWT is a stated follow-up, and the
  signature scheme (ed25519 over payload bytes) is forward-compatible with it.
- Flags bit 0 (`RV_ENV_FLAG_RETRANSMIT`) marks ring-buffer replay after an
  outage so gateways can distinguish store-and-forward from replay attacks
  (the sequence window still deduplicates).

## 12. Trust and governance

Countermeasures for the real failure mode (§1):

1. Signed calibration lineage — every `CalibrationRecord` chains to a parent
   up to a reference-grade anchor; broken chains are rejected
2. Reference grade anchor stations
3. Periodic co-location calibration
4. Measurement uncertainty on every observation
5. Automatic drift detection (EWMA residual vs anchor)
6. **Sensor quarantine rather than silent correction** — drifted sensors are
   quarantined and their data flagged unusable; values are never rewritten
7. Contradiction edges in WorldGraph
8. Geographic and seasonal validation sets
9. Public quality scores
10. Reproducible transformation receipts

Revocation is biome-local first: revoking a device invalidates its key at the
biome's gateways immediately and propagates outward as a signed event; the
biome keeps operating throughout.

## 13. Implementation sequence

1. Define `EnvSample`, `EnvFrame`, `CalibrationRecord`, `EnvironmentalEvent`
2. Add the stable C ABI and CBOR encoding
3. Implement temperature, humidity, soil, air quality, and acoustic adapters
4. Extend WorldGraph with environmental sensor and ecosystem nodes
5. Add RuView RF feature fusion
6. Implement local buffering and deterministic replay
7. Add OGC SensorThings projection
8. Add device signatures and revocation
9. Deploy one 64-node biome
10. Federate three biomes **before** designing the planetary service

Do not start with the global layer. Prove that one biome can remain
operational for 30 days without internet.

## 14. Acceptance test (v0.1)

A 64-node pilot passes when it:

1. operates for 30 days (simulated deterministically in v0.1 — labelled
   **SYNTHETIC**, exactly as ADR-260 labels its benchmark),
2. survives seven consecutive offline days,
3. restores buffered data without duplicates,
4. rejects **every** modified or replayed packet,
5. produces local alerts within 500 ms (v0.1 measures in-process pipeline
   latency, as rufield-bench does),
6. maps every accepted observation into SensorThings **and** WorldGraph,
7. revokes one compromised device without interrupting the biome,
8. maintains ≥ 95 % usable calibrated observations.

`cargo run -p rucelium-bench` prints the scorecard;
`cargo test -p rucelium-bench` asserts all eight criteria plus determinism
(two runs at the same seed produce identical reports).

## 15. Alternatives considered

1. **Flat global peer mesh** — rejected for the six failures in §1.
2. **Cloud-centralized ingestion** — rejected: violates sovereignty, fails the
   30-day-offline requirement, and creates a single revocation/consent choke
   point.
3. **MQTT + JSON everywhere** — rejected at the node boundary: JSON costs
   2–4× CBOR on constrained links and offers no deterministic encoding for
   signatures; retained as an optional gateway-side projection.
4. **Protobuf instead of CBOR** — viable, but CBOR's self-description,
   COSE alignment, and tiny encoder footprint fit spore nodes better.
5. **Requiring the ThreeFold Mycelium overlay** — rejected as a hard
   dependency; optional gateway transport only.
6. **A second, environmental-specific graph** — rejected; extend WorldGraph
   (ADR 139) modalities instead.

## 16. Consequences

Positive: sovereignty and revocation are containable; constrained links carry
only what they can; calibration is a first-class, auditable object; RF context
improves confidence without contaminating ground truth; the C surface stays
narrow and auditable.

Negative / accepted costs: federation adds protocol surface (summaries, keys,
revocation feeds); consolidated v0.1 crates will need splitting as layers
mature; the COSE envelope is not yet full RFC 9052; v0.1 numbers are synthetic
until a real 64-node deployment exists.

## Implementation status (v0.1)

| # | Criterion | Status |
|---|---|---|
| 1 | Core domain model (§5.1) | shipped — `rucelium-core` |
| 2 | C ABI + deterministic CBOR + header (§11) | shipped — `rucelium-abi` |
| 3 | Gateway ingest: verify/replay-window/normalize (§5) | shipped — `rucelium-ingest` |
| 4 | Calibration lineage + drift + quarantine (§12) | shipped — `rucelium-calibration` |
| 5 | WorldGraph env nodes + RF context bridge (§5.2, §8) | shipped — `rucelium-worldgraph` |
| 6 | Governed control path, typed stages (§9) | shipped — `rucelium-policy` |
| 7 | Biome sovereignty, outage buffer, summaries, revocation, SensorThings projection (§6, §7, §10) | shipped — `rucelium-federation` |
| 8 | 64-node biome acceptance benchmark (§14) | shipped — `rucelium-bench` |
| 9 | Real spore-node firmware, LoRaWAN transport, HTTP SensorThings service, three-biome federation | honest follow-up — not in v0.1 |
