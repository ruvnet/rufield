# ADR 266: Rydberg Quantum RF Vector Sensing for RuField and RuView

Status: Accepted for the software contract and replay reference implementation. Software property and performance gates are implemented. All live hardware validation remains pending.

Date: 2026 07 12

Deciders: rUv

Depends on: ADR 260 RuField Multimodal Field Sensing Specification

Tags: quantum rf, rydberg, electric field, vector polarimetry, direction finding, ruview, calibration, privacy, provenance, replay

## 1. Decision

RuField adds a distinct `quantum_rf` modality for Rydberg atom radio frequency electric field vector receivers.

The reference implementation includes:

1. `Modality::QuantumRf` with stable wire code `16` and wire name `quantum_rf`.
2. `FieldAxis::CartesianComponent`, `FieldAxis::ComplexComponent`, and `FieldAxis::DirectionCandidate`.
3. A `RydbergReplayAdapter` that validates a structured Rydberg frame, emits a signed `FieldEvent`, and supports derived bearing and explicit raw electric field output modes.
4. A sign honest direction representation containing both antipodal candidates, never a falsely resolved bearing.
5. Fail closed calibration, quality, privacy, and provenance gates.
6. A staged path from analytic synthetic vectors, to deterministic replay, to controlled live hardware, to RuView fusion.

The software decision is accepted because its data model, invariants, replay behavior, and security controls are testable without quantum hardware. No claim of live receiver accuracy, update rate, indoor source localization, or commercial hardware readiness is accepted by this ADR.

## 2. Evidence boundary

This decision is grounded in two different levels of evidence that must not be conflated.

### 2.1 Peer reviewed experimental evidence

Elgee et al. demonstrated a Rydberg atom electric field sensor that reconstructs a three dimensional complex electric field using three orthogonal radio frequency local oscillators and optical readout. For an elliptically polarized plane wave, the normal to the polarization ellipse constrains the wave vector to an antipodal pair.

The reported experiment used a rubidium 85 vapor cell, a 6.64 GHz signal, a signal field near 0.06 V/m, and local oscillator fields near 0.14 V/m. With a direction indexed iterative reflection correction, the reported average absolute errors were 33 mrad for polar angle and 43 mrad for azimuth, approximately 1.89 degrees and 2.46 degrees. The reported statistical noise was 1.3 mrad per square root hertz and 1.5 mrad per square root hertz. The authors associated this with electric field sensitivity of 58 microvolts per metre per square root hertz.

Those results establish physical feasibility under a calibrated laboratory setup. They do not establish indoor multipath performance, multi emitter separation, range, sign resolution, WiFi packet reception, production update rate, or unattended calibration stability.

Primary sources:

1. [Elgee et al., Electrically small Rydberg sensor for three dimensional determination of radio frequency k vectors, Physical Review Applied 23, 064022, 2025](https://doi.org/10.1103/pthj-gy98)
2. [Elgee et al. author preprint, arXiv 2503.04670](https://arxiv.org/abs/2503.04670)
3. [Elgee et al., Complete three dimensional vector polarimetry with a Rydberg atom RF electrometer, Physical Review Applied 22, 064012, 2024](https://doi.org/10.1103/PhysRevApplied.22.064012)

The implementation discussion was prompted by the [IEEE Spectrum overview of the direction finding result](https://spectrum.ieee.org/quantum-sensor-radio-signal-direction). Normative scientific claims in this ADR use the paper rather than the secondary summary.

### 2.2 Commercial status in 2026

Infleqtion publicly describes a Rydberg based Quantum Spectrum product line and lists a Gen 1 system at 9U covering 3 MHz to 6 GHz, a Gen 2 roadmap at 4U covering 1 MHz to 12 GHz, and a later rugged VPX generation. It also describes precision optics and future photonic integration.

The public material does not provide a price, public software API, power envelope, field update rate, instantaneous bandwidth under direction finding, bearing accuracy, angular covariance contract, or independent indoor validation. Therefore, the adapter is vendor neutral and replay first. It must not encode Infleqtion marketing claims as measured RuField capability.

Primary source: [Infleqtion Quantum Spectrum product and roadmap page](https://infleqtion.com/quantum-spectrum/)

### 2.3 Claims rule

Every result must carry one of these evidence labels:

| Label | Meaning | Permitted claim |
| --- | --- | --- |
| `ANALYTIC_SYNTHETIC` | Complex electric field generated from known mathematics | Schema, invariants, and numerical correctness only |
| `RECORDED_REPLAY` | Previously captured or externally supplied frames | Deterministic ingestion and replay behavior only |
| `CONTROLLED_LAB` | Live sensor with traceable source geometry | Accuracy and latency within the documented apparatus only |
| `FIELD_PILOT` | Live sensor in an operational environment | Performance only for the measured site, bands, emitters, and calibration interval |

Synthetic or replay evidence must never be presented as live quantum sensor performance.

For the reference adapter, signed `evidence_kind=synthetic_replay` maps to `ANALYTIC_SYNTHETIC`, while `evidence_kind=captured_replay` maps to `RECORDED_REPLAY`. A future hardware adapter must emit signed `evidence_kind=live` and pass the enrolled production trust chain before any live claim.

The current `rufield-viewer` `LIVE` banner describes transport connectivity; it does not yet render authenticated evidence kind. Quantum RF analytic or captured replay therefore MUST NOT be routed through the viewer's live source. Replay-aware `SYNTHETIC` and `RECORDED_REPLAY` viewer states are pending Stage S1 integration work. The implementation in this decision is the adapter, signed event contract, validation suite, and fusion library—not a completed evidence-aware viewer surface.

## 3. Context

ADR 260 reserves quantum magnetic and quantum inertial modalities. A Rydberg RF receiver measures a complex electric field and, under constrained propagation and polarization conditions, an RF propagation axis. It is neither a magnetic field sensor nor an inertial sensor. Overloading either existing modality would make units, calibration, privacy, and fusion semantics incorrect.

RuView already works with commodity RF observables such as CSI, CIR, BFLD, RSSI, and known access point geometry. A Rydberg vector receiver can contribute a compact, frequency selective propagation axis and electric field measurement. Its strongest initial role is a sparse calibration and bearing oracle for a larger inexpensive RuView deployment, not a sensor in every room.

The largest technical risk is multipath. A single complex electric field phasor always traces an ellipse, including the resultant field produced by several coherent paths. The normal to that resultant ellipse can point toward a reflection rather than the emitter. A mathematically valid vector is not automatically a physically valid source bearing.

## 4. Goals

1. Represent calibrated three dimensional complex electric field frames without vendor lock in.
2. Represent the unavoidable antipodal direction ambiguity explicitly.
3. Make tensor ordering, units, frames of reference, and confidence semantics checkable.
4. Reject degenerate polarization, stale calibration, bad optical lock, malformed covariance, and nonfinite values before fusion.
5. Preserve signed lineage from source frame through calibration and derived event.
6. Keep raw RF field data disabled by default and edge local when enabled.
7. Let RuView fuse quantum RF axes with CSI, CIR, BFLD, sensor pose, and known transmitter geometry.
8. Define separate software, laboratory, and field acceptance tests.

## 5. Non goals

1. Do not claim that quantum RF replaces WiFi CSI, CIR, BFLD, phased arrays, or spectrum analyzers.
2. Do not infer range from field strength.
3. Do not silently select one of the two direction candidates.
4. Do not claim source direction for a linearly polarized or otherwise ill conditioned frame.
5. Do not claim that a single frame separates several coherent emitters or propagation paths.
6. Do not decode communications payloads.
7. Do not classify people, health, pose, or identity from this modality.
8. Do not expose vendor control, laser control, or safety critical hardware commands through the replay adapter.
9. Do not treat atomic physics traceability as proof that the complete vector receiver is self calibrating. Local oscillator amplitude, phase, sensor pose, optical lock, vapor cell reflections, and environment still require calibration.

## 6. Terminology and coordinate conventions

`Electric field phasor` means the complex vector:

\[
\widetilde{\mathbf E} =
\begin{bmatrix}
E_x \\
E_y \\
E_z
\end{bmatrix}
= \mathbf a + i\mathbf b
\]

The reference convention is:

\[
\mathbf E(t)=\Re\left\{\widetilde{\mathbf E}e^{i\omega t}\right\}
=\mathbf a\cos\omega t-\mathbf b\sin\omega t
\]

The frame carries a right handed sensor local vector basis and a calibration bound sensor pose. `e_field_sensor_vpm` and `k_hat_sensor` use sensor local `x`, `y`, `z`. Each complex field component is ordered `real`, `imaginary`. `sensor_position_m` uses the named shared Cartesian frame. `sensor_orientation_xyzw` is an active unit quaternion mapping sensor local vectors into that shared frame. A global phasor rotation must not alter the derived propagation axis.

`Propagation axis` means the sign ambiguous normal to the polarization ellipse. Candidate zero is the validated supplied `k_hat_sensor` in the sensor local frame. Candidate one is its exact negative. The phasor cross product validates the axis with a sign invariant comparison, but does not impose a physical sign. This ordering does not resolve propagation direction.

`Wave vector` points in the direction of phase propagation. A source bearing normally points from the receiver toward the source and is therefore opposite the resolved incoming wave vector. The distinction becomes meaningful only after downstream sign resolution.

The v1 bearing and raw electric field tensors remain sensor local. `SensorDescriptor` carries canonical typed pose metadata:

| Field | Quantum RF requirement |
| --- | --- |
| `coordinate_frame: Option<String>` | `Some(nonempty shared frame id)` |
| `position_m: Option<[f32; 3]>` | `Some(sensor origin in coordinate_frame)` |
| `orientation_xyzw: Option<[f32; 4]>` | `Some(unit local to shared quaternion [x,y,z,w])` |

The fusion layer applies this rotation exactly once when it converts the sensor local bearing into the shared frame. The adapter must not pre rotate the tensor, and fusion must not rotate an already normalized internal observation twice. Typed pose is bound into the signed calibration receipt. `SensorDescriptor.placement` remains descriptive text and must not be treated as a pose transform.

Every event in one fusion window must carry the same nonempty coordinate frame identifier. A frame mismatch fails closed before line geometry.

## 7. Registry and tensor decision

### 7.1 Modality

| Property | Value |
| --- | --- |
| Rust variant | `Modality::QuantumRf` |
| Stable numeric code | `16` |
| Stable wire name | `quantum_rf` |
| Physical quantity | Complex RF electric field and derived propagation axis |
| Default output privacy | `P1` |
| Explicit raw output privacy | `P0` |

Numeric code 16 must never be reused. Unknown future codes must fail parsing rather than map to `SyntheticSim` or another modality.

### 7.2 New semantic axes

| Axis | Index meaning |
| --- | --- |
| `CartesianComponent` | `0=x`, `1=y`, `2=z` |
| `ComplexComponent` | `0=real`, `1=imaginary` |
| `DirectionCandidate` | `0=validated supplied k_hat_sensor`, `1=its exact negative` |

The index ordering is normative. Consumers must not infer it from display labels.

### 7.3 Derived bearing tensor

The default adapter output is:

```text
modality      quantum_rf
axes          [direction_candidate, cartesian_component]
shape         [2, 3]
values        [n_x, n_y, n_z, -n_x, -n_y, -n_z]
privacy       P1
units         dimensionless unit vectors
frame         sensor local, transform supplied by SensorDescriptor pose
```

Both rows are mandatory. A single vector is invalid even if a downstream system believes it has resolved the sign.

### 7.4 Raw electric field tensor

Raw output is explicit and disabled by default:

```text
modality      quantum_rf
axes          [cartesian_component, complex_component]
shape         [3, 2]
values        [Re(Ex), Im(Ex), Re(Ey), Im(Ey), Re(Ez), Im(Ez)]
privacy       P0
units         volts per metre
frame         sensor local, transform supplied by SensorDescriptor pose
```

Raw phasors can support later algorithms but can also expose modulation and emitter characteristics. They must not cross the default network boundary.

In raw mode, both `FieldTensor.privacy_class` and `Observation.privacy_class` are `P0`. The output label is `quantum_rf_complex_field`. A raw event must never carry the derived bearing label.

### 7.5 Noise floor semantics

For a derived bearing tensor, `FieldTensor.noise_floor` is the conservative one sigma angular uncertainty in radians, defined as the square root of the largest eigenvalue of the two dimensional angular covariance.

For a raw electric field tensor, `FieldTensor.noise_floor` is the electric field noise estimate in volts per metre for the represented integration interval:

\[
E_{noise}=\frac{E_{norm}}{10^{SNR_{dB}/20}}
\]

Mixing these unit conventions under the wrong tensor axes is invalid.

## 8. Adapter input contract

The replay and future live adapters normalize vendor output into this logical frame before constructing a `FieldEvent`:

```rust
pub struct RydbergFrame {
    pub timestamp_ns: u64,
    pub sensor_position_m: [f64; 3],
    pub sensor_orientation_xyzw: [f64; 4],
    pub coordinate_frame: String,
    pub signal_id: String,
    pub carrier_hz: f64,
    pub e_field_sensor_vpm: [[f64; 2]; 3],
    pub k_hat_sensor: [f64; 3],
    pub sign_ambiguous: bool,
    pub ellipticity: f64,
    pub snr_db: f64,
    pub integration_ms: f64,
    pub angular_covariance_rad2: [[f64; 2]; 2],
    pub calibration_id: String,
    pub calibration_created_ns: u64,
    pub calibration_expires_ns: u64,
    pub calibration_quality: f64,
    pub lock_quality: f64,
}
```

`RydbergQualityThresholds` carries all quality gates. Thresholds are configuration, not hidden constants, and their canonical hash must be bound into calibration provenance for live deployments.

`QuantumRfOutput` has exactly two modes:

1. `DerivedBearing`, the default P1 antipodal axis tensor.
2. `RawElectricField`, an explicit P0 complex electric field tensor.

The public reference source is `RydbergReplayAdapter`. A future vendor live adapter may use another transport, but must produce the same logical frame and pass the same validation function.

`field_strength_vpm` is derived from the complex field as its Euclidean phasor norm. It is not an independent trusted input:

\[
E_{norm}=\sqrt{\sum_{j\in\{x,y,z\}}\left(\Re(E_j)^2+\Im(E_j)^2\right)}
\]

### 8.1 Reference replay thresholds

The default `RydbergQualityThresholds` are software guardrails for deterministic replay. They are not validated hardware operating limits.

| Threshold | Default |
| --- | ---: |
| Minimum absolute ellipticity | `0.05` |
| Minimum calibration quality | `0.80` |
| Minimum optical lock quality | `0.90` |
| Minimum SNR | `6 dB` |
| Maximum angular standard deviation | `10 degrees` |
| Unit vector norm tolerance | `1e-5` |
| Covariance numeric tolerance | `1e-9` |
| Maximum phasor versus supplied axis disagreement | `10 degrees` |
| Reported ellipticity versus phasor observability tolerance | `0.10` |
| Quaternion norm tolerance | `1e-5` |

Live thresholds must be replaced or explicitly reaffirmed using calibration holdout evidence and bound into the signed calibration sidecar.

### 8.2 Observation feature keys

The adapter writes the following numeric keys to `Observation.features`:

| Key | Unit or encoding | Requirement |
| --- | --- | --- |
| `sensor_x_m` | metres | Required |
| `sensor_y_m` | metres | Required |
| `sensor_z_m` | metres | Required |
| `carrier_hz` | hertz stored as `f32` | Required, with acknowledged sub kilohertz precision loss at GHz carriers |
| `ellipticity` | signed `-1..1`, magnitude equals `q_axis` | Required |
| `field_strength_vpm` | volts per metre | Required |
| `snr_db` | decibels | Required |
| `integration_ms` | milliseconds | Required |
| `angle_cov_00_rad2` | radians squared | Required |
| `angle_cov_01_rad2` | radians squared | Required |
| `angle_cov_11_rad2` | radians squared | Required |
| `sign_ambiguous` | `1.0=true`, `0.0=false` | Must be `1.0` in a valid v1 bearing event |
| `quality_valid` | `1.0=true`, `0.0=false` | Must be `1.0` for every emitted event |
| `lock_quality` | normalized `0..1` | Required |
| `calibration_quality` | normalized `0..1` | Required |
| `calibration_remaining_s` | seconds | Required and strictly positive |

The tensor is canonical for direction components. Direction components must not be duplicated in feature keys because duplicated values can diverge.

`sensor_x_m`, `sensor_y_m`, and `sensor_z_m` are compatibility mirrors of typed sensor pose position in the shared calibration frame. Typed pose is canonical. The adapter and fusion decoder must reject any mismatch rather than choose one copy.

`Observation.range_m`, `velocity_mps`, and `motion_vector` must be `None`. Labels may describe the measurement contract, such as `quantum_rf_bearing_antipodal` or `quantum_rf_complex_field`, but must never contain source identity, inferred range, detection, or benchmark ground truth. Analytic ground truth belongs in benchmark records, not in the event consumed by fusion.

### 8.3 Authenticated string attributes

`Observation.attributes` carries signed string context that cannot safely be encoded as `f32`. The quantum RF contract defines:

| Key | Semantics |
| --- | --- |
| `signal_id` | Opaque exact identifier asserting that events observe the same emission, pilot, or capture evidence group |
| `tensor_frame` | Exactly `sensor_local` for v1 quantum RF tensors |
| `evidence_kind` | `synthetic_replay` or `captured_replay` for the reference adapter; `live` only for an enrolled production device |
| `calibration_data_hash` | Exact `sha256:<64 lowercase hex>` hash from the bound calibration receipt |
| `calibration_created_ns` | Unsigned base 10 `u64` nanosecond timestamp matching the bound validity start |
| `calibration_expires_ns` | Unsigned base 10 `u64` matching the bound exclusive expiry |

`signal_id` is signed as part of the complete event. It must be nonempty, bounded, and free of control characters. It is not transmitter identity, must not contain a person name, and must not be inferred from carrier frequency. Two unrelated emitters can share a carrier. Localization fusion requires exact `signal_id` equality unless an explicit trusted association policy supplies an equivalent grouping.

The three calibration attributes are also signed as part of the event. The timestamps must parse as unsigned base 10 `u64` values and agree numerically with the bound receipt validity window. The hash must match its exact canonical lowercase representation. The tensor and provenance calibration ID plus all three attributes must match the deployment registry in production. They exist as strings because `f32` cannot preserve nanosecond timestamps or cryptographic hashes.

## 9. Direction mathematics

Let:

\[
\mathbf a=\Re\{\widetilde{\mathbf E}\},\qquad
\mathbf b=\Im\{\widetilde{\mathbf E}\}
\]

For a nonlinearly polarized plane wave, a normal to the polarization ellipse is:

\[
\mathbf n=\mathbf a\times\mathbf b
\]

The phasor derived validation axis is:

\[
\widehat{\mathbf k}_{E}=\frac{\mathbf n}{\lVert\mathbf n\rVert}
\]

The cross product axis is invariant to a global phasor phase rotation. It is also invariant to positive amplitude scale after normalization. These are required property tests. It validates the supplied sensor local axis up to sign.

### 9.1 Direction observability

The reference conditioning score is:

\[
q_{\mathrm{axis}}=
\frac{2\lVert\mathbf a\times\mathbf b\rVert}
{\lVert\mathbf a\rVert^2+\lVert\mathbf b\rVert^2}
\]

It lies in `0..1` for valid finite input. It approaches zero for linear polarization and one for equal magnitude orthogonal quadratures. It is a numerical observability score, not a calibrated probability.

For the v1 frame, `abs(ellipticity)` is defined to equal `q_axis`; its sign carries receiver reported handedness under the sensor coordinate convention. The adapter rejects the frame when reported magnitude and phasor derived `q_axis` disagree by more than the configured consistency tolerance.

The adapter must reject frames below its configured phasor observability and reported ellipticity floors. A nonzero cross product alone is insufficient because a nearly linear field can have a numerically nonzero but unstable normal. The exact live floor must be selected using calibration holdout data because the 2025 experiment shows a sharp error increase near linear polarization but does not establish a universal production threshold.

### 9.2 Coordinate transform

Let unit quaternion `q=[x,y,z,w]` define the active sensor to shared frame rotation `R(q)`. The adapter validates the quaternion norm and does not silently repair it. The event tensor remains sensor local:

\[
\widehat{\mathbf k}_{0}=\widehat{\mathbf k}_{sensor},\qquad
\widehat{\mathbf k}_{1}=-\widehat{\mathbf k}_{sensor}
\]

The fusion decoder applies:

\[
\widehat{\mathbf k}_{shared}=R(q)\widehat{\mathbf k}_{0}
\]

If a downstream raw field consumer needs shared frame electric field components, it applies the same rotation independently to the real and imaginary vectors. Translation applies only to the sensor origin. No range or source translation is inferred.

`attributes[\"tensor_frame\"]=\"sensor_local\"` is required as a double rotation guard in every v1 replay bearing event. The typed pose remains canonical.

### 9.3 Supplied vector consistency

The adapter must not trust `k_hat_sensor` blindly. It must:

1. Check that every component is finite.
2. Check that its norm is within configured tolerance of one.
3. Derive the axis from the calibrated complex field when observable.
4. Compute sign invariant disagreement:

\[
e_{\mathrm{axis}}=\cos^{-1}
\left(\left|\widehat{\mathbf k}_{\mathrm{sensor}}
\cdot\widehat{\mathbf k}_{\mathrm{derived}}\right|\right)
\]

5. Reject the frame if disagreement exceeds the receipt bound tolerance.

The absolute value is necessary because the experiment does not resolve sign.

### 9.4 Angular covariance

`angular_covariance_rad2` is a symmetric two dimensional covariance on the tangent plane of candidate zero. The deterministic tangent basis is constructed by choosing reference vector `r=[0,0,1]` when `abs(k_z)<0.9`, otherwise `r=[0,1,0]`, then:

\[
\mathbf t_0=\frac{\mathbf r\times\widehat{\mathbf k}_0}
{\lVert\mathbf r\times\widehat{\mathbf k}_0\rVert},\qquad
\mathbf t_1=\widehat{\mathbf k}_0\times\mathbf t_0
\]

The covariance indices correspond to `t0`, `t1`. A vendor using polar and azimuth covariance must transform it into this basis before constructing `RydbergFrame`. This avoids a pole singularity and gives every consumer the same orientation.

The covariance must satisfy:

1. Finite values.
2. Strictly positive diagonal terms in the v1 reference adapter.
3. Symmetry within numeric tolerance.
4. Positive semidefiniteness within numeric tolerance.

When a vendor exposes Cartesian phasor covariance, the preferred propagation is:

\[
\Sigma_k=J\Sigma_EJ^T
\]

where `J` is the Jacobian of normalized cross product direction with respect to the six real phasor values. An orthonormal tangent basis `B` then gives:

\[
\Sigma_{\theta}=B^T\Sigma_kB
\]

If covariance is empirical rather than propagated, its method, sample count, band, integration time, and calibration holdout split must be recorded in the calibration sidecar.

### 9.5 Error metrics

Before sign resolution, accuracy uses axial angular error:

\[
e_{\mathrm{axial}}=\cos^{-1}
\left(\left|\widehat{\mathbf k}_{\mathrm{pred}}
\cdot\widehat{\mathbf k}_{\mathrm{true}}\right|\right)
\]

After an independent source resolves sign, accuracy uses directed angular error without the absolute value. Reports must state which metric is used.

## 10. Normative invariants

An adapter event is valid only when all applicable invariants pass.

### 10.1 Structural invariants

1. `sensor.modality`, `tensor.modality`, and wire modality all equal `quantum_rf`.
2. Tensor rank, axes, shape, value count, privacy class, and units match the selected output mode.
3. Every numeric input and output is finite.
4. `timestamp_ns` is the integration midpoint, `integration_start >= calibration_created_ns`, and `integration_end < calibration_expires_ns`. An interval ending exactly at expiry is deliberately rejected so `calibration_remaining_s` stays strictly positive, even though the capture interval itself is half open.
5. `calibration_id` is nonempty and identical in the frame, tensor, event provenance, and calibration receipt.
6. Carrier, field strength, integration time, and covariance diagonal values are nonnegative, with carrier and integration time strictly positive.
7. `SensorDescriptor.coordinate_frame`, `position_m`, and `orientation_xyzw` are all present for quantum RF.
8. Coordinate frame and signal ID are nonempty, bounded strings without control characters.
9. Typed position equals the `sensor_x_m`, `sensor_y_m`, and `sensor_z_m` compatibility features after the documented `f64` to `f32` conversion.
10. `calibration_remaining_s` is strictly positive at event construction.
11. Exact signed calibration hash, creation, and expiry attributes match the calibration receipt and the frame validity window.
12. Each typed sensor position component is finite and has absolute magnitude at most `1e6` metres in the declared frame.

### 10.2 Direction invariants

1. `sign_ambiguous` is true for all v1 derived bearings.
2. Both candidate vectors have norm one within the configured tolerance after `f32` conversion. The replay default is `1e-5`.
3. Candidate vectors are antipodal within the configured vector tolerance.
4. Candidate zero equals the validated supplied sensor local axis. Candidate one is its negative.
5. Direction observability clears the configured floor.
6. Supplied and derived axes agree within the configured axial tolerance.
7. No adapter populates range, velocity, or motion from this measurement.
8. `attributes[\"tensor_frame\"]` equals `sensor_local` and fusion rotates candidate zero exactly once.

### 10.3 Quality invariants

1. `ellipticity` lies in `-1..1`; `lock_quality` and `calibration_quality` lie in `0..1`.
2. SNR, lock quality, calibration quality, angular uncertainty, and calibration age clear all configured gates.
3. Phasor derived `q_axis` clears the observability floor and agrees with `abs(ellipticity)` within the configured tolerance.
4. The local to shared quaternion is unit length within the configured tolerance.
5. `quality_valid` is one only after all gates pass.
6. `FieldTensor.confidence` is a bounded quality score, not a probability of correctness.
7. A quality failure yields no fusable event. It must never be converted into a low confidence but otherwise valid looking bearing.

### 10.4 Replay resource invariants

1. A JSONL record is at most 65,536 UTF 8 bytes.
2. One adapter instance accepts at most 100,000 frames.
3. Frame timestamps are globally nondecreasing. Equal timestamps are allowed only for different `signal_id` values.
4. Timestamps are strictly increasing within each `signal_id`.
5. Calibration ID, validity window, pose, coordinate frame, and configured quality contract remain stable inside one replay stream.
6. Carrier is in `0 < carrier_hz <= 1e12`.
7. Integration time is in `0 < integration_ms <= 60000`.
8. SNR and the configured SNR floor are in `-300..300 dB`.
9. `ReplaySource::Captured` requires an explicit signing seed that is neither the public deterministic replay seed nor all zeroes.

### 10.5 Provenance invariants

1. Canonical source frame bytes are SHA 256 hashed before any `f64` to `f32` conversion.
2. The event is Ed25519 signed after tensor and observation construction.
3. Live events set `synthetic=false`, carry signed `evidence_kind=live`, and must pass signature verification plus deployment registry authorization.
4. Analytic replay events set `synthetic=true`, even when signed.
5. Captured replay sets `synthetic=false` only through explicit `ReplaySource::Captured` configuration. The deterministic replay signature attests packaging integrity, not capture hardware authenticity, and the evidence kind remains `captured_replay`, never live.
6. Replay, live, and synthetic states are visible to the consumer and must not be inferred from `SensorDescriptor.placement` alone.
7. Production authorization binds device ID, signer, coordinate frame, typed pose, calibration ID, calibration hash, calibration validity, revocation state, freshness, and a strictly monotonic per device timestamp.

## 11. Confidence and gating

The reference adapter uses hard gates first. Only a frame that passes every hard gate can become an event.

Ellipticity, SNR, covariance, axis agreement, calibration freshness, calibration quality, and optical lock are hard gates. For an accepted replay frame, the v1 confidence is:

\[
c=\min(q_{\mathrm{lock}},q_{\mathrm{cal}})
\]

The other accepted quantities are exposed as signed features instead of being hidden in a composite score. Live adapters may introduce a richer monotonic calibration only under a versioned model identifier and signed configuration. Until a live calibration study is complete, confidence means measurement quality only. It is not a calibrated posterior probability that the bearing points to a source.

The fusion engine must require a separate rule for semantic source bearing. It must not interpret `confidence=0.95` as 95 percent source localization accuracy.

## 12. Calibration model

The Rydberg atom transition can provide a stable physical reference for field amplitude, but the complete vector system still depends on non atomic elements. The 2025 result improved from roughly 60 and 63 mrad to 33 and 43 mrad by applying a direction indexed iterative correction for local oscillator amplitude, phase, and reflections. This makes calibration a first class product dependency.

### 12.1 Calibration sidecar

The generic `CalibrationReceipt` remains the RuField on wire summary. Its `data_hash` binds a modality specific sidecar with at least:

```json
{
  "schema": "rufield.quantum_rf.calibration.v1",
  "calibration_id": "qrf_lab_a_20260712",
  "sensor_device_id": "rydberg_01",
  "created_ns": 1783861200000000000,
  "expires_ns": 1783947600000000000,
  "carrier_ranges_hz": [[6600000000, 6680000000]],
  "world_frame_id": "site_a_enu_v1",
  "sensor_to_world_rotation_xyzw": [0, 0, 0, 1],
  "sensor_position_m": [0, 0, 1.8],
  "sensor_position_covariance_m2": "3x3 matrix",
  "local_oscillator_complex_matrix": "content-addressed artifact",
  "reflection_map": "content-addressed artifact",
  "thresholds": "canonical RydbergQualityThresholds",
  "holdout_manifest_hash": "sha256:...",
  "adapter_build_hash": "sha256:...",
  "operator_key_id": "lab-calibration-key-01"
}
```

Large matrices and calibration maps may be separate content addressed artifacts. Their hashes must be included in the signed sidecar.

The replay reference implementation exposes `calibration_receipt()`. It requires one stable calibration and pose contract across a recording and hashes the device ID, placement, zone, coordinate frame, sensor position, sensor orientation, carrier, calibration quality, calibration ID, half open validity window, and every quality threshold. Its task is `rydberg_vector_calibration_replay`. This content address proves deterministic replay configuration, not hardware calibration authority. A live adapter must replace it with an authority signed sidecar and artifact chain.

Every emitted event copies the receipt `data_hash`, `created_ns`, and `expires_ns` into the exact signed attributes `calibration_data_hash`, `calibration_created_ns`, and `calibration_expires_ns`. Fusion must verify agreement among those attributes, the tensor and provenance calibration IDs, and the applicable deployment registry entry. A hash or time mismatch is a hard rejection, not a confidence penalty.

### 12.2 Required calibration tasks

1. Verify local oscillator amplitude and phase on all three axes.
2. Estimate complex axis leakage and reflection transfer matrices.
3. Calibrate sensor local pose and position against the declared shared frame.
4. Sweep a known source across direction and polarization.
5. Reserve directions, polarizations, and times as a calibration holdout set.
6. Measure angular covariance against integration time and SNR.
7. Record optical lock baselines and recovery behavior.
8. Characterize temperature, mechanical movement, vapor cell replacement, firmware change, and laser relock triggers.
9. Bind every threshold and artifact into a signed receipt.

### 12.3 Calibration validity

Calibration is invalid when any of these occurs:

1. Receipt expiry.
2. Sensor pose or vapor cell changes.
3. Local oscillator, laser, optical, firmware, or adapter configuration changes.
4. Lock reacquisition outside the validated recovery envelope.
5. Temperature or other environment telemetry leaves its validated envelope.
6. Residual checks exceed the receipt bound threshold.
7. A signer or calibration key is revoked.

Until live drift evidence exists, production deployments should use a conservative maximum calibration interval and fail closed. The interval must be measured, not copied from the laboratory paper.

### 12.4 Leakage prevention

The iterative reflection method uses a map indexed by true source direction during calibration. Accuracy must therefore be reported on held out directions and later time windows. Scoring the same grid used to construct the reflection map is calibration leakage, not generalization evidence.

## 13. Provenance and trust

The existing RuField provenance signature proves event integrity under a key. It does not prove that the key belongs to an approved sensor, that the pose is surveyed, or that the calibration is current. Production fusion therefore requires cryptographic verification against an operator managed deployment registry. A bare signer allowlist is insufficient.

The signed chain is:

```text
raw source frame hash
calibration sidecar and artifact hashes
adapter build and threshold hashes
normalized tensor and observation
FieldEvent signature
fused inference supporting event list
```

Each production registry entry binds:

| Registry field | Required comparison |
| --- | --- |
| `device_id` | Exact event sensor device ID |
| `signer_pubkey_hex` | Exact verified Ed25519 signer |
| `coordinate_frame` | Exact typed sensor frame ID |
| `position_m` | Exact canonical typed sensor position |
| `orientation_xyzw` | Exact canonical local to shared quaternion |
| `calibration_id` | Exact tensor and provenance calibration ID |
| `calibration_data_hash` | Exact signed calibration content hash |
| `calibration_created_ns` | Exact signed validity start |
| `calibration_expires_ns` | Exact signed exclusive expiry |
| `revoked` | Must be false |

The registry also supplies a trusted evaluation time, maximum event age, permitted future clock skew, and a mutable high water timestamp per `device_id`. One production signer key may not be enrolled for multiple devices. The trusted time advances in place through `QuantumBearingFusion::advance_live_evaluation_time`; it may never move backward and the operation preserves replay watermarks. Time may advance only between empty geometry windows, after `clear()`, so retained observations cannot silently become stale without reauthorization. Reconstructing a policy to update time is forbidden because doing so would discard those watermarks.

Production authorization is fail closed and ordered:

1. Resolve an existing registry entry by `device_id`. Trust on first use is forbidden.
2. Reject a revoked device or calibration.
3. Strictly verify the event signature, reject weak or small-order Ed25519 public keys, and require the registry signer.
4. Require signed `evidence_kind=live`; replay evidence never enters production fusion.
5. Match coordinate frame and typed pose exactly.
6. Validate the exact canonical calibration hash, parse the signed calibration timestamps as `u64`, and match ID, hash, creation, and expiry to the registry.
7. Require `integration_start >= calibration_created_ns` and the stricter `integration_end < calibration_expires_ns`. Equality at expiry is rejected.
8. Enforce freshness using the trusted current time and reject events older than the configured maximum or farther in the future than allowed clock skew.
9. Require a timestamp strictly greater than the accepted high water mark for the same `device_id`.
10. Advance the high water mark only after the event passes the complete authorization and structural checks.
11. Preserve supporting event IDs and calibration IDs in every fused RuView estimate.

Clearing a fusion geometry window must not clear production replay watermarks. Resetting a device high water mark requires an explicit registry or operational action with an audit record.

Device signing keys and calibration authority keys remain separate. Registry updates provide explicit key rotation, calibration replacement, and revocation. No registry state may be inferred from an incoming event.

The deterministic replay signer is for reproducibility, not a production root of trust.

## 14. Privacy and governance

### 14.1 Classification

| Data | Default class | Reason |
| --- | --- | --- |
| Raw complex electric field or spectrum | `P0` | May expose modulation, emitter fingerprints, and communication activity |
| Antipodal direction, field strength, and quality without identity | `P1` | Derived non identity RF feature |
| Opaque signal ID used only for short lived correlation | `P1` | Signed grouping context, not identity |
| Direction correlated with room occupancy or movement | At least `P2` | Occupancy and behavior context |
| Direction correlated with a named device or person | `P5` | Identity linked inference |

The final inference takes the highest required class from its inputs and semantic use. A P1 bearing does not remain P1 after identity correlation.

### 14.2 Default handling

1. Derived bearing is the default output.
2. Raw output requires an explicit operator setting.
3. Raw P0 data stays edge local, is not persisted by default, and never crosses the default network boundary.
4. Any diagnostic raw retention requires encryption, access control, a bounded time to live, and an audit record.
5. Direction history retention must be purpose limited and documented.
6. Source identity correlation requires an explicit policy and audit trail.
7. The viewer must show output mode, privacy class, evidence label, calibration state, and sign ambiguity.
8. Signal IDs must be opaque, purpose limited, and rotated or expired with the fusion evidence window unless longer retention is justified.

This modality is dual use. Source localization, jammer localization, and spectrum monitoring can create security and export control obligations. Deployment review must address jurisdiction, customer, band, retention, and operator access. This ADR is not legal authorization.

## 15. Security model

| Threat | Failure | Required control |
| --- | --- | --- |
| Forged event | False source axis | Canonical frame hash, strict Ed25519 verification, weak-key rejection, enrolled device registry |
| Timestamp replay | Old bearing presented as current | Trusted clock freshness and per device high water mark |
| Calibration poisoning | Consistently biased direction | Separate calibration authority, signed artifacts, registry hash binding, holdout validation |
| Pose tampering | Correct local vector mapped to wrong world direction | Exact typed pose match against registry and movement trigger |
| Double or missing pose rotation | Wrong shared frame axis | Signed `tensor_frame`, typed quaternion, rotate exactly once |
| Cross signal fusion | Unrelated axes produce a plausible intersection | Exact signed signal ID, full carrier span tolerance, common half open integration overlap |
| Synthetic downgrade | Generated data presented as captured | Explicit evidence label, signed capture manifest, no implicit promotion |
| Malformed JSON or nonfinite number | Panic, NaN propagation, denial of service | Bounded input size, strict deserialization, finite checks |
| Oversized covariance or frequency | Numeric overflow or implausible event | Physical and configuration bounds before conversion to `f32` |
| Optical lock degradation | Precise looking wrong vector | Lock gate and visible health state |
| Multipath or coherent emitter mixture | Vector points at a wall or resultant field | Narrowband isolation, temporal consistency, CIR corroboration, multi sensor validation |
| RF spoofing | Attacker creates a plausible bearing | Treat bearing as signal evidence, not authenticated emitter identity |
| Raw data exfiltration | Communication or emitter leakage | Raw mode off, P0 edge only, least privilege diagnostics |
| Trust on first use signer | Attacker signs internally consistent events | Deployment key registry and revocation |
| Replay signer trusted as hardware | Packaged capture treated as live attestation | Separate replay and device roots, evidence kind gate |
| Stale estimate | Expired calibration result remains actionable | Estimate expiry capped by earliest supporting calibration expiry |

The most dangerous failure is a confidently wrong vector caused by reflections. Cryptography cannot correct physics. Quality gates and fusion policy must treat quantum RF as fallible evidence.

## 16. RuView fusion decision

The adapter terminates at the standard RuField `FieldEvent`, and the reference fusion library preserves both direction candidates. A future evidence-aware RuView integration will consume that event through the normal field ingest boundary. Until the viewer work called out in Section 2.3 and Stage S1 is complete, quantum RF replay remains a library, test, and benchmark path and must not be displayed through the live source.

### 16.1 Sign resolution

One sensor cannot resolve propagation sign from this electric field method. Directed sign may be resolved only with independent evidence such as:

1. A known transmitter location and verified sensor pose.
2. A valid multi sensor line intersection that passes geometry, residual, covariance, and source consistency gates.
3. A credible direct path selected from CIR.
4. Controlled motion of the sensor or transmitter.
5. A protocol pilot whose origin is authenticated and known.

The resolved sign belongs in a new fused inference. The original event is immutable.

### 16.2 Two sensor geometry

Two or more sign ambiguous axes can estimate source position by closest line geometry without first choosing a sign. The line projector:

\[
P=I-\widehat{\mathbf k}\widehat{\mathbf k}^{T}
\]

is identical for `+k` and `-k`. The reference solver minimizes weighted perpendicular distance to all observation lines. It must reject nearly parallel axes because localization covariance grows approximately as:

\[
\sigma_{position}\propto
\frac{\sigma_{angle}\,R}{\sin\alpha}
\]

where `R` is representative range and `alpha` is the intersection angle. Range and uncertainty must not be emitted when geometry is ill conditioned.

The line intersection estimates a position, not authenticated source identity. A directed source vector can be derived from a validated position while the original antipodal events remain immutable.

### 16.3 Reference fusion contract

`QuantumBearingFusion` is a bounded reference implementation with:

1. At most 64 independent sensors in one window.
2. A default maximum timestamp separation of 100 ms plus a common overlap across all integration intervals.
3. One unique event per physical sensor in a window.
4. Exact shared coordinate frame and signal ID equality.
5. A default carrier tolerance of 1 MHz applied to the full group span, so `max(carrier_hz) - min(carrier_hz) <= tolerance`.
6. A minimum sign invariant axis separation of 5 degrees.
7. A minimum surveyed sensor baseline of 0.25 m.
8. A maximum information matrix condition number of `1e8`.
9. Defence in depth floors of `0.05` absolute ellipticity, `0.90` lock quality, and `0.80` calibration quality.
10. A default estimate time to live of 200 ms, capped by the earliest supporting calibration expiry.
11. Production registry authorization, revocation, freshness, and monotonic timestamp enforcement before geometry.
12. Fail closed errors for trust, registry binding, freshness, frame, signal, full carrier span, provenance, calibration, modality, tensors, pose, covariance, timestamp skew, integration overlap, duplicates, capacity, baseline, geometry, and condition number.
13. Constructor validation that rejects nonfinite, negative, zero where forbidden, or out of range fusion thresholds. Configuration must never turn NaN comparisons into a gate bypass.

The solver starts with an unweighted line intersection, then performs two range aware refinements. For observation `i`, its lateral weight is:

\[
w_i=\frac{c_i^2}{\max(R_i,0.1\mathrm{m})^2\lambda_{max,i}}
\]

where `c_i` is adapter quality, `R_i` is estimated sensor to solution distance, and `lambda_max` is the largest angular covariance eigenvalue. The absolute information matrix inverse is inflated by `max(reduced_chi_squared,1)`, so a perfect geometric intersection cannot shrink uncertainty below the stated noise model.

For the v1 replay contract, `timestamp_ns` is the midpoint of the integration interval and `integration_ms` is its full width. After deterministic conversion to nanoseconds, each interval is half open:

\[
I_i=[t_i-\lfloor d_i/2\rfloor,\ t_i+\lceil d_i/2\rceil)
\]

Fusion requires a nonempty common intersection:

\[
\max_i start(I_i) < \min_i end(I_i)
\]

Equality means the intervals only touch and is rejected. Midpoint proximity alone is insufficient because sequential measurements can otherwise appear synchronized. Live adapters using a different hardware timestamp convention must normalize to the midpoint before creating a `FieldEvent`.

Every estimate carries shared coordinate frame, signal ID, representative carrier, P1 privacy class, production and expiry timestamps, `sign_invariant=true`, per sensor calibration IDs, supporting event IDs, residual RMSE, geometry angle, an explicitly uncalibrated `quality_score`, and approximate position covariance. Its expiry is:

\[
expires_{estimate}=\min(produced+ttl,\ \min_i calibration\_expires_i)
\]

An estimate whose computed expiry is not later than its production timestamp is rejected.

The covariance is not yet a calibrated physical uncertainty bound. It omits sensor position uncertainty, calibration correlation, multipath bias, and shared systematic errors. Hardware reports must calibrate its coverage before product use.

Synthetic events are accepted only in an explicit simulation policy and must carry `evidence_kind=synthetic_replay`; this remains a deliberate unsigned test bypass when no replay signature is present. Captured measurements require a separate captured replay policy, a replay signer allowlist, an explicit nondefault signing seed, and signed `evidence_kind=captured_replay`. A production policy requires signed `evidence_kind=live`, rejects both replay states, verifies the event signature, and applies the complete enrolled deployment registry contract from Section 13. Evidence kind is checked only after signature verification for nonsynthetic events.

### 16.4 Fusion policy

RuView may use quantum RF as:

1. A calibration oracle for RF geometry and phase models.
2. A candidate axis for rogue transmitter, interference, spoofing, or jammer localization.
3. A sparse anchor in an RF field digital twin indexed through RuVector.
4. A contradiction signal when CSI, CIR, BFLD, and quantum RF disagree.

RuView must not use it as evidence of a person, pose, vital sign, or identity without a separate governed inference path.

## 17. Implementation stages

### Stage S0: Analytic vectors

Inputs:

1. Known complex phasors generated from direction, polarization, magnitude, global phase, and deterministic noise.
2. Known invalid cases including linear polarization, zero field, NaN, stale calibration, bad lock, and malformed covariance.

Outputs:

1. Property tests for axis derivation and validation.
2. No hardware or accuracy claim.

### Stage S1: Deterministic replay

Inputs:

1. Versioned JSONL `RydbergFrame` fixtures.
2. Explicit source evidence label.
3. Deterministic signing seed used only in tests.

Outputs:

1. Signed P1 derived events by default.
2. Explicit P0 raw mode tests.
3. Deterministic serialized digest and benchmark report.
4. Pending viewer integration: honest `SYNTHETIC` or `RECORDED_REPLAY` state before replay is exposed in RuView.

### Stage S2: Controlled live laboratory adapter

Inputs:

1. Vendor or laboratory receiver API.
2. Traceable source location, polarization, carrier, and sensor pose.
3. Independent timing and angle reference.

Outputs:

1. Live `synthetic=false` signed events.
2. Held out angle, polarization, time, and calibration reports.
3. Latency, update rate, lock loss, and drift measurements.

### Stage S3: Controlled multipath and RuView fusion

Inputs:

1. Reflectors and obstruction scenarios.
2. Co located RuView CSI, CIR, BFLD, RSSI, and quantum RF observations.
3. One and two quantum sensor configurations.

Outputs:

1. Sign resolution accuracy.
2. Localization error and covariance calibration.
3. Baseline versus fused Pareto comparison for error, latency, cost, and false alarm rate.

### Stage S4: Field pilot

Inputs:

1. Signed live hardware in at least three materially different sites.
2. Operational emitters and authorized test sources.
3. Temperature, movement, relock, firmware, and calibration telemetry.

Outputs:

1. Site split results.
2. Eight hour and multi day drift results.
3. Failure rate, maintenance interval, and operator burden.
4. A deployment go or no go decision.

## 18. Benchmarks

### 18.1 Software benchmark

| Metric | Gate |
| --- | ---: |
| Workspace tests | 100 percent pass |
| Deterministic replay digest | Identical across two runs on the same release |
| Valid frame conversion | 100 percent of valid fixture frames |
| Invalid frame rejection | 100 percent of enumerated invalid fixture frames |
| Antipodal invariant | 100 percent |
| Analytic physics property sweep | At least 10,000 deterministic vectors |
| Pose rotation and double rotation guard | 100 percent |
| Frame, signal, carrier, and timestamp grouping rejection | 100 percent |
| Signature verification | 100 percent of emitted frames |
| Production rejection of synthetic or untrusted events | 100 percent |
| Privacy classification | 100 percent |
| Replay conversion latency | p95 below 1 ms per frame on the declared reference host |
| Replay throughput | At least 10,000 frames per second on the declared reference host |
| Provenance coverage | 100 percent |
| Privacy violations | 0 |

Throughput targets measure software headroom only. They say nothing about live hardware update rate.

These are normative acceptance gates, not claims about live hardware. The implementation includes `quantum_rf_properties.rs`, which exercises 10,000 deterministic analytic vectors plus covariance consistency, and `quantum_rf_performance.rs`, which executes three release trials over 10,000 signed frame conversions. The performance test fails below the throughput gate or at and above the latency gate. Its log declares operating system, architecture, build profile, frame count, trial count, measured median frames per second, and the median of the per trial p95 conversion latencies. The CI or PR log for the tested revision is the measured receipt; a transient result from one development machine is not part of the normative threshold.

### 18.2 Controlled laboratory benchmark

Every gate in this section is pending hardware evidence. RuField contains no live Rydberg capture or hardware adapter. The initial product gate is intentionally close to, but not presented as a reproduction of, the 2025 laboratory result.

| Metric | Gate |
| --- | ---: |
| Median axial angular error | At most 3 degrees |
| p95 axial angular error | At most 7 degrees |
| Valid solid angle coverage | At least 80 percent of the declared test grid |
| Near linear frame rejection | At least 99 percent |
| False valid rate for degenerate frames | At most 1 percent |
| Sustained live update rate | At least 20 accepted events per second |
| Adapter processing latency | p95 below 5 ms, excluding sensor integration time |
| End to end RuField latency | p95 below 100 ms |
| Angular covariance coverage | 95 percent interval contains at least 90 percent and at most 99 percent of held out errors |
| Provenance coverage | 100 percent |
| Calibration holdout | No test direction used to fit the reflection map |

Every report must include carrier, field amplitude, ellipticity distribution, SNR, integration time, cell geometry, environment, source grid, sample count, and calibration method.

### 18.3 RuView fusion benchmark

Compare three systems on the same timestamp aligned test trajectories:

1. RuView CSI plus CIR plus BFLD baseline.
2. Quantum RF alone.
3. RuView baseline plus quantum RF.

Report a Pareto surface across localization RMSE, p95 error, false bearings per hour, end to end latency, calibration minutes per day, hardware cost, and energy. The fused system advances only if:

1. Localization RMSE is at least 30 percent lower than the best non quantum RuView baseline.
2. p95 localization error improves.
3. False bearing rate does not increase by more than 10 percent.
4. Added p95 latency is below 20 ms after sensor integration.
5. The gain survives site held out evaluation.

If the quantum sensor improves median error but worsens the tail, it does not pass.

## 19. Failure modes and required behavior

| Failure mode | Detection | Behavior |
| --- | --- | --- |
| Pure or near linear polarization | Low observability and ellipticity | Reject before event construction |
| Reported ellipticity disagrees with phasor | q axis consistency gate | Reject |
| Zero or nonfinite electric field | Finite and norm checks | Reject |
| Bad `k_hat_sensor` norm | Norm tolerance | Reject |
| Supplied vector disagrees with phasor | Axial consistency error | Reject |
| Sign unresolved | Physics contract | Emit both candidates |
| Calibration expired | Timestamp interval | Reject |
| Calibration ID mismatch | Cross object invariant | Reject |
| Poor optical lock | Lock threshold | Reject |
| Poor SNR | SNR threshold | Reject |
| Invalid covariance | Symmetry and positive semidefinite checks | Reject |
| Sensor moved | Pose or movement trigger | Invalidate calibration |
| Missing or nonunit orientation | Typed pose validation | Reject |
| Coordinate frame mismatch | Exact frame comparison | Reject fusion group |
| Signal or carrier mismatch | Signed signal ID and full min to max carrier span tolerance | Reject fusion group |
| Integration intervals only touch or do not overlap | Half open common intersection test | Reject fusion group |
| Registry pose, calibration, freshness, or revocation mismatch | Deployment enrollment check | Reject before geometry |
| Multipath reflection | Cross modality contradiction or controlled validation | Downweight or reject fused source bearing, preserve raw evidence |
| Multiple coherent paths | Spectral and temporal inconsistency, when available | Do not claim single source direction |
| Nearly parallel triangulation | Small intersection angle | No range or position output |
| Insufficient baseline or ill conditioned matrix | Baseline and condition gates | No position output |
| Raw output accidentally enabled | Policy check | Deny network transmission and audit |
| Unknown signer | Trust policy | Reject from fusion |
| Replay presented as live | Evidence label and capture receipt | Reject live claim |

Some multipath and multi emitter cases are not identifiable from one complex phasor. The correct response is explicit uncertainty or no inference, not a stronger model claim.

## 20. Rollout and compatibility

### 20.1 Feature rollout

1. Merge core registry and axis support with round trip tests.
2. Merge the replay adapter behind a quantum RF feature boundary if optional dependencies are introduced.
3. Ship only analytic fixtures in the repository unless a captured dataset has explicit redistribution permission.
4. Add viewer labels for modality, evidence state, output mode, calibration, lock, uncertainty, and sign ambiguity before routing any quantum RF replay through the viewer.
5. Keep quantum RF out of safety or occupancy rules by default.
6. Add a live adapter only after an API contract, hardware access, calibration authority, and deployment registry are available.
7. Promote to field use only after the S2 and S3 gates pass with signed reports.
8. Keep the implemented workspace crate and internal dependency versions at 0.2.0 for this source breaking API change.

### 20.2 Rust compatibility

`Modality` and `FieldAxis` are currently exhaustive public enums. Adding variants can break downstream exhaustive matches even though the wire change is additive. `SensorDescriptor` gains optional coordinate frame, position, and orientation fields. `Observation` gains a string attribute map. Existing external Rust struct literals must add these fields or use constructors. `SensorDescriptor` also loses `Eq` because its typed pose uses `f32`. Any downstream `Eq` bound is a source compatibility break.

This is a source breaking pre 1.0 change. The implementation has therefore bumped the workspace package version, `rufield-core`, every dependent RuField crate, and their internal dependency requirements to 0.2.0. Release notes must call out the enum additions, new pose and attribute fields, and loss of `Eq` on `SensorDescriptor`.

Before the next registry extension, decide whether to mark public registries `non_exhaustive` or provide stable numeric wrapper types. That is a separate compatibility decision and must not be slipped into this change without review.

### 20.3 Wire compatibility

Existing codes 1 through 15 are unchanged. Code 16 is additive. New pose fields and observation attributes use Serde defaults and are omitted when absent, so legacy JSON remains readable. Older consumers that do not recognize `quantum_rf` must reject or quarantine the event, not reinterpret it. Crate version 0.2.0 and wire version `rufield.mfs.v0.1` are deliberately independent: the Rust API is source breaking while this wire extension remains additive.

### 20.4 Rollback

Rollback disables quantum RF ingest and removes it from fusion rules. Existing signed events remain readable by aware consumers. Numeric code 16 remains permanently reserved even if the adapter is withdrawn.

## 21. Cost and deployment assumptions

The reference replay implementation adds negligible marginal runtime cost relative to RF sensor integration. The main cost is hardware access, calibration labor, and optical system operations.

A planning range for a partner laboratory proof is USD 100,000 to USD 250,000 over 8 to 12 weeks when hardware is loaned or partner supplied. This is a budgeting assumption, not a public vendor quote. It includes integration, fixtures, source control, calibration, data capture, and engineering time.

The commercially preferred topology is one portable or sparse quantum RF anchor supporting many inexpensive RuView nodes. A quantum receiver in every room is rejected until price, maintenance, SWaP, update rate, and incremental accuracy justify it.

The business metric is cost per accepted reduction in localization error, not whether a quantum component is present.

## 22. Decision matrix

Scores use `1=poor` and `5=strong`. Risk is reverse scored, where 5 means lower delivery risk.

| Option | Physics honesty | RuField interoperability | Build now | Vendor independence | Delivery risk | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Vendor specific direct RuView plugin | 3 | 2 | 2 | 1 | 2 | 10 |
| Overload `quantum_magnetic` | 1 | 2 | 4 | 4 | 2 | 13 |
| Store one resolved direction vector | 1 | 4 | 5 | 5 | 2 | 17 |
| Store raw phasor only | 4 | 3 | 4 | 5 | 3 | 19 |
| New modality plus raw and antipodal derived contracts | 5 | 5 | 4 | 5 | 4 | 23 |

Decision: new modality plus raw and antipodal derived contracts.

## 23. Rejected alternatives

### 23.1 Reuse `QuantumMagnetic`

Rejected because a Rydberg RF electrometer measures electric field with different units, calibration, tensors, and failure modes.

### 23.2 Add a generic direction field to `Observation`

Rejected for v1 because it changes a common public struct, creates coordinate ambiguity for all modalities, and does not naturally preserve the antipodal pair. A future general direction type may be justified by several modalities.

### 23.3 Emit one chosen direction

Rejected because the single point electric field method determines the axis only up to sign. Silent selection manufactures information.

### 23.4 Store polar and azimuth angles only

Rejected because angle pairs have coordinate singularities, wraparound, and frame ambiguity. Unit vectors are easier to validate and fuse. UIs can derive angles.

### 23.5 Infer distance from field strength

Rejected because transmitter power, radiation pattern, absorption, near field behavior, and multipath are unknown.

### 23.6 Treat every replay as synthetic

Rejected as a universal rule because a signed captured hardware replay is real measured data, although it is not live. Evidence label and capture provenance must distinguish analytic, captured replay, and live states.

### 23.7 Treat a valid signature as trusted provenance

Rejected because an attacker can sign with an untrusted key. Deployment trust and revocation are required.

### 23.8 Deploy quantum hardware per room

Rejected for the initial product because public price, power, maintenance, API, and field performance are not established. Sparse anchors maximize information value per dollar.

### 23.9 Use synthetic accuracy as product evidence

Rejected. Synthetic vectors validate mathematics and code only.

## 24. Consequences

Positive consequences:

1. RuField gains a physically honest grammar for Rydberg RF vector sensing.
2. RuView can consume a quantum modality without vendor lock in.
3. Sign ambiguity, calibration, and provenance become visible data rather than tribal knowledge.
4. Replay first development can validate most software before expensive hardware access.
5. Sparse quantum anchors create a credible product path for calibration and spectrum intelligence.

Negative consequences:

1. Public enum variants create a pre 1.0 Rust compatibility event.
2. `FieldEvent` now has typed pose and authenticated string attributes, but tensor units and evidence kind remain convention based rather than closed enums.
3. `Observation.features` stores `f32`, so GHz carrier frequency loses sub kilohertz precision. This is acceptable for initial bearing fusion but not precision metrology.
4. Direction dependent calibration can be expensive and vulnerable to leakage.
5. Multipath can produce precise but wrong source bearings.
6. Real hardware integration may expose a vendor API mismatch that requires an additional adapter layer.

## 25. Follow up decisions

1. Decide whether MFS v0.2 adds first class units, evidence state, sequence number, and source kind.
2. Decide a stable extension policy for public modality and axis registries.
3. Select a hardware partner and obtain API, price, power, update rate, and export constraints under appropriate terms.
4. Define a reusable signed capture manifest shared by CSI replay and quantum RF replay.
5. Define a RuView bearing and triangulation inference type with covariance and explicit sign resolution evidence.
6. Determine whether raw phasor covariance needs a dedicated tensor or content addressed sidecar.

## 26. Acceptance tests

### 26.1 Software acceptance

```text
Given a valid calibrated RydbergFrame with an elliptically polarized field
When RydbergReplayAdapter emits DerivedBearing
Then the event modality is quantum_rf with code 16
And the tensor axes are [direction_candidate, cartesian_component]
And the tensor shape is [2, 3]
And both rows are finite unit vectors
And the second row is the negative of the first
And the tensor remains sensor local
And tensor_frame equals sensor_local
And typed coordinate frame, position, and orientation are present
And sign_ambiguous equals true
And signal_id is nonempty and signed
And calibration_data_hash, calibration_created_ns, and calibration_expires_ns are exact and signed
And privacy class equals P1
And range, velocity, and motion are absent
And the raw frame hash covers the canonical f64 input
And the event signature verifies
And all calibration identifiers agree
And calibration_receipt data_hash binds pose, validity, and thresholds
```

```text
Given a captured replay configuration
When its signer seed is the public deterministic replay seed or all zeroes
Then adapter construction fails
And no captured event is emitted
```

```text
Given a multi-signal replay stream
When timestamps are globally nondecreasing and strictly increasing per signal_id
Then equal timestamps across different signal_id values are accepted
But a global decrease or a repeated timestamp for the same signal_id is rejected
```

```text
Given the same valid frame
When RawElectricField is explicitly selected
Then the tensor axes are [cartesian_component, complex_component]
And the tensor shape is [3, 2]
And the values preserve x, y, z and real, imaginary order
And tensor and observation privacy classes equal P0
And the event label describes a complex field, not a bearing
And default network transmission is denied
```

```text
Given a zero field, linear polarization, inconsistent reported ellipticity,
nonunit orientation, invalid frame or signal id, nonfinite value, malformed covariance,
expired calibration, calibration mismatch, poor lock, poor SNR, or inconsistent k_hat_sensor
When the adapter processes the frame
Then it returns a typed error
And emits no FieldEvent
And produces no fusable inference
And an integration interval ending exactly at calibration expiry is also rejected
```

### 26.2 Physics property acceptance

This gate is implemented by `crates/rufield-adapters/tests/quantum_rf_properties.rs`. It deterministically enumerates 10,000 directions, amplitudes, axial ratios, and global phases, so it has no random seed. The executable test revision and its generation constants define the configuration.

```text
Given 10,000 deterministically generated analytic complex field vectors
When each vector is multiplied by a positive amplitude and arbitrary global phase
Then its normalized derived axial direction has dot product greater than 1 minus 1e-10 with ground truth
And its computed ellipticity agrees with the analytic value within 1e-12
And every configured degenerate vector is rejected
```

```text
Given two or more signed bearings with distinct sensors
When their coordinate frame and signal id match
And the full carrier span is within tolerance
And their half open integration intervals have a nonempty common overlap
And time, baseline, geometry, and condition gates pass
Then fusion rotates each sensor local axis exactly once
And returns a sign invariant P1 position estimate
And includes covariance, quality score, expiry, calibration ids, and supporting events
And estimate expiry does not exceed the earliest supporting calibration expiry
But touching integration intervals, frame mismatch, signal mismatch, full-span carrier mismatch,
stale or nonmonotonic timestamps, revoked enrollment, untrusted signer,
calibration registry mismatch, or synthetic production evidence fail closed
```

### 26.3 Software performance acceptance

This gate is implemented by `crates/rufield-adapters/tests/quantum_rf_performance.rs`. It is executable in an optimized release build. CI or PR output is the revision bound measured receipt and must be retained with the acceptance decision.

```text
Given the declared release build and reference host
When three trials of 10,000 valid replay frames are converted and signed after warmup
Then the median of the three per trial p95 conversion latencies is below 1 ms per frame
And median trial throughput is at least 10,000 frames per second
And the log records operating system, architecture, build profile, frame count, trial count, measured median p95, and measured median throughput
```

### 26.4 Hardware acceptance

Hardware status remains pending until a signed report shows:

1. Median axial error at most 3 degrees.
2. p95 axial error at most 7 degrees.
3. At least 20 accepted live events per second.
4. At least 99 percent rejection of declared near linear frames.
5. Held out directions, polarizations, and time windows.
6. End to end p95 latency below 100 ms.
7. One hundred percent trusted provenance coverage.
8. Zero raw P0 network transmissions under default policy.

### 26.5 RuView product acceptance

The integration is accepted for product rollout only when the fused system reduces localization RMSE by at least 30 percent against the best CSI plus CIR plus BFLD baseline on site held out data, improves p95 error, and does not increase false bearings by more than 10 percent.

That is the decisive acceptance test. A laboratory bearing demo alone is insufficient.
