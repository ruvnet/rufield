# ADR 266: Physical evidence manifests and leakage resistant promotion

Status: Accepted

Date: 2026-08-21

## Context

The v0.1 benchmark is deterministic and useful for pipeline conformance, but its labels and measurements come from the same simulator. Synthetic scores cannot establish field accuracy. Random row splits also overstate performance when samples from the same room, device, day, session, or participant occur in both training and evaluation.

## Decision

Add `rufield.evidence.v1`, an explicit manifest with one origin on every record: `simulation`, `captured_replay`, or `live_capture`. Captured replay means bytes captured from physical hardware and processed offline. It is not simulation.

Promotion computes metrics from physical records only. If no physical record exists, simulation metrics may be emitted for diagnostics but promotion fails. Repository fixtures set `fixture: true`, use a `fixture:` bundle URI, and can never promote.

Generate independent deterministic held out protocols for room, device, day, session, and participant. Each grouping key maps to one fold within its protocol. These assignments prevent fold overlap. They do not prove that a training job respected the assignment. Promotion therefore also requires either an immutable external split artifact or immutable model lineage artifact with a SHA256 digest.

For hybrid manifests, promotion constructs and counts folds from physical records only. Simulation rows remain available for diagnostics but cannot supply diversity or represented folds to a physical evidence decision.

The MetaHarness entry point is `sh harness/run-evidence-gate.sh`. It runs Node conformance checks everywhere. A complete gate always requires Cargo and fails when the Rust toolchain is unavailable. With Cargo it runs formatting, all workspace tests, Clippy with warnings denied, and the Rust promotion gate when `RUFIELD_EVIDENCE_MANIFEST` is supplied. `RUFIELD_REQUIRE_PROMOTION=1` also fails when the external manifest is absent.

A URI and digest are self assertions until bytes are checked. The CLI therefore requires local paths to the materialized evidence bundle, evaluated model, either the split assignment or model lineage artifact, and a separately provisioned evidence authority registry. It never fetches remote URIs.

Opaque bytes are not evidence. The bundle, split assignment, model lineage, attestation, and authority registry each use a strict versioned JSON schema with unknown fields denied. The bundle binds dataset, task, model digest, canonical manifest digest, exact ordered sample coverage, and the canonical digest of every record. Split artifacts contain exactly the five leakage axes with exact physical sample coverage and leakage validation. Model lineage names exactly the held out physical samples and binds nonempty immutable training material. The evaluated model digest is observed from local model bytes rather than trusted as a string.

An Ed25519 evidence authority signs the canonical bundle and isolation binding. The verifier resolves its public key only from the caller supplied registry, rejects unknown or revoked authorities, and does not accept a key embedded by the evidence producer as its own trust anchor. Signed split represented fold counts are retained and evaluated against the exact promotion policy, including custom policies.

Every JSON decision embeds policy schema identifier `rufield.promotion.v1` and a complete copy of the evaluated thresholds. A verified decision additionally embeds authority identity, the observed model digest, canonical manifest digest, observed bundle digest, isolation kind, observed isolation digest, and signed split fold evidence when applicable. An unverified or mismatched path omits that artifact receipt.

Artifact verification proves governed byte integrity, coverage consistency, evaluated model binding, training isolation evidence, and authority attestation. It does not prove scientific truth, label quality, experimental validity, or empirical authenticity. `evidence_origin` and `provenance_verified` remain assertions unless a deployment separately verifies signed capture receipts against an independently governed device trust store.

## Inputs

1. Immutable evidence bundle URI and SHA256 digest.
2. Task labels, probabilities, abstentions, latency, provenance result, privacy result, and negative session monitoring exposure.
3. Room, device, UTC day, session, participant, domain, modality, and source profile identifiers.
4. Immutable external split assignment or model lineage URI and SHA256 digest.
5. Local materializations of the evidence bundle, selected isolation artifact, and exact evaluated model bytes.
6. A caller supplied authority registry containing trusted and revoked Ed25519 identities.

## Outputs

1. Five deterministic leakage checked split plans.
2. F1, AUROC, expected calibration error, selective risk, false alarms per hour, p95 latency, provenance coverage, privacy violations, and cross domain degradation.
3. A stable JSON promotion decision containing every failed invariant, the exact policy, and verified artifact lineage when available.

## Assumptions

1. Ground truth is independently collected and its limitations are recorded.
2. Participant identifiers are pseudonymous and stable only within the governed study.
3. Negative exposure represents monitored session time, not the number of sampled rows. It is validated for consistency and counted once per session and domain.
4. Release automation materializes remote artifacts and model bytes; the RuField CLI verifies them before promotion.
5. Registry distribution and revocation are controlled independently of evidence producers.
6. A production promotion authority independently verifies signed capture receipts and origin claims.

## Promotion gates

1. At least 100,000 physical records.
2. At least three rooms, three devices, three days, three sessions, three participants, and three reporting domains.
3. F1 at least 0.80 and AUROC at least 0.85. Both must pass.
4. Expected calibration error at most 0.05.
5. Selective risk at most 0.10 with at least 50 percent accepted predictions.
6. At most one false alarm per negative monitoring hour.
7. p95 latency at most 100 milliseconds.
8. Verified provenance coverage of 100 percent and zero privacy violations.
9. At least three evaluable domains, each containing positive and negative truth, with overall to worst domain F1 degradation at most 0.10.
10. At least two represented folds in every leakage protocol.
11. A nonfixture external bundle plus immutable split or model lineage evidence.
12. SHA256 verification of actual local bundle, isolation, and evaluated model bytes.
13. Strict schema, exact sample and record digest coverage, model binding, and training material validation.
14. Valid Ed25519 attestation from a known nonrevoked authority in the caller supplied registry.
15. A receipt that embeds the exact promotion policy and verified authority, model, artifact, and split lineage.

## Alternatives considered

1. Keep the synthetic benchmark as a release gate. Rejected because it proves implementation consistency, not sensing accuracy.
2. Use random row splits. Rejected because temporal and identity correlation leaks across folds.
3. Use one joint connected component split across every key. Rejected because normal movement of devices or participants can collapse the entire dataset into one component.
4. Accept a manually reviewed report. Rejected because promotion thresholds must be reproducible and machine evaluated.

## Migration

The existing seeded `rufield-bench` command remains unchanged. Field programs add a separate manifest and invoke the `evidence-gate` subcommand. No existing report or public Rust type is removed.

## Rollback

Remove the evidence modules and harness without changing existing simulator, fusion, provenance, or viewer behavior. Previously generated promotion receipts remain independently readable JSON.

## Acceptance

The bundled six record conformance fixture must parse, generate five leakage clean protocols, and fail with `fixture_dataset`, `external_evidence_missing`, `synthetic_only`, `training_isolation_evidence_missing`, and `artifact_bytes_unverified`. Arbitrary bytes, unknown fields, bad signatures, unknown or revoked authorities, sample coverage changes, record digest changes, model mismatches, uppercase digest bypasses, and missing evaluated model bytes must fail closed. Hybrid simulation rows must not satisfy physical fold coverage. A custom policy must evaluate represented folds from the signed split artifact. Every decision exposes exact policy values, while artifact lineage appears only after full governance verification.
