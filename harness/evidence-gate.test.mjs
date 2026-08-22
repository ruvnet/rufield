import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { inspectManifest } from "./evidence-gate.mjs";

const fixture = JSON.parse(
  readFileSync(new URL("../fixtures/evidence/synthetic-only.json", import.meta.url), "utf8"),
);

test("simulation fixture is structurally valid but never promotable", () => {
  const result = inspectManifest(fixture);
  assert.equal(result.structurallyValid, true);
  assert.equal(result.policyId, "rufield.promotion.v1");
  assert.equal("artifactReceipt" in result, false);
  assert.equal(result.physicalRecords, 0);
  assert.deepEqual(result.rejectionCodes, [
    "fixture_dataset",
    "external_evidence_missing",
    "synthetic_only",
    "training_isolation_evidence_missing",
  ]);
});

test("captured replay and simulation remain distinct origins", () => {
  const copy = structuredClone(fixture);
  copy.records[0].evidence_origin = "captured_replay";
  const result = inspectManifest(copy);
  assert.equal(result.physicalRecords, 1);
  assert.equal(result.simulationRecords, 5);
});

test("duplicate sample identities fail structural validation", () => {
  const copy = structuredClone(fixture);
  copy.records[1].sample_id = copy.records[0].sample_id;
  const result = inspectManifest(copy);
  assert.equal(result.structurallyValid, false);
  assert.match(result.structuralErrors.join("\n"), /duplicate/);
});

test("empty external artifact URI never satisfies isolation evidence", () => {
  const copy = structuredClone(fixture);
  copy.split_assignment_uri = "   ";
  copy.split_assignment_digest = `sha256:${"a".repeat(64)}`;
  const result = inspectManifest(copy);
  assert.ok(result.rejectionCodes.includes("training_isolation_evidence_missing"));
});

test("capture day must be a real fixed width Gregorian date", () => {
  const copy = structuredClone(fixture);
  copy.records[0].capture_day = "2026-02-30";
  const result = inspectManifest(copy);
  assert.equal(result.structurallyValid, false);
  assert.match(result.structuralErrors.join("\n"), /capture_day/);
});

test("uppercase digest bypass is rejected", () => {
  const copy = structuredClone(fixture);
  copy.evidence_bundle_digest = copy.evidence_bundle_digest.toUpperCase();
  const result = inspectManifest(copy);
  assert.equal(result.structurallyValid, false);
  assert.match(result.structuralErrors.join("\n"), /lowercase sha256/);
});
