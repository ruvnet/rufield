import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const REQUIRED_RECORD_FIELDS = [
  "sample_id",
  "room_id",
  "device_id",
  "capture_day",
  "session_id",
  "domain_id",
  "modality",
  "source_profile",
  "evidence_origin",
  "ground_truth_positive",
  "predicted_probability",
  "abstained",
  "latency_ms",
  "provenance_verified",
  "privacy_violation",
  "negative_session_exposure_seconds",
];

const ORIGINS = new Set(["simulation", "captured_replay", "live_capture"]);

function validCaptureDay(value) {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(value ?? ""));
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (year === 0 || month < 1 || month > 12) return false;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day >= 1 && day <= days[month - 1];
}

export function inspectManifest(manifest) {
  const structuralErrors = [];
  if (manifest.schema_version !== "rufield.evidence.v1") {
    structuralErrors.push("unsupported evidence schema");
  }
  for (const field of [
    "dataset_id",
    "task",
    "evidence_bundle_uri",
    "evidence_bundle_digest",
    "collection_kind",
  ]) {
    if (typeof manifest[field] !== "string" || manifest[field].length === 0) {
      structuralErrors.push(`missing ${field}`);
    }
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(String(manifest.evidence_bundle_digest ?? ""))) {
    structuralErrors.push("evidence_bundle_digest must be lowercase sha256");
  }
  if (!Array.isArray(manifest.records) || manifest.records.length === 0) {
    structuralErrors.push("records must be a nonempty array");
  }

  const ids = new Set();
  for (const [index, record] of (manifest.records ?? []).entries()) {
    for (const field of REQUIRED_RECORD_FIELDS) {
      if (!(field in record)) structuralErrors.push(`record ${index} missing ${field}`);
    }
    if (ids.has(record.sample_id)) structuralErrors.push(`duplicate ${record.sample_id}`);
    ids.add(record.sample_id);
    if (!ORIGINS.has(record.evidence_origin)) {
      structuralErrors.push(`record ${index} has unknown evidence_origin`);
    }
    if (!validCaptureDay(record.capture_day)) {
      structuralErrors.push(`record ${index} has invalid capture_day`);
    }
  }

  const physicalRecords = (manifest.records ?? []).filter(
    record => record.evidence_origin !== "simulation",
  ).length;
  const rejectionCodes = [];
  if (manifest.fixture === true) rejectionCodes.push("fixture_dataset");
  if (String(manifest.evidence_bundle_uri ?? "").trim().toLowerCase().startsWith("fixture:")) {
    rejectionCodes.push("external_evidence_missing");
  }
  if (physicalRecords === 0) rejectionCodes.push("synthetic_only");
  const hasExternalArtifact = [
    [manifest.split_assignment_uri, manifest.split_assignment_digest],
    [manifest.model_lineage_uri, manifest.model_lineage_digest],
  ].some(
    ([uri, digest]) =>
      typeof uri === "string" &&
      uri.trim().length > 0 &&
      !uri.trim().toLowerCase().startsWith("fixture:") &&
      /^sha256:[0-9a-f]{64}$/.test(String(digest ?? "")),
  );
  if (!hasExternalArtifact) rejectionCodes.push("training_isolation_evidence_missing");

  return {
    policyId: "rufield.promotion.v1",
    structurallyValid: structuralErrors.length === 0,
    structuralErrors,
    physicalRecords,
    simulationRecords: (manifest.records ?? []).length - physicalRecords,
    rejectionCodes,
  };
}

function main(argv) {
  const path = argv[0];
  const expectRejected = argv.includes("--expect-rejected");
  if (!path) {
    process.stderr.write("usage: node harness/evidence-gate.mjs <manifest> [--expect-rejected]\n");
    return 2;
  }
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    process.stderr.write(`cannot parse evidence manifest: ${error.message}\n`);
    return 2;
  }
  const result = inspectManifest(manifest);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.structurallyValid) return 2;
  if (expectRejected) {
    const required = [
      "fixture_dataset",
      "external_evidence_missing",
      "synthetic_only",
      "training_isolation_evidence_missing",
    ];
    return required.every(code => result.rejectionCodes.includes(code)) ? 0 : 1;
  }
  process.stderr.write(
    "Node fallback validates schema and rejection fixtures only. Run the Rust evidence gate for promotion.\n",
  );
  return 1;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main(process.argv.slice(2));
}
