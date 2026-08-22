#!/usr/bin/env sh
set -eu

if [ "${RUFIELD_INTERNAL_STRICT_PROBE:-0}" = "1" ]; then
  if [ "${RUFIELD_FORCE_CARGO_UNAVAILABLE:-0}" = "1" ]; then
    exit 1
  fi
  exit 0
fi

node --test harness/evidence-gate.test.mjs harness/strict-mode.test.mjs
node harness/evidence-gate.mjs fixtures/evidence/synthetic-only.json --expect-rejected

if [ "${RUFIELD_FORCE_CARGO_UNAVAILABLE:-0}" != "1" ] && command -v cargo >/dev/null 2>&1; then
  cargo fmt --all -- --check
  cargo test --workspace --all-targets --locked
  cargo clippy --workspace --all-targets --locked -- -D warnings

  if [ -n "${RUFIELD_EVIDENCE_MANIFEST:-}" ]; then
    if [ -z "${RUFIELD_EVIDENCE_BUNDLE:-}" ]; then
      echo "RUFIELD_EVIDENCE_BUNDLE must point to materialized evidence bytes" >&2
      exit 1
    fi
    if [ -z "${RUFIELD_AUTHORITY_REGISTRY:-}" ]; then
      echo "RUFIELD_AUTHORITY_REGISTRY must point to an independently supplied trust registry" >&2
      exit 1
    fi
    if [ -z "${RUFIELD_EVALUATED_MODEL:-}" ]; then
      echo "RUFIELD_EVALUATED_MODEL must point to the exact evaluated model bytes" >&2
      exit 1
    fi
    set -- evidence-gate "$RUFIELD_EVIDENCE_MANIFEST" --evidence-bundle "$RUFIELD_EVIDENCE_BUNDLE" --evaluated-model "$RUFIELD_EVALUATED_MODEL" --authority-registry "$RUFIELD_AUTHORITY_REGISTRY" --json
    if [ -n "${RUFIELD_SPLIT_ARTIFACT:-}" ] && [ -n "${RUFIELD_MODEL_LINEAGE:-}" ]; then
      echo "Provide one isolation artifact, not both" >&2
      exit 1
    elif [ -n "${RUFIELD_SPLIT_ARTIFACT:-}" ]; then
      set -- "$@" --split-artifact "$RUFIELD_SPLIT_ARTIFACT"
    elif [ -n "${RUFIELD_MODEL_LINEAGE:-}" ]; then
      set -- "$@" --model-lineage "$RUFIELD_MODEL_LINEAGE"
    else
      echo "RUFIELD_SPLIT_ARTIFACT or RUFIELD_MODEL_LINEAGE is required" >&2
      exit 1
    fi
    cargo run -p rufield-bench --locked -- "$@"
  elif [ "${RUFIELD_REQUIRE_PROMOTION:-0}" = "1" ]; then
    echo "RUFIELD_EVIDENCE_MANIFEST is required for promotion" >&2
    exit 1
  else
    echo "Conformance passed. Physical evidence promotion was not attempted."
  fi
else
  echo "Cargo unavailable. Rust format, test, lint, and promotion checks were not run."
  echo "The evidence harness fails closed without the Rust gate." >&2
  exit 1
fi
