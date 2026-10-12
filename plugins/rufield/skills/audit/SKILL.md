---
name: audit
description: Audit RuField tests, trust boundaries, privacy projections, and evidence promotion. Use for conformance review, security regression review, release validation, or checking whether field accuracy claims have support.
---

# Audit RuField conformance

1. Locate the RuField checkout. Read `harness/run-evidence-gate.sh`, ADR 261 trust policy, ADR 266 evidence promotion, and ADR 267 composite privacy. Inspect the current diff. Default to assessment; apply fixes only when remediation is requested.
2. Run `python3 scripts/validate-plugin.py` when present. Run `sh harness/run-evidence-gate.sh` for the complete format, Rust test, Clippy, and Node evidence gate suite. Record failures accurately. Cargo unavailable is a failed gate, not a pass. Never set internal probe or forced-unavailable environment variables to bypass validation.
3. Check invariants: independently enrolled signer keys; sensor/key binding; rejection of revoked, synthetic, stale, future, tampered, or replayed events as required by the selected policy; verification before state mutation; P0 local only; P4 consent and P5 identity requirements; redaction before public live broadcasts; no automatic synthetic fallback under a LIVE banner.
4. Distinguish conformance from physical evidence promotion. For promotion, require the actual manifest, materialized evidence bundle, exact evaluated model bytes, an independently supplied authority registry, and exactly one split artifact or model lineage artifact. Use the arguments declared in `crates/rufield-bench/src/main.rs`. Do not create a passing registry from keys in the evidence, substitute fixture artifacts, or report synthetic benchmark scores as real world accuracy.
5. For each finding provide affected path, reproducer, impact, and a minimal fix. If authorized, add a regression that fails before the fix, then rerun the affected suite and required gate. Do not publish, deploy, merge, or alter credentials as part of an audit unless requested.

Acceptance: required gates exit zero, rejected evidence stays rejected, and the report states whether physical promotion was attempted and supported.
