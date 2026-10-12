---
name: demo
description: Run and explain the RuField deterministic synthetic benchmark and local sensing dashboard. Use for a RuField demo, quickstart, benchmark baseline, or viewer smoke test.
---

# Run a RuField demo

1. Locate the user's RuField checkout, then read its `Cargo.toml` and `README.md`. Confirm `crates/rufield-bench` and `crates/rufield-viewer` exist. The plugin installation directory is not the source checkout. If no checkout exists, ask for its path or clone `https://github.com/ruvnet/rufield` into a new directory only when requested. Never overwrite an existing checkout.
2. From that checkout run `cargo run --locked -p rufield-bench -- 2026 --json` and `cargo test --locked -p rufield-bench`. Preserve the actual exit status and measured values. These results are SYNTHETIC conformance, not physical sensor accuracy. Timing varies; do not require byte identical timing values across runs.
3. When a dashboard is requested, run `cargo run --locked -p rufield-viewer -- --source synthetic --port 8088` using a managed process. Use another available local port if needed. Verify `/health`, `/api/source`, and `/api/run` at `http://127.0.0.1:8088`, then inspect the page and confirm the SYNTHETIC banner. Stop only the process you started after a smoke test, or leave it running if the user requested an interactive demo and report how to stop it.
4. Report the revision, seed, commands, exit codes, measured report, and any unexecuted checks. Keep raw sensor data local. Do not enable live sources, enroll keys, publish a service, or imply hardware validation as a side effect of a demo.

Acceptance: benchmark tests pass, JSON parses, and the requested viewer endpoints respond with synthetic source state.
