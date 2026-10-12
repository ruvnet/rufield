# RuField for Claude Code

Three repository-aware skills for the Rust reference stack. Install the plugin and open Claude Code in a RuField source checkout. Installation does not bundle Cargo binaries, start services, configure MCP servers, or install automatic hooks.

```sh
claude plugin marketplace add ruvnet/rufield
claude plugin install rufield@rufield-marketplace
```

Inside Claude Code:

```text
/rufield:demo
/rufield:replay
/rufield:audit
```

For local development from the repository root:

```sh
python3 scripts/validate-plugin.py
claude plugin validate .
claude plugin validate ./plugins/rufield
claude --plugin-dir ./plugins/rufield
```

The static Python check verifies this repository's packaging contract; Claude's own validator and a loaded session remain the authoritative integration checks. Rust and Node are required for the workflows. Dependencies may need network access on the first Cargo build. Sensor data stays local; fixtures and deterministic signing seeds are not production credentials.

Skills cover synthetic benchmarks and viewer smoke tests, CSI and ultrasonic Rust API replay, and evidence/trust/privacy conformance. They do not claim live hardware accuracy or physical evidence promotion without real supporting artifacts.

References: [Claude plugin manifest](https://code.claude.com/docs/en/plugins-reference), [marketplace installation](https://code.claude.com/docs/en/plugin-marketplaces).
