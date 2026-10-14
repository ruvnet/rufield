# rufield-adapters 0.2.0

RuField bounded sensing adapters, W1700K RF diagnostics and advisory anomaly analysis.

![RuField RF observatory: unverified diagnostics remain advisory](https://raw.githubusercontent.com/ruvnet/rufield/025af0e02ad04124b07d371d447fd87d33d21b4e/docs/assets/rufield-rf-observatory.svg)

```sh
cargo install rufield-adapters --version 0.2.0 --locked
```

CLIs: rf-diagnostics-replay converts JSONL to unsigned advisory FieldEvents; rf-diagnostics-analyze reports quality faults and received-power anomalies.

RF diagnostics do not establish interference causality, occupancy or physical sensing accuracy. Synthetic tests validate software behavior only.

[Documentation and examples](https://github.com/ruvnet/rufield#readme) · [RF diagnostic architecture](https://github.com/ruvnet/rufield/blob/main/docs/ADR-271-w1700k-rf-diagnostics.md) · [Source](https://github.com/ruvnet/rufield)

MIT licensed.
