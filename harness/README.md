# rucelium-harness

The **RuCelium metaharness** — a Darwinian flywheel that drives the RuCelium
Rust implementation toward the [ADR-264](../docs/ADR-264-rucelium-federated-fabric.md)
§14 acceptance gate.

It is a *meta*harness: it adds no new truth of its own. Every score is derived
from the same commands CI runs — `cargo test --workspace`, `cargo clippy`,
and the deterministic 64-node biome benchmark (`rucelium-bench`). What it adds
is the **loop**:

```text
        ┌────────────────────────────────────────────────┐
        │                                                │
   VARY │  you / an agent swarm change the Rust code     │
        ▼                                                │
   EVALUATE  rucelium fitness                            │  RETAIN
        │    tests 45 + clippy 15 + §14 accept 30        │  survivors live in
        ▼    + data quality 10  = fitness 0..100         │  .rucelium/ledger.json
   SELECT    rucelium evolve -m "what changed"           │  (commit what survives)
        │    fitness < parent  → REJECTED (dies)         │
        │    fitness >= parent → generation recorded ────┘
        ▼
   rucelium gate   — the hard ADR-264 §14 acceptance gate (exit code)
```

Regressions don't get recorded — a change that lowers fitness is simply not
selected (override deliberately with `--allow-regression`, which records the
regression honestly rather than hiding it). Over iterations the ledger is the
lineage of surviving implementations: a fitness curve for the whole
implementation process, useful to humans and agent swarms alike.

## Usage

No install needed inside the repo:

```bash
node harness/bin/rucelium.js doctor      # environment sanity check
node harness/bin/rucelium.js fitness     # score the working tree
node harness/bin/rucelium.js evolve -m "tighten replay window"
node harness/bin/rucelium.js ledger      # show the generation lineage
node harness/bin/rucelium.js gate        # strict acceptance gate (CI-friendly)
```

Or via npm from `harness/`:

```bash
cd harness
npm run fitness
npm run gate
```

Flags: `--fast` skips clippy for quick inner-loop iterations (clippy score is
carried, not awarded); `--allow-regression` records a fitness regression
instead of rejecting it.

## Fitness function

| Component  | Weight | Source |
|------------|-------:|--------|
| tests      | 45     | fraction of workspace tests passing (0 if the build fails) |
| clippy     | 15     | `15 − warnings`, floored at 0 |
| acceptance | 30     | ADR-264 §14 criteria passed (of 8) from `rucelium-bench --json` |
| quality    | 10     | usable-calibrated-observation % from the biome benchmark, scaled from the 90–100 % band |

`rucelium gate` is stricter than fitness: it requires **all** tests green,
**zero** clippy warnings, and **8/8** §14 criteria — the same bar a real
64-node pilot would have to clear (on synthetic data; see the honesty notes
in the ADR).

## Prior art and convergence

This harness and [`agentic-flow`](https://github.com/ruvnet/agentic-flow)
arrived at the same principle independently — **freeze the model, evolve the
harness**, and select on measured fitness rather than tuning the model. Credit
where it is due: `agentic-flow` states that principle explicitly and
implements it far more broadly (trajectory rewards, adaptive routing,
retrieve → judge → distill → consolidate).

`rucelium-harness` stays narrow on purpose: its fitness function is
domain-specific (workspace tests + clippy + the ADR-264 §14 acceptance
benchmark) and it must run with **zero network** inside CI. If `agentic-flow`
exposes a pluggable fitness interface, this should become a fitness provider
for it rather than a parallel loop — see
[ADR-268](../docs/ADR-268-rucelium-ruvnet-stack-integration.md) §2.4.

## Using it from an agent swarm

The flywheel is designed to be driven by coding agents: after each edit
batch, run `evolve` with a one-line description; parse the JSON verdict. A
`"rejected"` verdict means the change must be fixed or abandoned before
continuing. The ledger gives the swarm (and its human) a shared, append-only
memory of which implementation lineages survived selection and why.

The ledger lives in `.rucelium/ledger.json` (gitignored by default — commit
it if you want the lineage shared across machines).
