# ADR 268: RuCelium and the ruvnet Stack — Integrate, Don't Reinvent

Status: Accepted — integration strategy

Date: 2026 08 02

Deciders: rUv

Tags: rucelium, agentdb, agenticow, ruvector, rvf, agentic-flow, ruflo, ruv-swarm, integration, memory, harness

## 1. Context

RuCelium was built bottom-up from the sensing boundary and, in the process,
independently arrived at several capabilities the ruvnet stack already ships
as mature packages. Continuing to build them in-tree would be duplicated
effort and a worse result. A survey of the published packages:

| Package | What it is | Overlap with RuCelium |
|---|---|---|
| `agentdb` (3.0.0-alpha) | Self-learning vector memory: **single-file `.rvf` cognitive container**, HNSW search, hybrid BM25+dense retrieval, causal graph + Cypher, episodic/Reflexion memory, provenance + audit log, offline-first, WASM/edge | ADR-264 §13 item 6 literally named "SQLite or **RVF** buffering"; §7 item 5 named "**RuVector similarity search**"; ADR-266 B8 (ecosystem memory) is a vector-similarity problem |
| `agenticow` (0.2.4) | "Git for agent memory": copy-on-write **vector branching**, branch a base memory in ~0.5 ms / 162 bytes regardless of base size; exact read-through queries; checkpoint/rollback; built on `@ruvector/rvf-node` | ADR-264 §9's **safety-simulation stage** needs exactly this: branch the biome state, simulate an actuation, discard or keep |
| `agentic-flow` (2.1.2) | "The agentic meta-harness — **freeze the model, evolve the harness**"; retrieve → judge → distill → consolidate; trajectory rewards; adaptive routing | `harness/` (ADR-266-era Darwin flywheel) converged on the same principle independently |
| `claude-flow` / ruflo (3.34) | Enterprise agent orchestration, 60+ specialized agents, swarm coordination, vector memory, MCP | ADR-264 §9's Mycelium agent layer (calibration, flood, biodiversity, governance agents) |
| `ruv-swarm` (1.0.20) | WASM neural swarm orchestration | Regional model execution at the gateway |

## 2. Decision

**Integrate at the seams RuCelium already defines; do not absorb, and do not
re-implement.** Three concrete bindings, one explicit non-binding.

### 2.1 `agentdb` becomes the biome memory substrate (accepted)

`rucelium-store` (ADR-265 §3) deliberately chose an append-only JSONL segment
log over SQLite for zero-dependency durability. That decision stands **for the
gateway's hot ingest path** — it is the write-ahead record of what was
accepted, and its guarantees (durable dedup index, CRC integrity, torn-tail
repair) are load-bearing for the restart-attack acceptance test.

But `rucelium-store` is a *log*, not a *memory*. ADR-266 B8 (ecosystem
memory / "ecological déjà vu") needs vector similarity over encoded biome
states, with provenance on every retrieved case. That is `agentdb`'s exact
shape, including the `.rvf` container the original ADR named.

Binding: a `rucelium-memory` adapter crate projects sealed observations and
biome-state vectors into an `.rvf` container, and answers "which historical
states resemble now?" with provenance references back to the observations
that produced each vector. The log remains the source of truth; the vector
container is derived and rebuildable.

### 2.2 `agenticow` becomes the safety-simulation substrate (accepted)

ADR-264 §9 requires a **safety simulation** between policy evaluation and
authority check. Today's `SafetySimulator` checks a static envelope. The
honest version simulates against *biome state* — and doing that safely means
branching the state, running the candidate action, and discarding the branch.

`agenticow`'s copy-on-write branching (≈0.5 ms, 162 bytes, independent of base
size) makes per-proposal branching affordable enough to do on every actuator
command, which is precisely where it matters. It also gives the governance
story a feature it lacked: an auditor can be handed the *branch* a decision
was made on, not just the decision.

Binding: the safety stage takes an optional branch handle; the ADR-264 §9
typestate chain is unchanged — this deepens one stage, it does not add one.

### 2.3 The agent layer runs on `ruflo` / `agentic-flow` (accepted)

ADR-264 §9 lists ten agents (calibration, wildfire, flood, biodiversity,
pollution-source, deployment, data-quality, hypothesis, governance). RuCelium
should ship **none of them as an agent runtime**. It ships the thing that
makes agents safe: typed proposals, deterministic policy, safety simulation,
authority, signed commands, receipts. Agents are drivers of that interface and
belong on an orchestration platform built for them.

Binding: publish the control path as an MCP tool surface so `ruflo`-hosted
agents can propose and read receipts, and can never actuate directly.

### 2.4 `harness/` acknowledges convergence with `agentic-flow` (accepted)

The Darwin flywheel in `harness/` and `agentic-flow`'s meta-harness are the
same idea — freeze the model, evolve the harness, select on measured fitness.
`harness/` stays, because its fitness function is *domain-specific* (workspace
tests + clippy + the ADR-264 §14 acceptance benchmark) and it must run with
zero network in CI. Its README now credits the convergence explicitly rather
than implying novelty. If `agentic-flow` exposes a pluggable fitness
interface, `harness/` should become a fitness provider for it rather than a
parallel loop.

### 2.5 Non-binding: the ThreeFold "Mycelium" overlay (restated)

Unchanged from ADR-264 §9: a different technology (encrypted IPv6 overlay),
optional gateway transport only, never a dependency of sensor nodes and never
in the data model. Recorded here because the name collision keeps resurfacing.

## 3. Consequences

Positive: RuCelium stops growing a vector database, a branching memory, and an
agent runtime it has no business owning, and concentrates on what nothing else
in the stack does — the signed sensing boundary, calibration authority,
sovereignty, and the governed control path. Each binding lands at a seam the
architecture already had, so none of them alters the ADR-264 layer model.

Negative / accepted: three external dependencies on packages at
alpha/early-minor versions (`agentdb` 3.0.0-alpha, `agenticow` 0.2.x), so
adapters must be thin and the core must remain functional without them —
every binding above is *additive*, and the ADR-264 §14 acceptance path must
continue to pass with none of them installed. That constraint is normative.

## Implementation status

| # | Item | Status |
|---|---|---|
| 1 | Survey + decision to integrate rather than reinvent | shipped — this ADR |
| 2 | `harness/` credits the `agentic-flow` convergence | shipped |
| 3 | `rucelium-memory` adapter over `agentdb` `.rvf` | planned |
| 4 | Branch-backed safety simulation over `agenticow` | planned |
| 5 | MCP tool surface for the governed control path | planned |
