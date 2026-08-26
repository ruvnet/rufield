# ADR 267: Long-Term Provenance — Merkle Notarization and Post-Quantum Readiness

Status: Accepted — v0.1 notary layer

Date: 2026 08 02

Deciders: rUv

Tags: rucelium, provenance, post-quantum, merkle, notarization, compliance, archival, lorawan

## 1. Context

RuCelium signs every observation with ed25519 at the spore node (ADR-264 §11)
and keeps `FederatedEvent`-class data for **years** (§10). Two facts collide:

1. **Environmental evidence is long-lived.** ADR-266's compliance wedge sells
   *regulator-verifiable* evidence. A discharge measurement taken in 2026 may
   need to be independently verified in 2040 — in a dispute, an insurance
   claim, or a scientific reanalysis. Climate baselines are worse: their whole
   value is decades of comparability.
2. **Ed25519 is not durable on that horizon.** A cryptographically relevant
   quantum computer breaks ECC signatures. Unlike confidentiality, signatures
   have no "harvest now" exposure — but they have a *verifiability* exposure:
   a signature that cannot be trusted in 2040 retroactively destroys the
   evidentiary value of data collected today. NIST standardized ML-DSA in
   FIPS 204 (August 2024) precisely for this class of problem.

The naive fix — sign each observation with ML-DSA — is **infeasible at the
sensor boundary**, and the numbers are not close:

| Scheme | Signature | Envelope | LoRaWAN DR0 datagrams (51 B) |
|---|---:|---:|---:|
| ed25519 (today) | 64 B | 114 B | **3** |
| ML-DSA-44 | 2,420 B | ~2,470 B | **~49** |

ML-DSA-44 also carries a 1,312-byte public key. A battery node on a duty-cycled
sub-GHz radio cannot send ~49 datagrams per reading; it would blow the airtime
budget, the battery, and the duty-cycle regulation simultaneously. ML-DSA's
*speed* is fine (≈0.65 ms signing, integer-only arithmetic, constant-time
friendly) — **size is the binding constraint**, exactly as it was for the
envelope-v2 work in ADR-265 §2.

## 2. Decision — hybrid provenance: cheap per-observation, notarized in batch

Split the two jobs that a signature is currently doing:

1. **Authenticity now** (is this packet from this device, unmodified?) stays
   **ed25519, per observation, at the node**. Unchanged. Fits the radio budget.
2. **Verifiability later** (can a stranger in 2040 prove this record existed,
   unaltered, in 2026?) moves to a **gateway-side Merkle notary**: the gateway
   accumulates accepted observations into an append-only Merkle tree and
   periodically signs only the **root**.

Because the expensive signature covers a whole batch, its cost amortizes to
near nothing per observation — the published figure for this pattern is
**≈2.4 bytes per event** even with a Dilithium-class signature ~38× the size
of ed25519. A 4,096-leaf batch signed with ML-DSA-44 costs 2,420 bytes total,
i.e. **0.6 bytes per observation**, and each observation's proof of membership
is a 12-hash (384-byte) inclusion path that the gateway can serve on demand
rather than transmit by default.

```text
spore node ──ed25519(48-byte record)──► gateway
                                          │  accepted observations
                                          ▼
                                   Merkle accumulator
                                          │ every N records / T seconds
                                          ▼
                                  signed NotaryRoot  ──► biome ──► federation
                                  (algorithm-agnostic:
                                   ed25519 today, ML-DSA when available)

verification in 2040:  observation  +  inclusion proof  +  signed root
                       └── recompute the root, check ONE signature ──┘
```

This is the same structure production transparency logs and the IETF Merkle
Tree Certificates work use to make post-quantum PKI affordable; we are
applying it to environmental evidence, where the archival horizon is longer
than the web's.

## 3. Decision — algorithm agility is the shipped feature, not ML-DSA itself

v0.1 ships `rucelium-notary` with:

- a binary Merkle tree over `sha256` with **domain-separated** leaf (`0x00`)
  and interior (`0x01`) hashing — the standard second-preimage defence, so a
  proof cannot be re-interpreted at another depth;
- deterministic, append-only batch construction with inclusion proofs and a
  stateless `verify_inclusion` that a third party can run with no access to
  the gateway;
- a `RootSigner` / `RootVerifier` trait pair, so the root signature algorithm
  is a **swap, not a rewrite**;
- `Ed25519RootSigner` as the v0.1 implementation, and a `NotaryAlgorithm` tag
  (`ed25519`, `ml-dsa-44`, `hybrid-ed25519+ml-dsa-44`) recorded **inside** the
  signed root so a verifier never has to guess, and a future ML-DSA root is
  self-describing to today's readers.

**Honest label:** RuCelium is *post-quantum ready*, not post-quantum. No
ML-DSA implementation ships in v0.1 — that requires a vetted, ideally
FIPS-validated implementation, and shipping a hand-rolled lattice
implementation would be worse than shipping none. What ships is the
architecture that makes the swap a configuration change instead of a protocol
break, plus the amortization that makes it *affordable* when it happens.

The migration is deliberately **hybrid-first**: sign roots with ed25519 **and**
ML-DSA concurrently during transition, so a root remains verifiable by old and
new verifiers alike, and no historical data needs re-signing. Data already
notarized under ed25519 gets its long-term guarantee by being *re-notarized*:
an old root is included as a leaf in a new PQ-signed tree, chaining the
history forward without touching a single stored observation.

## 4. Consequences

Positive: long-term evidentiary value stops depending on ed25519 surviving;
the compliance wedge (ADR-266 §3.1) gains a genuinely defensible claim; the
per-observation radio budget is untouched; verification is *cheaper* for a
third party (one signature check per batch, not per record); the notary root
is a natural federation artifact — it is small, signed, and carries no raw
data, exactly what ADR-264 §6 permits to leave a biome.

Negative / accepted: a new crate and a new artifact to persist and federate;
inclusion proofs must be retrievable for the life of the data (a gateway that
loses its tree can rebuild it from the durable store — the store is the source
of truth, the tree is derived); the notary adds a batching latency (a record
is not notarized the instant it is accepted — it is authentic immediately,
notarized within the batch interval, and that distinction must be stated in
any evidence bundle).

## Implementation status (v0.1)

| # | Item | Status |
|---|---|---|
| 1 | Domain-separated sha256 Merkle tree, inclusion proofs, stateless verify | shipped — `rucelium-notary` |
| 2 | `RootSigner`/`RootVerifier` traits + self-describing `NotaryAlgorithm` | shipped |
| 3 | Ed25519 root signing + third-party verification of a single observation | shipped |
| 4 | Re-notarization (old root as a leaf of a new tree) | shipped |
| 5 | ML-DSA-44 root signer, hybrid dual-signing, FIPS-validated implementation | honest follow-up — architecture ready, algorithm not shipped |

## Sources

- NIST FIPS 204 (ML-DSA) sizes and performance:
  <https://www.encryptionconsulting.com/education-center/ml-dsa-fips-204/>
- Batch/Merkle amortization of post-quantum signatures (≈2.4 B/event):
  <https://papers.ssrn.com/sol3/Delivery.cfm/5883842.pdf?abstractid=5883842&mirid=1>
- IETF Merkle Tree Certificates:
  <https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-01.html>
- Post-quantum audit evidence for long-lived regulated systems:
  <https://arxiv.org/pdf/2512.00110>
