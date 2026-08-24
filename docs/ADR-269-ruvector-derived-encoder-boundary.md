# ADR 269: Optional RuVector derived encoder boundary

Status: Accepted

Date: 2026-08-21

## Context

RuVector can improve multimodal embeddings and retrieval, but hardwiring an unverified package API would couple RuField to release churn. More importantly, an embedding is a derived representation. It cannot establish sensor identity, event authenticity, privacy authorization, or ground truth.

## Decision

Add `rufield-ruvector`, a backend neutral implementation of the existing `FieldEncoder` trait. `EmbeddingBackend` accepts normalized tensor values, axes, shape, modality, noise floor, and privacy class. A deployment implements that boundary only after pinning and verifying a compatible RuVector package or sidecar.

The host supplies local or network boundary metadata independently of the backend, preventing an adapter from self classifying as local. Before any tensor values reach the backend, an explicit privacy policy evaluates privacy class, backend identity, and the host supplied boundary. The bundled conservative policy denies every network transfer and denies P4 and P5 even locally because it has no consent or identity binding. Only an explicit deployment policy may authorize those cases.

Ship an in memory deterministic conformance backend. It validates the adapter and privacy propagation contract but is not a learned model and has no field accuracy claim.

RuVector output is derived only. The adapter inherits the source tensor privacy class and source event identity. It never verifies provenance, authorizes fusion, changes a source event, or becomes an evidence ledger.

## Inputs

1. A structurally valid `FieldTensor`.
2. Source event identity.
3. A verified backend implementation plus independently supplied deployment boundary.
4. An explicit privacy authorization policy.

## Outputs

1. A finite, nonempty `FieldEmbedding`.
2. Original modality, privacy class, and source event identity.
3. A stable backend identifier for deployment receipts.
4. An additive lineage receipt binding policy id, decision receipt id, privacy class, host supplied boundary, backend identity, SHA256 of canonical source event and tensor inputs, and SHA256 of the derived embedding.

## Assumptions

1. External backend versions and model weights are pinned outside this crate.
2. Backend isolation, resource limits, and model provenance are enforced by the host runtime.
3. Embedding consumers preserve the distinction between derived similarity and authoritative evidence.

## Alternatives considered

1. Add a direct dependency on the latest RuVector repository. Rejected until a published API and compatibility range can be verified.
2. Put embedding logic in `rufield-core`. Rejected because the core wire and trait layer should remain backend neutral.
3. Let embedding similarity influence provenance validity. Rejected because semantic similarity is not authentication.

## Migration

Existing encoders remain valid. A deployment wraps a verified backend with `RuVectorFieldEncoder` and injects it where a `FieldEncoder` is already accepted.

## Rollback

Remove the optional adapter and restore the prior encoder. No native event, inference, or provenance format changes.

## Acceptance

The conformance backend must produce deterministic finite embeddings, preserve the tensor privacy class and source event identity, reject empty identities, nonfinite output, and overflowing tensor shapes, and bind receipt hashes to canonical inputs. Denied network, P4, and P5 requests must leave backend invocation count at zero. The adapter exposes no operation that can mutate or authorize source evidence.
