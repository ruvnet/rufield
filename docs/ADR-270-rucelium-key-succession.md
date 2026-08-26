# ADR 270: Key Succession — Surviving the Institution

Status: Accepted — closes an identity-takeover vector

Date: 2026 08 02

Tags: rucelium, security, federation, key-rotation, succession, custodians, archival, tuf

## 1. Context — a vulnerability found by asking a 20-year question

The honest ledger asks: *could a stranger verify this record in 2046?* One row
came back amber — **"verify it after the institution that owned it is gone?"**
Chasing that row surfaced a live vulnerability in code already written.

`FederationBus::register_biome(biome_id, pubkey, epoch)` accepted **any**
strictly-higher epoch and rebound the identity to the presented key. There was
no proof of continuity: the incoming key was not signed by the outgoing one.

The attack is trivial. A peer — configured, malicious, or merely compromised —
announces `biome/thames-estuary` at epoch 999 with its own key. From that
moment the gateway accepts *the attacker's* summaries and revocations as
genuinely that biome's, and rejects the real biome's as an
`IdentityMismatch`. The identity-binding hardening added earlier
(`biome_id → key`) was doing real work, and rotation walked straight around
it.

This is the same class of bug TUF's root-rotation design exists to prevent:
new root keys become trusted only through metadata signed by a **quorum of
the currently trusted keys**.

## 2. Decision — genesis is trust-on-first-use; every rebinding is signed

`register_biome` becomes **genesis only** — the single unauthenticated
binding, and idempotent for an unchanged key. Any attempt to rebind an
established identity returns `SuccessionRequired`.

Rotation moves to `rotate_biome(&KeySuccession)`, a signed statement:

```rust
KeySuccession {
    biome_id, from_epoch, to_epoch, new_pubkey_hex, effective_ns,
    new_custodians, new_custodian_threshold,
    signatures: Vec<(signer_pubkey_hex, signature_hex)>,
}
```

Signatures cover the statement with the `signatures` list cleared, so they
commit to `from_epoch` — which is what stops a captured succession being
replayed onto a later state. `from_epoch` must equal the bus's current epoch
and `to_epoch` must strictly exceed it.

## 3. Decision — two authorisation paths, and no third

1. **Continuity.** The succession is signed by the key currently bound to the
   biome. Ordinary rotation: the holder hands over to its successor.
2. **Recovery.** The succession carries signatures from at least
   `custodian_threshold` **distinct** custodians declared at genesis.

Path 2 is the one that answers the ledger's amber row. Over twenty years an
institution being restructured, defunded, merged, or simply losing its key is
not an edge case — it is the *expected* case. An m-of-n custodian quorum
(a regulator, a university, a downstream authority) declared in advance can
hand the identity to a successor **without the original key ever existing
again**. A succession may also rotate the custodian set itself, so governance
can evolve without breaking the chain.

`custodian_threshold = 0` opts out: the identity dies with its key. That is a
legitimate choice for a short-lived deployment, and it is explicit rather than
accidental.

Anything else is refused — including an epoch bump with no signatures at all,
which is precisely what used to succeed.

## 4. Consequences

Positive: the takeover vector is closed; environmental records stay
attributable across institutional change, which is the only way a 2026
baseline is still citable in 2046; rotation and recovery are both auditable
artifacts rather than side effects of an API call.

Negative / accepted: genesis remains trust-on-first-use (a first contact must
be trusted from somewhere — publishing genesis keys in a transparency log is
the follow-up); custodian key management is now a real operational
responsibility; and a biome that declares no custodians has no recovery path
by construction.

Not addressed here: proving a *retired* key was validly retired to a verifier
who never saw the succession chain. Successions are Merkle-notarizable
(ADR-267) and chaining them into the notary is the natural next step.

## Implementation status

| # | Item | Status |
|---|---|---|
| 1 | `register_biome` is genesis-only; rebinding refused | shipped |
| 2 | `KeySuccession` + canonical bytes + `sign_succession` | shipped |
| 3 | Continuity path (outgoing key signs) | shipped |
| 4 | Recovery path (m-of-n custodian quorum) | shipped |
| 5 | Custodian-set handover; unreachable thresholds refused | shipped |
| 6 | Replay/rollback refusal bound to `from_epoch` | shipped |
| 7 | Genesis keys in a transparency log; successions notarized | follow-up |

## Sources

- TUF specification, root key rotation and thresholds:
  <https://theupdateframework.github.io/specification/latest/>
- TAP 8, generalised key rotation:
  <https://github.com/theupdateframework/taps/blob/master/tap8.md>
