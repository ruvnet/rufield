//! Domain-separated binary Merkle tree over `sha256`, with inclusion proofs
//! and a stateless verifier (ADR-267 §3, shipped item 1).
//!
//! # Domain separation is a second-preimage defence
//!
//! Leaves are hashed as `sha256(0x00 || data)` and interior nodes as
//! `sha256(0x01 || left || right)`. The one-byte prefix is not decoration: it
//! is what stops a proof from being **re-interpreted at another depth**.
//!
//! Without it, an interior node's preimage is exactly 64 bytes of hash
//! material, and a leaf whose data happens to be those same 64 bytes hashes to
//! the *same* digest. An attacker who is allowed to choose leaf content could
//! therefore submit a 64-byte "observation" that is secretly an interior node,
//! and later present a shortened proof in which their leaf stands in for a
//! whole subtree — proving membership of data the notary never accepted. With
//! the prefixes, a leaf digest and a node digest are drawn from disjoint
//! preimage spaces, so a leaf can never be replayed as an interior node and a
//! proof only ever verifies at the exact depth it was issued for.
//!
//! # Odd levels: promotion, not duplication
//!
//! When a level has an odd number of nodes, this tree **promotes the last node
//! unchanged** to the next level. It does *not* duplicate it.
//!
//! Implications, both deliberate:
//!
//! - The tree is not perfectly balanced, so inclusion paths for different
//!   leaves in the same batch may have different lengths (a promoted node
//!   contributes no sibling at that level). [`verify_inclusion`] reconstructs
//!   the exact same level geometry from `leaf_count` alone, so the shape is
//!   never taken on trust from the proof.
//! - Promotion avoids the duplication ambiguity that bit Bitcoin's Merkle
//!   construction (CVE-2012-2459), where duplicating the odd tail makes an
//!   `n`-leaf tree and a specific `n+1`-leaf tree collide on the same root.
//!   With promotion, the leaf multiset and its order determine the root
//!   uniquely for a fixed `leaf_count`.
//!
//! # Empty batches
//!
//! A batch with zero leaves has no natural root, and a notary running on a
//! quiet gateway must still be able to seal an interval. The root of an empty
//! tree is therefore the fixed sentinel `sha256(0x02 || "rucelium.notary.empty")`
//! — a third domain, so the empty root can never equal any leaf or interior
//! digest. [`verify_inclusion`] always rejects proofs against it: nothing is
//! ever included in an empty batch.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain prefix byte for leaf hashing (ADR-267 §3: leaf = `0x00`).
pub const LEAF_DOMAIN: u8 = 0x00;

/// Domain prefix byte for interior-node hashing (ADR-267 §3: interior = `0x01`).
pub const NODE_DOMAIN: u8 = 0x01;

/// Domain prefix byte for the empty-tree sentinel — a third domain, disjoint
/// from both leaves and interior nodes.
pub const EMPTY_DOMAIN: u8 = 0x02;

/// Label hashed under [`EMPTY_DOMAIN`] to form the empty-batch sentinel root.
pub const EMPTY_TREE_LABEL: &[u8] = b"rucelium.notary.empty";

/// Hash a leaf: `sha256(0x00 || data)`.
///
/// The `0x00` prefix separates the leaf domain from the interior domain so a
/// proof cannot be re-interpreted at another depth (see the module docs and
/// ADR-267 §3).
#[must_use]
pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([LEAF_DOMAIN]);
    h.update(data);
    h.finalize().into()
}

/// Hash an interior node: `sha256(0x01 || left || right)`.
///
/// The `0x01` prefix guarantees this digest can never coincide with the digest
/// of a 64-byte leaf (ADR-267 §3 second-preimage defence).
#[must_use]
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([NODE_DOMAIN]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The sentinel root of a zero-leaf batch: `sha256(0x02 || "rucelium.notary.empty")`.
///
/// A notary is allowed to seal an interval in which nothing was accepted; the
/// sealed root is still signed, chained and federated, it simply commits to the
/// empty set. Nothing verifies as included in it.
#[must_use]
pub fn empty_root() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([EMPTY_DOMAIN]);
    h.update(EMPTY_TREE_LABEL);
    h.finalize().into()
}

/// A Merkle inclusion path: everything a third party needs, together with the
/// leaf and the signed root, to prove membership without gateway access
/// (ADR-267 §3, shipped item 1).
///
/// `siblings` is ordered bottom-up. Each entry pairs the sibling digest with a
/// flag saying whether that sibling sits on the **right** of the running hash
/// (`true`) or the left (`false`). Levels at which this leaf's ancestor was
/// promoted (odd tail) contribute no entry at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Zero-based index of the proven leaf within the batch.
    pub leaf_index: usize,
    /// Total number of leaves in the batch — fixes the tree geometry, so a
    /// verifier never infers the shape from the proof itself.
    pub leaf_count: usize,
    /// Bottom-up sibling path: `(digest, sibling_is_right)`.
    pub siblings: Vec<([u8; 32], bool)>,
}

/// A deterministic, append-only binary Merkle tree over pre-hashed leaves.
///
/// Construction is a pure function of the leaf vector: same leaves in the same
/// order ⇒ byte-identical root, on any machine, forever (ADR-267 §3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleTree {
    /// `levels[0]` is the leaf level; each subsequent level is the parent
    /// level; the last level holds the single root (empty for a zero-leaf
    /// tree).
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Build a tree from already-hashed leaves (use [`leaf_hash`] to produce
    /// them from canonical bytes).
    ///
    /// Deterministic. Odd levels promote their last node unchanged; see the
    /// module docs for why duplication was rejected.
    #[must_use]
    pub fn build(leaves: Vec<[u8; 32]>) -> MerkleTree {
        if leaves.is_empty() {
            return MerkleTree { levels: Vec::new() };
        }
        let mut levels: Vec<Vec<[u8; 32]>> = vec![leaves];
        loop {
            let top = levels.len() - 1;
            if levels[top].len() <= 1 {
                break;
            }
            let next = {
                let current = &levels[top];
                let mut next = Vec::with_capacity(current.len().div_ceil(2));
                let mut i = 0;
                while i + 1 < current.len() {
                    next.push(node_hash(&current[i], &current[i + 1]));
                    i += 2;
                }
                if i < current.len() {
                    // Odd tail: promote unchanged.
                    next.push(current[i]);
                }
                next
            };
            levels.push(next);
        }
        MerkleTree { levels }
    }

    /// The Merkle root, or the documented [`empty_root`] sentinel when the tree
    /// has no leaves. Never panics.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|top| top.first().copied())
            .unwrap_or_else(empty_root)
    }

    /// Number of leaves in the batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.levels.first().map_or(0, Vec::len)
    }

    /// Whether the batch contains no leaves.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The leaf digests, in insertion order.
    #[must_use]
    pub fn leaves(&self) -> &[[u8; 32]] {
        self.levels.first().map_or(&[], Vec::as_slice)
    }

    /// Index of the first leaf equal to `leaf`, if the batch contains it.
    ///
    /// Used by `SealedBatch::bundle_for` to locate an observation's leaf; a
    /// duplicate observation (same canonical bytes) resolves to its first
    /// occurrence, which is sufficient because either occurrence proves the
    /// same membership fact.
    #[must_use]
    pub fn index_of(&self, leaf: &[u8; 32]) -> Option<usize> {
        self.leaves().iter().position(|l| l == leaf)
    }

    /// Produce an inclusion proof for `index`, or `None` if the index is out of
    /// range (which includes every index of an empty tree).
    #[must_use]
    pub fn prove(&self, index: usize) -> Option<InclusionProof> {
        if index >= self.len() {
            return None;
        }
        let mut siblings = Vec::new();
        let mut idx = index;
        for level in &self.levels {
            if level.len() <= 1 {
                break;
            }
            let is_promoted_tail = idx == level.len() - 1 && !level.len().is_multiple_of(2);
            if !is_promoted_tail {
                if idx.is_multiple_of(2) {
                    siblings.push((level[idx + 1], true));
                } else {
                    siblings.push((level[idx - 1], false));
                }
            }
            idx /= 2;
        }
        Some(InclusionProof {
            leaf_index: index,
            leaf_count: self.len(),
            siblings,
        })
    }
}

/// **Stateless** inclusion verification — the function a third party runs in
/// 2040 with no access to the gateway, no tree, and no network (ADR-267 §3,
/// shipped item 1).
///
/// Returns `true` only if *all* of the following hold:
///
/// - `leaf_count > 0` and `leaf_index < leaf_count` (a self-inconsistent proof
///   is rejected before any hashing);
/// - the sibling path has **exactly** the length the declared `leaf_count`
///   requires — a truncated path (claiming a shallower tree) or an extended one
///   (extra siblings) is rejected;
/// - every `sibling_is_right` flag agrees with the side implied by the position
///   at that level, so a flipped flag cannot re-order a hash;
/// - the recomputed root equals `root`.
///
/// The tree geometry is derived from `leaf_count` alone, never from the length
/// of the supplied path, so an attacker cannot choose a shape that makes their
/// path fit.
///
/// **Scope of `leaf_count` here:** this function checks that the declared count
/// is *self-consistent* with the path, not that it is the true size of the
/// notarized batch — a forger who supplies their own siblings can always name
/// some count with the same path shape. Binding the count to reality is the
/// signed root's job: [`crate::NotaryRoot::leaf_count`] is covered by the root
/// signature, and [`crate::verify_bundle`] requires the proof's count to equal
/// it.
#[must_use]
pub fn verify_inclusion(leaf: &[u8; 32], proof: &InclusionProof, root: &[u8; 32]) -> bool {
    if proof.leaf_count == 0 || proof.leaf_index >= proof.leaf_count {
        return false;
    }
    let mut acc = *leaf;
    let mut idx = proof.leaf_index;
    let mut size = proof.leaf_count;
    let mut consumed = 0usize;
    while size > 1 {
        let is_promoted_tail = idx == size - 1 && !size.is_multiple_of(2);
        if !is_promoted_tail {
            let Some(&(sibling, sibling_is_right)) = proof.siblings.get(consumed) else {
                return false; // path truncated for this tree size
            };
            if sibling_is_right != idx.is_multiple_of(2) {
                return false; // flag disagrees with the position
            }
            acc = if sibling_is_right {
                node_hash(&acc, &sibling)
            } else {
                node_hash(&sibling, &acc)
            };
            consumed += 1;
        }
        idx /= 2;
        size = size.div_ceil(2);
    }
    consumed == proof.siblings.len() && acc == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| leaf_hash(format!("observation-{i}").as_bytes()))
            .collect()
    }

    #[test]
    fn hashes_are_real_sha256_and_domain_separated() {
        // sha256(0x00) — the leaf hash of the empty byte string.
        assert_eq!(
            crate::hex_encode(&leaf_hash(b"")),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
        // A 64-byte leaf must not collide with the interior node over the same
        // 64 bytes: this is the whole point of the prefixes.
        let l = leaf_hash(b"left");
        let r = leaf_hash(b"right");
        let mut concat = Vec::with_capacity(64);
        concat.extend_from_slice(&l);
        concat.extend_from_slice(&r);
        assert_eq!(concat.len(), 64);
        assert_ne!(leaf_hash(&concat), node_hash(&l, &r));
        // And the empty sentinel lives in a third domain.
        assert_ne!(empty_root(), leaf_hash(EMPTY_TREE_LABEL));
        assert_ne!(empty_root(), node_hash(&l, &r));
        assert_eq!(empty_root(), empty_root());
    }

    #[test]
    fn empty_tree_uses_the_sentinel_and_proves_nothing() {
        let t = MerkleTree::build(Vec::new());
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        assert_eq!(t.root(), empty_root());
        assert!(t.prove(0).is_none());
        // A hand-forged proof against the sentinel root is rejected.
        let forged = InclusionProof {
            leaf_index: 0,
            leaf_count: 0,
            siblings: Vec::new(),
        };
        assert!(!verify_inclusion(&leaf_hash(b"x"), &forged, &empty_root()));
    }

    #[test]
    fn single_leaf_tree_is_its_own_root() {
        let l = leaf_hash(b"only");
        let t = MerkleTree::build(vec![l]);
        assert_eq!(t.len(), 1);
        assert_eq!(t.root(), l);
        let p = t.prove(0).unwrap();
        assert!(p.siblings.is_empty());
        assert!(verify_inclusion(&l, &p, &t.root()));
        assert!(t.prove(1).is_none());
    }

    #[test]
    fn build_prove_verify_across_sizes() {
        for n in [1usize, 2, 3, 5, 8, 1000] {
            let ls = leaves(n);
            let t = MerkleTree::build(ls.clone());
            assert_eq!(t.len(), n);
            let root = t.root();
            for (i, leaf) in ls.iter().enumerate() {
                let p = t.prove(i).expect("index in range");
                assert_eq!(p.leaf_index, i);
                assert_eq!(p.leaf_count, n);
                assert!(
                    verify_inclusion(leaf, &p, &root),
                    "size {n} index {i} failed"
                );
            }
            assert!(t.prove(n).is_none());
        }
    }

    #[test]
    fn promotion_rule_is_what_verification_implements() {
        // Three leaves: level0 = [a,b,c]; level1 = [H(a,b), c] (c promoted,
        // NOT duplicated); root = H(H(a,b), c).
        let ls = leaves(3);
        let t = MerkleTree::build(ls.clone());
        let expected = node_hash(&node_hash(&ls[0], &ls[1]), &ls[2]);
        assert_eq!(t.root(), expected);
        // The duplication variant would give a different root — assert we did
        // not implement it.
        let duplicated = node_hash(&node_hash(&ls[0], &ls[1]), &node_hash(&ls[2], &ls[2]));
        assert_ne!(t.root(), duplicated);
        // The promoted leaf's path is one hash shorter than its siblings'.
        assert_eq!(t.prove(2).unwrap().siblings.len(), 1);
        assert_eq!(t.prove(0).unwrap().siblings.len(), 2);
        // Five leaves exercise promotion at two levels.
        let ls = leaves(5);
        let t = MerkleTree::build(ls.clone());
        let l01 = node_hash(&ls[0], &ls[1]);
        let l23 = node_hash(&ls[2], &ls[3]);
        let expected = node_hash(&node_hash(&l01, &l23), &ls[4]);
        assert_eq!(t.root(), expected);
        assert!(verify_inclusion(&ls[4], &t.prove(4).unwrap(), &t.root()));
    }

    #[test]
    fn root_is_deterministic_and_order_sensitive() {
        let ls = leaves(9);
        let a = MerkleTree::build(ls.clone());
        let b = MerkleTree::build(ls.clone());
        assert_eq!(a.root(), b.root());
        assert_eq!(a, b);

        let mut swapped = ls.clone();
        swapped.swap(0, 1);
        assert_ne!(MerkleTree::build(swapped).root(), a.root());

        // A different leaf count is a different commitment.
        let mut shorter = ls;
        shorter.pop();
        assert_ne!(MerkleTree::build(shorter).root(), a.root());
    }

    #[test]
    fn verify_rejects_tampered_leaf_sibling_and_root() {
        let ls = leaves(8);
        let t = MerkleTree::build(ls.clone());
        let root = t.root();
        let p = t.prove(3).unwrap();
        assert!(verify_inclusion(&ls[3], &p, &root));

        // Tampered leaf.
        assert!(!verify_inclusion(&leaf_hash(b"forged"), &p, &root));

        // Tampered sibling.
        let mut bad = p.clone();
        bad.siblings[0].0[0] ^= 0x01;
        assert!(!verify_inclusion(&ls[3], &bad, &root));

        // Flipped side flag.
        let mut bad = p.clone();
        bad.siblings[0].1 = !bad.siblings[0].1;
        assert!(!verify_inclusion(&ls[3], &bad, &root));

        // Wrong root.
        let mut wrong_root = root;
        wrong_root[31] ^= 0xff;
        assert!(!verify_inclusion(&ls[3], &p, &wrong_root));
    }

    #[test]
    fn verify_rejects_inconsistent_index_and_count() {
        let ls = leaves(8);
        let t = MerkleTree::build(ls.clone());
        let root = t.root();
        let p = t.prove(3).unwrap();

        // Wrong leaf_index (in range, but not this leaf's position).
        let mut bad = p.clone();
        bad.leaf_index = 2;
        assert!(!verify_inclusion(&ls[3], &bad, &root));

        // leaf_index out of range for the declared count.
        let mut bad = p.clone();
        bad.leaf_index = 8;
        assert!(!verify_inclusion(&ls[3], &bad, &root));

        // A leaf_count that changes the geometry is rejected: the path no
        // longer has the right length for the claimed tree.
        for count in [4usize, 9, 12, 0] {
            let mut bad = p.clone();
            bad.leaf_count = count;
            assert!(
                !verify_inclusion(&ls[3], &bad, &root),
                "leaf_count {count} still verified"
            );
        }
        // Documented limit: a count in the same shape class (7 vs 8 at index 3)
        // recomputes the same path, so verify_inclusion alone cannot reject it.
        // The count is bound to reality by the *signed* root, which is why
        // verify_bundle cross-checks proof.leaf_count against root.leaf_count.
        let mut same_shape = p;
        same_shape.leaf_count = 7;
        assert!(verify_inclusion(&ls[3], &same_shape, &root));
    }

    #[test]
    fn verify_rejects_truncated_or_extended_paths() {
        let ls = leaves(8);
        let t = MerkleTree::build(ls.clone());
        let root = t.root();
        let p = t.prove(5).unwrap();
        assert_eq!(p.siblings.len(), 3);

        let mut truncated = p.clone();
        truncated.siblings.pop();
        assert!(!verify_inclusion(&ls[5], &truncated, &root));

        let mut extended = p.clone();
        extended.siblings.push(([0u8; 32], true));
        assert!(!verify_inclusion(&ls[5], &extended, &root));

        let empty_path = InclusionProof {
            leaf_index: 5,
            leaf_count: 8,
            siblings: Vec::new(),
        };
        assert!(!verify_inclusion(&ls[5], &empty_path, &root));
    }

    #[test]
    fn a_leaf_cannot_be_replayed_as_an_interior_node() {
        // The depth-confusion attack the domain prefixes exist to stop: an
        // attacker submits the concatenation of two real leaves as their own
        // "observation" and then presents a proof one level short.
        let ls = leaves(4);
        let t = MerkleTree::build(ls.clone());
        let root = t.root();
        let mut concat = Vec::with_capacity(64);
        concat.extend_from_slice(&ls[0]);
        concat.extend_from_slice(&ls[1]);
        let malicious_leaf = leaf_hash(&concat);
        // It is not the interior node, so no proof of the shallow shape works.
        assert_ne!(malicious_leaf, node_hash(&ls[0], &ls[1]));
        let shallow = InclusionProof {
            leaf_index: 0,
            leaf_count: 2,
            siblings: vec![(node_hash(&ls[2], &ls[3]), true)],
        };
        assert!(!verify_inclusion(&malicious_leaf, &shallow, &root));
    }

    #[test]
    fn proof_serde_round_trips() {
        let t = MerkleTree::build(leaves(5));
        let p = t.prove(1).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        let back: InclusionProof = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
        assert!(verify_inclusion(&t.leaves()[1], &back, &t.root()));
    }

    #[test]
    fn index_of_and_leaves_expose_the_batch() {
        let ls = leaves(6);
        let t = MerkleTree::build(ls.clone());
        assert_eq!(t.leaves(), ls.as_slice());
        assert_eq!(t.index_of(&ls[4]), Some(4));
        assert_eq!(t.index_of(&leaf_hash(b"absent")), None);
        assert_eq!(MerkleTree::build(Vec::new()).leaves(), &[] as &[[u8; 32]]);
    }
}
