//! `OutageBuffer` — gateway store-and-forward of **original signed
//! envelopes** with duplicate-free replay (ADR-264 §5 responsibility 7, §14
//! criteria 2–3).
//!
//! While the uplink is down the gateway pushes the raw signed envelope bytes
//! here (not decoded samples — decoded samples cannot be re-verified). The
//! buffer is a **dumb store**: [`OutageBuffer::push`] only structurally
//! decodes the envelope to extract the `(node_id, sequence)` dedup key; it
//! performs no signature or registry verification and never yields trusted
//! data by itself.
//!
//! # Restore contract
//!
//! On restore, [`OutageBuffer::drain`] returns the envelopes in
//! deterministic `(node_id, sequence)` order. **Every drained envelope must
//! go through `rucelium_ingest::IngestPipeline::reverify_stored`** — the
//! full cryptographic re-check (registry, revocation, key match, signature,
//! payload validation) — before the resulting
//! `rucelium_ingest::VerifiedEnvSample` can be handed to
//! [`crate::Biome::accept`]. An envelope tampered with while at rest fails
//! `reverify_stored` and never reaches the biome.
//!
//! The dedup index is part of the serialized form, so a gateway restart
//! (serialize → deserialize) never reintroduces an envelope it already
//! buffered.

use crate::sig;
use crate::FederationError;
use rucelium_abi::{RvEnvSampleV1, SignedEnvRecordV1};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Store-and-forward log of signed envelopes a gateway fills while its
/// uplink is down.
///
/// Duplicate suppression uses the stable `(node_id, sequence)` dedup key
/// extracted from the envelope payload (ADR-264 §14 criterion 3). The `seen`
/// index is retained across [`drain`](OutageBuffer::drain) calls and across
/// serialization, so replayed wire packets after a restart are still
/// dropped. See the module docs for the mandatory re-verification step on
/// restore.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutageBuffer {
    /// Buffered envelopes keyed by `(node_id, sequence)`; the value is the
    /// original envelope bytes plus the reception timestamp.
    entries: BTreeMap<(u64, u32), (Vec<u8>, u64)>,
    /// Every `(node_id, sequence)` key ever pushed — the dedup state.
    seen: BTreeSet<(u64, u32)>,
}

/// One persisted buffer entry: envelope bytes as lowercase hex.
#[derive(Serialize, Deserialize)]
struct PersistedEntry {
    node_id: u64,
    sequence: u32,
    envelope_hex: String,
    received_ns: u64,
}

/// The JSON form of the whole buffer — entries *and* dedup state.
#[derive(Serialize, Deserialize)]
struct PersistedBuffer {
    entries: Vec<PersistedEntry>,
    seen: Vec<(u64, u32)>,
}

impl OutageBuffer {
    /// Create an empty buffer.
    #[must_use]
    pub fn new() -> Self {
        OutageBuffer::default()
    }

    /// Buffer one signed envelope received at `received_ns`.
    ///
    /// The envelope is decoded (`SignedEnvRecordV1` + `RvEnvSampleV1` parse)
    /// **only** to extract the `(node_id, sequence)` dedup key — this is a
    /// structural check, not verification; full crypto re-checking happens
    /// on restore via `IngestPipeline::reverify_stored`. Returns
    /// `Ok(false)` (dropped) when the key has already been buffered —
    /// including keys seen before a serialize/deserialize restart cycle —
    /// and [`FederationError::BadEnvelope`] when the bytes do not decode as
    /// an envelope at all.
    pub fn push(
        &mut self,
        envelope_bytes: &[u8],
        received_ns: u64,
    ) -> Result<bool, FederationError> {
        let key = dedup_key_of(envelope_bytes)?;
        if !self.seen.insert(key) {
            return Ok(false);
        }
        self.entries
            .insert(key, (envelope_bytes.to_vec(), received_ns));
        Ok(true)
    }

    /// Number of envelopes currently buffered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no envelopes are currently buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove and return all buffered envelopes as
    /// `(envelope_bytes, received_ns)` pairs in `(node_id, sequence)` order
    /// (deterministic replay order). The dedup index is deliberately *not*
    /// cleared: a key that was drained is still a duplicate if it arrives
    /// again.
    ///
    /// The returned envelopes are **untrusted stored bytes**: each must pass
    /// `IngestPipeline::reverify_stored` before its sample may enter a
    /// [`crate::Biome`] (see the module docs).
    pub fn drain(&mut self) -> Vec<(Vec<u8>, u64)> {
        std::mem::take(&mut self.entries).into_values().collect()
    }

    /// Serialize the whole buffer — envelopes (as lowercase hex) *and* dedup
    /// state — so it survives a gateway restart.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let persisted = PersistedBuffer {
            entries: self
                .entries
                .iter()
                .map(
                    |(&(node_id, sequence), (bytes, received_ns))| PersistedEntry {
                        node_id,
                        sequence,
                        envelope_hex: sig::hex_encode(bytes),
                        received_ns: *received_ns,
                    },
                )
                .collect(),
            seen: self.seen.iter().copied().collect(),
        };
        serde_json::to_string(&persisted)
    }

    /// Restore a buffer previously produced by
    /// [`to_json`](OutageBuffer::to_json). Each entry's dedup key is
    /// re-derived from its envelope bytes (never trusted from the JSON), so
    /// the in-memory invariant that keys match envelope content holds even
    /// for a hand-edited file. Note that restoring does **not** verify
    /// signatures — that remains `reverify_stored`'s job after draining.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        use serde::de::Error as _;
        let persisted: PersistedBuffer = serde_json::from_str(json)?;
        let mut buf = OutageBuffer {
            entries: BTreeMap::new(),
            seen: persisted.seen.into_iter().collect(),
        };
        for entry in persisted.entries {
            let bytes = sig::hex_decode(&entry.envelope_hex)
                .ok_or_else(|| serde_json::Error::custom("invalid envelope hex"))?;
            let key = dedup_key_of(&bytes)
                .map_err(|e| serde_json::Error::custom(format!("stored envelope: {e}")))?;
            buf.seen.insert(key);
            buf.entries.insert(key, (bytes, entry.received_ns));
        }
        Ok(buf)
    }
}

/// Structurally decode an envelope just far enough to read its
/// `(node_id, sequence)` dedup key. No verification of any kind.
fn dedup_key_of(envelope_bytes: &[u8]) -> Result<(u64, u32), FederationError> {
    let record = SignedEnvRecordV1::decode(envelope_bytes)
        .map_err(|e| FederationError::BadEnvelope(e.to_string()))?;
    let wire = RvEnvSampleV1::parse(&record.payload)
        .map_err(|e| FederationError::BadEnvelope(e.to_string()))?;
    Ok((wire.node_id, wire.sequence))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::biome::{AcceptOutcome, Biome, BiomeConfig};
    use crate::testutil::{pipeline, signed_envelope, SEED};

    const RECV: u64 = 2_000_000;

    #[test]
    fn push_drops_duplicates_and_rejects_garbage() {
        let mut buf = OutageBuffer::new();
        assert!(buf.push(&signed_envelope(1, 1, 1_000, 20.0), RECV).unwrap());
        assert!(buf.push(&signed_envelope(1, 2, 2_000, 20.5), RECV).unwrap());
        // Same (node_id, sequence), even with a different payload: dropped.
        assert!(!buf.push(&signed_envelope(1, 1, 9_000, 99.0), RECV).unwrap());
        assert_eq!(buf.len(), 2);
        assert!(!buf.is_empty());

        // Bytes that are not an envelope at all.
        assert!(matches!(
            buf.push(b"not cbor", RECV),
            Err(FederationError::BadEnvelope(_))
        ));
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn drain_is_ordered_and_empties() {
        let mut buf = OutageBuffer::new();
        buf.push(&signed_envelope(2, 5, 5_000, 1.0), RECV).unwrap();
        buf.push(&signed_envelope(1, 9, 4_000, 2.0), RECV).unwrap();
        buf.push(&signed_envelope(1, 3, 3_000, 3.0), RECV).unwrap();
        let drained = buf.drain();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].0, signed_envelope(1, 3, 3_000, 3.0)); // (1, 3)
        assert_eq!(drained[1].0, signed_envelope(1, 9, 4_000, 2.0)); // (1, 9)
        assert_eq!(drained[2].0, signed_envelope(2, 5, 5_000, 1.0)); // (2, 5)
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn dedup_state_survives_restart() {
        let mut buf = OutageBuffer::new();
        buf.push(&signed_envelope(1, 1, 1_000, 20.0), RECV).unwrap();
        buf.push(&signed_envelope(1, 2, 2_000, 21.0), RECV).unwrap();
        let json = buf.to_json().unwrap();
        // Envelope bytes are persisted as lowercase hex.
        assert!(json.contains(&crate::sig::hex_encode(&signed_envelope(1, 1, 1_000, 20.0))));

        // Gateway restarts: restore from disk.
        let mut restored = OutageBuffer::from_json(&json).unwrap();
        assert_eq!(restored, buf);
        assert_eq!(restored.len(), 2);
        // Replayed wire packets with already-buffered keys are dropped.
        assert!(!restored
            .push(&signed_envelope(1, 1, 1_000, 20.0), RECV)
            .unwrap());
        assert!(!restored
            .push(&signed_envelope(1, 2, 2_000, 21.0), RECV)
            .unwrap());
        // New keys still flow.
        assert!(restored
            .push(&signed_envelope(1, 3, 3_000, 22.0), RECV)
            .unwrap());

        // Drain after restore contains zero duplicates, in key order.
        let drained = restored.drain();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[2].0, signed_envelope(1, 3, 3_000, 22.0));

        // Even after draining, previously seen keys stay duplicates.
        assert!(!restored
            .push(&signed_envelope(1, 3, 3_000, 22.0), RECV)
            .unwrap());
    }

    #[test]
    fn restored_envelopes_reverify_and_accept_into_a_biome() {
        let mut buf = OutageBuffer::new();
        buf.push(&signed_envelope(1, 1, 1_000, 20.0), RECV).unwrap();
        buf.push(&signed_envelope(1, 2, 2_000, 21.0), RECV).unwrap();

        // Restart cycle, then drain and run the mandatory restore contract:
        // reverify_stored (full crypto re-check) before Biome::accept.
        let mut restored = OutageBuffer::from_json(&buf.to_json().unwrap()).unwrap();
        let mut p = pipeline(&[1]);
        let mut b = Biome::new(BiomeConfig::new("biome/restore"), SEED);
        for (envelope, received_ns) in restored.drain() {
            let sealed = p.reverify_stored(&envelope, received_ns).unwrap();
            assert_eq!(b.accept(sealed), AcceptOutcome::Accepted);
        }
        assert_eq!(b.accepted_count(), 2);
        assert_eq!(p.stats().restored, 2);
    }

    #[test]
    fn tampered_buffered_envelope_fails_reverify_and_never_enters_biome() {
        // Flip a byte inside the signed payload (the value field, so the
        // dedup key is unchanged): the envelope still decodes structurally,
        // so the dumb buffer stores it — but restore-time verification kills
        // it.
        let mut tampered = signed_envelope(1, 1, 1_000, 20.0);
        // Envelope layout: array(3) head (1 byte) + bytes(48) head (2 bytes)
        // + 48-byte payload; value_q16 sits at payload offset 36.
        tampered[3 + 36] ^= 0x01;

        let mut buf = OutageBuffer::new();
        assert!(buf.push(&tampered, RECV).unwrap());

        let mut restored = OutageBuffer::from_json(&buf.to_json().unwrap()).unwrap();
        let mut p = pipeline(&[1]);
        let b = Biome::new(BiomeConfig::new("biome/tamper"), SEED);
        for (envelope, received_ns) in restored.drain() {
            assert!(matches!(
                p.reverify_stored(&envelope, received_ns),
                Err(rucelium_ingest::RejectReason::BadSignature(1))
            ));
            // No VerifiedEnvSample exists, so nothing can reach b.accept.
        }
        assert_eq!(b.accepted_count(), 0);
        assert_eq!(p.stats().bad_signature, 1);
    }

    #[test]
    fn from_json_rejects_bad_hex_and_bad_envelopes() {
        assert!(OutageBuffer::from_json(
            r#"{"entries":[{"node_id":1,"sequence":1,"envelope_hex":"zz","received_ns":1}],"seen":[]}"#
        )
        .is_err());
        assert!(OutageBuffer::from_json(
            r#"{"entries":[{"node_id":1,"sequence":1,"envelope_hex":"00ff","received_ns":1}],"seen":[]}"#
        )
        .is_err());
        assert!(OutageBuffer::from_json("not json").is_err());
    }
}
