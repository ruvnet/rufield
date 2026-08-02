//! MTU fragmentation and reassembly for links that cannot carry a whole
//! envelope in one datagram (ADR-265 §2).
//!
//! Even the compact 114-byte envelope ([`crate::envelope`]) exceeds the
//! 51-byte LoRaWAN DR0 application payload cap, so messages are split into
//! frames with a fixed 6-byte header:
//!
//! ```text
//! [0]     magic      = 0xF7
//! [1]     version    = 1
//! [2..4]  msg_id     (u16, little-endian)
//! [4]     frag_idx   (0-based)
//! [5]     frag_count (1..=255)
//! [6..]   chunk      (up to mtu - 6 bytes)
//! ```
//!
//! Single-fragment messages still carry the header so receivers parse every
//! datagram uniformly. Reassembly ([`Reassembler`]) is keyed by
//! `(from, msg_id)` where `from` is a link-layer hint (e.g. a source address
//! hash), so `msg_id` collisions across senders never merge. All timing is
//! caller-driven: `offer` and `evict_older_than` take `now_ns`, keeping the
//! layer deterministic.

use crate::envelope::CompactEnvV2;
use crate::TransportError;
use std::collections::HashMap;

/// LoRaWAN DR0 (EU868 SF12/125 kHz) maximum application payload per datagram.
pub const LORAWAN_DR0_MTU: usize = 51;

/// Magic byte identifying a fragment frame.
pub const FRAG_MAGIC: u8 = 0xF7;

/// Fragment header version.
pub const FRAG_VERSION: u8 = 1;

/// Fixed fragment header length in bytes.
pub const FRAG_HEADER_LEN: usize = 6;

/// Maximum number of fragments per message (`frag_count` is one byte).
const MAX_FRAG_COUNT: usize = 255;

/// A parsed fragment frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    /// Sender-chosen message identifier; scoped per sender, wraps freely.
    pub msg_id: u16,
    /// 0-based index of this fragment (`frag_idx < frag_count`).
    pub frag_idx: u8,
    /// Total fragments in the message (`1..=255`).
    pub frag_count: u8,
    /// The payload chunk carried by this frame.
    pub chunk: Vec<u8>,
}

impl Fragment {
    /// Parse one datagram. Bounds-checked, never panics on any input; the
    /// header magic, version, non-zero `frag_count`, and
    /// `frag_idx < frag_count` are all enforced.
    pub fn parse(datagram: &[u8]) -> Result<Fragment, TransportError> {
        if datagram.len() < FRAG_HEADER_LEN {
            return Err(TransportError::WrongLength {
                expected: FRAG_HEADER_LEN,
                actual: datagram.len(),
            });
        }
        if datagram[0] != FRAG_MAGIC {
            return Err(TransportError::BadMagic(datagram[0]));
        }
        if datagram[1] != FRAG_VERSION {
            return Err(TransportError::BadVersion(datagram[1]));
        }
        let msg_id = u16::from_le_bytes([datagram[2], datagram[3]]);
        let frag_idx = datagram[4];
        let frag_count = datagram[5];
        if frag_count == 0 {
            return Err(TransportError::BadFragment(
                "frag_count is zero".to_string(),
            ));
        }
        if frag_idx >= frag_count {
            return Err(TransportError::BadFragment(format!(
                "frag_idx {frag_idx} not below frag_count {frag_count}"
            )));
        }
        Ok(Fragment {
            msg_id,
            frag_idx,
            frag_count,
            chunk: datagram[FRAG_HEADER_LEN..].to_vec(),
        })
    }
}

/// Split `message` into datagrams of at most `mtu` bytes, each with a 6-byte
/// header followed by up to `mtu - 6` chunk bytes. Errors with
/// [`TransportError::MtuTooSmall`] when `mtu < 7` (no room for even one
/// chunk byte) and [`TransportError::TooLarge`] when the message needs more
/// than 255 fragments. An empty message yields one header-only datagram;
/// single-fragment messages still carry the header (uniform parsing).
pub fn fragment(message: &[u8], msg_id: u16, mtu: usize) -> Result<Vec<Vec<u8>>, TransportError> {
    if mtu < FRAG_HEADER_LEN + 1 {
        return Err(TransportError::MtuTooSmall(mtu));
    }
    let chunk_len = mtu - FRAG_HEADER_LEN;
    let max = chunk_len * MAX_FRAG_COUNT;
    if message.len() > max {
        return Err(TransportError::TooLarge {
            len: message.len(),
            max,
        });
    }
    let frag_count = message.len().div_ceil(chunk_len).max(1);
    let mut frames = Vec::with_capacity(frag_count);
    for (idx, chunk) in message
        .chunks(chunk_len)
        .chain(std::iter::once(&[][..]).take(usize::from(message.is_empty())))
        .enumerate()
    {
        let mut frame = Vec::with_capacity(FRAG_HEADER_LEN + chunk.len());
        frame.push(FRAG_MAGIC);
        frame.push(FRAG_VERSION);
        frame.extend_from_slice(&msg_id.to_le_bytes());
        frame.push(idx as u8);
        frame.push(frag_count as u8);
        frame.extend_from_slice(chunk);
        frames.push(frame);
    }
    debug_assert_eq!(frames.len(), frag_count);
    Ok(frames)
}

/// Fragment a compact envelope at [`LORAWAN_DR0_MTU`]. Infallible by
/// construction: 114 bytes split into 45-byte chunks is exactly 3 frames of
/// at most 51 bytes each (asserted in tests).
#[must_use]
pub fn fragment_compact(env: &CompactEnvV2, msg_id: u16) -> Vec<Vec<u8>> {
    fragment(&env.encode(), msg_id, LORAWAN_DR0_MTU)
        .expect("114-byte envelope always fits 3 DR0 frames")
}

/// One in-flight partially reassembled message.
#[derive(Debug)]
struct Pending {
    /// `frag_count` claimed by the first fragment seen for this key.
    frag_count: u8,
    /// Chunks received so far, indexed by `frag_idx`.
    chunks: Vec<Option<Vec<u8>>>,
    /// How many distinct fragments have arrived.
    received: usize,
    /// `now_ns` when the first fragment for this key arrived.
    first_seen_ns: u64,
    /// Monotonic insertion counter, tie-breaker for deterministic eviction.
    seq: u64,
}

/// Reassembles fragment datagrams back into messages, keyed by
/// `(from, msg_id)`.
///
/// Semantics:
///
/// - **Duplicates** of an already-held fragment index are silently ignored.
/// - A fragment whose `frag_count` **conflicts** with the pending entry drops
///   that entry and returns [`TransportError::Inconsistent`].
/// - [`Reassembler::offer`] returns `Some(message)` **exactly once**, when
///   the last missing fragment arrives; the completed state is then
///   forgotten. A later duplicate fragment of a completed message is
///   indistinguishable from a new message and starts a fresh pending entry —
///   callers wanting end-to-end deduplication use the payload's own sequence
///   number (the ingest sequence window), not this layer.
/// - **Capacity**: at most `max_pending` incomplete messages are held; when
///   full, the oldest pending entry (by first-seen `now_ns`, insertion order
///   breaking ties) is evicted, so a lost-fragment message can never leak
///   memory forever.
/// - **Timeout GC** is explicit and caller-driven: [`Reassembler::evict_older_than`].
#[derive(Debug)]
pub struct Reassembler {
    max_pending: usize,
    pending: HashMap<(u64, u16), Pending>,
    next_seq: u64,
}

impl Reassembler {
    /// Create a reassembler holding at most `max_pending` incomplete
    /// messages (clamped to at least 1).
    #[must_use]
    pub fn new(max_pending: usize) -> Self {
        Reassembler {
            max_pending: max_pending.max(1),
            pending: HashMap::new(),
            next_seq: 0,
        }
    }

    /// Offer one received datagram. `from` is a link-layer sender hint
    /// (e.g. a source address hash) scoping `msg_id`; `now_ns` is the
    /// caller's clock, recorded when a key is first seen and used for
    /// eviction ordering. Returns `Ok(Some(message))` when this datagram
    /// completes a message, `Ok(None)` when more fragments are needed (or
    /// the datagram was a duplicate), and an error for unparseable or
    /// inconsistent fragments.
    pub fn offer(
        &mut self,
        from: u64,
        datagram: &[u8],
        now_ns: u64,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        let frag = Fragment::parse(datagram)?;
        let key = (from, frag.msg_id);
        let count = usize::from(frag.frag_count);
        let idx = usize::from(frag.frag_idx);

        if let Some(p) = self.pending.get_mut(&key) {
            if p.frag_count != frag.frag_count {
                self.pending.remove(&key);
                return Err(TransportError::Inconsistent);
            }
            if p.chunks[idx].is_some() {
                return Ok(None); // duplicate fragment: ignored
            }
            p.chunks[idx] = Some(frag.chunk);
            p.received += 1;
            if p.received == count {
                let done = self.pending.remove(&key).expect("entry present");
                return Ok(Some(assemble(done.chunks)));
            }
            return Ok(None);
        }

        if count == 1 {
            // Complete in one datagram; nothing to store.
            return Ok(Some(frag.chunk));
        }
        if self.pending.len() >= self.max_pending {
            self.evict_oldest();
        }
        let mut chunks = vec![None; count];
        chunks[idx] = Some(frag.chunk);
        self.pending.insert(
            key,
            Pending {
                frag_count: frag.frag_count,
                chunks,
                received: 1,
                first_seen_ns: now_ns,
                seq: self.next_seq,
            },
        );
        self.next_seq += 1;
        Ok(None)
    }

    /// Drop every pending entry first seen strictly before `cutoff_ns` and
    /// return how many were evicted. Explicit, caller-driven timeout GC.
    pub fn evict_older_than(&mut self, cutoff_ns: u64) -> usize {
        let before = self.pending.len();
        self.pending.retain(|_, p| p.first_seen_ns >= cutoff_ns);
        before - self.pending.len()
    }

    /// Number of incomplete messages currently held.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Remove the oldest pending entry (deterministic: smallest
    /// `(first_seen_ns, seq)`).
    fn evict_oldest(&mut self) {
        if let Some(&key) = self
            .pending
            .iter()
            .min_by_key(|(_, p)| (p.first_seen_ns, p.seq))
            .map(|(k, _)| k)
        {
            self.pending.remove(&key);
        }
    }
}

/// Concatenate a complete chunk vector into the reassembled message.
fn assemble(chunks: Vec<Option<Vec<u8>>>) -> Vec<u8> {
    let mut out = Vec::with_capacity(chunks.iter().flatten().map(Vec::len).sum());
    for c in chunks {
        out.extend_from_slice(&c.expect("all fragments received"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{sign_compact, verify_compact, CompactEnvV2, COMPACT_ENV_V2_LEN};
    use rucelium_abi::NodeSigner;

    const SEED: &[u8; 32] = b"rucelium-provision-seed-32-byte!";

    fn signed_env() -> (CompactEnvV2, [u8; 32]) {
        let signer = NodeSigner::for_node(SEED, 42);
        let mut payload = [0u8; 48];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(29).wrapping_add(3);
        }
        (sign_compact(&signer, &payload), signer.public_key())
    }

    #[test]
    fn header_layout_pinned() {
        let frames = fragment(b"hello world", 0xBEEF, 10).unwrap();
        // chunk_len = 4 → ceil(11/4) = 3 frames.
        assert_eq!(frames.len(), 3);
        let f = &frames[0];
        assert_eq!(f[0], FRAG_MAGIC);
        assert_eq!(f[1], FRAG_VERSION);
        assert_eq!([f[2], f[3]], 0xBEEF_u16.to_le_bytes());
        assert_eq!(f[4], 0); // frag_idx
        assert_eq!(f[5], 3); // frag_count
        assert_eq!(&f[6..], b"hell");
        assert_eq!(&frames[2][6..], b"rld");
    }

    #[test]
    fn compact_envelope_fits_dr0_in_exactly_three_frames() {
        let (env, pk) = signed_env();
        let frames = fragment_compact(&env, 7);
        assert_eq!(frames.len(), 3);
        for f in &frames {
            assert!(f.len() <= LORAWAN_DR0_MTU, "frame of {} bytes", f.len());
        }
        // Reassemble and get the identical 114 bytes back.
        let mut r = Reassembler::new(8);
        assert_eq!(r.offer(1, &frames[0], 10).unwrap(), None);
        assert_eq!(r.offer(1, &frames[1], 20).unwrap(), None);
        let msg = r.offer(1, &frames[2], 30).unwrap().unwrap();
        assert_eq!(msg.len(), COMPACT_ENV_V2_LEN);
        assert_eq!(msg, env.encode().to_vec());
        // ...and the result parses and verifies.
        let back = CompactEnvV2::parse(&msg).unwrap();
        verify_compact(&back, &pk).unwrap();
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn out_of_order_reassembly_works() {
        let frames = fragment(b"the quick brown fox jumps", 9, 16).unwrap();
        assert_eq!(frames.len(), 3);
        let mut r = Reassembler::new(4);
        assert_eq!(r.offer(5, &frames[2], 1).unwrap(), None);
        assert_eq!(r.offer(5, &frames[0], 2).unwrap(), None);
        let msg = r.offer(5, &frames[1], 3).unwrap().unwrap();
        assert_eq!(msg, b"the quick brown fox jumps");
    }

    #[test]
    fn duplicate_fragments_ignored() {
        let frames = fragment(&[7u8; 30], 1, 16).unwrap();
        let mut r = Reassembler::new(4);
        assert_eq!(r.offer(1, &frames[0], 1).unwrap(), None);
        assert_eq!(r.offer(1, &frames[0], 2).unwrap(), None); // dup
        assert_eq!(r.offer(1, &frames[0], 3).unwrap(), None); // dup again
        assert_eq!(r.pending(), 1);
        assert_eq!(r.offer(1, &frames[1], 4).unwrap(), None);
        assert_eq!(r.offer(1, &frames[2], 5).unwrap().unwrap(), vec![7u8; 30]);
    }

    #[test]
    fn same_msg_id_from_two_senders_does_not_merge() {
        let msg_a = vec![0xAA; 30];
        let msg_b = vec![0xBB; 30];
        let fa = fragment(&msg_a, 77, 16).unwrap();
        let fb = fragment(&msg_b, 77, 16).unwrap();
        let mut r = Reassembler::new(8);
        // Interleave fragments from senders 1 and 2 with the same msg_id.
        assert_eq!(r.offer(1, &fa[0], 1).unwrap(), None);
        assert_eq!(r.offer(2, &fb[0], 2).unwrap(), None);
        assert_eq!(r.offer(1, &fa[1], 3).unwrap(), None);
        assert_eq!(r.offer(2, &fb[1], 4).unwrap(), None);
        assert_eq!(r.pending(), 2);
        assert_eq!(r.offer(1, &fa[2], 5).unwrap().unwrap(), msg_a);
        assert_eq!(r.offer(2, &fb[2], 6).unwrap().unwrap(), msg_b);
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn interleaved_msg_ids_from_one_sender_both_complete() {
        let msg_a = vec![1u8; 25];
        let msg_b = vec![2u8; 25];
        let fa = fragment(&msg_a, 10, 16).unwrap();
        let fb = fragment(&msg_b, 11, 16).unwrap();
        let mut r = Reassembler::new(8);
        assert_eq!(r.offer(9, &fa[0], 1).unwrap(), None);
        assert_eq!(r.offer(9, &fb[0], 2).unwrap(), None);
        assert_eq!(r.offer(9, &fb[1], 3).unwrap(), None);
        assert_eq!(r.offer(9, &fa[1], 4).unwrap(), None);
        assert_eq!(r.offer(9, &fb[2], 5).unwrap().unwrap(), msg_b);
        assert_eq!(r.offer(9, &fa[2], 6).unwrap().unwrap(), msg_a);
    }

    #[test]
    fn lost_fragment_stays_pending_until_explicit_eviction() {
        let frames = fragment(&[3u8; 30], 5, 16).unwrap();
        let mut r = Reassembler::new(4);
        assert_eq!(r.offer(1, &frames[0], 1_000).unwrap(), None);
        assert_eq!(r.offer(1, &frames[2], 2_000).unwrap(), None);
        // frames[1] is lost: never completes.
        assert_eq!(r.pending(), 1);
        // Cutoff at or before first-seen keeps it...
        assert_eq!(r.evict_older_than(1_000), 0);
        assert_eq!(r.pending(), 1);
        // ...a later cutoff clears it.
        assert_eq!(r.evict_older_than(1_001), 1);
        assert_eq!(r.pending(), 0);
        // The surviving fragment alone can no longer complete anything.
        assert_eq!(r.offer(1, &frames[1], 3_000).unwrap(), None);
        assert_eq!(r.pending(), 1);
    }

    #[test]
    fn max_pending_evicts_oldest_first() {
        let mut r = Reassembler::new(2);
        let fa = fragment(&[1u8; 20], 1, 16).unwrap();
        let fb = fragment(&[2u8; 20], 2, 16).unwrap();
        let fc = fragment(&[3u8; 20], 3, 16).unwrap();
        assert_eq!(r.offer(1, &fa[0], 100).unwrap(), None); // oldest
        assert_eq!(r.offer(1, &fb[0], 200).unwrap(), None);
        assert_eq!(r.pending(), 2);
        // Third message evicts msg_id 1 (first seen at 100).
        assert_eq!(r.offer(1, &fc[0], 300).unwrap(), None);
        assert_eq!(r.pending(), 2);
        // B and C still complete...
        assert_eq!(r.offer(1, &fb[1], 400).unwrap().unwrap(), vec![2u8; 20]);
        assert_eq!(r.offer(1, &fc[1], 500).unwrap().unwrap(), vec![3u8; 20]);
        // ...A's remaining fragment starts over from nothing.
        assert_eq!(r.offer(1, &fa[1], 600).unwrap(), None);
        assert_eq!(r.pending(), 1);
    }

    #[test]
    fn completed_message_state_is_forgotten() {
        let frames = fragment(&[9u8; 20], 4, 16).unwrap();
        let mut r = Reassembler::new(4);
        assert_eq!(r.offer(1, &frames[0], 1).unwrap(), None);
        assert!(r.offer(1, &frames[1], 2).unwrap().is_some());
        assert_eq!(r.pending(), 0);
        // A late duplicate starts a fresh pending message.
        assert_eq!(r.offer(1, &frames[0], 3).unwrap(), None);
        assert_eq!(r.pending(), 1);
    }

    #[test]
    fn conflicting_frag_count_drops_entry_and_errors() {
        let frames = fragment(&[8u8; 30], 6, 16).unwrap(); // frag_count 3
        let mut r = Reassembler::new(4);
        assert_eq!(r.offer(1, &frames[0], 1).unwrap(), None);
        let mut lying = frames[1].clone();
        lying[5] = 4; // claims frag_count 4 for the same (from, msg_id)
        assert_eq!(r.offer(1, &lying, 2), Err(TransportError::Inconsistent));
        assert_eq!(r.pending(), 0, "conflicting entry must be dropped");
    }

    #[test]
    fn single_fragment_and_empty_messages_round_trip() {
        let mut r = Reassembler::new(1);
        // Small message: one frame, still headered, completes immediately.
        let frames = fragment(b"hi", 1, 51).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), FRAG_HEADER_LEN + 2);
        assert_eq!(r.offer(1, &frames[0], 1).unwrap().unwrap(), b"hi".to_vec());
        // Empty message: one header-only frame.
        let frames = fragment(&[], 2, 51).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), FRAG_HEADER_LEN);
        assert_eq!(
            r.offer(1, &frames[0], 2).unwrap().unwrap(),
            Vec::<u8>::new()
        );
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn mtu_edges() {
        // mtu 7: 1-byte chunks, works.
        let msg = [0xABu8; 5];
        let frames = fragment(&msg, 3, 7).unwrap();
        assert_eq!(frames.len(), 5);
        let mut r = Reassembler::new(4);
        let mut out = None;
        for (i, f) in frames.iter().enumerate() {
            out = r.offer(1, f, i as u64).unwrap();
        }
        assert_eq!(out.unwrap(), msg.to_vec());
        // mtu 6: header only, no room for data.
        assert_eq!(fragment(&msg, 3, 6), Err(TransportError::MtuTooSmall(6)));
        assert_eq!(fragment(&msg, 3, 0), Err(TransportError::MtuTooSmall(0)));
    }

    #[test]
    fn oversized_message_rejected() {
        // mtu 7 → chunk 1 byte → max 255 bytes.
        assert!(fragment(&[0u8; 255], 1, 7).is_ok());
        assert_eq!(
            fragment(&[0u8; 256], 1, 7),
            Err(TransportError::TooLarge { len: 256, max: 255 })
        );
    }

    #[test]
    fn parse_rejects_bad_headers() {
        assert!(matches!(
            Fragment::parse(&[]),
            Err(TransportError::WrongLength { expected: 6, .. })
        ));
        assert!(matches!(
            Fragment::parse(&[FRAG_MAGIC, FRAG_VERSION, 0, 0, 0]),
            Err(TransportError::WrongLength { .. })
        ));
        assert_eq!(
            Fragment::parse(&[0x00, FRAG_VERSION, 0, 0, 0, 1]),
            Err(TransportError::BadMagic(0x00))
        );
        assert_eq!(
            Fragment::parse(&[FRAG_MAGIC, 2, 0, 0, 0, 1]),
            Err(TransportError::BadVersion(2))
        );
        assert!(matches!(
            Fragment::parse(&[FRAG_MAGIC, FRAG_VERSION, 0, 0, 0, 0]),
            Err(TransportError::BadFragment(_))
        ));
        // frag_idx >= frag_count
        assert!(matches!(
            Fragment::parse(&[FRAG_MAGIC, FRAG_VERSION, 0, 0, 3, 3]),
            Err(TransportError::BadFragment(_))
        ));
    }

    #[test]
    fn parse_never_panics_on_arbitrary_bytes() {
        // Deterministic LCG pseudo-fuzz over lengths 0..80.
        let mut x: u64 = 0xF701_F701_F701_F701;
        for len in 0..80usize {
            let mut buf = vec![0u8; len];
            for b in &mut buf {
                x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                *b = (x >> 56) as u8;
            }
            let _ = Fragment::parse(&buf); // must not panic
                                           // And a reassembler must swallow whatever parses.
            let mut r = Reassembler::new(2);
            let _ = r.offer(0, &buf, len as u64);
        }
    }
}
