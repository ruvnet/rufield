//! # rucelium-store
//!
//! Durable gateway store for **RuCelium** (ADR-265 §3): an append-only,
//! segmented, JSONL-on-disk log with a persistent dedup index, crash
//! recovery, deterministic replay, and retention enforcement.
//!
//! Two stores share the same segment machinery:
//!
//! * [`ObservationStore`] — normalized [`rucelium_core::EnvSample`]s, deduped
//!   by the stable `(node_id, sequence)` key, files `obs-NNNNNN.jsonl`.
//! * [`EventStore`] — [`rucelium_core::EnvironmentalEvent`]s, deduped by
//!   `event_id`, files `evt-NNNNNN.jsonl`.
//!
//! ## Design notes
//!
//! * **Durability** is a per-store choice: `open(dir, segment_max_records,
//!   sync)`. With `sync = true`, every accepted append is
//!   `sync_data()`-fsynced — segment file *and* dedup index — before
//!   `append` returns, so an accepted record survives OS crash and power
//!   loss (to the extent the storage stack honors fsync). With
//!   `sync = false`, appends are only flushed to the OS page cache
//!   (`File::flush`): a *process* crash loses nothing already flushed, but
//!   a host power loss or kernel panic may lose the unsynced tail; crash
//!   recovery then treats the partial last line as a torn tail, and any
//!   fully-lost trailing records are simply absent (callers must be able
//!   to replay them). "Durable" below means durable *for the chosen mode*.
//! * **Integrity**: each stored line is `<crc32-hex> <json>` — CRC-32
//!   (IEEE) over the exact JSON bytes. On open a newline-terminated line
//!   whose CRC does not match is [`StoreError::Corrupt`] with reason
//!   `"crc mismatch"` — an integrity failure, never repaired. Legacy lines
//!   of bare JSON (written before the CRC prefix existed) are still
//!   accepted on read; new writes always carry a CRC.
//! * **Crash recovery**: on open, a *final* line of the *final* segment
//!   that lacks its trailing newline and cannot be decoded (partial JSON
//!   or an incomplete CRC prefix) is a torn write and is truncated away —
//!   a crash mid-write must not poison the store. Malformed data anywhere
//!   else is [`StoreError::Corrupt`].
//! * **Retention** is segment-level: whole expired segment files are
//!   deleted, never rewritten — cheap and O(1) per segment. The current
//!   (last) segment is never deleted.
//! * **Dedup persistence**: every accepted key is also appended to a
//!   per-store `dedup.idx` file (observations: `node_id sequence` per
//!   line; events: one `event_id` per line). On open the index file is
//!   authoritative; keys found in segments but missing from the index
//!   (legacy directories) are merged in and written back. Dedup keys are
//!   kept forever — in memory *and* in `dedup.idx` — even after retention
//!   deletes their payload segments, so replaying an expired record after
//!   a restart is still a duplicate. Keys are tiny (a `(u64, u32)` pair or
//!   a short id string); retention frees payload bytes, not dedup state.
//! * **Determinism**: the library never reads a wall clock — callers pass
//!   `now_ns` to [`ObservationStore::enforce_retention`].

#![doc(html_root_url = "https://docs.rs/rucelium-store/0.1.0")]

mod events;
mod observations;
mod segment;

pub use events::EventStore;
pub use observations::{ObservationStore, StoreStats};
pub use segment::SegmentInfo;

use std::fmt;

/// Errors raised by the durable gateway store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// An underlying filesystem operation failed (carries the
    /// `std::io::Error` message).
    Io(String),
    /// A segment file contains malformed data outside the tolerated
    /// torn-tail position.
    Corrupt {
        /// Segment file name (e.g. `obs-000003.jsonl`).
        segment: String,
        /// 1-based line number of the malformed line.
        line: usize,
        /// Parser diagnostic.
        reason: String,
    },
    /// A core data-model rule was violated (invalid sample/event, or a
    /// serialization failure).
    Core(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io(m) => write!(f, "storage I/O error: {m}"),
            StoreError::Corrupt {
                segment,
                line,
                reason,
            } => write!(f, "corrupt segment {segment} at line {line}: {reason}"),
            StoreError::Core(m) => write!(f, "core data error: {m}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e.to_string())
    }
}

/// Result of an append attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendOutcome {
    /// The record was new and was written to the current segment (fsynced
    /// when the store was opened with `sync = true`; otherwise flushed to
    /// the OS only — see the crate durability notes).
    Appended,
    /// The record's dedup key was already known; nothing was written.
    Duplicate,
}

#[cfg(test)]
pub(crate) mod testutil {
    use rucelium_core::{
        EnvSample, EnvironmentalEvent, EventKind, EvidenceRef, GeoPoint, SampleProvenance,
        SensorModality, Severity, Uncertainty,
    };
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Unique per-test temp dir under `std::env::temp_dir()`. `std::time` is
    /// used only to make the *name* unique — never for store logic.
    pub(crate) fn temp_dir(tag: &str) -> PathBuf {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rucelium-store-{tag}-{}-{n}-{t}",
            std::process::id()
        ))
    }

    /// A valid sample with the given identity, measurement time, and value.
    pub(crate) fn sample(node_id: u64, sequence: u32, measured_ns: u64, value: f64) -> EnvSample {
        EnvSample {
            node_id,
            sequence,
            measured_ns,
            received_ns: measured_ns + 1_000,
            geo: GeoPoint::new(514_778_216, -14_767, 46_000).expect("valid geo"),
            modality: SensorModality::Weather,
            observed_property: "air_temperature".into(),
            unit: "Cel".into(),
            value,
            quality: 0.98,
            uncertainty: Uncertainty::symmetric(value, 0.3),
            calibration_id: 3,
            flags: 0,
            battery_mv: 3600,
            provenance: SampleProvenance {
                firmware_hash: "sha256:abc".into(),
                signer_pubkey_hex: "00ff".into(),
                verified: true,
                lineage: vec!["cal:3".into()],
            },
        }
    }

    /// A valid event with the given id and detection time.
    pub(crate) fn event(event_id: &str, detected_ns: u64) -> EnvironmentalEvent {
        EnvironmentalEvent {
            evidence_digest: None,
            spec_version: rucelium_core::SPEC_VERSION.into(),
            event_id: event_id.into(),
            biome_id: "biome/thames-estuary".into(),
            kind: EventKind::FloodRisk,
            severity: Severity::Warning,
            modality: SensorModality::WaterQuality,
            geo: GeoPoint::new(514_000_000, 500_000, 0).expect("valid geo"),
            window_start_ns: detected_ns.saturating_sub(4_000),
            window_end_ns: detected_ns,
            detected_ns,
            evidence: vec![EvidenceRef {
                node_id: 7,
                sequence: 42,
            }],
            confidence: 0.9,
            message: "water level rising".into(),
            signature_hex: None,
            signer_pubkey_hex: None,
        }
    }
}
