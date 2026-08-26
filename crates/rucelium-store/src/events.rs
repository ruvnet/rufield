//! `EventStore` — the durable event log, mirroring
//! [`crate::ObservationStore`] for [`EnvironmentalEvent`]s (ADR-265 §3).
//!
//! Events are `DataClass::FederatedEvent` with a retention measured in
//! years (ADR-264 §10), so v0.1 has no retention enforcement here.

use crate::segment::{
    append_dedup_lines, encode_line, list_segments, read_dedup_index, read_segment,
    segment_file_name,
};
use crate::{AppendOutcome, StoreError};
use rucelium_core::EnvironmentalEvent;
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Event segment file prefix (`evt-NNNNNN.jsonl`).
const PREFIX: &str = "evt";

/// One live event segment.
struct SegmentState {
    name: String,
    records: usize,
}

/// Durable append-only store for [`EnvironmentalEvent`]s, deduped by
/// `event_id`.
///
/// Same design as [`crate::ObservationStore`]: one CRC-framed JSON line
/// (`<crc32-hex> <json>`) per event in zero-padded `evt-NNNNNN.jsonl`
/// segments, a persistent `dedup.idx` (one `event_id` per line) that is
/// authoritative on open, torn-tail repair on the final segment, and the
/// same two durability modes selected by the `sync` flag (crate docs).
pub struct EventStore {
    dir: PathBuf,
    segment_max_records: usize,
    /// Fsync (`sync_data`) segment and dedup-index writes on every append.
    sync: bool,
    /// Every `event_id` ever appended.
    seen: BTreeSet<String>,
    segments: Vec<SegmentState>,
    next_segment_index: u64,
}

fn parse_event(line: &str) -> Result<EnvironmentalEvent, String> {
    serde_json::from_str(line).map_err(|e| e.to_string())
}

/// Parse one `dedup.idx` line: a bare, non-empty `event_id`.
fn parse_dedup_id(line: &str) -> Result<String, String> {
    if line.is_empty() {
        return Err("empty event_id".to_string());
    }
    Ok(line.to_string())
}

impl EventStore {
    /// Open (or create) an event store at `dir`.
    ///
    /// The dedup index is rebuilt from the persistent `dedup.idx` file
    /// (authoritative), then existing `evt-*.jsonl` segments are scanned;
    /// any `event_id` present in a segment but missing from `dedup.idx`
    /// (legacy store) is merged in and appended back to the index. Recovery
    /// and durability rules match [`crate::ObservationStore::open`] —
    /// including the meaning of the `sync` flag; a `segment_max_records` of
    /// `0` is treated as `1`.
    pub fn open(dir: &Path, segment_max_records: usize, sync: bool) -> Result<Self, StoreError> {
        fs::create_dir_all(dir)?;
        let mut seen: BTreeSet<String> =
            read_dedup_index(dir, parse_dedup_id)?.into_iter().collect();
        let listed = list_segments(dir, PREFIX)?;
        let n = listed.len();
        let mut segments = Vec::with_capacity(n);
        let mut next_segment_index = 0u64;
        let mut missing_from_index = Vec::new();
        for (i, (name, index)) in listed.into_iter().enumerate() {
            let repair_torn_tail = i + 1 == n;
            let (records, _) =
                read_segment(&dir.join(&name), &name, repair_torn_tail, parse_event)?;
            for e in &records {
                if seen.insert(e.event_id.clone()) {
                    missing_from_index.push(e.event_id.clone());
                }
            }
            segments.push(SegmentState {
                name,
                records: records.len(),
            });
            next_segment_index = index + 1;
        }
        // Legacy upgrade / crash repair: persist ids the index was missing.
        append_dedup_lines(dir, &missing_from_index, sync)?;
        Ok(EventStore {
            dir: dir.to_path_buf(),
            segment_max_records: segment_max_records.max(1),
            sync,
            seen,
            segments,
            next_segment_index,
        })
    }

    /// Append an event, deduplicating by `event_id`. The event is validated
    /// first (invalid → [`StoreError::Core`]). The CRC-framed line is
    /// written to the segment, then the `event_id` is appended to
    /// `dedup.idx`; both writes are flushed to the OS, and additionally
    /// `sync_data()`-fsynced when the store was opened with `sync = true`
    /// (crate docs describe what each mode guarantees).
    pub fn append(&mut self, event: &EnvironmentalEvent) -> Result<AppendOutcome, StoreError> {
        event
            .validate()
            .map_err(|e| StoreError::Core(e.to_string()))?;
        if self.seen.contains(&event.event_id) {
            return Ok(AppendOutcome::Duplicate);
        }
        let roll = match self.segments.last() {
            None => true,
            Some(s) => s.records >= self.segment_max_records,
        };
        if roll {
            let name = segment_file_name(PREFIX, self.next_segment_index);
            self.next_segment_index += 1;
            self.segments.push(SegmentState { name, records: 0 });
        }
        let json = serde_json::to_string(event).map_err(|e| StoreError::Core(e.to_string()))?;
        let line = encode_line(&json);
        let seg = self.segments.last_mut().expect("segment exists after roll");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join(&seg.name))?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        file.flush()?;
        if self.sync {
            file.sync_data()?;
        }
        // Segment first, index second (see ObservationStore::append).
        append_dedup_lines(&self.dir, std::slice::from_ref(&event.event_id), self.sync)?;
        self.seen.insert(event.event_id.clone());
        seg.records += 1;
        Ok(AppendOutcome::Appended)
    }

    /// Number of unique events stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.segments.iter().map(|s| s.records).sum()
    }

    /// Whether no events are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Live segment file names, sorted.
    #[must_use]
    pub fn segments(&self) -> Vec<String> {
        self.segments.iter().map(|s| s.name.clone()).collect()
    }

    /// Full deterministic replay: every stored event in append order, read
    /// back from disk. CRC prefixes are verified and stripped.
    pub fn iter(&self) -> Result<Vec<EnvironmentalEvent>, StoreError> {
        let mut out = Vec::with_capacity(self.len());
        for seg in &self.segments {
            let (records, _) =
                read_segment(&self.dir.join(&seg.name), &seg.name, false, parse_event)?;
            out.extend(records);
        }
        Ok(out)
    }

    /// The last `limit` events, in append order.
    pub fn recent(&self, limit: usize) -> Result<Vec<EnvironmentalEvent>, StoreError> {
        let mut all = self.iter()?;
        let skip = all.len().saturating_sub(limit);
        Ok(all.split_off(skip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{event, temp_dir};

    #[test]
    fn append_dedup_and_replay() {
        let dir = temp_dir("evt");
        let mut store = EventStore::open(&dir, 2, false).unwrap();
        let events = [
            event("evt-0001", 5_000),
            event("evt-0002", 6_000),
            event("evt-0003", 7_000),
        ];
        for e in &events {
            assert_eq!(store.append(e).unwrap(), AppendOutcome::Appended);
        }
        assert_eq!(
            store.append(&event("evt-0002", 9_999)).unwrap(),
            AppendOutcome::Duplicate
        );
        assert_eq!(store.len(), 3);
        assert!(!store.is_empty());
        assert_eq!(
            store.segments(),
            vec!["evt-000000.jsonl", "evt-000001.jsonl"]
        );
        assert_eq!(store.iter().unwrap(), events.to_vec());
        assert_eq!(store.recent(1).unwrap(), events[2..].to_vec());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reopen_preserves_dedup_and_order() {
        let dir = temp_dir("evt-reopen");
        let mut store = EventStore::open(&dir, 2, false).unwrap();
        store.append(&event("evt-0001", 5_000)).unwrap();
        store.append(&event("evt-0002", 6_000)).unwrap();
        drop(store);

        // The event ids were persisted to dedup.idx.
        assert_eq!(
            fs::read_to_string(dir.join("dedup.idx")).unwrap(),
            "evt-0001\nevt-0002\n"
        );
        let mut reopened = EventStore::open(&dir, 2, false).unwrap();
        assert_eq!(reopened.len(), 2);
        assert_eq!(
            reopened.append(&event("evt-0001", 5_000)).unwrap(),
            AppendOutcome::Duplicate
        );
        assert_eq!(
            reopened.append(&event("evt-0003", 7_000)).unwrap(),
            AppendOutcome::Appended
        );
        let ids: Vec<String> = reopened
            .iter()
            .unwrap()
            .into_iter()
            .map(|e| e.event_id)
            .collect();
        assert_eq!(ids, vec!["evt-0001", "evt-0002", "evt-0003"]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn legacy_store_without_index_upgrades_on_open() {
        let dir = temp_dir("evt-legacy");
        fs::create_dir_all(&dir).unwrap();
        // Pre-CRC, pre-index layout: bare JSON line, no dedup.idx.
        let e = event("evt-legacy-1", 5_000);
        let legacy = serde_json::to_string(&e).unwrap() + "\n";
        fs::write(dir.join("evt-000000.jsonl"), legacy).unwrap();

        let mut store = EventStore::open(&dir, 10, false).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.iter().unwrap(), vec![e.clone()]);
        assert_eq!(
            fs::read_to_string(dir.join("dedup.idx")).unwrap(),
            "evt-legacy-1\n"
        );
        assert_eq!(store.append(&e).unwrap(), AppendOutcome::Duplicate);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sync_mode_appends_and_reopens() {
        let dir = temp_dir("evt-sync");
        let mut store = EventStore::open(&dir, 10, true).unwrap();
        store.append(&event("evt-0001", 5_000)).unwrap();
        drop(store);
        let mut reopened = EventStore::open(&dir, 10, true).unwrap();
        assert_eq!(
            reopened.append(&event("evt-0001", 5_000)).unwrap(),
            AppendOutcome::Duplicate
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn invalid_event_is_a_core_error() {
        let dir = temp_dir("evt-invalid");
        let mut store = EventStore::open(&dir, 10, false).unwrap();
        let mut bad = event("evt-0001", 5_000);
        bad.evidence.clear();
        assert!(matches!(store.append(&bad), Err(StoreError::Core(_))));
        assert!(store.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }
}
