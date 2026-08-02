//! Segment file machinery shared by [`crate::ObservationStore`] and
//! [`crate::EventStore`]: naming, directory scan, per-line CRC framing,
//! line-oriented reads with torn-tail repair, and the persistent dedup
//! index file.
//!
//! ## On-disk line format
//!
//! Every record line written since v0.2 is `<crc08x> <json>` — eight
//! lowercase hex digits of the CRC-32 (IEEE) of the exact JSON bytes, one
//! space, then the JSON, then `\n`. Legacy lines that are bare JSON (no CRC
//! prefix) are still accepted on read so pre-CRC store directories keep
//! working; new writes always carry a CRC.

use crate::StoreError;
use serde::Serialize;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::OnceLock;

/// Name of the persistent append-only dedup index file, one per store
/// directory (each store owns its own directory).
pub(crate) const DEDUP_INDEX_FILE: &str = "dedup.idx";

/// In-memory metadata for one on-disk segment file, rebuilt on open and
/// updated on append.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SegmentInfo {
    /// Segment file name (e.g. `obs-000002.jsonl`).
    pub name: String,
    /// Number of records in the segment.
    pub records: usize,
    /// Smallest `measured_ns` in the segment (`u64::MAX` while empty).
    pub min_measured_ns: u64,
    /// Largest `measured_ns` in the segment (`0` while empty).
    pub max_measured_ns: u64,
}

impl SegmentInfo {
    /// An empty segment about to receive its first record.
    pub(crate) fn empty(name: String) -> Self {
        SegmentInfo {
            name,
            records: 0,
            min_measured_ns: u64::MAX,
            max_measured_ns: 0,
        }
    }
}

/// CRC-32 lookup table (IEEE 802.3 reflected polynomial `0xEDB88320`),
/// built once.
fn crc32_table() -> &'static [u32; 256] {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [0u32; 256];
        for (i, slot) in table.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *slot = c;
        }
        table
    })
}

/// CRC-32 (IEEE) of `bytes` — the standard checksum used by Ethernet, gzip,
/// and zip (`crc32(b"123456789") == 0xCBF4_3926`).
pub(crate) fn crc32(bytes: &[u8]) -> u32 {
    let table = crc32_table();
    let mut c = 0xFFFF_FFFFu32;
    for &b in bytes {
        c = table[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

/// Encode one record line (without the trailing newline): `<crc08x> <json>`.
pub(crate) fn encode_line(json: &str) -> String {
    format!("{:08x} {json}", crc32(json.as_bytes()))
}

/// Split a stored line into its CRC prefix and JSON payload. Returns `None`
/// when the line does not have a complete `<8 hex digits><space>` prefix
/// (legacy bare-JSON line, or a torn/garbage line).
fn split_crc(line: &str) -> Option<(u32, &str)> {
    let b = line.as_bytes();
    if b.len() < 9 || b[8] != b' ' || !b[..8].iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let crc = u32::from_str_radix(&line[..8], 16).ok()?;
    Some((crc, &line[9..]))
}

/// Why a stored line failed to decode.
enum LineFailure {
    /// The line is well-formed `<crc> <json>` and the JSON parses, but the
    /// CRC does not match the JSON bytes: an integrity failure, never
    /// repaired by torn-tail truncation.
    CrcMismatch,
    /// The line is not decodable at all (truncated JSON, garbage, invalid
    /// UTF-8, ...). Repairable as a torn tail only in the final,
    /// non-newline-terminated position.
    Malformed(String),
}

/// Decode one stored line: CRC-framed (`<crc08x> <json>`) or legacy bare
/// JSON.
fn decode_line<T, F>(line: &str, parse: &F) -> Result<T, LineFailure>
where
    F: Fn(&str) -> Result<T, String>,
{
    if let Some((crc, json)) = split_crc(line) {
        match parse(json) {
            Ok(record) => {
                if crc32(json.as_bytes()) == crc {
                    Ok(record)
                } else {
                    Err(LineFailure::CrcMismatch)
                }
            }
            Err(e) => Err(LineFailure::Malformed(e)),
        }
    } else {
        // Legacy (pre-CRC) bare-JSON line — accepted for migration.
        parse(line).map_err(LineFailure::Malformed)
    }
}

/// Segment file name for `index`: `{prefix}-{index:06}.jsonl`. Zero-padding
/// to six digits keeps lexicographic order equal to numeric order for up to
/// a million segments — far beyond any v0.1 deployment.
pub(crate) fn segment_file_name(prefix: &str, index: u64) -> String {
    format!("{prefix}-{index:06}.jsonl")
}

/// List `{prefix}-NNNNNN.jsonl` files in `dir` as `(name, index)`, sorted
/// lexicographically by name. Non-matching files are ignored.
pub(crate) fn list_segments(dir: &Path, prefix: &str) -> Result<Vec<(String, u64)>, StoreError> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(index) = parse_segment_index(name, prefix) {
            out.push((name.to_string(), index));
        }
    }
    out.sort();
    Ok(out)
}

/// Parse the numeric index out of `{prefix}-NNNNNN.jsonl`; `None` when the
/// name does not match the pattern.
fn parse_segment_index(name: &str, prefix: &str) -> Option<u64> {
    let digits = name
        .strip_prefix(prefix)?
        .strip_prefix('-')?
        .strip_suffix(".jsonl")?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Read one segment file, decoding each line (CRC-framed or legacy bare
/// JSON) with `parse` for the JSON payload. Returns the parsed records and
/// the file's size in bytes after any repair.
///
/// With `repair_torn_tail` set (open-time recovery of the *last* segment
/// only), a **final** line that lacks its trailing newline and cannot be
/// decoded — a partial JSON body or an incomplete CRC prefix — is a
/// crash-torn write: the file is truncated to just before it and the scan
/// succeeds. Everything else malformed is [`StoreError::Corrupt`] with a
/// 1-based line number; in particular a newline-terminated, well-formed
/// `<crc> <json>` line whose CRC does not match its JSON bytes is
/// `Corrupt` with reason `"crc mismatch"` and is **never** truncated.
pub(crate) fn read_segment<T, F>(
    path: &Path,
    name: &str,
    repair_torn_tail: bool,
    parse: F,
) -> Result<(Vec<T>, u64), StoreError>
where
    F: Fn(&str) -> Result<T, String>,
{
    let bytes = fs::read(path)?;
    let mut records = Vec::new();
    let mut offset = 0usize;
    let mut line_no = 0usize;
    while offset < bytes.len() {
        line_no += 1;
        let newline_at = bytes[offset..].iter().position(|&b| b == b'\n');
        let end = newline_at.map_or(bytes.len(), |p| offset + p);
        let decoded = match std::str::from_utf8(&bytes[offset..end]) {
            Ok(line) => decode_line(line, &parse),
            Err(e) => Err(LineFailure::Malformed(e.to_string())),
        };
        match decoded {
            Ok(record) => records.push(record),
            Err(failure) => {
                // Torn-tail repair applies only to the final line, only when
                // it lacks its trailing newline (crash mid-write), and never
                // to a CRC mismatch (that is corruption, not a torn write).
                let is_final_line = end + 1 >= bytes.len();
                let has_newline = newline_at.is_some();
                if repair_torn_tail
                    && is_final_line
                    && !has_newline
                    && matches!(failure, LineFailure::Malformed(_))
                {
                    let file = fs::OpenOptions::new().write(true).open(path)?;
                    file.set_len(offset as u64)?;
                    return Ok((records, offset as u64));
                }
                let reason = match failure {
                    LineFailure::CrcMismatch => "crc mismatch".to_string(),
                    LineFailure::Malformed(e) => e,
                };
                return Err(StoreError::Corrupt {
                    segment: name.to_string(),
                    line: line_no,
                    reason,
                });
            }
        }
        offset = end + 1;
    }
    Ok((records, bytes.len() as u64))
}

/// Read the persistent dedup index (`dedup.idx`) in `dir`, parsing each
/// line with `parse`. A missing file yields an empty list (fresh or legacy
/// store). A **final** line lacking its trailing newline is a torn write
/// and is truncated away *even if it parses* — a torn prefix of a longer
/// key can itself be parseable, and the writer always appends the newline
/// in the same write, so a complete index line is always terminated. (The
/// truncated key is not lost: its record is in the final segment, which is
/// written before the index, and the open-scan merge re-appends it.) Any
/// malformed newline-terminated line is [`StoreError::Corrupt`] (with
/// `segment: "dedup.idx"`).
pub(crate) fn read_dedup_index<T, F>(dir: &Path, parse: F) -> Result<Vec<T>, StoreError>
where
    F: Fn(&str) -> Result<T, String>,
{
    let path = dir.join(DEDUP_INDEX_FILE);
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut keys = Vec::new();
    let mut offset = 0usize;
    let mut line_no = 0usize;
    while offset < bytes.len() {
        line_no += 1;
        let newline_at = bytes[offset..].iter().position(|&b| b == b'\n');
        let Some(pos) = newline_at else {
            // Torn final line (no trailing newline): truncate it away.
            let file = fs::OpenOptions::new().write(true).open(&path)?;
            file.set_len(offset as u64)?;
            return Ok(keys);
        };
        let end = offset + pos;
        let parsed = std::str::from_utf8(&bytes[offset..end])
            .map_err(|e| e.to_string())
            .and_then(&parse);
        match parsed {
            Ok(key) => keys.push(key),
            Err(reason) => {
                return Err(StoreError::Corrupt {
                    segment: DEDUP_INDEX_FILE.to_string(),
                    line: line_no,
                    reason,
                });
            }
        }
        offset = end + 1;
    }
    Ok(keys)
}

/// Append `lines` (each without its newline) to the dedup index in `dir`,
/// flushing to the OS and — when `sync` is set — `sync_data()`-fsyncing
/// before returning. A no-op for an empty `lines`.
pub(crate) fn append_dedup_lines(
    dir: &Path,
    lines: &[String],
    sync: bool,
) -> Result<(), StoreError> {
    if lines.is_empty() {
        return Ok(());
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(DEDUP_INDEX_FILE))?;
    let mut buf = String::with_capacity(lines.iter().map(|l| l.len() + 1).sum());
    for line in lines {
        buf.push_str(line);
        buf.push('\n');
    }
    file.write_all(buf.as_bytes())?;
    file.flush()?;
    if sync {
        file.sync_data()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_are_zero_padded() {
        assert_eq!(segment_file_name("obs", 0), "obs-000000.jsonl");
        assert_eq!(segment_file_name("evt", 42), "evt-000042.jsonl");
    }

    #[test]
    fn index_parsing_rejects_foreign_names() {
        assert_eq!(parse_segment_index("obs-000007.jsonl", "obs"), Some(7));
        assert_eq!(parse_segment_index("obs-000007.jsonl", "evt"), None);
        assert_eq!(parse_segment_index("obs-x7.jsonl", "obs"), None);
        assert_eq!(parse_segment_index("obs-.jsonl", "obs"), None);
        assert_eq!(parse_segment_index("obs-000007.tmp", "obs"), None);
    }

    #[test]
    fn crc32_matches_the_ieee_check_value() {
        // The canonical CRC-32 (IEEE) check value.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn encode_line_prefixes_the_crc_of_the_exact_json_bytes() {
        let json = r#"{"a":1}"#;
        let line = encode_line(json);
        let (crc, payload) = split_crc(&line).expect("framed line splits");
        assert_eq!(payload, json);
        assert_eq!(crc, crc32(json.as_bytes()));
    }

    #[test]
    fn split_crc_rejects_bare_json_and_short_lines() {
        assert!(split_crc(r#"{"a":1}"#).is_none());
        assert!(split_crc("deadbe").is_none());
        assert!(split_crc("nothexno {}").is_none());
        assert!(split_crc("deadbeef{}").is_none()); // no space
    }
}
