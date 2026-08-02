//! The durable command-phase journal (ADR-265 §4, ADR-264 §9 restart
//! posture).
//!
//! [`rucelium_policy::GatewayValidator`] keeps the command lifecycle table
//! ([`rucelium_policy::CommandPhase`]) in memory; the **daemon owns the
//! disk**. This module is that ownership: a tiny `commands.jsonl` file, one
//! JSON object per line (`{"command_id":"cmd-42","phase":"executed"}`),
//! rewritten from `GatewayValidator::export_phases()` after every execution
//! attempt and fed back through `GatewayValidator::restore_phases()` on
//! startup.
//!
//! Why a full rewrite rather than an append: the table is bounded by the
//! number of command ids a gateway has ever seen (tiny), and a rewrite makes
//! the file a straightforward snapshot with no compaction story. The write is
//! atomic — a temporary file is written, flushed, fsynced, and renamed over
//! the journal — so a crash mid-write leaves the previous complete journal
//! intact rather than a truncated one.
//!
//! Recovery is deliberately **fail-open on parse, fail-closed on content**: a
//! malformed line is skipped (a corrupt journal must not stop the gateway
//! from booting), but every phase it *does* restore — including `executing`,
//! left behind by a crash mid-execution — permanently blocks re-execution of
//! that command id.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// File name of the command journal inside the gateway data directory.
pub const JOURNAL_FILE: &str = "commands.jsonl";

/// The journal path for a data directory.
#[must_use]
pub fn journal_path(data_dir: &Path) -> PathBuf {
    data_dir.join(JOURNAL_FILE)
}

/// One journaled command phase.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct JournalLine {
    /// The command id (`"cmd-{proposal_id}"`).
    command_id: String,
    /// Phase string, as produced by `CommandPhase::as_str`.
    phase: String,
}

/// Load the journaled `(command_id, phase)` pairs, ready to hand to
/// `GatewayValidator::restore_phases`.
///
/// A missing journal yields an empty list (fresh data directory). Individual
/// unparseable lines are skipped so a damaged journal cannot wedge startup;
/// an unreadable *file* is an error the caller should surface.
pub fn load(path: &Path) -> Result<Vec<(String, String)>, String> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("read command journal {}: {e}", path.display())),
    };
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<JournalLine>(line) {
            Ok(entry) => out.push((entry.command_id, entry.phase)),
            Err(e) => eprintln!(
                "gateway: skipping malformed command-journal line in {}: {e}",
                path.display()
            ),
        }
    }
    Ok(out)
}

/// Atomically rewrite the journal from a `GatewayValidator::export_phases()`
/// snapshot: write a sibling temp file, flush, `sync_data`, then rename over
/// the journal (and fsync the directory so the rename itself is durable).
pub fn store(path: &Path, phases: &[(String, String)]) -> Result<(), String> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let tmp = path.with_extension("jsonl.tmp");

    let mut buf = String::new();
    for (command_id, phase) in phases {
        let line = serde_json::to_string(&JournalLine {
            command_id: command_id.clone(),
            phase: phase.clone(),
        })
        .map_err(|e| format!("encode command journal: {e}"))?;
        buf.push_str(&line);
        buf.push('\n');
    }

    {
        let mut file =
            fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
        file.write_all(buf.as_bytes())
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        file.flush()
            .map_err(|e| format!("flush {}: {e}", tmp.display()))?;
        file.sync_data()
            .map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
    }
    fs::rename(&tmp, path).map_err(|e| format!("rename into {}: {e}", path.display()))?;
    // Best effort: fsync the directory so the rename survives power loss.
    // Not every platform/filesystem supports opening a directory for sync;
    // failure here does not invalidate the (already durable) file contents.
    if let Ok(handle) = fs::File::open(dir) {
        let _ = handle.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::testutil::temp_dir;

    #[test]
    fn missing_journal_loads_empty() {
        let dir = temp_dir("journal-missing");
        assert!(load(&journal_path(&dir)).unwrap().is_empty());
    }

    #[test]
    fn store_then_load_round_trips_in_order() {
        let dir = temp_dir("journal-round-trip");
        fs::create_dir_all(&dir).unwrap();
        let path = journal_path(&dir);
        let phases = vec![
            ("cmd-1".to_string(), "executed".to_string()),
            ("cmd-2".to_string(), "executing".to_string()),
            ("cmd-3".to_string(), "failed".to_string()),
        ];
        store(&path, &phases).unwrap();
        assert_eq!(load(&path).unwrap(), phases);

        // Rewriting replaces the whole snapshot (no stale leftovers).
        let smaller = vec![("cmd-9".to_string(), "executed".to_string())];
        store(&path, &smaller).unwrap();
        assert_eq!(load(&path).unwrap(), smaller);

        // No temp file is left behind.
        assert!(!path.with_extension("jsonl.tmp").exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let dir = temp_dir("journal-malformed");
        fs::create_dir_all(&dir).unwrap();
        let path = journal_path(&dir);
        fs::write(
            &path,
            "{\"command_id\":\"cmd-1\",\"phase\":\"executed\"}\nnot json\n\n{\"command_id\":\"cmd-2\",\"phase\":\"failed\"}\n",
        )
        .unwrap();
        assert_eq!(
            load(&path).unwrap(),
            vec![
                ("cmd-1".to_string(), "executed".to_string()),
                ("cmd-2".to_string(), "failed".to_string()),
            ]
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_snapshot_writes_an_empty_journal() {
        let dir = temp_dir("journal-empty");
        fs::create_dir_all(&dir).unwrap();
        let path = journal_path(&dir);
        store(&path, &[]).unwrap();
        assert!(path.exists());
        assert!(load(&path).unwrap().is_empty());
        fs::remove_dir_all(&dir).ok();
    }
}
