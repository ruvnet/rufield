//! Convert advisory bridge JSONL on stdin to unsigned P1 FieldEvents.
use rufield_adapters::rf_spectrum_quality::RfDiagnosticReader;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().len() != 1 {
        return Err("usage: rf-diagnostics-replay < diagnostics.jsonl > events.jsonl".into());
    }
    let stdin = io::stdin();
    let mut reader = RfDiagnosticReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());
    while let Some(record) = reader.next_record()? {
        let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
        let event = record.to_event(now)?;
        serde_json::to_writer(&mut writer, &event)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}
