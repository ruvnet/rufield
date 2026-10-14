//! Analyze bounded advisory JSONL on stdin. No automatic actions.
use rufield_adapters::rf_quality_analysis::RfQualityAnalyzer;
use rufield_adapters::rf_spectrum_quality::RfDiagnosticReader;
use std::io::{self, Write};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().len() != 1 {
        return Err("usage: rf-diagnostics-analyze < diagnostics.jsonl > quality.jsonl".into());
    }
    let stdin = io::stdin();
    let mut reader = RfDiagnosticReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());
    let mut analyzer = RfQualityAnalyzer::new();
    while let Some(record) = reader.next_record()? {
        serde_json::to_writer(&mut writer, &analyzer.analyze(&record)?)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}
