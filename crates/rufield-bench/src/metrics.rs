//! Scoring primitives: confusion-matrix F1 and latency percentiles. All
//! deterministic (integer-stable where possible).

/// Binary confusion-matrix accumulator for one task.
#[derive(Debug, Clone, Default)]
pub struct Confusion {
    /// True positives.
    pub tp: u32,
    /// False positives.
    pub fp: u32,
    /// False negatives.
    pub fn_: u32,
    /// True negatives.
    pub tn: u32,
}

impl Confusion {
    /// Record one prediction vs ground truth.
    pub fn record(&mut self, predicted: bool, truth: bool) {
        match (predicted, truth) {
            (true, true) => self.tp += 1,
            (true, false) => self.fp += 1,
            (false, true) => self.fn_ += 1,
            (false, false) => self.tn += 1,
        }
    }

    /// Precision = tp / (tp + fp); 0 when no positives predicted.
    #[must_use]
    pub fn precision(&self) -> f32 {
        let denom = self.tp + self.fp;
        if denom == 0 {
            0.0
        } else {
            self.tp as f32 / denom as f32
        }
    }

    /// Recall = tp / (tp + fn); 0 when no positives in truth.
    #[must_use]
    pub fn recall(&self) -> f32 {
        let denom = self.tp + self.fn_;
        if denom == 0 {
            0.0
        } else {
            self.tp as f32 / denom as f32
        }
    }

    /// F1 = harmonic mean of precision and recall.
    #[must_use]
    pub fn f1(&self) -> f32 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }
}

/// p-th percentile of a slice of latencies (nanoseconds). `p` in `0.0..=1.0`.
/// Uses nearest-rank on a sorted copy — fully deterministic.
#[must_use]
pub fn percentile_ns(samples: &[u64], p: f32) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = (p * (sorted.len() as f32 - 1.0)).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perfect_f1() {
        let mut c = Confusion::default();
        c.record(true, true);
        c.record(true, true);
        c.record(false, false);
        assert!((c.f1() - 1.0).abs() < 1e-6);
    }

    #[test]
    fn half_recall() {
        let mut c = Confusion::default();
        c.record(true, true);
        c.record(false, true); // missed
        assert!((c.recall() - 0.5).abs() < 1e-6);
    }

    #[test]
    fn p95_deterministic() {
        let s: Vec<u64> = (1..=100).collect();
        let a = percentile_ns(&s, 0.95);
        let b = percentile_ns(&s, 0.95);
        assert_eq!(a, b);
        // nearest-rank: round(0.95 * 99) = 94 -> sorted[94] = 95
        assert_eq!(a, 95);
    }
}
