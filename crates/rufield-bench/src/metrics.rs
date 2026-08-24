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

/// Area under the receiver operating characteristic curve using sorted average
/// ranks with exact tie handling. Complexity is `O(n log n)`. Returns `None`
/// when either class is absent.
#[must_use]
pub fn binary_auroc(samples: &[(f32, bool)]) -> Option<f32> {
    let positives = samples.iter().filter(|(_, truth)| *truth).count();
    let negatives = samples.len() - positives;
    if positives == 0 || negatives == 0 {
        return None;
    }

    let mut ranked = samples.to_vec();
    ranked.sort_by(|left, right| left.0.total_cmp(&right.0));
    let mut positive_rank_sum = 0.0f64;
    let mut start = 0usize;
    while start < ranked.len() {
        let mut end = start + 1;
        while end < ranked.len() && ranked[end].0 == ranked[start].0 {
            end += 1;
        }
        let average_rank = (start + 1 + end) as f64 / 2.0;
        let positive_ties = ranked[start..end]
            .iter()
            .filter(|(_, truth)| *truth)
            .count();
        positive_rank_sum += average_rank * positive_ties as f64;
        start = end;
    }
    let positive_baseline = positives as f64 * (positives + 1) as f64 / 2.0;
    let pair_count = positives as f64 * negatives as f64;
    Some(((positive_rank_sum - positive_baseline) / pair_count) as f32)
}

/// Expected calibration error for binary probabilities. Confidence is the
/// probability assigned to the predicted class and accuracy is observed in
/// equal width bins.
#[must_use]
pub fn expected_calibration_error(samples: &[(f32, bool)], bins: usize) -> f32 {
    if samples.is_empty() || bins == 0 {
        return 0.0;
    }
    let mut counts = vec![0usize; bins];
    let mut confidence_sums = vec![0.0f64; bins];
    let mut correct = vec![0usize; bins];
    for (probability, truth) in samples {
        let predicted = *probability >= 0.5;
        let confidence = if predicted {
            *probability
        } else {
            1.0 - *probability
        };
        let index = ((confidence * bins as f32).floor() as usize).min(bins - 1);
        counts[index] += 1;
        confidence_sums[index] += confidence as f64;
        if predicted == *truth {
            correct[index] += 1;
        }
    }
    let total = samples.len() as f64;
    counts
        .iter()
        .enumerate()
        .filter(|(_, count)| **count > 0)
        .map(|(index, count)| {
            let count = *count as f64;
            let accuracy = correct[index] as f64 / count;
            let confidence = confidence_sums[index] / count;
            (count / total) * (accuracy - confidence).abs()
        })
        .sum::<f64>() as f32
}

/// Error rate among predictions the system did not abstain from. Returns
/// `None` when every prediction was withheld.
#[must_use]
pub fn selective_risk(samples: &[(f32, bool, bool)]) -> Option<f32> {
    let accepted: Vec<_> = samples
        .iter()
        .filter(|(_, _, abstained)| !*abstained)
        .collect();
    if accepted.is_empty() {
        return None;
    }
    let errors = accepted
        .iter()
        .filter(|(probability, truth, _)| (*probability >= 0.5) != *truth)
        .count();
    Some(errors as f32 / accepted.len() as f32)
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

    #[test]
    fn auroc_is_one_for_perfect_ranking() {
        let samples = vec![(0.9, true), (0.8, true), (0.2, false), (0.1, false)];
        assert_eq!(binary_auroc(&samples), Some(1.0));
    }

    #[test]
    fn auroc_gives_half_credit_to_ties() {
        let samples = vec![(0.5, true), (0.5, false), (0.5, true), (0.5, false)];
        assert_eq!(binary_auroc(&samples), Some(0.5));
    }

    #[test]
    fn auroc_scales_to_default_promotion_corpus() {
        let samples = (0..100_000)
            .map(|index| {
                let positive = index % 2 == 0;
                (if positive { 0.75 } else { 0.25 }, positive)
            })
            .collect::<Vec<_>>();
        assert_eq!(binary_auroc(&samples), Some(1.0));
    }

    #[test]
    fn ece_is_zero_for_calibrated_certain_predictions() {
        let samples = vec![(1.0, true), (0.0, false)];
        assert!(expected_calibration_error(&samples, 10) < f32::EPSILON);
    }

    #[test]
    fn selective_risk_excludes_abstentions() {
        let samples = vec![(0.9, true, false), (0.9, false, true)];
        assert_eq!(selective_risk(&samples), Some(0.0));
    }
}
