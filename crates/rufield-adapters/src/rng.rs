//! Deterministic, seedable PRNG (SplitMix64) for the synthetic simulator.
//!
//! No `Date::now`, no OS entropy — same seed produces an identical sequence so
//! the whole event stream (and therefore the benchmark) is reproducible.

/// A SplitMix64 generator. Tiny, fast, fully deterministic.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Seed the generator.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        SplitMix64 { state: seed }
    }

    /// Next raw `u64`.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform `f32` in `[0, 1)`.
    pub fn next_f32(&mut self) -> f32 {
        // Top 24 bits → mantissa precision.
        let bits = (self.next_u64() >> 40) as u32; // 24 bits
        (bits as f32) / (1u32 << 24) as f32
    }

    /// Uniform `f32` in `[lo, hi)`.
    pub fn range_f32(&mut self, lo: f32, hi: f32) -> f32 {
        lo + (hi - lo) * self.next_f32()
    }

    /// Approximately normal noise (sum of 4 uniforms, centered), scaled by `sd`.
    pub fn noise(&mut self, sd: f32) -> f32 {
        let s = self.next_f32() + self.next_f32() + self.next_f32() + self.next_f32();
        (s - 2.0) * sd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_sequence() {
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seed_differs() {
        let mut a = SplitMix64::new(1);
        let mut b = SplitMix64::new(2);
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn f32_in_unit_interval() {
        let mut r = SplitMix64::new(7);
        for _ in 0..1000 {
            let x = r.next_f32();
            assert!((0.0..1.0).contains(&x));
        }
    }
}
