//! The §19 camera-free room-intelligence demo timeline with ground-truth
//! labels. The simulator walks these phases deterministically so the benchmark
//! can score inferences against known truth.

/// Ground-truth activity phases for the §19 demo sequence.
///
/// enter → sit → breathing → sleep → scratch → bed-exit → leave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Room empty before the person enters.
    EmptyBefore,
    /// Person walking into the room.
    Enter,
    /// Person sitting down / seated.
    Sit,
    /// Seated, steady breathing detectable.
    Breathing,
    /// Lying down / asleep (in bed).
    Sleep,
    /// Nocturnal scratch event while in bed.
    Scratch,
    /// Getting out of bed.
    BedExit,
    /// Walking out / leaving the room.
    Leave,
    /// Room empty after the person leaves.
    EmptyAfter,
}

impl Phase {
    /// Whether a person is physically present during this phase.
    #[must_use]
    pub fn person_present(self) -> bool {
        !matches!(self, Phase::EmptyBefore | Phase::EmptyAfter)
    }

    /// Whether the person is in/at the bed (for bed-exit scoring).
    #[must_use]
    pub fn in_bed(self) -> bool {
        matches!(self, Phase::Sleep | Phase::Scratch)
    }

    /// Ground-truth inference labels active during this phase. These are the
    /// labels the benchmark scores produced inferences against.
    #[must_use]
    pub fn truth_labels(self) -> &'static [&'static str] {
        match self {
            Phase::EmptyBefore | Phase::EmptyAfter => &[],
            Phase::Enter => &["person_present"],
            Phase::Sit => &["person_present", "sitting"],
            Phase::Breathing => &["person_present", "sitting", "breathing"],
            // A sleeping person is still breathing — the band is physically
            // present during sleep, so breathing is ground-truth here too.
            Phase::Sleep => &["person_present", "sleeping", "breathing"],
            Phase::Scratch => &["person_present", "sleeping", "breathing", "nocturnal_scratch"],
            Phase::BedExit => &["person_present", "bed_exit"],
            Phase::Leave => &["person_present", "room_transition"],
        }
    }
}

/// One scheduled phase: which phase, and how many sampling ticks it lasts.
#[derive(Debug, Clone, Copy)]
pub struct PhaseSpan {
    /// The phase.
    pub phase: Phase,
    /// Number of per-modality sampling ticks this phase occupies.
    pub ticks: u32,
}

/// The full demo timeline. Tick counts are chosen so each scored task has
/// enough samples to compute a meaningful F1.
#[must_use]
pub fn demo_timeline() -> Vec<PhaseSpan> {
    vec![
        PhaseSpan { phase: Phase::EmptyBefore, ticks: 8 },
        PhaseSpan { phase: Phase::Enter, ticks: 6 },
        PhaseSpan { phase: Phase::Sit, ticks: 6 },
        PhaseSpan { phase: Phase::Breathing, ticks: 12 },
        PhaseSpan { phase: Phase::Sleep, ticks: 14 },
        PhaseSpan { phase: Phase::Scratch, ticks: 6 },
        PhaseSpan { phase: Phase::BedExit, ticks: 6 },
        PhaseSpan { phase: Phase::Leave, ticks: 6 },
        PhaseSpan { phase: Phase::EmptyAfter, ticks: 8 },
    ]
}

/// Flatten the timeline into a per-tick phase vector.
#[must_use]
pub fn ticks(timeline: &[PhaseSpan]) -> Vec<Phase> {
    let mut out = Vec::new();
    for span in timeline {
        for _ in 0..span.ticks {
            out.push(span.phase);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeline_covers_full_sequence() {
        let tl = demo_timeline();
        let phases: Vec<Phase> = tl.iter().map(|s| s.phase).collect();
        assert!(phases.contains(&Phase::Enter));
        assert!(phases.contains(&Phase::Breathing));
        assert!(phases.contains(&Phase::Sleep));
        assert!(phases.contains(&Phase::Scratch));
        assert!(phases.contains(&Phase::BedExit));
        assert!(phases.contains(&Phase::Leave));
    }

    #[test]
    fn empty_phases_have_no_person() {
        assert!(!Phase::EmptyBefore.person_present());
        assert!(!Phase::EmptyAfter.person_present());
        assert!(Phase::Sit.person_present());
    }

    #[test]
    fn ticks_flatten_matches_sum() {
        let tl = demo_timeline();
        let total: u32 = tl.iter().map(|s| s.ticks).sum();
        assert_eq!(ticks(&tl).len(), total as usize);
    }
}
