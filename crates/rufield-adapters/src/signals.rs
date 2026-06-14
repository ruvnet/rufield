//! Per-modality synthetic signal generation. Each modality produces a
//! `FieldTensor` whose summary features correlate with the ground-truth phase,
//! so the fusion engine can recover room-state labels. Values are deterministic
//! given the RNG, and carry realistic-looking (but SYNTHETIC) structure.

use crate::rng::SplitMix64;
use crate::scenario::Phase;
use rufield_core::{FieldAxis, FieldTensor, Modality, PrivacyClass};

/// Summary features the simulator embeds into each tensor, exposed via the
/// observation so the fusion engine reads them without re-deriving from raw
/// values. (In a real adapter these are computed by a `FieldEncoder`.)
#[derive(Debug, Clone, Copy)]
pub struct SignalFeatures {
    /// Overall energy / motion magnitude (0 = still room, high = moving).
    pub motion_energy: f32,
    /// Periodic ~0.2–0.3 Hz component magnitude (breathing band).
    pub breathing_band: f32,
    /// Low posture height proxy (1.0 = standing, 0.5 = sitting, 0.0 = lying).
    pub posture_height: f32,
    /// Short transient spike magnitude (scratch / sudden limb motion).
    pub transient: f32,
    /// Range estimate in metres (proxy for position / bed vs door).
    pub range_m: f32,
    /// Occupancy energy: high whenever a body is in the room, even when still
    /// (thermal warmth + static radar reflector + breathing micro-Doppler).
    /// This is what makes presence detectable for a motionless sleeper, exactly
    /// as a real multimodal presence detector behaves.
    pub presence: f32,
}

/// Generate a tensor + features for a modality at a phase. The `motion`,
/// `breathing`, etc. signatures are modality-weighted: radar leads on motion &
/// range, CSI leads on breathing micro-Doppler, thermal leads on presence &
/// posture.
pub fn generate(
    modality: Modality,
    phase: Phase,
    tick: u32,
    rng: &mut SplitMix64,
) -> (FieldTensor, SignalFeatures, PrivacyClass) {
    let base = phase_signature(phase, tick);
    let weighted = weight_for_modality(modality, base, rng);
    let (axes, shape, values) = synthesize_values(modality, weighted, rng);
    let privacy = PrivacyClass::P0; // raw tensor frames are always P0
    let tensor = FieldTensor::new(
        0, // timestamp filled by the adapter
        modality,
        axes,
        shape,
        values,
        0.85 + rng.range_f32(-0.05, 0.1),
        0.02,
        Some("synthetic_room_cal_v1".into()),
        privacy,
    )
    .expect("synthetic tensor is always shape-valid");
    (tensor, weighted, privacy)
}

/// The phase's ideal (noise-free) feature signature.
fn phase_signature(phase: Phase, tick: u32) -> SignalFeatures {
    // breathing phase term: periodic, ~0.25 Hz at our tick rate.
    let breath = ((tick as f32) * 0.25 * std::f32::consts::TAU).sin().abs();
    // Presence is high (~0.9) whenever a body is in the room — driven by
    // thermal warmth + static reflector + breathing micro-Doppler — and near
    // zero in an empty room. It does NOT depend on motion.
    let present = phase.person_present();
    let presence = if present { 0.9 } else { 0.03 };
    match phase {
        Phase::EmptyBefore | Phase::EmptyAfter => SignalFeatures {
            motion_energy: 0.02,
            breathing_band: 0.0,
            posture_height: 0.0,
            transient: 0.0,
            range_m: 5.0,
            presence,
        },
        Phase::Enter => SignalFeatures {
            motion_energy: 0.85,
            breathing_band: 0.0,
            posture_height: 1.0,
            transient: 0.0,
            range_m: 4.0,
            presence,
        },
        Phase::Sit => SignalFeatures {
            motion_energy: 0.30,
            breathing_band: 0.10,
            posture_height: 0.5,
            transient: 0.0,
            range_m: 3.0,
            presence,
        },
        Phase::Breathing => SignalFeatures {
            motion_energy: 0.12,
            breathing_band: 0.6 + 0.3 * breath,
            posture_height: 0.5,
            transient: 0.0,
            range_m: 3.0,
            presence,
        },
        Phase::Sleep => SignalFeatures {
            motion_energy: 0.06,
            breathing_band: 0.45 + 0.2 * breath,
            posture_height: 0.05,
            transient: 0.0,
            range_m: 2.0,
            presence,
        },
        Phase::Scratch => SignalFeatures {
            motion_energy: 0.25,
            // Still breathing during a scratch — band stays detectable (the
            // limb motion adds the transient but does not stop respiration).
            breathing_band: 0.45,
            posture_height: 0.05,
            transient: 0.9,
            range_m: 2.0,
            presence,
        },
        Phase::BedExit => SignalFeatures {
            motion_energy: 0.7,
            breathing_band: 0.1,
            posture_height: 0.8,
            transient: 0.2,
            range_m: 2.5,
            presence,
        },
        Phase::Leave => SignalFeatures {
            motion_energy: 0.8,
            breathing_band: 0.0,
            posture_height: 1.0,
            transient: 0.0,
            range_m: 4.5,
            presence,
        },
    }
}

/// Apply modality strengths + per-sample noise. Each modality is better at some
/// features and adds small Gaussian-ish noise (deterministic via RNG).
fn weight_for_modality(
    modality: Modality,
    base: SignalFeatures,
    rng: &mut SplitMix64,
) -> SignalFeatures {
    let n = |sd: f32, rng: &mut SplitMix64| rng.noise(sd);
    match modality {
        Modality::WifiCsi => SignalFeatures {
            // CSI: strong on breathing micro-Doppler, decent motion.
            motion_energy: clamp01(base.motion_energy * 0.9 + n(0.04, rng)),
            breathing_band: clamp01(base.breathing_band * 1.0 + n(0.04, rng)),
            posture_height: clamp01(base.posture_height * 0.7 + n(0.08, rng)),
            transient: clamp01(base.transient * 0.8 + n(0.05, rng)),
            range_m: base.range_m + n(0.3, rng),
            presence: clamp01(base.presence * 0.85 + n(0.03, rng)),
        },
        Modality::MmwaveRadar => SignalFeatures {
            // Radar: strong on motion + range, weaker on fine breathing.
            motion_energy: clamp01(base.motion_energy * 1.0 + n(0.03, rng)),
            breathing_band: clamp01(base.breathing_band * 0.7 + n(0.05, rng)),
            posture_height: clamp01(base.posture_height * 0.85 + n(0.06, rng)),
            transient: clamp01(base.transient * 1.0 + n(0.04, rng)),
            range_m: base.range_m + n(0.1, rng),
            presence: clamp01(base.presence * 0.9 + n(0.03, rng)),
        },
        Modality::InfraredThermal => SignalFeatures {
            // Thermal: strong presence + posture, no real breathing band.
            motion_energy: clamp01(base.motion_energy * 0.6 + n(0.05, rng)),
            breathing_band: clamp01(base.breathing_band * 0.2 + n(0.03, rng)),
            posture_height: clamp01(base.posture_height * 1.0 + n(0.05, rng)),
            transient: clamp01(base.transient * 0.5 + n(0.05, rng)),
            range_m: base.range_m + n(0.5, rng),
            // Thermal is the strongest, most motion-independent presence cue.
            presence: clamp01(base.presence * 1.0 + n(0.02, rng)),
        },
        _ => base,
    }
}

/// Build the actual numeric tensor for a modality from its features. Shapes are
/// modality-realistic; values encode the features in a recoverable way but the
/// fusion engine reads features from the observation, not the raw tensor.
fn synthesize_values(
    modality: Modality,
    f: SignalFeatures,
    rng: &mut SplitMix64,
) -> (Vec<FieldAxis>, Vec<usize>, Vec<f32>) {
    match modality {
        Modality::WifiCsi => {
            // 8 subcarriers x amplitude/phase = [8, 2]
            let mut v = Vec::with_capacity(16);
            for i in 0..8 {
                let carrier = (i as f32) / 8.0;
                let amp = 0.5 + f.motion_energy * 0.5 * (carrier * 6.0).sin()
                    + f.breathing_band * 0.3
                    + rng.noise(0.02);
                let phase = f.range_m * 0.1 + carrier + rng.noise(0.02);
                v.push(amp);
                v.push(phase);
            }
            (vec![FieldAxis::Frequency, FieldAxis::Amplitude], vec![8, 2], v)
        }
        Modality::MmwaveRadar => {
            // range x velocity bins = [6, 4]
            let mut v = Vec::with_capacity(24);
            let peak_bin = ((f.range_m / 6.0) * 6.0).clamp(0.0, 5.0) as usize;
            for r in 0..6 {
                for d in 0..4 {
                    let range_term = if r == peak_bin { 1.0 } else { 0.1 };
                    let dopp = f.motion_energy * ((d as f32) / 4.0);
                    v.push(range_term * (0.3 + dopp) + rng.noise(0.02));
                }
            }
            (vec![FieldAxis::Range, FieldAxis::Velocity], vec![6, 4], v)
        }
        Modality::InfraredThermal => {
            // 4x4 thermal array
            let mut v = Vec::with_capacity(16);
            for y in 0..4 {
                for _x in 0..4 {
                    // warmer where the body is; posture shifts the warm row.
                    let body_row = (3.0 * (1.0 - f.posture_height)) as usize;
                    let warm = if y == body_row { f.motion_energy.max(0.3) } else { 0.0 };
                    v.push(20.0 + 8.0 * warm + rng.noise(0.1)); // °C-ish
                }
            }
            (vec![FieldAxis::Temperature, FieldAxis::Channel], vec![4, 4], v)
        }
        _ => (vec![FieldAxis::Amplitude], vec![1], vec![0.0]),
    }
}

fn clamp01(x: f32) -> f32 {
    x.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_deterministic() {
        let mut a = SplitMix64::new(99);
        let mut b = SplitMix64::new(99);
        let (ta, fa, _) = generate(Modality::WifiCsi, Phase::Breathing, 3, &mut a);
        let (tb, fb, _) = generate(Modality::WifiCsi, Phase::Breathing, 3, &mut b);
        assert_eq!(ta.values, tb.values);
        assert_eq!(fa.breathing_band, fb.breathing_band);
    }

    #[test]
    fn breathing_phase_has_higher_band_than_empty() {
        let mut r = SplitMix64::new(1);
        let (_, fb, _) = generate(Modality::WifiCsi, Phase::Breathing, 2, &mut r);
        let (_, fe, _) = generate(Modality::WifiCsi, Phase::EmptyBefore, 2, &mut r);
        assert!(fb.breathing_band > fe.breathing_band);
    }

    #[test]
    fn empty_phase_low_motion() {
        let mut r = SplitMix64::new(2);
        let (_, f, _) = generate(Modality::MmwaveRadar, Phase::EmptyBefore, 0, &mut r);
        assert!(f.motion_energy < 0.3);
    }

    #[test]
    fn tensor_shapes_valid_per_modality() {
        let mut r = SplitMix64::new(3);
        for m in [Modality::WifiCsi, Modality::MmwaveRadar, Modality::InfraredThermal] {
            let (t, _, _) = generate(m, Phase::Sit, 1, &mut r);
            t.validate().unwrap();
        }
    }
}
