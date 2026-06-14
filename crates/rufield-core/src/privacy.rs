//! Privacy classes (ADR-260 §10).

use serde::{Deserialize, Serialize};

/// Privacy class of a field observation (ADR-260 §10). Ordered P0 (rawest,
/// most sensitive) through P5 (identity-linked). The `Ord` derive orders by
/// declaration so `P0 < P1 < ... < P5`; "≤ P2" policy checks rely on this.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "UPPERCASE")]
pub enum PrivacyClass {
    /// Raw waveform / raw sensor frame (raw CSI, raw radar cube).
    P0,
    /// Derived non-identity features (Doppler peak, thermal blob).
    P1,
    /// Occupancy and motion only (person present, bed exit).
    P2,
    /// Anonymous aggregate state (room count, zone activity).
    P3,
    /// Biometric or health inference (breathing, gait, sleep, scratch).
    P4,
    /// Identity-linked inference (named person state).
    P5,
}

impl PrivacyClass {
    /// Numeric level 0..=5.
    #[must_use]
    pub fn level(self) -> u8 {
        match self {
            PrivacyClass::P0 => 0,
            PrivacyClass::P1 => 1,
            PrivacyClass::P2 => 2,
            PrivacyClass::P3 => 3,
            PrivacyClass::P4 => 4,
            PrivacyClass::P5 => 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_p0_lowest() {
        assert!(PrivacyClass::P0 < PrivacyClass::P2);
        assert!(PrivacyClass::P2 < PrivacyClass::P4);
        assert!(PrivacyClass::P4 < PrivacyClass::P5);
    }

    #[test]
    fn serde_uppercase() {
        assert_eq!(serde_json::to_string(&PrivacyClass::P2).unwrap(), "\"P2\"");
        let p: PrivacyClass = serde_json::from_str("\"P4\"").unwrap();
        assert_eq!(p, PrivacyClass::P4);
    }

    #[test]
    fn levels() {
        assert_eq!(PrivacyClass::P0.level(), 0);
        assert_eq!(PrivacyClass::P5.level(), 5);
    }
}
