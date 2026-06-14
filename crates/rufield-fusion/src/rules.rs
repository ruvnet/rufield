//! Fusion rule format (ADR-260 §13) — parsed from TOML.

use serde::Deserialize;
use std::collections::BTreeMap;

/// The fusion method a rule uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// Combine weighted per-modality evidence into a probability.
    WeightedBayes,
    /// Detect a state transition within a temporal window.
    TemporalWindow,
}

/// A single fusion rule.
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    /// Modalities whose evidence feeds this rule.
    pub inputs: Vec<String>,
    /// Fusion method.
    pub method: Method,
    /// Feature key driving the rule (may be a derived key).
    pub feature: String,
    /// Decision threshold on the fused confidence.
    pub threshold: f32,
    /// Maximum privacy class of the produced inference.
    pub privacy_max: String,
    /// Temporal window in ms (temporal_window rules).
    #[serde(default)]
    pub window_ms: Option<u64>,
    /// Whether the inference requires consent (P4+ rules).
    #[serde(default)]
    pub requires_consent: bool,
}

/// Top-level TOML document: `[rule.<label>]` tables.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleSet {
    /// Map of rule label → rule.
    pub rule: BTreeMap<String, Rule>,
}

impl RuleSet {
    /// Parse a rule set from TOML text.
    pub fn from_toml(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// The default room-state rule set shipped with the crate.
    #[must_use]
    pub fn default_room_state() -> Self {
        // Embedded so the crate is self-contained (no runtime file IO).
        const SRC: &str = include_str!("../rules/room_state.toml");
        RuleSet::from_toml(SRC).expect("embedded room_state.toml is valid")
    }

    /// Rules in deterministic (sorted) order.
    #[must_use]
    pub fn ordered(&self) -> Vec<(&String, &Rule)> {
        self.rule.iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ruleset_parses_and_has_min_5() {
        let rs = RuleSet::default_room_state();
        assert!(rs.rule.len() >= 5, "need >=5 rules, got {}", rs.rule.len());
        for label in [
            "person_present",
            "sitting",
            "sleeping",
            "bed_exit",
            "room_transition",
        ] {
            assert!(rs.rule.contains_key(label), "missing rule {label}");
        }
    }

    #[test]
    fn p4_rules_require_consent() {
        let rs = RuleSet::default_room_state();
        let breathing = &rs.rule["breathing"];
        assert_eq!(breathing.privacy_max, "P4");
        assert!(breathing.requires_consent);
    }

    #[test]
    fn methods_parse() {
        let rs = RuleSet::default_room_state();
        assert_eq!(rs.rule["person_present"].method, Method::WeightedBayes);
        assert_eq!(rs.rule["bed_exit"].method, Method::TemporalWindow);
    }
}
