//! # rufield-privacy
//!
//! Privacy policy + [`PrivacyGuard`] for RuField MFS (ADR-260 §10).
//!
//! Default system policy (§10):
//! - edge storage may retain **P0** only temporarily,
//! - **network transmission defaults to P2 or lower**,
//! - **P4** (biometric / health) requires explicit consent,
//! - **P5** (identity-linked) requires explicit identity binding + audit log.
//!
//! [`DefaultPrivacyGuard::authorize`] returns [`PrivacyDecision::Allow`],
//! [`PrivacyDecision::Deny`], or [`PrivacyDecision::RequiresConsent`].

#![doc(html_root_url = "https://docs.rs/rufield-privacy/0.1.0")]

use rufield_core::{Destination, PrivacyClass, PrivacyDecision, PrivacyGuard};

/// Tunable privacy policy. Defaults match ADR-260 §10.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyPolicy {
    /// Maximum privacy class allowed onto the network by default.
    pub network_max: PrivacyClass,
    /// Whether P0 raw frames may ever leave the edge.
    pub allow_p0_network: bool,
}

impl Default for PrivacyPolicy {
    fn default() -> Self {
        // Network defaults to P2 or lower; P0 never goes to network by default.
        PrivacyPolicy {
            network_max: PrivacyClass::P2,
            allow_p0_network: false,
        }
    }
}

/// The default privacy guard implementing the §10 policy.
#[derive(Debug, Clone, Default)]
pub struct DefaultPrivacyGuard {
    policy: PrivacyPolicy,
}

impl DefaultPrivacyGuard {
    /// Construct with a custom policy.
    #[must_use]
    pub fn with_policy(policy: PrivacyPolicy) -> Self {
        DefaultPrivacyGuard { policy }
    }

    /// The active policy.
    #[must_use]
    pub fn policy(&self) -> &PrivacyPolicy {
        &self.policy
    }
}

impl PrivacyGuard for DefaultPrivacyGuard {
    fn authorize(
        &self,
        class: PrivacyClass,
        destination: Destination,
        consent: bool,
        identity_bound: bool,
    ) -> PrivacyDecision {
        // P5 always requires identity binding + audit, regardless of destination.
        if class == PrivacyClass::P5 && !identity_bound {
            return PrivacyDecision::Deny(
                "P5 identity-linked inference requires identity binding + audit log".into(),
            );
        }
        // P4 requires explicit consent, regardless of destination.
        if class == PrivacyClass::P4 && !consent {
            return PrivacyDecision::RequiresConsent(
                "P4 biometric/health inference requires explicit consent".into(),
            );
        }

        match destination {
            Destination::EdgeLocal => {
                // Edge-local retention is permitted for all classes (P0 only
                // temporarily, but that is a retention concern, not an
                // authorization denial). Consent/identity gates above still
                // apply to P4/P5.
                PrivacyDecision::Allow
            }
            Destination::Network => {
                if class == PrivacyClass::P0 && !self.policy.allow_p0_network {
                    return PrivacyDecision::Deny(
                        "P0 raw waveform transmission disabled by default".into(),
                    );
                }
                // P4/P5 reaching this point have already passed their consent /
                // identity-binding gates above — that explicit authorization is
                // the controlling policy and overrides the default ceiling.
                if matches!(class, PrivacyClass::P4 | PrivacyClass::P5) {
                    return PrivacyDecision::Allow;
                }
                if class > self.policy.network_max {
                    // Above the default network ceiling with no consent gate
                    // (e.g. P3 anonymous aggregate) — denied by default.
                    return PrivacyDecision::Deny(format!(
                        "{class:?} exceeds default network ceiling {:?}",
                        self.policy.network_max
                    ));
                }
                PrivacyDecision::Allow
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> DefaultPrivacyGuard {
        DefaultPrivacyGuard::default()
    }

    #[test]
    fn p0_transmit_denied_by_default() {
        let d = guard().authorize(PrivacyClass::P0, Destination::Network, false, false);
        matches!(d, PrivacyDecision::Deny(_));
        assert!(matches!(d, PrivacyDecision::Deny(_)));
    }

    #[test]
    fn p2_network_allowed() {
        let d = guard().authorize(PrivacyClass::P2, Destination::Network, false, false);
        assert_eq!(d, PrivacyDecision::Allow);
    }

    #[test]
    fn p4_without_consent_requires_consent() {
        let d = guard().authorize(PrivacyClass::P4, Destination::Network, false, false);
        assert!(matches!(d, PrivacyDecision::RequiresConsent(_)));
    }

    #[test]
    fn p4_with_consent_allowed() {
        // P4 with consent is allowed even though it exceeds the network ceiling:
        // the consent gate is the controlling policy for biometric/health data.
        let d = guard().authorize(PrivacyClass::P4, Destination::Network, true, false);
        assert_eq!(d, PrivacyDecision::Allow);
    }

    #[test]
    fn p5_requires_identity_binding() {
        let denied = guard().authorize(PrivacyClass::P5, Destination::Network, true, false);
        assert!(matches!(denied, PrivacyDecision::Deny(_)));
        let allowed = guard().authorize(PrivacyClass::P5, Destination::Network, true, true);
        assert_eq!(allowed, PrivacyDecision::Allow);
    }

    #[test]
    fn p0_edge_local_allowed() {
        let d = guard().authorize(PrivacyClass::P0, Destination::EdgeLocal, false, false);
        assert_eq!(d, PrivacyDecision::Allow);
    }

    #[test]
    fn p3_network_denied_above_ceiling() {
        let d = guard().authorize(PrivacyClass::P3, Destination::Network, false, false);
        assert!(matches!(d, PrivacyDecision::Deny(_)));
    }
}
