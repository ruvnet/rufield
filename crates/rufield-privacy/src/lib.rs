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
//! [`DefaultPrivacyGuard::authorize`] authorizes one classified component.
//! [`DefaultPrivacyGuard::authorize_event`] authorizes a complete [`FieldEvent`]
//! by requiring every independently classified component to pass policy. Use
//! the latter before serializing or transmitting a whole event.

#![doc(html_root_url = "https://docs.rs/rufield-privacy/0.1.0")]

use rufield_core::{Destination, FieldEvent, PrivacyClass, PrivacyDecision, PrivacyGuard};

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

    /// Authorize a complete [`FieldEvent`] for a destination.
    ///
    /// A `FieldEvent` contains independently classified data. In v0.1 that
    /// includes at least the numeric tensor and the derived observation. A
    /// caller that authorizes only `event.observation.privacy_class` can
    /// otherwise approve a P1/P2 observation while serializing a P0 raw tensor
    /// in the same object.
    ///
    /// This method is deliberately conjunctive rather than reducing P0..P5 to
    /// one scalar with `min` or `max`: the classes encode different policy
    /// semantics. P0 has a special raw-waveform network prohibition, while P4
    /// and P5 have consent and identity requirements. Every component must
    /// therefore be authorized independently.
    ///
    /// Decision precedence is fail closed: any `Deny` dominates;
    /// `RequiresConsent` dominates `Allow`. The returned reason identifies the
    /// component that blocked the event.
    #[must_use]
    pub fn authorize_event(
        &self,
        event: &FieldEvent,
        destination: Destination,
        consent: bool,
        identity_bound: bool,
    ) -> PrivacyDecision {
        let tensor = self.authorize(
            event.tensor.privacy_class,
            destination,
            consent,
            identity_bound,
        );
        let observation = self.authorize(
            event.observation.privacy_class,
            destination,
            consent,
            identity_bound,
        );

        match (tensor, observation) {
            (PrivacyDecision::Deny(reason), _) => {
                PrivacyDecision::Deny(format!("tensor: {reason}"))
            }
            (_, PrivacyDecision::Deny(reason)) => {
                PrivacyDecision::Deny(format!("observation: {reason}"))
            }
            (PrivacyDecision::RequiresConsent(reason), _) => {
                PrivacyDecision::RequiresConsent(format!("tensor: {reason}"))
            }
            (_, PrivacyDecision::RequiresConsent(reason)) => {
                PrivacyDecision::RequiresConsent(format!("observation: {reason}"))
            }
            (PrivacyDecision::Allow, PrivacyDecision::Allow) => PrivacyDecision::Allow,
        }
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
    use rufield_core::{
        FieldAxis, FieldTensor, Modality, Observation, ProvenanceRef, SensorDescriptor,
    };

    fn guard() -> DefaultPrivacyGuard {
        DefaultPrivacyGuard::default()
    }

    fn event_with_classes(
        tensor_class: PrivacyClass,
        observation_class: PrivacyClass,
    ) -> FieldEvent {
        let tensor = FieldTensor::new(
            1,
            Modality::WifiCsi,
            vec![FieldAxis::Frequency],
            vec![1],
            vec![0.5],
            0.9,
            0.01,
            Some("cal-1".into()),
            tensor_class,
        )
        .unwrap();
        FieldEvent::new(
            "event-1",
            1,
            SensorDescriptor {
                modality: "wifi_csi".into(),
                vendor: "test".into(),
                device_id: "device-1".into(),
                placement: "test".into(),
                clock_domain: "test".into(),
            },
            tensor,
            Observation::occupancy(0.9, observation_class),
            ProvenanceRef {
                raw_hash: "sha256:test".into(),
                firmware_hash: "sha256:test".into(),
                model_id: "test".into(),
                calibration_id: "cal-1".into(),
                synthetic: true,
                signature_hex: None,
                signer_pubkey_hex: None,
            },
        )
    }

    #[test]
    fn p0_transmit_denied_by_default() {
        let d = guard().authorize(PrivacyClass::P0, Destination::Network, false, false);
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

    #[test]
    fn event_denies_p0_tensor_even_when_p2_observation_is_allowed() {
        let event = event_with_classes(PrivacyClass::P0, PrivacyClass::P2);
        assert_eq!(
            guard().authorize(PrivacyClass::P2, Destination::Network, false, false),
            PrivacyDecision::Allow
        );
        let decision = guard().authorize_event(&event, Destination::Network, false, false);
        match decision {
            PrivacyDecision::Deny(reason) => {
                assert!(reason.starts_with("tensor:"));
                assert!(reason.contains("P0 raw waveform"));
            }
            other => panic!("expected composite event denial, got {other:?}"),
        }
    }

    #[test]
    fn event_allows_p1_tensor_and_p2_observation() {
        let event = event_with_classes(PrivacyClass::P1, PrivacyClass::P2);
        assert_eq!(
            guard().authorize_event(&event, Destination::Network, false, false),
            PrivacyDecision::Allow
        );
    }

    #[test]
    fn event_propagates_observation_consent_requirement() {
        let event = event_with_classes(PrivacyClass::P1, PrivacyClass::P4);
        let required = guard().authorize_event(&event, Destination::Network, false, false);
        match required {
            PrivacyDecision::RequiresConsent(reason) => {
                assert!(reason.starts_with("observation:"));
            }
            other => panic!("expected consent requirement, got {other:?}"),
        }
        assert_eq!(
            guard().authorize_event(&event, Destination::Network, true, false),
            PrivacyDecision::Allow
        );
    }

    #[test]
    fn event_propagates_observation_identity_requirement() {
        let event = event_with_classes(PrivacyClass::P1, PrivacyClass::P5);
        let denied = guard().authorize_event(&event, Destination::Network, true, false);
        match denied {
            PrivacyDecision::Deny(reason) => assert!(reason.starts_with("observation:")),
            other => panic!("expected identity denial, got {other:?}"),
        }
        assert_eq!(
            guard().authorize_event(&event, Destination::Network, true, true),
            PrivacyDecision::Allow
        );
    }

    #[test]
    fn event_allows_p0_tensor_edge_local_when_observation_policy_allows() {
        let event = event_with_classes(PrivacyClass::P0, PrivacyClass::P2);
        assert_eq!(
            guard().authorize_event(&event, Destination::EdgeLocal, false, false),
            PrivacyDecision::Allow
        );
    }
}
