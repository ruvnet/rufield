//! `Biome` — the sovereign regional aggregate (ADR-264 §6, §12): verified-only
//! ingest with global dedup, device revocation as signed events, and
//! policy-driven disclosure (delay + coordinate coarsening).
//!
//! Admission is **sealed at the type level**: [`Biome::accept`] takes a
//! [`VerifiedEnvSample`], which is not serializable and has no public
//! constructor — the only producers are
//! `rucelium_ingest::IngestPipeline::ingest` and
//! `rucelium_ingest::IngestPipeline::reverify_stored`, both of which run the
//! full registry + signature verification. A `serde`-deserialized
//! [`rucelium_core::EnvSample`] whose bytes claim `provenance.verified =
//! true` cannot reach `accept` at all: the call does not type-check.

use crate::sig;
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use rucelium_core::{
    DataClass, EnvSample, EnvironmentalEvent, EventKind, EvidenceRef, GeoPoint, SensorModality,
    Severity, SPEC_VERSION,
};
use rucelium_ingest::VerifiedEnvSample;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// How a biome discloses events beyond its own boundary (ADR-264 §6:
/// sensitive biodiversity locations support coordinate coarsening, delayed
/// disclosure, and access-controlled raw data).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosurePolicy {
    /// Coordinate coarsening: `None` keeps full precision, `Some(d)` snaps
    /// event locations to a `d`-decimal-degree grid via [`GeoPoint::coarsen`].
    pub coarsen_decimals: Option<u32>,
    /// Delayed disclosure: events are withheld until
    /// `detected_ns + delay_ns` has passed.
    pub delay_ns: u64,
    /// Whether raw data behind the event is open access (`false` = access
    /// controlled by the biome owner).
    pub open_access: bool,
}

impl Default for DisclosurePolicy {
    /// Privacy-preserving default: ≈1.1 km coarsening, no delay, access
    /// controlled.
    fn default() -> Self {
        DisclosurePolicy {
            coarsen_decimals: Some(2),
            delay_ns: 0,
            open_access: false,
        }
    }
}

/// Per-biome sovereignty configuration: identity, retention per data class,
/// and disclosure policy (ADR-264 §6, §10).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BiomeConfig {
    /// Biome identity (e.g. `"biome/thames-estuary"`).
    pub biome_id: String,
    /// Retention for `DataClass::RawSignal`, nanoseconds.
    pub raw_retention_ns: u64,
    /// Retention for `DataClass::DerivedFeature`, nanoseconds.
    pub derived_retention_ns: u64,
    /// Retention for `DataClass::FederatedEvent`, nanoseconds.
    pub event_retention_ns: u64,
    /// Disclosure policy applied to everything that leaves the biome.
    pub disclosure: DisclosurePolicy,
}

impl BiomeConfig {
    /// Config with the [`DataClass::default_retention_ns`] retention defaults
    /// and the default (privacy-preserving) disclosure policy.
    #[must_use]
    pub fn new(biome_id: impl Into<String>) -> Self {
        BiomeConfig {
            biome_id: biome_id.into(),
            raw_retention_ns: DataClass::RawSignal.default_retention_ns(),
            derived_retention_ns: DataClass::DerivedFeature.default_retention_ns(),
            event_retention_ns: DataClass::FederatedEvent.default_retention_ns(),
            disclosure: DisclosurePolicy::default(),
        }
    }
}

/// Outcome of [`Biome::accept`] for one sample.
///
/// There is deliberately **no `Unverified` variant**: `accept` takes a
/// [`VerifiedEnvSample`], which can only be produced by the ingest
/// pipeline's full cryptographic verification — an unverified sample is
/// unrepresentable at this API, so the outcome cannot occur (ADR-264 §12,
/// enforced by the type system instead of a runtime boolean).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptOutcome {
    /// Stored in the biome's observation log.
    Accepted,
    /// The `(node_id, sequence)` key was already accepted (live or replay).
    Duplicate,
    /// The producing device has been revoked.
    Revoked,
}

/// A sovereign biome region. Owns its observations, its ed25519 identity key
/// (derived deterministically from a seed), its revocation list, and its
/// disclosure policy (ADR-264 §6).
pub struct Biome {
    /// Sovereignty configuration.
    config: BiomeConfig,
    /// Deterministic biome identity key.
    key: SigningKey,
    /// Accepted observations, in arrival order.
    observations: Vec<EnvSample>,
    /// Global `(node_id, sequence)` index spanning live ingest *and* buffer
    /// replay — this is what makes post-outage restore duplicate-free.
    seen: BTreeSet<(u64, u32)>,
    /// Revoked devices with revocation reason.
    revoked: BTreeMap<u64, String>,
    /// How many samples were rejected as duplicates.
    duplicate_count: usize,
}

impl Biome {
    /// Create a biome whose ed25519 identity derives deterministically from
    /// `signer_seed` (same seed ⇒ same key ⇒ same signatures).
    #[must_use]
    pub fn new(config: BiomeConfig, signer_seed: &[u8; 32]) -> Self {
        Biome {
            config,
            key: SigningKey::from_bytes(signer_seed),
            observations: Vec::new(),
            seen: BTreeSet::new(),
            revoked: BTreeMap::new(),
            duplicate_count: 0,
        }
    }

    /// The biome's sovereignty configuration.
    #[must_use]
    pub fn config(&self) -> &BiomeConfig {
        &self.config
    }

    /// Hex-encoded ed25519 public key — the biome's federated identity.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        sig::hex_encode(self.key.verifying_key().as_bytes())
    }

    /// Crate-internal access to the identity key (used by summary signing).
    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    /// Admit one cryptographically verified sample. Revoked devices are
    /// blocked, and the global dedup index rejects any `(node_id, sequence)`
    /// key already accepted — whether it arrived live or via
    /// [`crate::OutageBuffer`] replay (re-verified through
    /// `IngestPipeline::reverify_stored`) after an outage.
    ///
    /// Unverified data is unrepresentable here (ADR-264 §12): the parameter
    /// type [`VerifiedEnvSample`] has no public constructor and is not
    /// deserializable, so only the ingest pipeline's full registry +
    /// signature checks can mint one. Passing a bare
    /// [`rucelium_core::EnvSample`] — however its `provenance.verified` flag
    /// is set — does not compile:
    ///
    /// ```compile_fail
    /// use rucelium_federation::Biome;
    ///
    /// fn smuggle(biome: &mut Biome, forged: rucelium_core::EnvSample) {
    ///     // ERROR: expected `VerifiedEnvSample`, found `EnvSample` — a
    ///     // deserialized sample claiming `provenance.verified = true`
    ///     // cannot impersonate a sealed one.
    ///     biome.accept(forged);
    /// }
    /// ```
    pub fn accept(&mut self, sample: VerifiedEnvSample) -> AcceptOutcome {
        let sample = sample.into_inner();
        if self.revoked.contains_key(&sample.node_id) {
            return AcceptOutcome::Revoked;
        }
        if !self.seen.insert(sample.dedup_key()) {
            self.duplicate_count += 1;
            return AcceptOutcome::Duplicate;
        }
        self.observations.push(sample);
        AcceptOutcome::Accepted
    }

    /// Accepted observations, in arrival order.
    #[must_use]
    pub fn observations(&self) -> &[EnvSample] {
        &self.observations
    }

    /// Number of accepted observations.
    #[must_use]
    pub fn accepted_count(&self) -> usize {
        self.observations.len()
    }

    /// Number of samples rejected as duplicates.
    #[must_use]
    pub fn duplicate_count(&self) -> usize {
        self.duplicate_count
    }

    /// Whether a device has been revoked.
    #[must_use]
    pub fn is_revoked(&self, node_id: u64) -> bool {
        self.revoked.contains_key(&node_id)
    }

    /// Revoke a device: its key is invalid at this biome immediately —
    /// subsequent [`accept`](Biome::accept) calls return
    /// [`AcceptOutcome::Revoked`] while other nodes keep flowing — and the
    /// revocation propagates outward as a signed [`EnvironmentalEvent`]
    /// (ADR-264 §12, §14 criterion 7).
    pub fn revoke_device(&mut self, node_id: u64, now_ns: u64, reason: &str) -> EnvironmentalEvent {
        let last = self
            .observations
            .iter()
            .rev()
            .find(|s| s.node_id == node_id);
        let evidence = vec![EvidenceRef {
            node_id,
            sequence: last.map_or(0, |s| s.sequence),
        }];
        let modality = last.map_or(SensorModality::WifiCsi, |s| s.modality);
        let geo = last.map_or(
            GeoPoint {
                latitude_e7: 0,
                longitude_e7: 0,
                altitude_mm: 0,
            },
            |s| s.geo,
        );
        let window_start_ns = last.map_or(now_ns, |s| s.measured_ns.min(now_ns));
        self.revoked.insert(node_id, reason.to_string());

        let mut event = EnvironmentalEvent {
            spec_version: SPEC_VERSION.into(),
            event_id: format!("revoke:{}:{node_id}:{now_ns}", self.config.biome_id),
            biome_id: self.config.biome_id.clone(),
            kind: EventKind::DeviceRevoked,
            severity: Severity::Warning,
            modality,
            geo,
            window_start_ns,
            window_end_ns: now_ns,
            detected_ns: now_ns,
            evidence,
            confidence: 1.0,
            // A revocation makes no claim about observation content.
            evidence_digest: None,
            message: format!("device {node_id} revoked: {reason}"),
            signature_hex: None,
            signer_pubkey_hex: None,
        };
        self.sign_event(&mut event);
        event
    }

    /// Sign an event in place with the biome key: the signature covers the
    /// canonical JSON of the event with both signature fields cleared (same
    /// pattern as `rufield-provenance`).
    pub fn sign_event(&self, event: &mut EnvironmentalEvent) {
        // Fail closed: never mint a signature over a payload that cannot
        // survive its own wire format (see `crate::round_trips`). A
        // non-finite float becomes JSON `null`, which verifies in-process and
        // is unparseable at the peer — so leave it unsigned and let
        // `FederationBus::publish_event` reject it as `Unsigned`, rather than
        // shipping an artifact that looks valid and is not.
        if !crate::round_trips(event) {
            event.signature_hex = None;
            event.signer_pubkey_hex = None;
            return;
        }
        let bytes = canonical_event_bytes(event);
        let signature: Signature = self.key.sign(&bytes);
        event.signature_hex = Some(sig::hex_encode(&signature.to_bytes()));
        event.signer_pubkey_hex = Some(self.public_key_hex());
    }

    /// Apply the disclosure policy to an event bound for outside the biome
    /// (ADR-264 §6). Returns `None` while the delayed-disclosure window is
    /// still open (`now_ns < detected_ns + delay_ns`); otherwise a clone with
    /// its location coarsened per policy, re-signed by the biome so the
    /// disclosed form still verifies.
    #[must_use]
    pub fn disclose_event(
        &self,
        event: &EnvironmentalEvent,
        now_ns: u64,
    ) -> Option<EnvironmentalEvent> {
        let release_ns = event
            .detected_ns
            .saturating_add(self.config.disclosure.delay_ns);
        if now_ns < release_ns {
            return None;
        }
        let mut out = event.clone();
        if let Some(d) = self.config.disclosure.coarsen_decimals {
            out.geo = out.geo.coarsen(d);
        }
        self.sign_event(&mut out);
        Some(out)
    }
}

impl std::fmt::Debug for Biome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Biome")
            .field("biome_id", &self.config.biome_id)
            .field("public_key_hex", &self.public_key_hex())
            .field("accepted", &self.observations.len())
            .field("duplicates", &self.duplicate_count)
            .field("revoked", &self.revoked.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// Canonical bytes signed for an event: the event with its signature fields
/// cleared, as compact JSON.
pub(crate) fn canonical_event_bytes(event: &EnvironmentalEvent) -> Vec<u8> {
    let mut ev = event.clone();
    ev.signature_hex = None;
    ev.signer_pubkey_hex = None;
    serde_json::to_vec(&ev).expect("EnvironmentalEvent JSON serialization cannot fail")
}

/// Verify the biome signature carried on an event. `true` only when both
/// signature fields are present and the signature verifies over the
/// canonical bytes — any field tamper breaks it.
#[must_use]
pub fn verify_event(event: &EnvironmentalEvent) -> bool {
    let (Some(sig_hex), Some(pk_hex)) = (&event.signature_hex, &event.signer_pubkey_hex) else {
        return false;
    };
    sig::verify_detached(pk_hex, sig_hex, &canonical_event_bytes(event))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{pipeline, sample, signed_envelope, verified_sample, SEED};
    use crate::OutageBuffer;

    fn biome() -> Biome {
        Biome::new(BiomeConfig::new("biome/test-forest"), SEED)
    }

    #[test]
    fn config_defaults_track_data_classes() {
        let c = BiomeConfig::new("biome/x");
        assert_eq!(
            c.raw_retention_ns,
            DataClass::RawSignal.default_retention_ns()
        );
        assert_eq!(
            c.derived_retention_ns,
            DataClass::DerivedFeature.default_retention_ns()
        );
        assert_eq!(
            c.event_retention_ns,
            DataClass::FederatedEvent.default_retention_ns()
        );
        assert!(!c.disclosure.open_access);
    }

    /// The only way to reach `accept` is through the ingest pipeline's full
    /// cryptographic verification — `VerifiedEnvSample` is not
    /// deserializable and has no public constructor, so a
    /// `serde_json`-deserialized `EnvSample` with `provenance.verified =
    /// true` cannot be passed in (see the `compile_fail` doctest on
    /// [`Biome::accept`]). This test exercises the one honest path.
    #[test]
    fn only_the_ingest_pipeline_can_mint_acceptable_samples() {
        // A forged serialized sample claiming verified = true deserializes
        // fine as an EnvSample...
        let forged = sample(1, 1, 1_000, 20.0);
        let json = serde_json::to_string(&forged).unwrap();
        let back: EnvSample = serde_json::from_str(&json).unwrap();
        assert!(back.provenance.verified);
        // ...but `Biome::accept(back)` does not compile. The honest path:
        let mut p = pipeline(&[1]);
        let mut b = biome();
        let sealed = verified_sample(&mut p, 1, 1, 1_000, 20.0);
        assert!(sealed.sample().provenance.verified);
        assert_eq!(b.accept(sealed), AcceptOutcome::Accepted);
        assert_eq!(b.accepted_count(), 1);
    }

    #[test]
    fn duplicates_across_live_and_replay_counted_once() {
        let mut p = pipeline(&[1]);
        let mut b = biome();
        // Live ingest.
        assert_eq!(
            b.accept(verified_sample(&mut p, 1, 1, 1_000, 20.0)),
            AcceptOutcome::Accepted
        );
        assert_eq!(
            b.accept(verified_sample(&mut p, 1, 2, 2_000, 20.5)),
            AcceptOutcome::Accepted
        );

        // Outage: the gateway buffered overlapping signed envelopes, then
        // replays them through full re-verification.
        let mut buf = OutageBuffer::new();
        // Already live-ingested.
        assert!(buf
            .push(&signed_envelope(1, 2, 2_000, 20.5), 3_000_000)
            .unwrap());
        // New.
        assert!(buf
            .push(&signed_envelope(1, 3, 3_000, 21.0), 3_000_000)
            .unwrap());
        let mut outcomes = Vec::new();
        for (envelope, received_ns) in buf.drain() {
            let sealed = p.reverify_stored(&envelope, received_ns).unwrap();
            outcomes.push(b.accept(sealed));
        }
        assert_eq!(
            outcomes,
            vec![AcceptOutcome::Duplicate, AcceptOutcome::Accepted]
        );
        assert_eq!(b.accepted_count(), 3);
        assert_eq!(b.duplicate_count(), 1);
    }

    #[test]
    fn revoked_device_blocked_while_healthy_device_flows() {
        let mut p = pipeline(&[7, 8]);
        let mut b = biome();
        assert_eq!(
            b.accept(verified_sample(&mut p, 7, 1, 1_000, 20.0)),
            AcceptOutcome::Accepted
        );
        assert_eq!(
            b.accept(verified_sample(&mut p, 8, 1, 1_000, 19.0)),
            AcceptOutcome::Accepted
        );

        let event = b.revoke_device(7, 5_000, "key compromised");
        assert!(b.is_revoked(7));
        assert!(!b.is_revoked(8));
        assert_eq!(event.kind, EventKind::DeviceRevoked);
        assert_eq!(event.severity, Severity::Warning);
        assert_eq!(
            event.evidence,
            vec![EvidenceRef {
                node_id: 7,
                sequence: 1
            }]
        );
        event.validate().unwrap();

        // Revoked node blocked (even with a cryptographically valid sample),
        // healthy node keeps flowing.
        assert_eq!(
            b.accept(verified_sample(&mut p, 7, 2, 2_000, 20.5)),
            AcceptOutcome::Revoked
        );
        assert_eq!(
            b.accept(verified_sample(&mut p, 8, 2, 2_000, 19.5)),
            AcceptOutcome::Accepted
        );
        assert_eq!(b.accepted_count(), 3);
    }

    #[test]
    fn revoking_never_seen_device_uses_sequence_zero() {
        let mut b = biome();
        let event = b.revoke_device(99, 1_000, "preemptive");
        assert_eq!(
            event.evidence,
            vec![EvidenceRef {
                node_id: 99,
                sequence: 0
            }]
        );
        assert!(verify_event(&event));
    }

    #[test]
    fn revocation_event_verifies_and_tamper_breaks_it() {
        let mut p = pipeline(&[7]);
        let mut b = biome();
        b.accept(verified_sample(&mut p, 7, 1, 1_000, 20.0));
        let event = b.revoke_device(7, 5_000, "drift");
        assert!(verify_event(&event));

        let mut t = event.clone();
        t.severity = Severity::Advisory;
        assert!(!verify_event(&t));

        let mut t = event.clone();
        t.biome_id = "biome/other".into();
        assert!(!verify_event(&t));

        let mut t = event.clone();
        t.message.push('!');
        assert!(!verify_event(&t));

        let mut t = event.clone();
        t.signature_hex = None;
        assert!(!verify_event(&t));
    }

    /// An unsigned event for determinism checks.
    fn unsigned_event() -> EnvironmentalEvent {
        EnvironmentalEvent {
            evidence_digest: None,
            spec_version: SPEC_VERSION.into(),
            event_id: "evt-det".into(),
            biome_id: "biome/test-forest".into(),
            kind: EventKind::Anomaly,
            severity: Severity::Watch,
            modality: SensorModality::Weather,
            geo: GeoPoint::new(1, 2, 3).unwrap(),
            window_start_ns: 1,
            window_end_ns: 2,
            detected_ns: 3,
            evidence: vec![EvidenceRef {
                node_id: 1,
                sequence: 1,
            }],
            confidence: 0.5,
            message: "det".into(),
            signature_hex: None,
            signer_pubkey_hex: None,
        }
    }

    #[test]
    fn signing_is_deterministic() {
        let b1 = biome();
        let b2 = biome();
        assert_eq!(b1.public_key_hex(), b2.public_key_hex());
        let mut e1 = unsigned_event();
        let mut e2 = unsigned_event();
        b1.sign_event(&mut e1);
        b2.sign_event(&mut e2);
        assert_eq!(e1.signature_hex, e2.signature_hex);
        assert!(verify_event(&e1));
    }

    #[test]
    fn disclosure_delay_withholds_then_releases_coarsened() {
        let mut config = BiomeConfig::new("biome/protected");
        config.disclosure = DisclosurePolicy {
            coarsen_decimals: Some(2),
            delay_ns: 1_000_000,
            open_access: false,
        };
        let mut b = Biome::new(config, SEED);
        let mut p = pipeline(&[7]);
        b.accept(verified_sample(&mut p, 7, 1, 1_000, 20.0));
        let event = b.revoke_device(7, 5_000, "tamper");

        // Before the delay elapses: withheld.
        assert!(b.disclose_event(&event, 5_000).is_none());
        assert!(b.disclose_event(&event, 5_000 + 999_999).is_none());

        // After: released with coarsened geo, still verifying.
        let out = b.disclose_event(&event, 5_000 + 1_000_000).unwrap();
        assert_eq!(out.geo, event.geo.coarsen(2));
        assert_ne!(out.geo, event.geo);
        assert!(verify_event(&out));
    }

    #[test]
    fn open_full_precision_policy_passes_geo_through() {
        let mut config = BiomeConfig::new("biome/open");
        config.disclosure = DisclosurePolicy {
            coarsen_decimals: None,
            delay_ns: 0,
            open_access: true,
        };
        let mut b = Biome::new(config, SEED);
        let mut p = pipeline(&[7]);
        b.accept(verified_sample(&mut p, 7, 1, 1_000, 20.0));
        let event = b.revoke_device(7, 5_000, "x");
        let out = b.disclose_event(&event, 5_000).unwrap();
        assert_eq!(out.geo, event.geo);
        assert!(verify_event(&out));
    }
}
