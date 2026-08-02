//! Signed regional summaries and the minimal federation exchange
//! (ADR-264 §6): biomes federate **signed events and statistical
//! summaries**, never raw measurements.

use crate::biome::{verify_event, Biome};
use crate::sig;
use ed25519_dalek::{Signature, Signer as _};
use rucelium_core::EnvironmentalEvent;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Per-modality aggregate statistics over one summary window.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ModalityStats {
    /// Number of contributing observations.
    pub count: u64,
    /// Arithmetic mean of the calibrated values.
    pub mean: f64,
    /// Minimum value in the window.
    pub min: f64,
    /// Maximum value in the window.
    pub max: f64,
    /// Mean quality score of the contributing observations.
    pub mean_quality: f64,
}

/// A signed statistical summary of one biome over one time window — the
/// `DataClass::FederatedEvent`-class aggregate that leaves the biome instead
/// of raw data (ADR-264 §6, §10).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegionalSummary {
    /// Wire spec version.
    pub spec_version: String,
    /// Producing biome.
    pub biome_id: String,
    /// Window start (inclusive), ns since Unix epoch.
    pub window_start_ns: u64,
    /// Window end (exclusive), ns since Unix epoch.
    pub window_end_ns: u64,
    /// Per-modality statistics, keyed by `SensorModality::as_str()` (BTreeMap
    /// for deterministic canonical bytes).
    pub stats: BTreeMap<String, ModalityStats>,
    /// Hex ed25519 signature by the biome key, if signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
    /// Hex signer public key, if signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_pubkey_hex: Option<String>,
}

/// Canonical bytes signed for a summary: the summary with its signature
/// fields cleared, as compact JSON.
fn canonical_summary_bytes(summary: &RegionalSummary) -> Vec<u8> {
    let mut s = summary.clone();
    s.signature_hex = None;
    s.signer_pubkey_hex = None;
    serde_json::to_vec(&s).expect("RegionalSummary JSON serialization cannot fail")
}

/// Verify the biome signature on a summary. `true` only when both signature
/// fields are present and verify over the canonical bytes — any field tamper
/// breaks it.
#[must_use]
pub fn verify_summary(summary: &RegionalSummary) -> bool {
    let (Some(sig_hex), Some(pk_hex)) = (&summary.signature_hex, &summary.signer_pubkey_hex) else {
        return false;
    };
    sig::verify_detached(pk_hex, sig_hex, &canonical_summary_bytes(summary))
}

impl Biome {
    /// Aggregate accepted observations with `measured_ns` in
    /// `[window_start_ns, window_end_ns)` into a per-modality summary, signed
    /// with the biome key. Deterministic: plain sum/count means over the
    /// arrival-ordered observation log.
    #[must_use]
    pub fn summarize(&self, window_start_ns: u64, window_end_ns: u64) -> RegionalSummary {
        struct Acc {
            count: u64,
            sum: f64,
            min: f64,
            max: f64,
            quality_sum: f64,
        }
        let mut acc: BTreeMap<String, Acc> = BTreeMap::new();
        for s in self.observations() {
            if s.measured_ns < window_start_ns || s.measured_ns >= window_end_ns {
                continue;
            }
            let e = acc.entry(s.modality.as_str().to_string()).or_insert(Acc {
                count: 0,
                sum: 0.0,
                min: f64::INFINITY,
                max: f64::NEG_INFINITY,
                quality_sum: 0.0,
            });
            e.count += 1;
            e.sum += s.value;
            e.min = e.min.min(s.value);
            e.max = e.max.max(s.value);
            e.quality_sum += f64::from(s.quality);
        }

        let stats = acc
            .into_iter()
            .map(|(k, a)| {
                let n = a.count as f64;
                (
                    k,
                    ModalityStats {
                        count: a.count,
                        mean: a.sum / n,
                        min: a.min,
                        max: a.max,
                        mean_quality: a.quality_sum / n,
                    },
                )
            })
            .collect();

        let mut summary = RegionalSummary {
            spec_version: rucelium_core::SPEC_VERSION.into(),
            biome_id: self.config().biome_id.clone(),
            window_start_ns,
            window_end_ns,
            stats,
            signature_hex: None,
            signer_pubkey_hex: None,
        };
        self.sign_summary(&mut summary);
        summary
    }

    /// Sign a summary in place with the biome key (canonical bytes with the
    /// signature fields cleared, same pattern as event signing).
    pub fn sign_summary(&self, summary: &mut RegionalSummary) {
        // Fail closed — see `Biome::sign_event` and `crate::round_trips`.
        if !crate::round_trips(summary) {
            summary.signature_hex = None;
            summary.signer_pubkey_hex = None;
            return;
        }
        let bytes = canonical_summary_bytes(summary);
        let signature: Signature = self.signing_key().sign(&bytes);
        summary.signature_hex = Some(sig::hex_encode(&signature.to_bytes()));
        summary.signer_pubkey_hex = Some(self.public_key_hex());
    }
}

/// Errors raised by [`FederationBus`] registration and publication, and by
/// [`crate::OutageBuffer`] envelope handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationError {
    /// The payload carried no signature / signer key.
    Unsigned,
    /// The signature did not verify over the canonical bytes.
    BadSignature,
    /// The payload's `biome_id` is not a registered biome.
    UnknownBiome(String),
    /// The payload's signer key is not the key registered for its claimed
    /// `biome_id` — a registered key may not publish under another biome's
    /// identity.
    IdentityMismatch {
        /// The biome identity the payload claimed.
        biome_id: String,
    },
    /// Re-registration attempted with a key epoch at or below the current
    /// one while changing the key — rotation requires a strictly higher
    /// epoch.
    StaleKeyEpoch {
        /// The biome being (re-)registered.
        biome_id: String,
        /// The rejected epoch.
        epoch: u32,
    },
    /// A summary for this `(biome_id, window_start_ns, window_end_ns)` was
    /// already accepted — replayed summaries are rejected.
    /// An established identity cannot be rebound without a signed
    /// succession (ADR-270 §3) — the takeover path, closed.
    SuccessionRequired {
        /// The biome whose rebinding was refused.
        biome_id: String,
    },
    /// A succession carried neither the outgoing key's signature nor a
    /// sufficient custodian quorum.
    SuccessionUnauthorised {
        /// The biome the succession targeted.
        biome_id: String,
        /// Distinct valid custodian signatures present.
        custodian_signatures: u32,
        /// How many were required.
        threshold: u32,
    },
    /// A custodian threshold larger than the custodian set can satisfy.
    UnreachableThreshold {
        /// The biome the declaration targeted.
        biome_id: String,
        /// The threshold requested.
        threshold: u32,
        /// How many custodians were declared.
        custodians: usize,
    },
    DuplicateSummary,
    /// An event with this `event_id` was already accepted — replayed events
    /// are rejected.
    DuplicateEvent,
    /// Bytes did not structurally decode as a signed wire envelope.
    BadEnvelope(String),
}

impl std::fmt::Display for FederationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FederationError::Unsigned => write!(f, "payload is unsigned"),
            FederationError::BadSignature => write!(f, "signature verification failed"),
            FederationError::UnknownBiome(id) => {
                write!(f, "not a registered biome: {id}")
            }
            FederationError::IdentityMismatch { biome_id } => {
                write!(f, "signer key is not the registered key for {biome_id}")
            }
            FederationError::StaleKeyEpoch { biome_id, epoch } => {
                write!(f, "stale key epoch {epoch} for {biome_id}")
            }
            FederationError::SuccessionRequired { biome_id } => write!(
                f,
                "biome {biome_id} is already bound; rebinding requires a signed succession"
            ),
            FederationError::SuccessionUnauthorised {
                biome_id,
                custodian_signatures,
                threshold,
            } => write!(
                f,
                "succession for {biome_id} unauthorised: no continuity signature and \
                 {custodian_signatures}/{threshold} custodian signatures"
            ),
            FederationError::UnreachableThreshold {
                biome_id,
                threshold,
                custodians,
            } => write!(
                f,
                "biome {biome_id}: custodian threshold {threshold} exceeds {custodians} declared custodians"
            ),
            FederationError::DuplicateSummary => {
                write!(f, "summary for this biome and window already accepted")
            }
            FederationError::DuplicateEvent => {
                write!(f, "event with this event_id already accepted")
            }
            FederationError::BadEnvelope(m) => write!(f, "envelope decode failed: {m}"),
        }
    }
}

impl std::error::Error for FederationError {}

/// A signed statement rotating a biome's federation key (ADR-270 §3).
///
/// This is the artifact that makes rotation *provable* rather than merely
/// asserted. Without it an epoch bump is an unauthenticated rebinding: the
/// loudest claimant wins the identity. With it, a rotation must carry either
/// the outgoing key's signature (continuity) or a quorum of pre-declared
/// custodian signatures (recovery after the holder is gone).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySuccession {
    /// The biome whose key is being rotated.
    pub biome_id: String,
    /// The epoch this succession replaces; must equal the bus's current epoch
    /// so a stale succession cannot be replayed forward.
    pub from_epoch: u32,
    /// The new epoch; must strictly exceed `from_epoch`.
    pub to_epoch: u32,
    /// The incoming hex ed25519 public key.
    pub new_pubkey_hex: String,
    /// When the succession takes effect (ns since Unix epoch); recorded for
    /// audit, not enforced by the bus, which has no clock.
    pub effective_ns: u64,
    /// Optional replacement custodian set — a succession may hand over the
    /// recovery quorum as well as the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_custodians: Option<Vec<String>>,
    /// Threshold for `new_custodians` when present.
    #[serde(default)]
    pub new_custodian_threshold: u32,
    /// `(signer_pubkey_hex, signature_hex)` pairs over
    /// [`canonical_succession_bytes`]. Order is irrelevant; duplicates by the
    /// same signer count once toward a quorum.
    #[serde(default)]
    pub signatures: Vec<(String, String)>,
}

/// Canonical bytes a succession is signed over: the statement with its
/// `signatures` list cleared, so a signature commits to every other field —
/// including `from_epoch`, which is what stops replay onto a later epoch.
#[must_use]
pub fn canonical_succession_bytes(succession: &KeySuccession) -> Vec<u8> {
    let mut bare = succession.clone();
    bare.signatures.clear();
    serde_json::to_vec(&bare).unwrap_or_default()
}

/// Append a signature to a succession using a raw 32-byte ed25519 seed.
/// Used by biome owners (continuity) and custodians (recovery) alike.
pub fn sign_succession(succession: &mut KeySuccession, seed: &[u8; 32]) {
    use ed25519_dalek::{Signer as _, SigningKey};
    let key = SigningKey::from_bytes(seed);
    let canonical = canonical_succession_bytes(succession);
    let sig = key.sign(&canonical);
    succession.signatures.push((
        sig::hex_encode(key.verifying_key().as_bytes()),
        sig::hex_encode(&sig.to_bytes()),
    ));
}

/// A biome's registered federation identity: current key, rotation epoch,
/// and the custodian quorum that can outlive its holder (ADR-270 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
struct BiomeKey {
    /// Hex ed25519 public key currently bound to the biome id.
    pubkey_hex: String,
    /// Monotonic rotation epoch; a succession must strictly increase it.
    key_epoch: u32,
    /// Custodian keys able to jointly authorise a rotation when the biome's
    /// own key is *lost* rather than compromised (ADR-270 §3).
    custodians: std::collections::BTreeSet<String>,
    /// How many distinct custodians must sign a recovery succession.
    /// Zero means the identity dies with its key — a valid choice.
    custodian_threshold: u32,
}

/// Minimal in-memory federation exchange (ADR-264 §7): registered biomes
/// publish signed summaries and events. Publication binds federation
/// identity to biome identity — the payload's `biome_id` must be registered
/// and its signer key must be the key registered *for that id* — and is
/// replay-protected: a summary window or event id is accepted at most once.
#[derive(Debug, Clone, Default)]
pub struct FederationBus {
    /// Registered biome identities and their current keys.
    biomes: BTreeMap<String, BiomeKey>,
    /// Accepted summaries, in publication order.
    summaries: Vec<RegionalSummary>,
    /// Accepted events, in publication order.
    events: Vec<EnvironmentalEvent>,
    /// Replay guard: every accepted `(biome_id, window_start_ns,
    /// window_end_ns)` summary window.
    seen_windows: BTreeSet<(String, u64, u64)>,
    /// Replay guard: every accepted `event_id`.
    seen_events: BTreeSet<String>,
}

impl FederationBus {
    /// Create an empty bus.
    #[must_use]
    pub fn new() -> Self {
        FederationBus::default()
    }

    /// Register a biome's **genesis** key (ADR-270 §3).
    ///
    /// Genesis is trust-on-first-use and is the *only* unauthenticated
    /// binding this bus performs. Re-registering the same key is idempotent;
    /// changing a key requires [`Self::rotate_biome`] with a signed
    /// succession, because an unauthenticated epoch bump is an identity
    /// takeover, not a rotation.
    pub fn register_biome(
        &mut self,
        biome_id: impl Into<String>,
        pubkey_hex: impl Into<String>,
        key_epoch: u32,
    ) -> Result<(), FederationError> {
        self.register_biome_with_custodians(biome_id, pubkey_hex, key_epoch, &[], 0)
    }

    /// Genesis registration that also declares a custodian recovery quorum.
    ///
    /// The custodians answer the twenty-year question a lone key cannot:
    /// what happens when the *institution* holding it is dissolved, merged,
    /// or simply loses it? An m-of-n quorum declared here can jointly
    /// authorise a succession without the original key ever being available
    /// again. `custodian_threshold = 0` opts out — the identity then dies
    /// with its key, which is a legitimate choice, not an oversight.
    pub fn register_biome_with_custodians(
        &mut self,
        biome_id: impl Into<String>,
        pubkey_hex: impl Into<String>,
        key_epoch: u32,
        custodians: &[String],
        custodian_threshold: u32,
    ) -> Result<(), FederationError> {
        let biome_id = biome_id.into();
        let pubkey_hex = pubkey_hex.into();
        if custodian_threshold as usize > custodians.len() {
            return Err(FederationError::UnreachableThreshold {
                biome_id,
                threshold: custodian_threshold,
                custodians: custodians.len(),
            });
        }
        if let Some(current) = self.biomes.get(&biome_id) {
            if pubkey_hex == current.pubkey_hex && key_epoch <= current.key_epoch {
                return Ok(()); // idempotent re-registration of the same key
            }
            return Err(FederationError::SuccessionRequired { biome_id });
        }
        self.biomes.insert(
            biome_id,
            BiomeKey {
                pubkey_hex,
                key_epoch,
                custodians: custodians.iter().cloned().collect(),
                custodian_threshold,
            },
        );
        Ok(())
    }

    /// Rotate a biome's key by presenting a **signed succession**
    /// (ADR-270 §3). Two authorisation paths, and no third:
    ///
    /// 1. **Continuity** — signed by the key currently bound to the biome.
    /// 2. **Recovery** — signed by at least `custodian_threshold` *distinct*
    ///    declared custodians. This is the path that outlives the
    ///    institution.
    ///
    /// Everything else is refused, including an epoch bump carrying no
    /// signatures — which, before this existed, silently rebound the
    /// identity to whoever asked last.
    pub fn rotate_biome(&mut self, succession: &KeySuccession) -> Result<(), FederationError> {
        let current = self
            .biomes
            .get(&succession.biome_id)
            .ok_or_else(|| FederationError::UnknownBiome(succession.biome_id.clone()))?;

        if succession.to_epoch <= succession.from_epoch
            || succession.from_epoch != current.key_epoch
        {
            return Err(FederationError::StaleKeyEpoch {
                biome_id: succession.biome_id.clone(),
                epoch: succession.to_epoch,
            });
        }
        if succession.new_pubkey_hex.is_empty() || succession.signatures.is_empty() {
            return Err(FederationError::Unsigned);
        }

        let canonical = canonical_succession_bytes(succession);
        let continuity = succession
            .signatures
            .iter()
            .any(|(k, sig)| *k == current.pubkey_hex && sig::verify_detached(k, sig, &canonical));

        let mut quorum = std::collections::BTreeSet::new();
        if current.custodian_threshold > 0 {
            for (k, sig) in &succession.signatures {
                if current.custodians.contains(k) && sig::verify_detached(k, sig, &canonical) {
                    quorum.insert(k.clone());
                }
            }
        }
        let recovered =
            current.custodian_threshold > 0 && quorum.len() as u32 >= current.custodian_threshold;

        if !continuity && !recovered {
            return Err(FederationError::SuccessionUnauthorised {
                biome_id: succession.biome_id.clone(),
                custodian_signatures: quorum.len() as u32,
                threshold: current.custodian_threshold,
            });
        }

        // A succession may also hand over the recovery quorum itself.
        let (custodians, threshold) = match &succession.new_custodians {
            Some(list) => {
                if succession.new_custodian_threshold as usize > list.len() {
                    return Err(FederationError::UnreachableThreshold {
                        biome_id: succession.biome_id.clone(),
                        threshold: succession.new_custodian_threshold,
                        custodians: list.len(),
                    });
                }
                (
                    list.iter().cloned().collect(),
                    succession.new_custodian_threshold,
                )
            }
            None => (current.custodians.clone(), current.custodian_threshold),
        };

        self.biomes.insert(
            succession.biome_id.clone(),
            BiomeKey {
                pubkey_hex: succession.new_pubkey_hex.clone(),
                key_epoch: succession.to_epoch,
                custodians,
                custodian_threshold: threshold,
            },
        );
        Ok(())
    }

    /// The identity gate every published artifact passes: the `biome_id` must
    /// be registered, and the signer key must be *the key registered for that
    /// id* — not merely some key the bus knows.
    fn check_identity(
        &self,
        biome_id: &str,
        signer_pubkey_hex: &str,
    ) -> Result<(), FederationError> {
        let Some(registered) = self.biomes.get(biome_id) else {
            return Err(FederationError::UnknownBiome(biome_id.to_string()));
        };
        if registered.pubkey_hex != signer_pubkey_hex {
            return Err(FederationError::IdentityMismatch {
                biome_id: biome_id.to_string(),
            });
        }
        Ok(())
    }

    /// Publish a signed regional summary. Checks, in order: signature fields
    /// present ([`FederationError::Unsigned`]); `summary.biome_id` registered
    /// ([`FederationError::UnknownBiome`]); signer key is the key registered
    /// for that id ([`FederationError::IdentityMismatch`] — a registered key
    /// claiming another biome's id is rejected); signature verifies
    /// ([`FederationError::BadSignature`]); and the `(biome_id,
    /// window_start_ns, window_end_ns)` window was never accepted before
    /// ([`FederationError::DuplicateSummary`] — replay protection).
    pub fn publish(&mut self, summary: RegionalSummary) -> Result<(), FederationError> {
        let (Some(_), Some(pk)) = (&summary.signature_hex, &summary.signer_pubkey_hex) else {
            return Err(FederationError::Unsigned);
        };
        self.check_identity(&summary.biome_id, pk)?;
        if !verify_summary(&summary) {
            return Err(FederationError::BadSignature);
        }
        let window = (
            summary.biome_id.clone(),
            summary.window_start_ns,
            summary.window_end_ns,
        );
        if !self.seen_windows.insert(window) {
            return Err(FederationError::DuplicateSummary);
        }
        self.summaries.push(summary);
        Ok(())
    }

    /// Publish a signed environmental event with the same identity binding
    /// (via `event.biome_id`) and signature checks as [`Self::publish`],
    /// plus dedup by `event_id` ([`FederationError::DuplicateEvent`]).
    pub fn publish_event(&mut self, event: EnvironmentalEvent) -> Result<(), FederationError> {
        let (Some(_), Some(pk)) = (&event.signature_hex, &event.signer_pubkey_hex) else {
            return Err(FederationError::Unsigned);
        };
        self.check_identity(&event.biome_id, pk)?;
        if !verify_event(&event) {
            return Err(FederationError::BadSignature);
        }
        if !self.seen_events.insert(event.event_id.clone()) {
            return Err(FederationError::DuplicateEvent);
        }
        self.events.push(event);
        Ok(())
    }

    /// Accepted summaries, in publication order.
    #[must_use]
    pub fn summaries(&self) -> &[RegionalSummary] {
        &self.summaries
    }

    /// Accepted events, in publication order.
    #[must_use]
    pub fn events(&self) -> &[EnvironmentalEvent] {
        &self.events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::biome::BiomeConfig;
    use crate::testutil::{pipeline, verified_sample, SEED};

    const BIOME_ID: &str = "biome/test-forest";

    /// A biome populated through the sealed ingest path — `summarize` runs
    /// over observations that all arrived via `Biome::accept`.
    fn biome_with_data() -> Biome {
        let mut p = pipeline(&[1, 2]);
        let mut b = Biome::new(BiomeConfig::new(BIOME_ID), SEED);
        b.accept(verified_sample(&mut p, 1, 1, 1_000, 10.0));
        b.accept(verified_sample(&mut p, 1, 2, 2_000, 20.0));
        b.accept(verified_sample(&mut p, 2, 1, 3_000, 30.0));
        b.accept(verified_sample(&mut p, 2, 2, 9_000, 99.0)); // outside [0, 5000) window
        b
    }

    /// A registered bus for `biome_with_data`'s biome at epoch 1.
    fn registered_bus(b: &Biome) -> FederationBus {
        let mut bus = FederationBus::new();
        bus.register_biome(BIOME_ID, b.public_key_hex(), 1).unwrap();
        bus
    }

    #[test]
    fn summarize_produces_exact_stats_over_sealed_observations() {
        let b = biome_with_data();
        assert_eq!(b.accepted_count(), 4);
        let s = b.summarize(0, 5_000);
        assert_eq!(s.spec_version, rucelium_core::SPEC_VERSION);
        assert_eq!(s.biome_id, BIOME_ID);
        let w = &s.stats["weather"];
        assert_eq!(w.count, 3);
        assert!((w.mean - 20.0).abs() < 1e-12);
        assert!((w.min - 10.0).abs() < f64::EPSILON);
        assert!((w.max - 30.0).abs() < f64::EPSILON);
        // 0x7000 / 0x8000 in Q0.15 = 0.875 exactly.
        assert!((w.mean_quality - 0.875).abs() < 1e-12);
        // Window is half-open: measured_ns = 9_000 excluded.
        assert_eq!(s.stats.len(), 1);
    }

    #[test]
    fn summary_sign_verify_round_trip_and_tamper() {
        let b = biome_with_data();
        let s = b.summarize(0, 5_000);
        assert!(verify_summary(&s));

        // Serde round trip preserves the signature.
        let json = serde_json::to_string(&s).unwrap();
        let back: RegionalSummary = serde_json::from_str(&json).unwrap();
        assert!(verify_summary(&back));

        // Tampered mean fails.
        let mut t = s.clone();
        t.stats.get_mut("weather").unwrap().mean = 21.0;
        assert!(!verify_summary(&t));

        // Tampered window fails.
        let mut t = s.clone();
        t.window_end_ns += 1;
        assert!(!verify_summary(&t));

        // Unsigned fails.
        let mut t = s.clone();
        t.signature_hex = None;
        assert!(!verify_summary(&t));
    }

    #[test]
    fn bus_rejects_unknown_tampered_and_unsigned_accepts_good() {
        let b = biome_with_data();
        let s = b.summarize(0, 5_000);
        let mut bus = FederationBus::new();

        // Unregistered biome id.
        assert_eq!(
            bus.publish(s.clone()),
            Err(FederationError::UnknownBiome(BIOME_ID.into()))
        );

        bus.register_biome(BIOME_ID, b.public_key_hex(), 1).unwrap();

        // Unsigned.
        let mut unsigned = s.clone();
        unsigned.signature_hex = None;
        unsigned.signer_pubkey_hex = None;
        assert_eq!(bus.publish(unsigned), Err(FederationError::Unsigned));

        // Tampered.
        let mut tampered = s.clone();
        tampered.stats.get_mut("weather").unwrap().count = 999;
        assert_eq!(bus.publish(tampered), Err(FederationError::BadSignature));

        // Good.
        bus.publish(s).unwrap();
        assert_eq!(bus.summaries().len(), 1);
    }

    #[test]
    fn registered_key_claiming_another_biome_id_is_rejected() {
        let b = biome_with_data();
        let mut bus = registered_bus(&b);
        // A second, honestly registered biome with a different key.
        let other = Biome::new(
            BiomeConfig::new("biome/other"),
            b"rucelium-other-seed-32-bytes-ok!",
        );
        bus.register_biome("biome/other", other.public_key_hex(), 1)
            .unwrap();

        // Attack: our registered key signs a summary claiming biome/other's
        // identity. The signature verifies and the key IS registered — but
        // not for that biome_id.
        let mut cross = b.summarize(0, 5_000);
        cross.biome_id = "biome/other".into();
        b.sign_summary(&mut cross);
        assert!(verify_summary(&cross));
        assert_eq!(
            bus.publish(cross),
            Err(FederationError::IdentityMismatch {
                biome_id: "biome/other".into()
            })
        );
        assert!(bus.summaries().is_empty());
    }

    #[test]
    fn duplicate_summary_window_is_rejected() {
        let b = biome_with_data();
        let mut bus = registered_bus(&b);
        let s = b.summarize(0, 5_000);
        bus.publish(s.clone()).unwrap();
        // Exact replay.
        assert_eq!(bus.publish(s), Err(FederationError::DuplicateSummary));
        // Same window, freshly re-signed: still a duplicate.
        let mut again = b.summarize(0, 5_000);
        b.sign_summary(&mut again);
        assert_eq!(bus.publish(again), Err(FederationError::DuplicateSummary));
        // A different window is fine.
        bus.publish(b.summarize(5_000, 10_000)).unwrap();
        assert_eq!(bus.summaries().len(), 2);
    }

    #[test]
    fn key_rotation_replaces_key_and_rejects_stale_epochs() {
        const ROTATED: &[u8; 32] = b"rucelium-rotated-seed-32-bytes-!";
        let b = biome_with_data();
        let mut bus = registered_bus(&b);
        let old_key_summary = b.summarize(0, 5_000);

        // Rotation now requires a succession the outgoing key signed
        // (ADR-270 §3) — an epoch bump alone is refused.
        let rotated = Biome::new(BiomeConfig::new(BIOME_ID), ROTATED);
        assert!(matches!(
            bus.register_biome(BIOME_ID, rotated.public_key_hex(), 2),
            Err(FederationError::SuccessionRequired { .. })
        ));
        let mut handover = KeySuccession {
            biome_id: BIOME_ID.to_string(),
            from_epoch: 1,
            to_epoch: 2,
            new_pubkey_hex: rotated.public_key_hex(),
            effective_ns: 1_000,
            new_custodians: None,
            new_custodian_threshold: 0,
            signatures: Vec::new(),
        };
        sign_succession(&mut handover, SEED);
        bus.rotate_biome(&handover).unwrap();

        // The old key's summary is now an identity mismatch.
        assert_eq!(
            bus.publish(old_key_summary),
            Err(FederationError::IdentityMismatch {
                biome_id: BIOME_ID.into()
            })
        );
        // The rotated key publishes fine.
        bus.publish(rotated.summarize(0, 5_000)).unwrap();

        // Rolling the identity back to the retired key is refused, with or
        // without an epoch that looks plausible.
        assert!(matches!(
            bus.register_biome(BIOME_ID, b.public_key_hex(), 1),
            Err(FederationError::SuccessionRequired { .. })
        ));
        assert!(matches!(
            bus.register_biome(BIOME_ID, b.public_key_hex(), 3),
            Err(FederationError::SuccessionRequired { .. })
        ));
        // Idempotent re-registration of the current key is still a no-op.
        bus.register_biome(BIOME_ID, rotated.public_key_hex(), 2)
            .unwrap();
    }

    #[test]
    fn bus_publishes_events_with_identity_binding_and_event_dedup() {
        let mut b = biome_with_data();
        let event = b.revoke_device(1, 10_000, "compromised");
        let mut bus = FederationBus::new();

        assert_eq!(
            bus.publish_event(event.clone()),
            Err(FederationError::UnknownBiome(BIOME_ID.into()))
        );

        bus.register_biome(BIOME_ID, b.public_key_hex(), 1).unwrap();

        let mut tampered = event.clone();
        tampered.message.push('!');
        assert_eq!(
            bus.publish_event(tampered),
            Err(FederationError::BadSignature)
        );

        let mut unsigned = event.clone();
        unsigned.signature_hex = None;
        assert_eq!(bus.publish_event(unsigned), Err(FederationError::Unsigned));

        // Identity binding: the same registered key claiming another
        // registered biome's id is rejected.
        let other = Biome::new(
            BiomeConfig::new("biome/other"),
            b"rucelium-other-seed-32-bytes-ok!",
        );
        bus.register_biome("biome/other", other.public_key_hex(), 1)
            .unwrap();
        let mut cross = event.clone();
        cross.biome_id = "biome/other".into();
        b.sign_event(&mut cross);
        assert_eq!(
            bus.publish_event(cross),
            Err(FederationError::IdentityMismatch {
                biome_id: "biome/other".into()
            })
        );

        bus.publish_event(event.clone()).unwrap();
        assert_eq!(bus.events().len(), 1);

        // Replay by event_id is rejected.
        assert_eq!(
            bus.publish_event(event),
            Err(FederationError::DuplicateEvent)
        );
        assert_eq!(bus.events().len(), 1);
    }

    #[test]
    fn federation_error_displays() {
        assert_eq!(FederationError::Unsigned.to_string(), "payload is unsigned");
        assert!(FederationError::UnknownBiome("biome/x".into())
            .to_string()
            .contains("biome/x"));
        assert!(!FederationError::BadSignature.to_string().is_empty());
        assert!(FederationError::IdentityMismatch {
            biome_id: "biome/x".into()
        }
        .to_string()
        .contains("biome/x"));
        assert!(FederationError::StaleKeyEpoch {
            biome_id: "biome/x".into(),
            epoch: 3
        }
        .to_string()
        .contains('3'));
        assert!(!FederationError::DuplicateSummary.to_string().is_empty());
        assert!(!FederationError::DuplicateEvent.to_string().is_empty());
        assert!(FederationError::BadEnvelope("boom".into())
            .to_string()
            .contains("boom"));
    }

    /// A signed summary must still verify **after a JSON wire round-trip**.
    ///
    /// This is the real federation path: a biome signs canonical JSON, sends
    /// it, and the peer verifies by re-serializing what it parsed. Exact
    /// float parsing is therefore load-bearing — with `serde_json`'s default
    /// (fast, non-exact) float parser, roughly 9% of realistic sensor values
    /// come back one ULP off and a *genuine* summary fails verification. The
    /// workspace pins `serde_json`'s `float_roundtrip` feature for exactly
    /// this reason; this test is the guard that keeps it pinned.
    #[test]
    fn signed_summary_survives_a_json_wire_round_trip() {
        let biome = biome_with_data();
        // Values chosen to land on awkward binary fractions.
        let mut summary = biome.summarize(0, u64::MAX);
        summary.stats.insert(
            "weather".into(),
            ModalityStats {
                count: 3,
                mean: 23.470000000000002,
                min: 0.1 + 0.2,
                max: 1.0e-7 * 3.0,
                mean_quality: 0.9700000000000001,
            },
        );
        biome.sign_summary(&mut summary);
        assert!(verify_summary(&summary), "verifies before the wire");

        // Exactly what a peer does: serialize, transmit, parse, verify.
        let wire = serde_json::to_string(&summary).expect("serialize");
        let received: RegionalSummary = serde_json::from_str(&wire).expect("parse");
        assert!(
            verify_summary(&received),
            "a genuine signed summary must verify after a JSON wire round-trip"
        );

        // And the floats must be bit-identical, not merely close.
        for (k, before) in &summary.stats {
            let after = &received.stats[k];
            assert_eq!(before.mean.to_bits(), after.mean.to_bits(), "mean {k}");
            assert_eq!(before.min.to_bits(), after.min.to_bits(), "min {k}");
            assert_eq!(before.max.to_bits(), after.max.to_bits(), "max {k}");
            assert_eq!(
                before.mean_quality.to_bits(),
                after.mean_quality.to_bits(),
                "mean_quality {k}"
            );
        }
    }

    // --- ADR-270: key succession -------------------------------------------

    const CUST_A: &[u8; 32] = b"rucelium-custodian-a-seed-32byt!";
    const CUST_B: &[u8; 32] = b"rucelium-custodian-b-seed-32byt!";
    const CUST_C: &[u8; 32] = b"rucelium-custodian-c-seed-32byt!";
    const HEIR: &[u8; 32] = b"rucelium-successor-key-seed-32b!";
    const THIEF: &[u8; 32] = b"rucelium-attacker-key-seed-32by!";

    fn pubhex(seed: &[u8; 32]) -> String {
        use ed25519_dalek::SigningKey;
        sig::hex_encode(SigningKey::from_bytes(seed).verifying_key().as_bytes())
    }

    fn succession(from: u32, to: u32, new_key: &str) -> KeySuccession {
        KeySuccession {
            biome_id: BIOME_ID.to_string(),
            from_epoch: from,
            to_epoch: to,
            new_pubkey_hex: new_key.to_string(),
            effective_ns: 1_000,
            new_custodians: None,
            new_custodian_threshold: 0,
            signatures: Vec::new(),
        }
    }

    /// THE VULNERABILITY THIS CLOSES. Before signed succession existed, a
    /// higher epoch alone rebound the identity — so whoever claimed the
    /// biome last owned it. An unsigned rotation must now be refused.
    #[test]
    fn an_unsigned_epoch_bump_cannot_steal_an_identity() {
        let b = biome_with_data();
        let mut bus = registered_bus(&b);
        let thief = pubhex(THIEF);

        // The old path: just assert a higher epoch.
        assert!(matches!(
            bus.register_biome(BIOME_ID, &thief, 999),
            Err(FederationError::SuccessionRequired { .. })
        ));
        // And via the succession API with no signatures at all.
        assert!(matches!(
            bus.rotate_biome(&succession(1, 999, &thief)),
            Err(FederationError::Unsigned)
        ));
        // The identity is untouched: the biome's own summary still publishes.
        let mut sum = b.summarize(0, 5_000);
        b.sign_summary(&mut sum);
        assert!(bus.publish(sum).is_ok());
    }

    /// A succession signed by an attacker's key is not authorisation.
    #[test]
    fn a_succession_signed_by_a_stranger_is_refused() {
        let b = biome_with_data();
        let mut bus = registered_bus(&b);
        let mut s = succession(1, 2, &pubhex(HEIR));
        sign_succession(&mut s, THIEF);
        assert!(matches!(
            bus.rotate_biome(&s),
            Err(FederationError::SuccessionUnauthorised { .. })
        ));
    }

    /// Continuity: the outgoing key authorises its own replacement.
    #[test]
    fn the_outgoing_key_can_hand_over() {
        let b = biome_with_data();
        let mut bus = registered_bus(&b);
        let heir = pubhex(HEIR);
        let mut s = succession(1, 2, &heir);
        sign_succession(&mut s, SEED); // SEED is the biome's own key
        bus.rotate_biome(&s).expect("continuity succession");

        // The heir can now publish; the retired key cannot.
        let heir_biome = Biome::new(BiomeConfig::new(BIOME_ID), HEIR);
        let mut sum = heir_biome.summarize(0, 5_000);
        heir_biome.sign_summary(&mut sum);
        assert!(bus.publish(sum).is_ok());

        let mut old = b.summarize(5_001, 9_999);
        b.sign_summary(&mut old);
        assert!(matches!(
            bus.publish(old),
            Err(FederationError::IdentityMismatch { .. })
        ));
    }

    /// INSTITUTIONAL MORTALITY (ADR-270 §3). The body that held the biome key
    /// is dissolved and the key is gone forever. A pre-declared 2-of-3
    /// custodian quorum can still hand the identity to a successor — which is
    /// the only reason a 2026 record stays verifiable in 2046.
    #[test]
    fn custodians_can_recover_an_identity_whose_holder_is_gone() {
        let b = biome_with_data();
        let mut bus = FederationBus::new();
        let custodians = vec![pubhex(CUST_A), pubhex(CUST_B), pubhex(CUST_C)];
        bus.register_biome_with_custodians(BIOME_ID, b.public_key_hex(), 1, &custodians, 2)
            .unwrap();

        let heir = pubhex(HEIR);

        // One custodian is not a quorum.
        let mut one = succession(1, 2, &heir);
        sign_succession(&mut one, CUST_A);
        assert!(matches!(
            bus.rotate_biome(&one),
            Err(FederationError::SuccessionUnauthorised {
                custodian_signatures: 1,
                threshold: 2,
                ..
            })
        ));

        // Two are — with no involvement from the original key at all.
        let mut two = succession(1, 2, &heir);
        sign_succession(&mut two, CUST_A);
        sign_succession(&mut two, CUST_B);
        bus.rotate_biome(&two).expect("2-of-3 recovery");

        let heir_biome = Biome::new(BiomeConfig::new(BIOME_ID), HEIR);
        let mut sum = heir_biome.summarize(0, 5_000);
        heir_biome.sign_summary(&mut sum);
        assert!(bus.publish(sum).is_ok());
    }

    /// One custodian signing twice is still one custodian.
    #[test]
    fn duplicate_custodian_signatures_do_not_make_a_quorum() {
        let b = biome_with_data();
        let mut bus = FederationBus::new();
        let custodians = vec![pubhex(CUST_A), pubhex(CUST_B)];
        bus.register_biome_with_custodians(BIOME_ID, b.public_key_hex(), 1, &custodians, 2)
            .unwrap();
        let mut s = succession(1, 2, &pubhex(HEIR));
        sign_succession(&mut s, CUST_A);
        sign_succession(&mut s, CUST_A);
        assert!(matches!(
            bus.rotate_biome(&s),
            Err(FederationError::SuccessionUnauthorised {
                custodian_signatures: 1,
                ..
            })
        ));
    }

    /// A succession is bound to the epoch it was written for, so a captured
    /// one cannot be replayed against a later state.
    #[test]
    fn a_succession_cannot_be_replayed_onto_a_later_epoch() {
        let b = biome_with_data();
        let mut bus = registered_bus(&b);
        let mut first = succession(1, 2, &pubhex(HEIR));
        sign_succession(&mut first, SEED);
        bus.rotate_biome(&first).unwrap();

        // Replaying the same statement now targets a stale from_epoch.
        assert!(matches!(
            bus.rotate_biome(&first),
            Err(FederationError::StaleKeyEpoch { .. })
        ));
    }

    /// A succession may hand over the recovery quorum as well as the key,
    /// and an impossible threshold is refused rather than silently stored.
    #[test]
    fn a_succession_can_rotate_the_custodian_set() {
        let b = biome_with_data();
        let mut bus = registered_bus(&b);

        let mut bad = succession(1, 2, &pubhex(HEIR));
        bad.new_custodians = Some(vec![pubhex(CUST_A)]);
        bad.new_custodian_threshold = 2; // 2-of-1 is unsatisfiable
        sign_succession(&mut bad, SEED);
        assert!(matches!(
            bus.rotate_biome(&bad),
            Err(FederationError::UnreachableThreshold { .. })
        ));

        let mut ok = succession(1, 2, &pubhex(HEIR));
        ok.new_custodians = Some(vec![pubhex(CUST_A), pubhex(CUST_B)]);
        ok.new_custodian_threshold = 1;
        sign_succession(&mut ok, SEED);
        bus.rotate_biome(&ok).expect("quorum handover");

        // The new quorum is live: one of the new custodians can now recover.
        let mut rec = succession(2, 3, &pubhex(THIEF));
        sign_succession(&mut rec, CUST_B);
        assert!(bus.rotate_biome(&rec).is_ok());
    }

    /// Genesis with threshold 0 is an explicit choice: no recovery path.
    #[test]
    fn threshold_zero_means_the_identity_dies_with_its_key() {
        let b = biome_with_data();
        let mut bus = FederationBus::new();
        bus.register_biome_with_custodians(BIOME_ID, b.public_key_hex(), 1, &[pubhex(CUST_A)], 0)
            .unwrap();
        let mut s = succession(1, 2, &pubhex(HEIR));
        sign_succession(&mut s, CUST_A);
        assert!(matches!(
            bus.rotate_biome(&s),
            Err(FederationError::SuccessionUnauthorised { threshold: 0, .. })
        ));
    }

    /// A succession survives the JSON wire the same way summaries must.
    #[test]
    fn succession_survives_a_json_wire_round_trip() {
        let b = biome_with_data();
        let mut bus = registered_bus(&b);
        let mut s = succession(1, 2, &pubhex(HEIR));
        sign_succession(&mut s, SEED);
        let wire = serde_json::to_string(&s).unwrap();
        let received: KeySuccession = serde_json::from_str(&wire).unwrap();
        assert_eq!(s, received);
        bus.rotate_biome(&received)
            .expect("verifies after the wire");
    }

    // --- wire-faithfulness: sign only what round-trips -----------------------

    /// JSON has no NaN and no Infinity — `serde_json` writes both as `null`,
    /// and parsing `null` into an f32 fails. So a signature over a non-finite
    /// float verifies IN-PROCESS and is unparseable at the peer: signable,
    /// undeliverable. The signing path must refuse instead.
    #[test]
    fn a_non_finite_float_is_never_signed() {
        let b = biome_with_data();
        let mut src = biome_with_data();
        let template = src.revoke_device(1, 10_000, "compromised");
        for poison in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let mut ev = template.clone();
            ev.confidence = poison;
            b.sign_event(&mut ev);
            assert!(
                ev.signature_hex.is_none(),
                "{poison:?} must not be signed — it cannot survive the wire"
            );
            assert!(!verify_event(&ev));

            // And the bus rejects it rather than accepting an unusable artifact.
            let mut bus = registered_bus(&b);
            assert_eq!(bus.publish_event(ev), Err(FederationError::Unsigned));
        }
    }

    /// The same guard on summaries.
    #[test]
    fn a_summary_with_a_non_finite_stat_is_never_signed() {
        let b = biome_with_data();
        let mut sum = b.summarize(0, 5_000);
        assert!(verify_summary(&sum), "the honest summary signs");

        sum.stats.insert(
            "weather".into(),
            ModalityStats {
                count: 1,
                mean: f64::NAN,
                min: 0.0,
                max: 1.0,
                mean_quality: 1.0,
            },
        );
        b.sign_summary(&mut sum);
        assert!(sum.signature_hex.is_none());
        assert!(!verify_summary(&sum));
    }

    /// `round_trips` is the invariant itself: true exactly when serialize →
    /// parse → compare is an identity.
    #[test]
    fn round_trips_detects_exactly_the_unfaithful() {
        let b = biome_with_data();
        let good = b.summarize(0, 5_000);
        assert!(crate::round_trips(&good));

        let mut bad = good.clone();
        bad.stats.insert(
            "acoustic".into(),
            ModalityStats {
                count: 1,
                mean: 1.0,
                min: f64::NEG_INFINITY,
                max: 1.0,
                mean_quality: 1.0,
            },
        );
        assert!(!crate::round_trips(&bad));

        // Awkward-but-finite values are fine — this is not a blanket ban on
        // hard floats, only on ones JSON cannot represent.
        let mut fine = good.clone();
        fine.stats.insert(
            "soil_moisture".into(),
            ModalityStats {
                count: 3,
                mean: 23.470000000000002,
                min: 0.1 + 0.2,
                max: f64::MIN_POSITIVE,
                mean_quality: 0.9700000000000001,
            },
        );
        assert!(crate::round_trips(&fine));
    }

    /// A real summarize() can never produce a non-finite stat: an accumulator
    /// exists only when it has at least one sample, so there is no 0/0, and
    /// sample values are validated finite before they are ever accepted.
    #[test]
    fn summarize_cannot_produce_non_finite_stats() {
        let b = biome_with_data();
        for window in [(0, 5_000), (0, u64::MAX), (9_000, 9_001), (7_000, 7_000)] {
            let s = b.summarize(window.0, window.1);
            for (k, st) in &s.stats {
                assert!(st.mean.is_finite(), "{k} mean");
                assert!(st.min.is_finite(), "{k} min");
                assert!(st.max.is_finite(), "{k} max");
                assert!(st.mean_quality.is_finite(), "{k} mean_quality");
            }
            // An empty window yields no stats at all — not NaN-filled ones.
            assert!(crate::round_trips(&s));
        }
    }
}
