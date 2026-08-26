//! Calibration record store with anchor-rooted lineage verification
//! (ADR-264 §12 items 1–3).

use crate::authority::{verify_record_signature, AuthorityRegistry};
use crate::error::CalibrationError;
use rucelium_core::{CalibrationRecord, SensorModality};
use std::collections::BTreeMap;

/// Whether a lineage root with this method counts as anchored: only records
/// produced at the factory or directly against a reference-grade anchor
/// station may terminate a chain (ADR-264 §12 items 1–3).
fn is_anchored_method(method: &str) -> bool {
    method == "factory" || method == "anchor_reference"
}

/// An in-memory store of [`CalibrationRecord`]s keyed by `calibration_id`,
/// enforcing anchor-rooted lineage at insert time and on demand via
/// [`CalibrationStore::verify_lineage`].
///
/// Records are immutable once inserted — a duplicate `calibration_id` is
/// rejected rather than overwritten, because rewriting calibration history
/// would be exactly the silent correction ADR-264 §12 item 6 forbids.
///
/// The store has two modes:
///
/// - **Strict** ([`CalibrationStore::with_authorities`]): every record —
///   roots and children alike — must carry an ed25519 signature that verifies
///   over its canonical bytes, and the signing key must be a registered
///   [`crate::CalibrationAuthority`] for the record's modality. Lineage
///   verification re-checks each link's signature, so a chain containing any
///   unsigned or untrusted record fails.
/// - **Permissive** ([`CalibrationStore::new`]): structure-only checks, for
///   tests and simulation only.
#[derive(Debug, Clone, Default)]
pub struct CalibrationStore {
    records: BTreeMap<u32, CalibrationRecord>,
    /// `Some` = strict mode: signatures required and checked against these
    /// authorities. `None` = permissive legacy mode.
    authorities: Option<AuthorityRegistry>,
}

impl CalibrationStore {
    /// Create an empty **permissive** store.
    ///
    /// # WARNING — legacy mode, tests/simulation only
    ///
    /// A store built with `new()` accepts **unsigned** records and never
    /// checks signatures: anyone who can insert a record can declare an
    /// "anchor" just by writing `method: "anchor_reference"`. Production
    /// deployments must use [`CalibrationStore::with_authorities`], which
    /// cryptographically verifies every record against a registry of trusted
    /// calibration authorities (ADR-264 §12 items 1–3).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty **strict** store: every inserted record must carry a
    /// valid ed25519 signature ([`verify_record_signature`]) from a key that
    /// `registry` trusts for the record's modality
    /// ([`AuthorityRegistry::trusted_for`]), and [`Self::verify_lineage`]
    /// re-verifies every link of a chain. This applies to roots and children
    /// alike — an anchored method string alone proves nothing.
    #[must_use]
    pub fn with_authorities(registry: AuthorityRegistry) -> Self {
        CalibrationStore {
            records: BTreeMap::new(),
            authorities: Some(registry),
        }
    }

    /// In strict mode, check the record's signature and its signer's
    /// registration for the record's modality; permissive mode accepts all.
    fn check_authority(&self, record: &CalibrationRecord) -> Result<(), CalibrationError> {
        let Some(registry) = &self.authorities else {
            return Ok(());
        };
        verify_record_signature(record)?;
        // `verify_record_signature` guarantees the pubkey field is present.
        let signer = record.signer_pubkey_hex.as_deref().unwrap_or_default();
        if !registry.trusted_for(signer, record.modality) {
            return Err(CalibrationError::UntrustedSigner {
                id: record.calibration_id,
                signer: signer.to_string(),
            });
        }
        Ok(())
    }

    /// Number of records in the store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the store holds no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Insert a record after validating it structurally
    /// ([`CalibrationRecord::validate`]) and against the lineage rules:
    /// a `parent_id` must already exist in the store, and a root record
    /// (`parent_id: None`) must use an anchored method (`factory` or
    /// `anchor_reference`). Duplicate ids are rejected.
    ///
    /// In strict mode ([`CalibrationStore::with_authorities`]) the record —
    /// root or child — must additionally carry a signature that verifies
    /// ([`verify_record_signature`]) from a key trusted for its modality,
    /// else [`CalibrationError::MissingSignature`],
    /// [`CalibrationError::BadSignature`], or
    /// [`CalibrationError::UntrustedSigner`] is returned.
    pub fn insert(&mut self, record: CalibrationRecord) -> Result<(), CalibrationError> {
        record.validate()?;
        self.check_authority(&record)?;
        if self.records.contains_key(&record.calibration_id) {
            return Err(CalibrationError::Core(rucelium_core::EnvError::Invalid(
                format!(
                    "calibration id {} already exists; records are immutable",
                    record.calibration_id
                ),
            )));
        }
        match record.parent_id {
            Some(parent) => {
                if !self.records.contains_key(&parent) {
                    return Err(CalibrationError::BrokenLineage {
                        id: record.calibration_id,
                        missing_parent: parent,
                    });
                }
            }
            None => {
                if !is_anchored_method(&record.method) {
                    return Err(CalibrationError::UnanchoredRoot(record.calibration_id));
                }
            }
        }
        self.records.insert(record.calibration_id, record);
        Ok(())
    }

    /// Look up a record by id.
    #[must_use]
    pub fn get(&self, id: u32) -> Option<&CalibrationRecord> {
        self.records.get(&id)
    }

    /// Walk the parent chain from `id` to its root and return the visited ids
    /// root-last (`[id, parent, …, root]`).
    ///
    /// Fails with [`CalibrationError::UnknownRecord`] if `id` is absent,
    /// [`CalibrationError::BrokenLineage`] if an ancestor's parent is missing,
    /// [`CalibrationError::LineageCycle`] if the chain revisits a record, and
    /// [`CalibrationError::UnanchoredRoot`] if the root's method is not
    /// anchored (ADR-264 §12 items 1–3).
    ///
    /// In strict mode every record along the chain is additionally
    /// re-verified: its signature must check out and its signer must be a
    /// trusted authority for its modality — a chain with any unsigned,
    /// tampered, or untrusted link fails with
    /// [`CalibrationError::MissingSignature`],
    /// [`CalibrationError::BadSignature`], or
    /// [`CalibrationError::UntrustedSigner`] respectively.
    pub fn verify_lineage(&self, id: u32) -> Result<Vec<u32>, CalibrationError> {
        let mut chain: Vec<u32> = Vec::new();
        let mut current = id;
        loop {
            if chain.contains(&current) {
                return Err(CalibrationError::LineageCycle(current));
            }
            let Some(record) = self.records.get(&current) else {
                return match chain.last() {
                    None => Err(CalibrationError::UnknownRecord(current)),
                    Some(&child) => Err(CalibrationError::BrokenLineage {
                        id: child,
                        missing_parent: current,
                    }),
                };
            };
            self.check_authority(record)?;
            chain.push(current);
            match record.parent_id {
                Some(parent) => current = parent,
                None => {
                    if !is_anchored_method(&record.method) {
                        return Err(CalibrationError::UnanchoredRoot(current));
                    }
                    return Ok(chain);
                }
            }
        }
    }

    /// The newest (highest `created_ns`, ties broken by highest id) record for
    /// `node_id` + `modality` that has not expired at `now_ns` and whose
    /// lineage verifies. `None` when no such record exists.
    #[must_use]
    pub fn active_for(
        &self,
        node_id: u64,
        modality: SensorModality,
        now_ns: u64,
    ) -> Option<&CalibrationRecord> {
        self.records
            .values()
            .filter(|r| {
                r.node_id == node_id
                    && r.modality == modality
                    && !r.is_expired(now_ns)
                    && self.verify_lineage(r.calibration_id).is_ok()
            })
            .max_by_key(|r| (r.created_ns, r.calibration_id))
    }

    /// Test-only backdoor that bypasses all checks, used to forge broken
    /// stores (e.g. lineage cycles) that `insert` correctly refuses to build.
    #[cfg(test)]
    pub(crate) fn insert_unchecked(&mut self, record: CalibrationRecord) {
        self.records.insert(record.calibration_id, record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{CalibrationAuthority, CalibrationSigner};
    use rucelium_core::calibration::Q16_ONE;
    use std::collections::BTreeSet;

    fn record(id: u32, method: &str, parent_id: Option<u32>, created_ns: u64) -> CalibrationRecord {
        CalibrationRecord {
            calibration_id: id,
            node_id: 7,
            modality: SensorModality::Weather,
            method: method.into(),
            reference_station: Some("anchor-01".into()),
            parent_id,
            created_ns,
            expires_ns: created_ns + 1_000_000,
            scale_q16: Q16_ONE,
            offset_q16: 0,
            uncertainty_q16: Q16_ONE / 10,
            data_hash: "sha256:cal".into(),
            signature_hex: None,
            signer_pubkey_hex: None,
        }
    }

    #[test]
    fn anchor_rooted_chain_inserts_and_verifies_root_last() {
        let mut store = CalibrationStore::new();
        store
            .insert(record(1, "anchor_reference", None, 1_000))
            .unwrap();
        store
            .insert(record(2, "colocation", Some(1), 2_000))
            .unwrap();
        store
            .insert(record(3, "colocation", Some(2), 3_000))
            .unwrap();
        assert_eq!(store.len(), 3);
        assert!(!store.is_empty());
        assert_eq!(store.verify_lineage(3).unwrap(), vec![3, 2, 1]);
        assert_eq!(store.verify_lineage(1).unwrap(), vec![1]);
    }

    #[test]
    fn missing_parent_is_rejected_at_insert() {
        let mut store = CalibrationStore::new();
        let err = store
            .insert(record(2, "colocation", Some(99), 2_000))
            .unwrap_err();
        assert_eq!(
            err,
            CalibrationError::BrokenLineage {
                id: 2,
                missing_parent: 99
            }
        );
        assert!(store.get(2).is_none());
    }

    #[test]
    fn unanchored_root_is_rejected() {
        let mut store = CalibrationStore::new();
        let err = store
            .insert(record(1, "colocation", None, 1_000))
            .unwrap_err();
        assert_eq!(err, CalibrationError::UnanchoredRoot(1));
        // Factory roots are fine.
        store.insert(record(1, "factory", None, 1_000)).unwrap();
    }

    #[test]
    fn invalid_record_and_duplicate_id_are_rejected() {
        let mut store = CalibrationStore::new();
        let mut bad = record(1, "factory", None, 1_000);
        bad.scale_q16 = 0;
        assert!(matches!(store.insert(bad), Err(CalibrationError::Core(_))));
        store.insert(record(1, "factory", None, 1_000)).unwrap();
        assert!(matches!(
            store.insert(record(1, "factory", None, 2_000)),
            Err(CalibrationError::Core(_))
        ));
    }

    #[test]
    fn unknown_record_and_forged_dangling_parent() {
        let mut store = CalibrationStore::new();
        assert_eq!(
            store.verify_lineage(42).unwrap_err(),
            CalibrationError::UnknownRecord(42)
        );
        // Forge a record whose parent vanished (insert would refuse this).
        store.insert_unchecked(record(5, "colocation", Some(4), 1_000));
        assert_eq!(
            store.verify_lineage(5).unwrap_err(),
            CalibrationError::BrokenLineage {
                id: 5,
                missing_parent: 4
            }
        );
    }

    #[test]
    fn forged_cycle_reports_lineage_cycle() {
        let mut store = CalibrationStore::new();
        store.insert_unchecked(record(10, "colocation", Some(11), 1_000));
        store.insert_unchecked(record(11, "colocation", Some(10), 1_000));
        assert_eq!(
            store.verify_lineage(10).unwrap_err(),
            CalibrationError::LineageCycle(10)
        );
        // Self-loop is also a cycle.
        store.insert_unchecked(record(12, "colocation", Some(12), 1_000));
        assert_eq!(
            store.verify_lineage(12).unwrap_err(),
            CalibrationError::LineageCycle(12)
        );
    }

    #[test]
    fn forged_unanchored_root_fails_verification() {
        let mut store = CalibrationStore::new();
        store.insert_unchecked(record(20, "colocation", None, 1_000));
        store.insert_unchecked(record(21, "colocation", Some(20), 2_000));
        assert_eq!(
            store.verify_lineage(21).unwrap_err(),
            CalibrationError::UnanchoredRoot(20)
        );
    }

    #[test]
    fn active_for_picks_newest_non_expired_with_valid_lineage() {
        let mut store = CalibrationStore::new();
        // Old but long-lived.
        store
            .insert(record(1, "anchor_reference", None, 1_000))
            .unwrap();
        // Newest, but expires early.
        let mut short = record(2, "colocation", Some(1), 3_000);
        short.expires_ns = 4_000;
        store.insert(short).unwrap();
        // Middle age, long-lived.
        store
            .insert(record(3, "colocation", Some(1), 2_000))
            .unwrap();

        // Before record 2 expires it wins (newest created_ns).
        assert_eq!(
            store
                .active_for(7, SensorModality::Weather, 3_500)
                .unwrap()
                .calibration_id,
            2
        );
        // After it expires, record 3 (created 2_000) beats record 1.
        assert_eq!(
            store
                .active_for(7, SensorModality::Weather, 5_000)
                .unwrap()
                .calibration_id,
            3
        );
        // Wrong node or modality: nothing.
        assert!(store
            .active_for(8, SensorModality::Weather, 3_500)
            .is_none());
        assert!(store
            .active_for(7, SensorModality::SoilMoisture, 3_500)
            .is_none());
        // Broken lineage disqualifies even a fresh record.
        store.insert_unchecked(record(9, "colocation", Some(999), 4_000));
        assert_eq!(
            store
                .active_for(7, SensorModality::Weather, 4_500)
                .unwrap()
                .calibration_id,
            3
        );
    }

    // ------------------------------------------------------------------
    // Strict mode (calibration authorities, ADR-264 §12 items 1–3)
    // ------------------------------------------------------------------

    const AUTHORITY_SEED: &[u8; 32] = b"rucelium-cal-test-seed-32-bytes!";
    const ATTACKER_SEED: &[u8; 32] = b"attacker-controlled-seed-32bytes";

    fn signer() -> CalibrationSigner {
        CalibrationSigner::from_seed(AUTHORITY_SEED)
    }

    /// Registry trusting the test authority for the given modalities
    /// (empty slice = all modalities).
    fn registry(modalities: &[SensorModality]) -> AuthorityRegistry {
        let mut reg = AuthorityRegistry::new();
        reg.add(CalibrationAuthority {
            name: "test-authority".into(),
            pubkey_hex: signer().public_hex(),
            modalities: modalities.iter().copied().collect::<BTreeSet<_>>(),
        });
        reg
    }

    fn signed(id: u32, method: &str, parent_id: Option<u32>, created_ns: u64) -> CalibrationRecord {
        let mut r = record(id, method, parent_id, created_ns);
        signer().sign_record(&mut r).unwrap();
        r
    }

    #[test]
    fn strict_store_accepts_signed_anchor_and_child() {
        let mut store = CalibrationStore::with_authorities(registry(&[]));
        store
            .insert(signed(1, "anchor_reference", None, 1_000))
            .unwrap();
        store
            .insert(signed(2, "colocation", Some(1), 2_000))
            .unwrap();
        assert_eq!(store.verify_lineage(2).unwrap(), vec![2, 1]);
        assert_eq!(
            store
                .active_for(7, SensorModality::Weather, 2_500)
                .unwrap()
                .calibration_id,
            2
        );
    }

    #[test]
    fn strict_store_rejects_unsigned_root() {
        let mut store = CalibrationStore::with_authorities(registry(&[]));
        let err = store
            .insert(record(1, "anchor_reference", None, 1_000))
            .unwrap_err();
        assert_eq!(err, CalibrationError::MissingSignature(1));
        assert!(store.is_empty());
    }

    #[test]
    fn strict_store_rejects_unsigned_child_too() {
        let mut store = CalibrationStore::with_authorities(registry(&[]));
        store
            .insert(signed(1, "anchor_reference", None, 1_000))
            .unwrap();
        let err = store
            .insert(record(2, "colocation", Some(1), 2_000))
            .unwrap_err();
        assert_eq!(err, CalibrationError::MissingSignature(2));
    }

    #[test]
    fn strict_store_rejects_tampered_record() {
        let mut store = CalibrationStore::with_authorities(registry(&[]));
        let mut r = signed(1, "anchor_reference", None, 1_000);
        r.offset_q16 += 1; // tampered after signing
        assert_eq!(
            store.insert(r).unwrap_err(),
            CalibrationError::BadSignature(1)
        );
    }

    #[test]
    fn strict_store_rejects_signer_not_in_registry() {
        let mut store = CalibrationStore::with_authorities(registry(&[]));
        let rogue = CalibrationSigner::from_seed(ATTACKER_SEED);
        let mut r = record(1, "colocation", None, 1_000);
        rogue.sign_record(&mut r).unwrap();
        // The signature itself is valid — but the key is nobody we trust.
        assert_eq!(
            store.insert(r).unwrap_err(),
            CalibrationError::UntrustedSigner {
                id: 1,
                signer: rogue.public_hex(),
            }
        );
    }

    #[test]
    fn modality_scoped_authority_cannot_sign_other_modalities() {
        // Trusted for Weather only.
        let mut store = CalibrationStore::with_authorities(registry(&[SensorModality::Weather]));
        store
            .insert(signed(1, "anchor_reference", None, 1_000))
            .unwrap();
        // Same authority signing a SoilMoisture record: untrusted.
        let mut soil = record(2, "anchor_reference", None, 1_000);
        soil.modality = SensorModality::SoilMoisture;
        signer().sign_record(&mut soil).unwrap();
        assert_eq!(
            store.insert(soil).unwrap_err(),
            CalibrationError::UntrustedSigner {
                id: 2,
                signer: signer().public_hex(),
            }
        );
    }

    #[test]
    fn attacker_cannot_declare_anchor_with_method_string_alone() {
        // The reviewer's exact attack: insert a record claiming
        // method == "anchor_reference", self-signed with a key that is not a
        // registered authority. The structural checks would pass — the
        // authority check must reject it.
        let mut store = CalibrationStore::with_authorities(registry(&[]));
        let attacker = CalibrationSigner::from_seed(ATTACKER_SEED);
        let mut forged = record(66, "anchor_reference", None, 1_000);
        attacker.sign_record(&mut forged).unwrap();
        assert_eq!(
            store.insert(forged).unwrap_err(),
            CalibrationError::UntrustedSigner {
                id: 66,
                signer: attacker.public_hex(),
            }
        );
        assert!(store.get(66).is_none());
        // And an entirely unsigned forgery fails even earlier.
        assert_eq!(
            store
                .insert(record(67, "anchor_reference", None, 1_000))
                .unwrap_err(),
            CalibrationError::MissingSignature(67)
        );
    }

    #[test]
    fn strict_verify_lineage_recheck_catches_forged_links() {
        let mut store = CalibrationStore::with_authorities(registry(&[]));
        store
            .insert(signed(1, "anchor_reference", None, 1_000))
            .unwrap();
        // Forge an unsigned link past `insert` via the test backdoor.
        store.insert_unchecked(record(2, "colocation", Some(1), 2_000));
        store.insert_unchecked(signed(3, "colocation", Some(2), 3_000));
        assert_eq!(
            store.verify_lineage(3).unwrap_err(),
            CalibrationError::MissingSignature(2)
        );
        // A tampered link fails with BadSignature.
        let mut tampered = signed(4, "colocation", Some(1), 2_000);
        tampered.scale_q16 += 1;
        store.insert_unchecked(tampered);
        store.insert_unchecked(signed(5, "colocation", Some(4), 3_000));
        assert_eq!(
            store.verify_lineage(5).unwrap_err(),
            CalibrationError::BadSignature(4)
        );
        // `active_for` routes through verify_lineage, so forged chains never
        // win: only the clean anchor remains eligible.
        assert_eq!(
            store
                .active_for(7, SensorModality::Weather, 3_500)
                .unwrap()
                .calibration_id,
            1
        );
    }

    #[test]
    fn permissive_store_still_accepts_unsigned_records() {
        // Legacy mode: no registry, no signature checks (tests/simulation).
        let mut store = CalibrationStore::new();
        store
            .insert(record(1, "anchor_reference", None, 1_000))
            .unwrap();
        store
            .insert(record(2, "colocation", Some(1), 2_000))
            .unwrap();
        assert_eq!(store.verify_lineage(2).unwrap(), vec![2, 1]);
    }
}
