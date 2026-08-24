//! Governed, versioned artifacts required before physical evidence promotion.

use crate::manifest::{valid_sha256_digest, CollectionKind, EvidenceManifest, EvidenceRecord};
use crate::split::{represented_folds, validate_no_leakage, SplitAxis, SplitPlan};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

/// Version of the governed evidence bundle JSON document.
pub const EVIDENCE_BUNDLE_SCHEMA_VERSION: &str = "rufield.evidence.bundle.v1";
/// Version of the external split assignment JSON document.
pub const SPLIT_ARTIFACT_SCHEMA_VERSION: &str = "rufield.split-assignment.v1";
/// Version of the model lineage JSON document.
pub const MODEL_LINEAGE_SCHEMA_VERSION: &str = "rufield.model-lineage.v1";
/// Version of the detached evidence authority statement.
pub const EVIDENCE_ATTESTATION_SCHEMA_VERSION: &str = "rufield.evidence.attestation.v1";
/// Version of the caller supplied authority registry.
pub const AUTHORITY_REGISTRY_SCHEMA_VERSION: &str = "rufield.authority-registry.v1";

/// Which immutable artifact establishes training isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationArtifactKind {
    /// Five leakage resistant held out split plans.
    SplitAssignment,
    /// Immutable training lineage plus the exact held out physical samples.
    ModelLineage,
}

/// Canonical digest binding for one evidence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecordBinding {
    /// Manifest sample identifier.
    pub sample_id: String,
    /// SHA256 of the canonical serialized [`EvidenceRecord`].
    pub record_digest: String,
}

/// Signed authority statement embedded in the evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAuthorityAttestation {
    /// Exact attestation schema version.
    pub schema_version: String,
    /// Identity resolved only through the caller supplied registry.
    pub authority_id: String,
    /// Digest of the canonical governance manifest projection.
    pub manifest_digest: String,
    /// Digest of the evidence bundle fields excluding this attestation.
    pub bundle_payload_digest: String,
    /// Digest of the evaluated model bytes.
    pub model_digest: String,
    /// Selected isolation artifact type.
    pub isolation_kind: IsolationArtifactKind,
    /// Digest of the exact materialized isolation artifact bytes.
    pub isolation_digest: String,
    /// Lowercase hex Ed25519 signature over all preceding fields.
    pub signature_hex: String,
}

/// Strict evidence bundle. Arbitrary captures or opaque files do not satisfy
/// this schema and cannot create a [`VerifiedArtifacts`] capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundleArtifact {
    /// Exact evidence bundle schema version.
    pub schema_version: String,
    /// Dataset identity copied from the manifest.
    pub dataset_id: String,
    /// Evaluated task copied from the manifest.
    pub task: String,
    /// SHA256 of the evaluated model bytes.
    pub model_digest: String,
    /// Digest of the canonical governance manifest projection.
    pub manifest_digest: String,
    /// Exact, ordered coverage and digest of every manifest record.
    pub records: Vec<EvidenceRecordBinding>,
    /// Independent authority signature binding bundle and isolation evidence.
    pub attestation: EvidenceAuthorityAttestation,
}

/// One physical sample assignment in a leakage resistant split.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitSampleAssignment {
    /// Physical sample identifier.
    pub sample_id: String,
    /// Zero based fold index.
    pub fold: usize,
}

/// One held out split protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitArtifactPlan {
    /// Leakage unit isolated by this protocol.
    pub axis: SplitAxis,
    /// Exact assignment coverage for every physical sample.
    pub assignments: Vec<SplitSampleAssignment>,
}

/// Strict external split artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitIsolationArtifact {
    /// Exact split schema version.
    pub schema_version: String,
    /// Canonical governance manifest digest.
    pub manifest_digest: String,
    /// Evaluated model digest, identical to the evidence bundle.
    pub model_digest: String,
    /// Number of folds referenced by every plan.
    pub folds: usize,
    /// Exactly one plan for each of the five leakage axes.
    pub plans: Vec<SplitArtifactPlan>,
}

/// Immutable training input bound into a model lineage artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingMaterialBinding {
    /// Immutable external locator.
    pub uri: String,
    /// Lowercase SHA256 digest of the referenced bytes.
    pub digest: String,
}

/// Strict alternative to a split assignment artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelLineageArtifact {
    /// Exact lineage schema version.
    pub schema_version: String,
    /// Canonical governance manifest digest.
    pub manifest_digest: String,
    /// Evaluated model digest, identical to the evidence bundle.
    pub model_digest: String,
    /// Exact set of physical samples held out from training.
    pub held_out_physical_sample_ids: Vec<String>,
    /// Nonempty immutable inputs used to train the evaluated model.
    pub training_material: Vec<TrainingMaterialBinding>,
}

/// One trusted evidence authority configured outside evidence artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAuthority {
    /// Stable authority identity referenced by attestations.
    pub authority_id: String,
    /// Lowercase hex Ed25519 public key.
    pub ed25519_public_key_hex: String,
    /// Revocation state controlled by the registry owner.
    pub revoked: bool,
}

/// Caller supplied trust roots. Evidence artifacts never embed their own key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAuthorityRegistry {
    /// Exact registry schema version.
    pub schema_version: String,
    /// Configured authorities.
    pub authorities: Vec<EvidenceAuthority>,
}

/// Public audit receipt derived from a private verified capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactReceipt {
    /// Authority whose configured key verified the attestation.
    pub authority_id: String,
    /// SHA256 of the evaluated model.
    pub model_digest: String,
    /// SHA256 of the canonical governance manifest projection.
    pub manifest_digest: String,
    /// SHA256 observed from materialized evidence bundle bytes.
    pub bundle_digest: String,
    /// Kind of isolation evidence verified.
    pub isolation_kind: IsolationArtifactKind,
    /// SHA256 observed from materialized isolation bytes.
    pub isolation_digest: String,
    /// Fold count declared by a verified split artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub split_folds: Option<usize>,
    /// Per axis represented physical folds from the signed split artifact.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub split_represented_folds: BTreeMap<SplitAxis, usize>,
}

/// Capability created only after schemas, coverage, digests, isolation, and an
/// independently anchored authority signature all verify. Fields stay private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedArtifacts {
    authority_id: String,
    model_digest: String,
    manifest_digest: String,
    bundle_digest: String,
    isolation_kind: IsolationArtifactKind,
    isolation_digest: String,
    split_folds: Option<usize>,
    split_represented_folds: BTreeMap<SplitAxis, usize>,
}

impl VerifiedArtifacts {
    pub(crate) fn matches_manifest(&self, manifest: &EvidenceManifest) -> bool {
        let isolation_matches = match self.isolation_kind {
            IsolationArtifactKind::SplitAssignment => manifest
                .split_assignment_digest
                .as_ref()
                .is_some_and(|digest| digest == &self.isolation_digest),
            IsolationArtifactKind::ModelLineage => manifest
                .model_lineage_digest
                .as_ref()
                .is_some_and(|digest| digest == &self.isolation_digest),
        };
        self.manifest_digest == canonical_manifest_digest(manifest)
            && self.bundle_digest == manifest.evidence_bundle_digest
            && isolation_matches
    }

    pub(crate) fn receipt(&self) -> ArtifactReceipt {
        ArtifactReceipt {
            authority_id: self.authority_id.clone(),
            model_digest: self.model_digest.clone(),
            manifest_digest: self.manifest_digest.clone(),
            bundle_digest: self.bundle_digest.clone(),
            isolation_kind: self.isolation_kind,
            isolation_digest: self.isolation_digest.clone(),
            split_folds: self.split_folds,
            split_represented_folds: self.split_represented_folds.clone(),
        }
    }

    pub(crate) fn signed_split_evidence(&self) -> Option<(usize, &BTreeMap<SplitAxis, usize>)> {
        self.split_folds
            .map(|folds| (folds, &self.split_represented_folds))
    }
}

/// Artifact parsing, governance, or signature verification error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactVerificationError(String);

impl ArtifactVerificationError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ArtifactVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ArtifactVerificationError {}

#[derive(Serialize)]
struct CanonicalManifestBinding<'a> {
    schema_version: &'a str,
    dataset_id: &'a str,
    task: &'a str,
    collection_kind: CollectionKind,
    fixture: bool,
    limitations: &'a [String],
    records: &'a [EvidenceRecord],
}

#[derive(Serialize)]
struct CanonicalBundlePayload<'a> {
    schema_version: &'a str,
    dataset_id: &'a str,
    task: &'a str,
    model_digest: &'a str,
    manifest_digest: &'a str,
    records: &'a [EvidenceRecordBinding],
}

#[derive(Serialize)]
struct CanonicalAttestationPayload<'a> {
    schema_version: &'a str,
    authority_id: &'a str,
    manifest_digest: &'a str,
    bundle_payload_digest: &'a str,
    model_digest: &'a str,
    isolation_kind: IsolationArtifactKind,
    isolation_digest: &'a str,
}

/// Canonical governance digest. Artifact locators and their digests are
/// intentionally excluded to avoid a digest cycle; all scientific fields and
/// every evidence record are included.
#[must_use]
pub fn canonical_manifest_digest(manifest: &EvidenceManifest) -> String {
    let binding = CanonicalManifestBinding {
        schema_version: &manifest.schema_version,
        dataset_id: &manifest.dataset_id,
        task: &manifest.task,
        collection_kind: manifest.collection_kind,
        fixture: manifest.fixture,
        limitations: &manifest.limitations,
        records: &manifest.records,
    };
    sha256_digest(&serde_json::to_vec(&binding).expect("manifest binding serializes"))
}

/// Canonical digest of one complete evidence record.
#[must_use]
pub fn canonical_record_digest(record: &EvidenceRecord) -> String {
    sha256_digest(&serde_json::to_vec(record).expect("evidence record serializes"))
}

/// Canonical digest of evidence bundle fields excluding its attestation.
#[must_use]
pub fn canonical_bundle_payload_digest(bundle: &EvidenceBundleArtifact) -> String {
    let payload = CanonicalBundlePayload {
        schema_version: &bundle.schema_version,
        dataset_id: &bundle.dataset_id,
        task: &bundle.task,
        model_digest: &bundle.model_digest,
        manifest_digest: &bundle.manifest_digest,
        records: &bundle.records,
    };
    sha256_digest(&serde_json::to_vec(&payload).expect("bundle payload serializes"))
}

/// Canonical Ed25519 message for an evidence authority attestation.
#[must_use]
pub fn canonical_attestation_bytes(attestation: &EvidenceAuthorityAttestation) -> Vec<u8> {
    serde_json::to_vec(&CanonicalAttestationPayload {
        schema_version: &attestation.schema_version,
        authority_id: &attestation.authority_id,
        manifest_digest: &attestation.manifest_digest,
        bundle_payload_digest: &attestation.bundle_payload_digest,
        model_digest: &attestation.model_digest,
        isolation_kind: attestation.isolation_kind,
        isolation_digest: &attestation.isolation_digest,
    })
    .expect("attestation payload serializes")
}

/// Verify materialized JSON artifacts and an independently supplied trust
/// registry. Remote URIs are never fetched.
pub fn verify_local_artifacts(
    manifest: &EvidenceManifest,
    evidence_bundle_path: impl AsRef<Path>,
    split_assignment_path: Option<&Path>,
    model_lineage_path: Option<&Path>,
    evaluated_model_path: impl AsRef<Path>,
    authority_registry_path: impl AsRef<Path>,
) -> Result<VerifiedArtifacts, ArtifactVerificationError> {
    manifest
        .validate()
        .map_err(|error| ArtifactVerificationError::new(error.to_string()))?;
    let manifest_digest = canonical_manifest_digest(manifest);

    let (
        isolation_kind,
        isolation_digest,
        isolation_model_digest,
        split_folds,
        split_represented_folds,
    ) = match (split_assignment_path, model_lineage_path) {
        (Some(_), Some(_)) => {
            return Err(ArtifactVerificationError::new(
                "provide one isolation artifact, not both",
            ))
        }
        (Some(path), None) => {
            let expected = manifest.split_assignment_digest.as_deref().ok_or_else(|| {
                ArtifactVerificationError::new(
                    "split artifact path supplied but manifest has no split digest",
                )
            })?;
            let (bytes, observed) = read_and_digest(path)?;
            if observed != expected {
                return Err(ArtifactVerificationError::new(format!(
                    "split assignment digest mismatch: expected {expected}, observed {observed}"
                )));
            }
            let artifact: SplitIsolationArtifact = parse_json(&bytes, "split assignment")?;
            let represented = validate_split_artifact(&artifact, manifest, &manifest_digest)?;
            (
                IsolationArtifactKind::SplitAssignment,
                observed,
                artifact.model_digest,
                Some(artifact.folds),
                represented,
            )
        }
        (None, Some(path)) => {
            let expected = manifest.model_lineage_digest.as_deref().ok_or_else(|| {
                ArtifactVerificationError::new(
                    "model lineage path supplied but manifest has no lineage digest",
                )
            })?;
            let (bytes, observed) = read_and_digest(path)?;
            if observed != expected {
                return Err(ArtifactVerificationError::new(format!(
                    "model lineage digest mismatch: expected {expected}, observed {observed}"
                )));
            }
            let artifact: ModelLineageArtifact = parse_json(&bytes, "model lineage")?;
            validate_lineage_artifact(&artifact, manifest, &manifest_digest)?;
            (
                IsolationArtifactKind::ModelLineage,
                observed,
                artifact.model_digest,
                None,
                BTreeMap::new(),
            )
        }
        (None, None) => {
            return Err(ArtifactVerificationError::new(
                "a materialized split assignment or model lineage artifact is required",
            ))
        }
    };

    let (bundle_bytes, bundle_digest) = read_and_digest(evidence_bundle_path.as_ref())?;
    if bundle_digest != manifest.evidence_bundle_digest {
        return Err(ArtifactVerificationError::new(format!(
            "evidence bundle digest mismatch: expected {}, observed {bundle_digest}",
            manifest.evidence_bundle_digest
        )));
    }
    let bundle: EvidenceBundleArtifact = parse_json(&bundle_bytes, "evidence bundle")?;
    validate_bundle(&bundle, manifest, &manifest_digest)?;
    if bundle.model_digest != isolation_model_digest {
        return Err(ArtifactVerificationError::new(
            "evidence bundle and isolation artifact model digests differ",
        ));
    }
    let (_, observed_model_digest) = read_and_digest(evaluated_model_path.as_ref())?;
    if observed_model_digest != bundle.model_digest {
        return Err(ArtifactVerificationError::new(format!(
            "evaluated model digest mismatch: expected {}, observed {observed_model_digest}",
            bundle.model_digest
        )));
    }

    validate_attestation_fields(&bundle, &manifest_digest, isolation_kind, &isolation_digest)?;
    let registry_bytes = std::fs::read(authority_registry_path.as_ref()).map_err(|error| {
        ArtifactVerificationError::new(format!(
            "cannot read authority registry {}: {error}",
            authority_registry_path.as_ref().display()
        ))
    })?;
    let registry: EvidenceAuthorityRegistry = parse_json(&registry_bytes, "authority registry")?;
    verify_authority(&bundle.attestation, &registry)?;

    Ok(VerifiedArtifacts {
        authority_id: bundle.attestation.authority_id,
        model_digest: observed_model_digest,
        manifest_digest,
        bundle_digest,
        isolation_kind,
        isolation_digest,
        split_folds,
        split_represented_folds,
    })
}

fn validate_bundle(
    bundle: &EvidenceBundleArtifact,
    manifest: &EvidenceManifest,
    manifest_digest: &str,
) -> Result<(), ArtifactVerificationError> {
    require_schema(
        &bundle.schema_version,
        EVIDENCE_BUNDLE_SCHEMA_VERSION,
        "evidence bundle",
    )?;
    if bundle.dataset_id != manifest.dataset_id || bundle.task != manifest.task {
        return Err(ArtifactVerificationError::new(
            "evidence bundle dataset id or task does not match manifest",
        ));
    }
    if bundle.manifest_digest != manifest_digest {
        return Err(ArtifactVerificationError::new(
            "evidence bundle manifest digest mismatch",
        ));
    }
    if !valid_sha256_digest(&bundle.model_digest) {
        return Err(ArtifactVerificationError::new(
            "evidence bundle model digest must use lowercase sha256:<64 hex>",
        ));
    }
    if bundle.records.len() != manifest.records.len() {
        return Err(ArtifactVerificationError::new(
            "evidence bundle sample coverage length mismatch",
        ));
    }
    for (binding, record) in bundle.records.iter().zip(&manifest.records) {
        if binding.sample_id != record.sample_id {
            return Err(ArtifactVerificationError::new(
                "evidence bundle sample coverage or ordering mismatch",
            ));
        }
        if !valid_sha256_digest(&binding.record_digest)
            || binding.record_digest != canonical_record_digest(record)
        {
            return Err(ArtifactVerificationError::new(format!(
                "evidence record digest mismatch for {}",
                record.sample_id
            )));
        }
    }
    Ok(())
}

fn validate_split_artifact(
    artifact: &SplitIsolationArtifact,
    manifest: &EvidenceManifest,
    manifest_digest: &str,
) -> Result<BTreeMap<SplitAxis, usize>, ArtifactVerificationError> {
    require_schema(
        &artifact.schema_version,
        SPLIT_ARTIFACT_SCHEMA_VERSION,
        "split assignment",
    )?;
    validate_isolation_binding(
        &artifact.manifest_digest,
        &artifact.model_digest,
        manifest_digest,
    )?;
    if artifact.folds < 2 {
        return Err(ArtifactVerificationError::new(
            "split assignment requires at least two folds",
        ));
    }
    if artifact.plans.len() != SplitAxis::all().len() {
        return Err(ArtifactVerificationError::new(
            "split assignment must contain exactly five axis plans",
        ));
    }
    let physical_manifest = physical_manifest(manifest);
    let expected_ids = physical_sample_ids(manifest);
    let mut seen_axes = BTreeSet::new();
    let mut represented_by_axis = BTreeMap::new();
    for artifact_plan in &artifact.plans {
        if !seen_axes.insert(artifact_plan.axis) {
            return Err(ArtifactVerificationError::new(
                "split assignment contains a duplicate axis",
            ));
        }
        let mut assignments = BTreeMap::new();
        for assignment in &artifact_plan.assignments {
            if assignment.sample_id.trim().is_empty() || assignment.fold >= artifact.folds {
                return Err(ArtifactVerificationError::new(
                    "split assignment contains an empty sample or out of range fold",
                ));
            }
            if assignments
                .insert(assignment.sample_id.clone(), assignment.fold)
                .is_some()
            {
                return Err(ArtifactVerificationError::new(
                    "split assignment contains a duplicate sample",
                ));
            }
        }
        if assignments.keys().cloned().collect::<BTreeSet<_>>() != expected_ids {
            return Err(ArtifactVerificationError::new(
                "split assignment physical sample coverage mismatch",
            ));
        }
        let plan = SplitPlan {
            axis: artifact_plan.axis,
            folds: artifact.folds,
            assignments,
        };
        validate_no_leakage(&physical_manifest, &plan)
            .map_err(|error| ArtifactVerificationError::new(error.to_string()))?;
        let represented = represented_folds(&plan);
        if represented < 2 {
            return Err(ArtifactVerificationError::new(
                "split assignment must represent at least two physical folds per axis",
            ));
        }
        represented_by_axis.insert(plan.axis, represented);
    }
    if seen_axes != SplitAxis::all().into_iter().collect() {
        return Err(ArtifactVerificationError::new(
            "split assignment axes are incomplete",
        ));
    }
    Ok(represented_by_axis)
}

fn validate_lineage_artifact(
    artifact: &ModelLineageArtifact,
    manifest: &EvidenceManifest,
    manifest_digest: &str,
) -> Result<(), ArtifactVerificationError> {
    require_schema(
        &artifact.schema_version,
        MODEL_LINEAGE_SCHEMA_VERSION,
        "model lineage",
    )?;
    validate_isolation_binding(
        &artifact.manifest_digest,
        &artifact.model_digest,
        manifest_digest,
    )?;
    let held_out = artifact
        .held_out_physical_sample_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if held_out.len() != artifact.held_out_physical_sample_ids.len()
        || held_out.iter().any(|sample| sample.trim().is_empty())
        || held_out != physical_sample_ids(manifest)
    {
        return Err(ArtifactVerificationError::new(
            "model lineage held out physical sample coverage mismatch",
        ));
    }
    if artifact.training_material.is_empty() {
        return Err(ArtifactVerificationError::new(
            "model lineage must bind immutable training material",
        ));
    }
    let mut material_uris = BTreeSet::new();
    for material in &artifact.training_material {
        let uri = material.uri.trim();
        if uri.is_empty()
            || uri != material.uri
            || uri.to_ascii_lowercase().starts_with("fixture:")
            || !valid_sha256_digest(&material.digest)
            || !material_uris.insert(uri)
        {
            return Err(ArtifactVerificationError::new(
                "model lineage contains invalid or duplicate immutable training material",
            ));
        }
    }
    Ok(())
}

fn validate_isolation_binding(
    observed_manifest_digest: &str,
    model_digest: &str,
    expected_manifest_digest: &str,
) -> Result<(), ArtifactVerificationError> {
    if observed_manifest_digest != expected_manifest_digest {
        return Err(ArtifactVerificationError::new(
            "isolation artifact manifest digest mismatch",
        ));
    }
    if !valid_sha256_digest(model_digest) {
        return Err(ArtifactVerificationError::new(
            "isolation model digest must use lowercase sha256:<64 hex>",
        ));
    }
    Ok(())
}

fn validate_attestation_fields(
    bundle: &EvidenceBundleArtifact,
    manifest_digest: &str,
    isolation_kind: IsolationArtifactKind,
    isolation_digest: &str,
) -> Result<(), ArtifactVerificationError> {
    let attestation = &bundle.attestation;
    require_schema(
        &attestation.schema_version,
        EVIDENCE_ATTESTATION_SCHEMA_VERSION,
        "evidence attestation",
    )?;
    if attestation.authority_id.trim().is_empty()
        || attestation.authority_id != attestation.authority_id.trim()
    {
        return Err(ArtifactVerificationError::new(
            "evidence attestation authority id is invalid",
        ));
    }
    if attestation.manifest_digest != manifest_digest
        || attestation.bundle_payload_digest != canonical_bundle_payload_digest(bundle)
        || attestation.model_digest != bundle.model_digest
        || attestation.isolation_kind != isolation_kind
        || attestation.isolation_digest != isolation_digest
    {
        return Err(ArtifactVerificationError::new(
            "evidence attestation does not bind this bundle and isolation artifact",
        ));
    }
    for digest in [
        &attestation.manifest_digest,
        &attestation.bundle_payload_digest,
        &attestation.model_digest,
        &attestation.isolation_digest,
    ] {
        if !valid_sha256_digest(digest) {
            return Err(ArtifactVerificationError::new(
                "evidence attestation digests must use lowercase sha256:<64 hex>",
            ));
        }
    }
    if !valid_lower_hex(&attestation.signature_hex, 128) {
        return Err(ArtifactVerificationError::new(
            "evidence attestation signature must be 128 lowercase hex characters",
        ));
    }
    Ok(())
}

fn verify_authority(
    attestation: &EvidenceAuthorityAttestation,
    registry: &EvidenceAuthorityRegistry,
) -> Result<(), ArtifactVerificationError> {
    require_schema(
        &registry.schema_version,
        AUTHORITY_REGISTRY_SCHEMA_VERSION,
        "authority registry",
    )?;
    let mut authorities = BTreeMap::new();
    for authority in &registry.authorities {
        if authority.authority_id.trim().is_empty()
            || authority.authority_id != authority.authority_id.trim()
            || !valid_lower_hex(&authority.ed25519_public_key_hex, 64)
            || authorities
                .insert(authority.authority_id.as_str(), authority)
                .is_some()
        {
            return Err(ArtifactVerificationError::new(
                "authority registry contains an invalid or duplicate authority",
            ));
        }
    }
    let authority = authorities
        .get(attestation.authority_id.as_str())
        .ok_or_else(|| {
            ArtifactVerificationError::new("evidence attestation authority is unknown")
        })?;
    if authority.revoked {
        return Err(ArtifactVerificationError::new(
            "evidence attestation authority is revoked",
        ));
    }
    let public_key = decode_fixed_hex::<32>(&authority.ed25519_public_key_hex)?;
    let signature = decode_fixed_hex::<64>(&attestation.signature_hex)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| ArtifactVerificationError::new("authority public key is invalid"))?;
    verifying_key
        .verify_strict(
            &canonical_attestation_bytes(attestation),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| ArtifactVerificationError::new("evidence attestation signature is invalid"))
}

fn physical_manifest(manifest: &EvidenceManifest) -> EvidenceManifest {
    let mut physical = manifest.clone();
    physical
        .records
        .retain(|record| record.evidence_origin.is_physical());
    physical
}

fn physical_sample_ids(manifest: &EvidenceManifest) -> BTreeSet<String> {
    manifest
        .records
        .iter()
        .filter(|record| record.evidence_origin.is_physical())
        .map(|record| record.sample_id.clone())
        .collect()
}

fn require_schema(
    observed: &str,
    expected: &str,
    artifact: &str,
) -> Result<(), ArtifactVerificationError> {
    if observed == expected {
        Ok(())
    } else {
        Err(ArtifactVerificationError::new(format!(
            "unsupported {artifact} schema version"
        )))
    }
}

fn parse_json<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    artifact: &str,
) -> Result<T, ArtifactVerificationError> {
    serde_json::from_slice(bytes).map_err(|error| {
        ArtifactVerificationError::new(format!("invalid {artifact} JSON: {error}"))
    })
}

fn read_and_digest(path: &Path) -> Result<(Vec<u8>, String), ArtifactVerificationError> {
    let bytes = std::fs::read(path).map_err(|error| {
        ArtifactVerificationError::new(format!(
            "cannot read materialized artifact {}: {error}",
            path.display()
        ))
    })?;
    let digest = sha256_digest(&bytes);
    Ok((bytes, digest))
}

pub(crate) fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], ArtifactVerificationError> {
    if !valid_lower_hex(value, N * 2) {
        return Err(ArtifactVerificationError::new(
            "hex value has invalid length or uppercase characters",
        ));
    }
    let mut output = [0u8; N];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (decode_nibble(chunk[0])? << 4) | decode_nibble(chunk[1])?;
    }
    Ok(output)
}

fn decode_nibble(byte: u8) -> Result<u8, ArtifactVerificationError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ArtifactVerificationError::new(
            "hex value contains an invalid character",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{evaluate_promotion_with_artifacts, PromotionPolicy};
    use crate::manifest::{CollectionKind, EvidenceOrigin};
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    struct ArtifactSet {
        manifest: EvidenceManifest,
        bundle_path: std::path::PathBuf,
        isolation_path: std::path::PathBuf,
        model_path: std::path::PathBuf,
        registry_path: std::path::PathBuf,
        directory: std::path::PathBuf,
        kind: IsolationArtifactKind,
    }

    impl ArtifactSet {
        fn verify(&self) -> Result<VerifiedArtifacts, ArtifactVerificationError> {
            verify_local_artifacts(
                &self.manifest,
                &self.bundle_path,
                (self.kind == IsolationArtifactKind::SplitAssignment)
                    .then_some(self.isolation_path.as_path()),
                (self.kind == IsolationArtifactKind::ModelLineage)
                    .then_some(self.isolation_path.as_path()),
                &self.model_path,
                &self.registry_path,
            )
        }

        fn write_bundle_value(&mut self, value: &serde_json::Value) {
            let bytes = serde_json::to_vec_pretty(value).unwrap();
            std::fs::write(&self.bundle_path, &bytes).unwrap();
            self.manifest.evidence_bundle_digest = sha256_digest(&bytes);
        }

        fn write_isolation_value(&mut self, value: &serde_json::Value) {
            let bytes = serde_json::to_vec_pretty(value).unwrap();
            std::fs::write(&self.isolation_path, &bytes).unwrap();
            match self.kind {
                IsolationArtifactKind::SplitAssignment => {
                    self.manifest.split_assignment_digest = Some(sha256_digest(&bytes));
                }
                IsolationArtifactKind::ModelLineage => {
                    self.manifest.model_lineage_digest = Some(sha256_digest(&bytes));
                }
            }
        }
    }

    impl Drop for ArtifactSet {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn physical_manifest(kind: IsolationArtifactKind) -> EvidenceManifest {
        let mut manifest = EvidenceManifest::from_json(include_str!(
            "../../../fixtures/evidence/synthetic-only.json"
        ))
        .unwrap();
        manifest.fixture = false;
        manifest.collection_kind = CollectionKind::CapturedReplay;
        manifest.dataset_id = "governed.physical.fixture.v1".into();
        manifest.evidence_bundle_uri = "https://evidence.invalid/bundle.json".into();
        for record in &mut manifest.records {
            record.evidence_origin = EvidenceOrigin::CapturedReplay;
        }
        match kind {
            IsolationArtifactKind::SplitAssignment => {
                manifest.split_assignment_uri = Some("https://evidence.invalid/split.json".into());
                manifest.split_assignment_digest = Some(sha256_digest(b"pending split"));
            }
            IsolationArtifactKind::ModelLineage => {
                manifest.model_lineage_uri = Some("https://evidence.invalid/lineage.json".into());
                manifest.model_lineage_digest = Some(sha256_digest(b"pending lineage"));
            }
        }
        manifest.validate().unwrap();
        manifest
    }

    fn split_artifact(manifest: &EvidenceManifest, model_digest: &str) -> SplitIsolationArtifact {
        let plans = SplitAxis::all()
            .into_iter()
            .map(|axis| SplitArtifactPlan {
                axis,
                assignments: manifest
                    .records
                    .iter()
                    .enumerate()
                    .map(|(index, record)| SplitSampleAssignment {
                        sample_id: record.sample_id.clone(),
                        fold: index / 4,
                    })
                    .collect(),
            })
            .collect();
        SplitIsolationArtifact {
            schema_version: SPLIT_ARTIFACT_SCHEMA_VERSION.into(),
            manifest_digest: canonical_manifest_digest(manifest),
            model_digest: model_digest.into(),
            folds: 3,
            plans,
        }
    }

    fn lineage_artifact(manifest: &EvidenceManifest, model_digest: &str) -> ModelLineageArtifact {
        ModelLineageArtifact {
            schema_version: MODEL_LINEAGE_SCHEMA_VERSION.into(),
            manifest_digest: canonical_manifest_digest(manifest),
            model_digest: model_digest.into(),
            held_out_physical_sample_ids: manifest
                .records
                .iter()
                .map(|record| record.sample_id.clone())
                .collect(),
            training_material: vec![TrainingMaterialBinding {
                uri: "https://evidence.invalid/training-corpus.tar".into(),
                digest: sha256_digest(b"immutable training corpus"),
            }],
        }
    }

    fn artifact_set(kind: IsolationArtifactKind) -> ArtifactSet {
        let mut manifest = physical_manifest(kind);
        let model_digest = sha256_digest(b"evaluated model bytes");
        let manifest_digest = canonical_manifest_digest(&manifest);
        let isolation_bytes = match kind {
            IsolationArtifactKind::SplitAssignment => {
                serde_json::to_vec_pretty(&split_artifact(&manifest, &model_digest)).unwrap()
            }
            IsolationArtifactKind::ModelLineage => {
                serde_json::to_vec_pretty(&lineage_artifact(&manifest, &model_digest)).unwrap()
            }
        };
        let isolation_digest = sha256_digest(&isolation_bytes);
        match kind {
            IsolationArtifactKind::SplitAssignment => {
                manifest.split_assignment_digest = Some(isolation_digest.clone());
            }
            IsolationArtifactKind::ModelLineage => {
                manifest.model_lineage_digest = Some(isolation_digest.clone());
            }
        }
        assert_eq!(canonical_manifest_digest(&manifest), manifest_digest);

        let authority_id = "fixture-evidence-authority";
        let signing_key = SigningKey::from_bytes(&[23u8; 32]);
        let mut bundle = EvidenceBundleArtifact {
            schema_version: EVIDENCE_BUNDLE_SCHEMA_VERSION.into(),
            dataset_id: manifest.dataset_id.clone(),
            task: manifest.task.clone(),
            model_digest: model_digest.clone(),
            manifest_digest: manifest_digest.clone(),
            records: manifest
                .records
                .iter()
                .map(|record| EvidenceRecordBinding {
                    sample_id: record.sample_id.clone(),
                    record_digest: canonical_record_digest(record),
                })
                .collect(),
            attestation: EvidenceAuthorityAttestation {
                schema_version: EVIDENCE_ATTESTATION_SCHEMA_VERSION.into(),
                authority_id: authority_id.into(),
                manifest_digest,
                bundle_payload_digest: String::new(),
                model_digest,
                isolation_kind: kind,
                isolation_digest,
                signature_hex: String::new(),
            },
        };
        bundle.attestation.bundle_payload_digest = canonical_bundle_payload_digest(&bundle);
        bundle.attestation.signature_hex = lower_hex(
            &signing_key
                .sign(&canonical_attestation_bytes(&bundle.attestation))
                .to_bytes(),
        );
        let bundle_bytes = serde_json::to_vec_pretty(&bundle).unwrap();
        manifest.evidence_bundle_digest = sha256_digest(&bundle_bytes);

        let registry = EvidenceAuthorityRegistry {
            schema_version: AUTHORITY_REGISTRY_SCHEMA_VERSION.into(),
            authorities: vec![EvidenceAuthority {
                authority_id: authority_id.into(),
                ed25519_public_key_hex: lower_hex(&signing_key.verifying_key().to_bytes()),
                revoked: false,
            }],
        };
        let suffix = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "rufield_governed_artifacts_{}_{}",
            std::process::id(),
            suffix
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let bundle_path = directory.join("bundle.json");
        let isolation_path = directory.join("isolation.json");
        let registry_path = directory.join("authority-registry.json");
        let model_path = directory.join("evaluated-model.bin");
        std::fs::write(&bundle_path, bundle_bytes).unwrap();
        std::fs::write(&isolation_path, isolation_bytes).unwrap();
        std::fs::write(&model_path, b"evaluated model bytes").unwrap();
        std::fs::write(
            &registry_path,
            serde_json::to_vec_pretty(&registry).unwrap(),
        )
        .unwrap();

        ArtifactSet {
            manifest,
            bundle_path,
            isolation_path,
            model_path,
            registry_path,
            directory,
            kind,
        }
    }

    fn lower_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn governed_split_artifacts_produce_a_manifest_bound_public_receipt() {
        let set = artifact_set(IsolationArtifactKind::SplitAssignment);
        let verified = set.verify().unwrap();
        let receipt = verified.receipt();
        assert_eq!(receipt.authority_id, "fixture-evidence-authority");
        assert_eq!(
            receipt.model_digest,
            sha256_digest(b"evaluated model bytes")
        );
        assert_eq!(
            receipt.manifest_digest,
            canonical_manifest_digest(&set.manifest)
        );
        assert_eq!(receipt.bundle_digest, set.manifest.evidence_bundle_digest);
        assert_eq!(
            receipt.isolation_kind,
            IsolationArtifactKind::SplitAssignment
        );

        let decision = evaluate_promotion_with_artifacts(
            &set.manifest,
            &PromotionPolicy::default(),
            &verified,
        );
        assert_eq!(decision.artifact_receipt, Some(receipt));

        let stricter_split_policy = PromotionPolicy {
            split_folds: 3,
            minimum_represented_folds: 3,
            ..PromotionPolicy::default()
        };
        let strict_decision =
            evaluate_promotion_with_artifacts(&set.manifest, &stricter_split_policy, &verified);
        assert!(strict_decision
            .failures
            .iter()
            .any(|failure| failure.code == "signed_split_room"));

        let mut changed = set.manifest.clone();
        changed.task = "different task".into();
        let changed_decision =
            evaluate_promotion_with_artifacts(&changed, &PromotionPolicy::default(), &verified);
        assert!(changed_decision.artifact_receipt.is_none());
    }

    #[test]
    fn opaque_unknown_and_incomplete_bundle_bytes_are_rejected() {
        let mut opaque = artifact_set(IsolationArtifactKind::SplitAssignment);
        std::fs::write(&opaque.bundle_path, b"arbitrary opaque bytes").unwrap();
        opaque.manifest.evidence_bundle_digest = sha256_digest(b"arbitrary opaque bytes");
        assert!(opaque.verify().unwrap_err().to_string().contains("JSON"));

        let mut unknown = artifact_set(IsolationArtifactKind::SplitAssignment);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&unknown.bundle_path).unwrap()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("embedded_public_key".into(), "self-anchor".into());
        unknown.write_bundle_value(&value);
        assert!(unknown
            .verify()
            .unwrap_err()
            .to_string()
            .contains("unknown field"));

        let mut missing = artifact_set(IsolationArtifactKind::SplitAssignment);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&missing.bundle_path).unwrap()).unwrap();
        value["records"].as_array_mut().unwrap().pop();
        missing.write_bundle_value(&value);
        assert!(missing
            .verify()
            .unwrap_err()
            .to_string()
            .contains("coverage"));

        let mut extra = artifact_set(IsolationArtifactKind::SplitAssignment);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&extra.bundle_path).unwrap()).unwrap();
        let mut extra_binding = value["records"][0].clone();
        extra_binding["sample_id"] = serde_json::Value::String("unexpected_sample".into());
        value["records"].as_array_mut().unwrap().push(extra_binding);
        extra.write_bundle_value(&value);
        assert!(extra.verify().unwrap_err().to_string().contains("coverage"));

        let mut bad_record = artifact_set(IsolationArtifactKind::SplitAssignment);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&bad_record.bundle_path).unwrap()).unwrap();
        value["records"][0]["record_digest"] = serde_json::Value::String(sha256_digest(b"wrong"));
        bad_record.write_bundle_value(&value);
        assert!(bad_record
            .verify()
            .unwrap_err()
            .to_string()
            .contains("record digest"));
    }

    #[test]
    fn authority_registry_and_signatures_fail_closed() {
        let mut bad_signature = artifact_set(IsolationArtifactKind::SplitAssignment);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&bad_signature.bundle_path).unwrap()).unwrap();
        value["attestation"]["signature_hex"] = serde_json::Value::String("00".repeat(64));
        bad_signature.write_bundle_value(&value);
        assert!(bad_signature
            .verify()
            .unwrap_err()
            .to_string()
            .contains("signature"));

        let mut unknown = artifact_set(IsolationArtifactKind::SplitAssignment);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&unknown.bundle_path).unwrap()).unwrap();
        value["attestation"]["authority_id"] =
            serde_json::Value::String("unknown-authority".into());
        unknown.write_bundle_value(&value);
        assert!(unknown
            .verify()
            .unwrap_err()
            .to_string()
            .contains("unknown"));

        let revoked = artifact_set(IsolationArtifactKind::SplitAssignment);
        let mut registry: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&revoked.registry_path).unwrap()).unwrap();
        registry["authorities"][0]["revoked"] = serde_json::Value::Bool(true);
        std::fs::write(
            &revoked.registry_path,
            serde_json::to_vec_pretty(&registry).unwrap(),
        )
        .unwrap();
        assert!(revoked
            .verify()
            .unwrap_err()
            .to_string()
            .contains("revoked"));
    }

    #[test]
    fn split_schema_rejects_coverage_leakage_model_and_case_bypasses() {
        let mut missing = artifact_set(IsolationArtifactKind::SplitAssignment);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&missing.isolation_path).unwrap()).unwrap();
        value["plans"][0]["assignments"]
            .as_array_mut()
            .unwrap()
            .pop();
        missing.write_isolation_value(&value);
        assert!(missing
            .verify()
            .unwrap_err()
            .to_string()
            .contains("coverage"));

        let mut leakage = artifact_set(IsolationArtifactKind::SplitAssignment);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&leakage.isolation_path).unwrap()).unwrap();
        value["plans"][0]["assignments"][1]["fold"] = serde_json::Value::from(2);
        leakage.write_isolation_value(&value);
        assert!(leakage.verify().unwrap_err().to_string().contains("leaks"));

        let mut model = artifact_set(IsolationArtifactKind::SplitAssignment);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&model.isolation_path).unwrap()).unwrap();
        value["model_digest"] = serde_json::Value::String(sha256_digest(b"other model"));
        model.write_isolation_value(&value);
        assert!(model
            .verify()
            .unwrap_err()
            .to_string()
            .contains("model digests differ"));

        let uppercase = artifact_set(IsolationArtifactKind::SplitAssignment);
        let mut manifest = uppercase.manifest.clone();
        manifest.evidence_bundle_digest = manifest.evidence_bundle_digest.to_uppercase();
        assert!(verify_local_artifacts(
            &manifest,
            &uppercase.bundle_path,
            Some(&uppercase.isolation_path),
            None,
            &uppercase.model_path,
            &uppercase.registry_path,
        )
        .unwrap_err()
        .to_string()
        .contains("lowercase"));
    }

    #[test]
    fn model_lineage_requires_exact_holdout_and_training_material() {
        let valid = artifact_set(IsolationArtifactKind::ModelLineage);
        assert!(valid.verify().is_ok());

        let mut missing = artifact_set(IsolationArtifactKind::ModelLineage);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&missing.isolation_path).unwrap()).unwrap();
        value["held_out_physical_sample_ids"]
            .as_array_mut()
            .unwrap()
            .pop();
        missing.write_isolation_value(&value);
        assert!(missing
            .verify()
            .unwrap_err()
            .to_string()
            .contains("coverage"));

        let mut training = artifact_set(IsolationArtifactKind::ModelLineage);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&training.isolation_path).unwrap()).unwrap();
        value["training_material"] = serde_json::Value::Array(vec![]);
        training.write_isolation_value(&value);
        assert!(training
            .verify()
            .unwrap_err()
            .to_string()
            .contains("training material"));
    }

    #[test]
    fn evaluated_model_bytes_are_required_and_hashed() {
        let mismatch = artifact_set(IsolationArtifactKind::SplitAssignment);
        std::fs::write(&mismatch.model_path, b"different model bytes").unwrap();
        assert!(mismatch
            .verify()
            .unwrap_err()
            .to_string()
            .contains("evaluated model digest mismatch"));

        let missing = artifact_set(IsolationArtifactKind::SplitAssignment);
        std::fs::remove_file(&missing.model_path).unwrap();
        assert!(missing
            .verify()
            .unwrap_err()
            .to_string()
            .contains("cannot read materialized artifact"));
    }
}
