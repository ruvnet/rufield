//! Optional RuVector integration boundary.
//!
//! This crate intentionally does not pin an unpublished or unstable RuVector
//! API. A deployment supplies an [`EmbeddingBackend`] implementation after it
//! verifies a compatible package version. The included backend is a
//! deterministic in memory conformance implementation, not a learned model.
//! Embeddings are derived indexes and must never authorize an event or replace
//! RuField provenance.

use rufield_core::{FieldAxis, FieldEmbedding, FieldEncoder, FieldTensor, Modality, PrivacyClass};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Backend neutral request passed across the integration seam.
#[derive(Debug, Clone, PartialEq)]
pub struct EmbeddingRequest<'a> {
    /// Source modality.
    pub modality: Modality,
    /// Semantic axes in tensor order.
    pub axes: &'a [FieldAxis],
    /// Tensor shape.
    pub shape: &'a [usize],
    /// Flattened, row major tensor values.
    pub values: &'a [f32],
    /// Estimated sensor noise floor.
    pub noise_floor: f32,
    /// Privacy classification retained across the backend boundary.
    pub privacy_class: PrivacyClass,
}

/// Whether tensor values remain in process or cross a network boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendBoundary {
    /// Backend executes in the same process and receives no network transfer.
    LocalProcess,
    /// Backend receives tensor values across a network boundary.
    Network,
}

/// Deployment owned boundary classification. It is supplied independently of
/// the backend implementation so a remote adapter cannot self classify as
/// local to bypass policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderDeployment {
    boundary: BackendBoundary,
}

impl EncoderDeployment {
    /// Declare the real backend boundary from governed deployment metadata.
    #[must_use]
    pub fn new(boundary: BackendBoundary) -> Self {
        Self { boundary }
    }

    /// Boundary evaluated by privacy policy and recorded in receipts.
    #[must_use]
    pub fn boundary(self) -> BackendBoundary {
        self.boundary
    }
}

/// Metadata supplied to policy before tensor values reach a backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyAuthorizationContext<'a> {
    /// Privacy class of the source tensor.
    pub privacy_class: PrivacyClass,
    /// Stable backend identity.
    pub backend_id: &'a str,
    /// Local or network transfer boundary.
    pub boundary: BackendBoundary,
}

/// Explicit policy decision required before backend invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyAuthorization {
    /// Whether this exact transfer is authorized.
    pub allowed: bool,
    /// Stable decision receipt retained in the encoding receipt when allowed.
    pub decision_receipt_id: String,
}

/// Privacy policy seam. It receives metadata, never tensor values.
pub trait PrivacyAuthorizer {
    /// Stable policy identifier bound into encoding receipts.
    fn policy_id(&self) -> &str;

    /// Decide whether the backend may receive this tensor.
    fn authorize(&self, context: &PrivacyAuthorizationContext<'_>) -> PrivacyAuthorization;
}

/// Bundled conservative policy: local P0 through P3 execution is allowed.
/// Network transfer and sensitive P4 or P5 tensors are always denied. A
/// deployment must explicitly supply a consent and identity aware policy to
/// authorize those cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LocalOnlyPrivacyPolicy;

impl PrivacyAuthorizer for LocalOnlyPrivacyPolicy {
    fn policy_id(&self) -> &str {
        "rufield.privacy.local_only.v1"
    }

    fn authorize(&self, context: &PrivacyAuthorizationContext<'_>) -> PrivacyAuthorization {
        let local = context.boundary == BackendBoundary::LocalProcess;
        let nonsensitive = context.privacy_class <= PrivacyClass::P3;
        let allowed = local && nonsensitive;
        PrivacyAuthorization {
            allowed,
            decision_receipt_id: if allowed {
                "rufield.privacy.local_only.v1:allow_local".into()
            } else if !local {
                "rufield.privacy.local_only.v1:deny_network".into()
            } else {
                "rufield.privacy.local_only.v1:deny_sensitive".into()
            },
        }
    }
}

/// Stable backend error independent of any external RuVector package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendError {
    message: String,
}

impl BackendError {
    /// Construct an error without leaking backend specific error types.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for BackendError {}

/// Minimal ABI that a verified RuVector release or sidecar can implement.
pub trait EmbeddingBackend {
    /// Stable implementation identifier captured in deployment receipts.
    fn backend_id(&self) -> &str;

    /// Produce a finite embedding from the normalized tensor request.
    fn embed(&self, request: &EmbeddingRequest<'_>) -> Result<Vec<f32>, BackendError>;
}

/// Errors returned by the FieldEncoder adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncoderError {
    /// The tensor itself violates core structural invariants.
    InvalidTensor(String),
    /// The backend rejected the request.
    Backend(BackendError),
    /// A backend returned an empty or nonfinite vector.
    InvalidEmbedding,
    /// Source event identity is required for derived lineage.
    EmptySourceEventId,
    /// Backend identity is required for deployment receipts.
    EmptyBackendId,
    /// Canonical encoder input could not be serialized.
    Canonicalization,
    /// The privacy policy identifier is required for an auditable decision.
    EmptyPrivacyPolicyId,
    /// An allowed decision must carry a stable receipt identifier.
    EmptyDecisionReceiptId,
    /// Policy denied this backend transfer before tensor values were exposed.
    PrivacyDenied,
}

impl fmt::Display for EncoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTensor(message) => write!(f, "invalid tensor: {message}"),
            Self::Backend(error) => write!(f, "embedding backend failed: {error}"),
            Self::InvalidEmbedding => write!(f, "embedding must be nonempty and finite"),
            Self::EmptySourceEventId => write!(f, "source event id must be nonempty"),
            Self::EmptyBackendId => write!(f, "backend id must be nonempty"),
            Self::Canonicalization => write!(f, "encoder input canonicalization failed"),
            Self::EmptyPrivacyPolicyId => write!(f, "privacy policy id must be nonempty"),
            Self::EmptyDecisionReceiptId => {
                write!(f, "allowed privacy decision must carry a receipt id")
            }
            Self::PrivacyDenied => write!(f, "privacy policy denied backend transfer"),
        }
    }
}

impl std::error::Error for EncoderError {}

/// Backend neutral [`FieldEncoder`] composition point.
#[derive(Debug, Clone)]
pub struct RuVectorFieldEncoder<B, P> {
    backend: B,
    deployment: EncoderDeployment,
    privacy_policy: P,
}

/// Receipt binding a derived embedding to its backend and canonical input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodingReceipt {
    /// Privacy policy that authorized backend invocation.
    pub policy_id: String,
    /// Identifier of the exact authorization decision.
    pub decision_receipt_id: String,
    /// Privacy class supplied to policy and backend.
    pub privacy_class: PrivacyClass,
    /// Backend identity supplied by the verified adapter.
    pub backend_id: String,
    /// Explicit local or network backend boundary.
    pub boundary: BackendBoundary,
    /// SHA256 of canonical JSON containing source event identity and tensor.
    pub canonical_input_sha256: String,
    /// SHA256 of canonical JSON for the derived embedding.
    pub embedding_sha256: String,
}

/// Additive encoded result with a nonauthoritative lineage receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EncodedField {
    /// Derived vector. It is not provenance or an authorization decision.
    pub embedding: FieldEmbedding,
    /// Backend and input binding.
    pub receipt: EncodingReceipt,
}

#[derive(Serialize)]
struct CanonicalEncoderInput<'a> {
    source_event_id: &'a str,
    tensor: &'a FieldTensor,
}

impl<B, P> RuVectorFieldEncoder<B, P> {
    /// Wrap a verified backend and an explicit privacy policy.
    #[must_use]
    pub fn new(backend: B, deployment: EncoderDeployment, privacy_policy: P) -> Self {
        Self {
            backend,
            deployment,
            privacy_policy,
        }
    }

    /// Access the backend for health and receipt metadata.
    #[must_use]
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Access the policy used before every backend invocation.
    #[must_use]
    pub fn privacy_policy(&self) -> &P {
        &self.privacy_policy
    }

    /// Independently supplied deployment boundary.
    #[must_use]
    pub fn deployment(&self) -> EncoderDeployment {
        self.deployment
    }
}

impl<B: EmbeddingBackend, P: PrivacyAuthorizer> RuVectorFieldEncoder<B, P> {
    /// Encode and bind the derived output to backend and canonical source
    /// tensor inputs. This receipt is lineage only and never authenticates the
    /// underlying sensor event.
    pub fn encode_with_receipt(
        &self,
        tensor: &FieldTensor,
        source_event_id: &str,
    ) -> Result<EncodedField, EncoderError> {
        let (embedding, authorization) = self.encode_authorized(tensor, source_event_id)?;
        let canonical = serde_json::to_vec(&CanonicalEncoderInput {
            source_event_id,
            tensor,
        })
        .map_err(|_| EncoderError::Canonicalization)?;
        let canonical_embedding =
            serde_json::to_vec(&embedding).map_err(|_| EncoderError::Canonicalization)?;
        Ok(EncodedField {
            embedding,
            receipt: EncodingReceipt {
                policy_id: self.privacy_policy.policy_id().into(),
                decision_receipt_id: authorization.decision_receipt_id,
                privacy_class: tensor.privacy_class,
                backend_id: self.backend.backend_id().into(),
                boundary: self.deployment.boundary(),
                canonical_input_sha256: sha256_digest(&canonical),
                embedding_sha256: sha256_digest(&canonical_embedding),
            },
        })
    }

    fn encode_authorized(
        &self,
        tensor: &FieldTensor,
        source_event_id: &str,
    ) -> Result<(FieldEmbedding, PrivacyAuthorization), EncoderError> {
        if source_event_id.trim().is_empty() {
            return Err(EncoderError::EmptySourceEventId);
        }
        if self.backend.backend_id().trim().is_empty() {
            return Err(EncoderError::EmptyBackendId);
        }
        if self.privacy_policy.policy_id().trim().is_empty() {
            return Err(EncoderError::EmptyPrivacyPolicyId);
        }
        tensor
            .validate()
            .map_err(|error| EncoderError::InvalidTensor(error.to_string()))?;
        if tensor.values.is_empty()
            || tensor.values.iter().any(|value| !value.is_finite())
            || !tensor.noise_floor.is_finite()
        {
            return Err(EncoderError::InvalidTensor(
                "values must be nonempty and finite, and noise floor must be finite".into(),
            ));
        }
        let authorization = self.privacy_policy.authorize(&PrivacyAuthorizationContext {
            privacy_class: tensor.privacy_class,
            backend_id: self.backend.backend_id(),
            boundary: self.deployment.boundary(),
        });
        if !authorization.allowed {
            return Err(EncoderError::PrivacyDenied);
        }
        if authorization.decision_receipt_id.trim().is_empty() {
            return Err(EncoderError::EmptyDecisionReceiptId);
        }
        let request = EmbeddingRequest {
            modality: tensor.modality,
            axes: &tensor.axes,
            shape: &tensor.shape,
            values: &tensor.values,
            noise_floor: tensor.noise_floor,
            privacy_class: tensor.privacy_class,
        };
        let vector = self
            .backend
            .embed(&request)
            .map_err(EncoderError::Backend)?;
        if vector.is_empty() || vector.iter().any(|value| !value.is_finite()) {
            return Err(EncoderError::InvalidEmbedding);
        }

        Ok((
            FieldEmbedding {
                modality: modality_name(tensor.modality).into(),
                vector,
                privacy_class: tensor.privacy_class,
                source_event_id: source_event_id.into(),
            },
            authorization,
        ))
    }
}

impl<B: EmbeddingBackend, P: PrivacyAuthorizer> FieldEncoder for RuVectorFieldEncoder<B, P> {
    type Error = EncoderError;

    fn encode(
        &self,
        tensor: &FieldTensor,
        source_event_id: &str,
    ) -> Result<FieldEmbedding, Self::Error> {
        self.encode_authorized(tensor, source_event_id)
            .map(|(embedding, _)| embedding)
    }
}

fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

/// Deterministic local backend used only to verify the adapter contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InMemoryConformanceBackend {
    output_dimensions: usize,
}

impl InMemoryConformanceBackend {
    /// Create a deterministic projection with a fixed nonzero dimension.
    pub fn new(output_dimensions: usize) -> Result<Self, BackendError> {
        if output_dimensions == 0 {
            return Err(BackendError::new("output dimensions must be nonzero"));
        }
        Ok(Self { output_dimensions })
    }
}

impl EmbeddingBackend for InMemoryConformanceBackend {
    fn backend_id(&self) -> &str {
        "rufield.in_memory_conformance.v1"
    }

    fn embed(&self, request: &EmbeddingRequest<'_>) -> Result<Vec<f32>, BackendError> {
        if request.values.is_empty() || request.values.iter().any(|value| !value.is_finite()) {
            return Err(BackendError::new(
                "input tensor values must be nonempty and finite",
            ));
        }
        let mut vector = vec![0.0f32; self.output_dimensions];
        for (index, value) in request.values.iter().enumerate() {
            // Signed bucket folding is deterministic and deliberately simple.
            let bucket = index % self.output_dimensions;
            let sign = if (index / self.output_dimensions).is_multiple_of(2) {
                1.0
            } else {
                -1.0
            };
            vector[bucket] += value * sign;
        }
        let norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
        if norm > f32::EPSILON {
            for value in &mut vector {
                *value /= norm;
            }
        }
        Ok(vector)
    }
}

fn modality_name(modality: Modality) -> &'static str {
    match modality {
        Modality::WifiCsi => "wifi_csi",
        Modality::WifiCir => "wifi_cir",
        Modality::WifiBfld => "wifi_bfld",
        Modality::UwbHrp => "uwb_hrp",
        Modality::BleAdvertisementRssi => "ble_advertisement_rssi",
        Modality::BleChannelSounding => "ble_channel_sounding",
        Modality::MmwaveRadar => "mmwave_radar",
        Modality::Ultrasonic => "ultrasonic",
        Modality::Subsonic => "subsonic",
        Modality::InfraredThermal => "infrared_thermal",
        Modality::ActiveInfrared => "active_infrared",
        Modality::LidarPhase => "lidar_phase",
        Modality::QuantumMagnetic => "quantum_magnetic",
        Modality::QuantumInertial => "quantum_inertial",
        Modality::EventCamera => "event_camera",
        Modality::SyntheticSim => "synthetic_sim",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rufield_core::{FieldAxis, PrivacyClass};

    #[test]
    fn conformance_backend_implements_field_encoder() {
        let tensor = FieldTensor::new(
            1,
            Modality::WifiCsi,
            vec![FieldAxis::Frequency],
            vec![4],
            vec![1.0, 2.0, 3.0, 4.0],
            0.9,
            0.01,
            Some("cal_fixture".into()),
            PrivacyClass::P1,
        )
        .unwrap();
        let backend = InMemoryConformanceBackend::new(3).unwrap();
        let encoder = RuVectorFieldEncoder::new(
            backend,
            EncoderDeployment::new(BackendBoundary::LocalProcess),
            LocalOnlyPrivacyPolicy,
        );
        let first = encoder.encode(&tensor, "event_1").unwrap();
        let second = encoder.encode(&tensor, "event_1").unwrap();
        assert_eq!(first, second);
        assert_eq!(first.vector.len(), 3);
        assert_eq!(first.privacy_class, PrivacyClass::P1);
        assert_eq!(first.source_event_id, "event_1");
        assert_eq!(
            encoder.backend().backend_id(),
            "rufield.in_memory_conformance.v1"
        );
    }

    #[test]
    fn nonfinite_backend_output_is_rejected() {
        struct BadBackend;
        impl EmbeddingBackend for BadBackend {
            fn backend_id(&self) -> &str {
                "bad"
            }

            fn embed(&self, _request: &EmbeddingRequest<'_>) -> Result<Vec<f32>, BackendError> {
                Ok(vec![f32::NAN])
            }
        }

        let tensor = FieldTensor::new(
            1,
            Modality::WifiCsi,
            vec![FieldAxis::Frequency],
            vec![1],
            vec![1.0],
            0.9,
            0.01,
            None,
            PrivacyClass::P1,
        )
        .unwrap();
        let error = RuVectorFieldEncoder::new(
            BadBackend,
            EncoderDeployment::new(BackendBoundary::LocalProcess),
            LocalOnlyPrivacyPolicy,
        )
        .encode(&tensor, "event_1")
        .unwrap_err();
        assert_eq!(error, EncoderError::InvalidEmbedding);
    }

    #[test]
    fn empty_source_and_backend_identities_are_rejected() {
        let tensor = FieldTensor::new(
            1,
            Modality::WifiCsi,
            vec![FieldAxis::Frequency],
            vec![1],
            vec![1.0],
            0.9,
            0.01,
            None,
            PrivacyClass::P1,
        )
        .unwrap();
        let encoder = RuVectorFieldEncoder::new(
            InMemoryConformanceBackend::new(2).unwrap(),
            EncoderDeployment::new(BackendBoundary::LocalProcess),
            LocalOnlyPrivacyPolicy,
        );
        assert_eq!(
            encoder.encode(&tensor, "").unwrap_err(),
            EncoderError::EmptySourceEventId
        );

        struct EmptyIdentityBackend;
        impl EmbeddingBackend for EmptyIdentityBackend {
            fn backend_id(&self) -> &str {
                ""
            }

            fn embed(&self, _request: &EmbeddingRequest<'_>) -> Result<Vec<f32>, BackendError> {
                Ok(vec![1.0])
            }
        }
        assert_eq!(
            RuVectorFieldEncoder::new(
                EmptyIdentityBackend,
                EncoderDeployment::new(BackendBoundary::LocalProcess),
                LocalOnlyPrivacyPolicy,
            )
            .encode(&tensor, "event_1")
            .unwrap_err(),
            EncoderError::EmptyBackendId
        );
    }

    #[test]
    fn encoding_receipt_binds_backend_input_and_privacy() {
        let tensor = FieldTensor::new(
            1,
            Modality::WifiCsi,
            vec![FieldAxis::Frequency],
            vec![2],
            vec![1.0, 2.0],
            0.9,
            0.01,
            None,
            PrivacyClass::P1,
        )
        .unwrap();
        let encoder = RuVectorFieldEncoder::new(
            InMemoryConformanceBackend::new(2).unwrap(),
            EncoderDeployment::new(BackendBoundary::LocalProcess),
            LocalOnlyPrivacyPolicy,
        );
        let first = encoder.encode_with_receipt(&tensor, "event_1").unwrap();
        let second = encoder.encode_with_receipt(&tensor, "event_1").unwrap();
        assert_eq!(first, second);
        assert_eq!(first.embedding.privacy_class, PrivacyClass::P1);
        assert_eq!(first.receipt.privacy_class, PrivacyClass::P1);
        assert_eq!(first.receipt.policy_id, "rufield.privacy.local_only.v1");
        assert_eq!(
            first.receipt.decision_receipt_id,
            "rufield.privacy.local_only.v1:allow_local"
        );
        assert_eq!(first.receipt.backend_id, "rufield.in_memory_conformance.v1");
        assert_eq!(first.receipt.boundary, BackendBoundary::LocalProcess);
        assert_eq!(first.receipt.canonical_input_sha256.len(), 71);
        assert_eq!(first.receipt.embedding_sha256.len(), 71);

        let changed = encoder.encode_with_receipt(&tensor, "event_2").unwrap();
        assert_ne!(
            first.receipt.canonical_input_sha256,
            changed.receipt.canonical_input_sha256
        );
    }

    #[test]
    fn denied_remote_backend_never_receives_tensor_values() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct CountingRemoteBackend(Arc<AtomicUsize>);
        impl EmbeddingBackend for CountingRemoteBackend {
            fn backend_id(&self) -> &str {
                "remote.test.v1"
            }

            fn embed(&self, _request: &EmbeddingRequest<'_>) -> Result<Vec<f32>, BackendError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(vec![1.0])
            }
        }

        let invocations = Arc::new(AtomicUsize::new(0));
        let encoder = RuVectorFieldEncoder::new(
            CountingRemoteBackend(Arc::clone(&invocations)),
            EncoderDeployment::new(BackendBoundary::Network),
            LocalOnlyPrivacyPolicy,
        );
        let tensor = FieldTensor::new(
            1,
            Modality::WifiCsi,
            vec![FieldAxis::Frequency],
            vec![1],
            vec![1.0],
            0.9,
            0.01,
            None,
            PrivacyClass::P1,
        )
        .unwrap();

        assert_eq!(
            encoder.encode(&tensor, "event_1").unwrap_err(),
            EncoderError::PrivacyDenied
        );
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn bundled_policy_denies_sensitive_local_tensors_before_backend_invocation() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct CountingBackend(Arc<AtomicUsize>);
        impl EmbeddingBackend for CountingBackend {
            fn backend_id(&self) -> &str {
                "local.sensitive.test.v1"
            }

            fn embed(&self, _request: &EmbeddingRequest<'_>) -> Result<Vec<f32>, BackendError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(vec![1.0])
            }
        }

        for privacy_class in [PrivacyClass::P4, PrivacyClass::P5] {
            let invocations = Arc::new(AtomicUsize::new(0));
            let encoder = RuVectorFieldEncoder::new(
                CountingBackend(Arc::clone(&invocations)),
                EncoderDeployment::new(BackendBoundary::LocalProcess),
                LocalOnlyPrivacyPolicy,
            );
            let tensor = FieldTensor::new(
                1,
                Modality::WifiCsi,
                vec![FieldAxis::Frequency],
                vec![1],
                vec![1.0],
                0.9,
                0.01,
                None,
                privacy_class,
            )
            .unwrap();
            assert_eq!(
                encoder.encode(&tensor, "event_1").unwrap_err(),
                EncoderError::PrivacyDenied
            );
            assert_eq!(invocations.load(Ordering::SeqCst), 0);
        }
    }
}
