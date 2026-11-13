//! Lossless interoperability projections for RuField field events.
//!
//! IEEE 802.11bf and Bluetooth Channel Sounding appear only as source profile
//! identifiers. This crate does not reimplement either radio protocol. It maps
//! an already normalized [`rufield_core::FieldEvent`] to CloudEvents 1.0 and a
//! compact SOSA observation envelope while preserving the native event as the
//! lossless payload.
//!
//! Moving standards drafts such as 3GPP Release 20 ISAC and ETSI ISAC work are
//! represented separately as bounded [`StandardsReference`] metadata. A
//! reference records which document informed an integration; it is never a
//! protocol implementation, certification, or compliance claim.

use rufield_core::{FieldEvent, Modality};
use serde::{Deserialize, Serialize};
use std::fmt;

/// CloudEvents profile version supported by this projection.
pub const CLOUD_EVENTS_SPEC_VERSION: &str = "1.0";
/// SOSA namespace used by the JSON LD projection.
pub const SOSA_NAMESPACE: &str = "http://www.w3.org/ns/sosa/";
/// RuField namespace used by the JSON LD projection.
pub const RUFIELD_NAMESPACE: &str = "https://github.com/ruvnet/rufield/spec/";
/// Maximum standards references attached to one interop envelope.
pub const MAX_STANDARDS_REFERENCES: usize = 16;
/// Maximum bytes accepted in a standards document identifier.
pub const MAX_STANDARD_DOCUMENT_ID_BYTES: usize = 96;
/// Maximum bytes accepted in a standards version.
pub const MAX_STANDARD_VERSION_BYTES: usize = 32;
/// Maximum bytes accepted in an optional release or stage descriptor.
pub const MAX_STANDARD_STAGE_BYTES: usize = 48;

/// The acquisition profile represented by an already normalized event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceProfile {
    /// IEEE 802.11bf sensing source. The standard itself is not implemented.
    Ieee80211bf2025,
    /// Bluetooth Core 6.0 Channel Sounding source. The protocol is not implemented.
    BluetoothCore60ChannelSounding,
    /// Native RuField source where no external radio profile applies.
    RufieldNativeV01,
}

impl SourceProfile {
    /// Stable identifier suitable for a CloudEvents extension attribute.
    #[must_use]
    pub fn identifier(self) -> &'static str {
        match self {
            Self::Ieee80211bf2025 => "ieee.802.11bf.2025",
            Self::BluetoothCore60ChannelSounding => "bluetooth.core.6.0.channel_sounding",
            Self::RufieldNativeV01 => "rufield.mfs.v0.1",
        }
    }
}

/// Standards organization associated with a non-normative reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StandardsOrganization {
    /// Third Generation Partnership Project.
    ThreeGpp,
    /// European Telecommunications Standards Institute.
    Etsi,
    /// Institute of Electrical and Electronics Engineers.
    Ieee,
    /// Bluetooth Special Interest Group.
    BluetoothSig,
    /// Wi-Fi Alliance.
    WifiAlliance,
    /// O-RAN Alliance.
    ORan,
    /// Internet Engineering Task Force.
    Ietf,
}

/// Architectural role played by a standards reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StandardsRole {
    /// Measurement or radio acquisition profile.
    Acquisition,
    /// Sensing service or network function interface.
    SensingService,
    /// Exposure of sensing results to vertical applications.
    VerticalExposure,
    /// Evaluation, demonstrability, or technology adoption profile.
    EvaluationProfile,
    /// Security, privacy, resilience, or trust guidance.
    SecurityPrivacy,
    /// Compute placement or edge inference guidance.
    ComputePlacement,
}

/// Bounded, explicitly non-compliance metadata linking an interop envelope to a
/// standards document that informed its shape or semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandardsReference {
    /// Standards body that owns the referenced document.
    pub organization: StandardsOrganization,
    /// Document identifier, for example `TS 23.138` or `GR ISC 009`.
    pub document_id: String,
    /// Exact version being referenced, for example `0.2.0`.
    pub version: String,
    /// Optional release or stage, for example `Release 20` or `Early draft`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_or_stage: Option<String>,
    /// Reference date in `YYYY-MM-DD` form.
    pub reference_date: String,
    /// How this document relates to the RuField envelope.
    pub role: StandardsRole,
    /// Must remain false. RuField metadata cannot manufacture a compliance claim.
    #[serde(default)]
    pub compliance_claim: bool,
}

impl StandardsReference {
    /// Construct and validate an explicitly non-compliance standards reference.
    pub fn new(
        organization: StandardsOrganization,
        document_id: impl Into<String>,
        version: impl Into<String>,
        release_or_stage: Option<String>,
        reference_date: impl Into<String>,
        role: StandardsRole,
    ) -> Result<Self, InteropError> {
        let reference = Self {
            organization,
            document_id: document_id.into(),
            version: version.into(),
            release_or_stage,
            reference_date: reference_date.into(),
            role,
            compliance_claim: false,
        };
        reference.validate()?;
        Ok(reference)
    }

    /// Validate bounds, text hygiene, date shape, and the non-compliance invariant.
    pub fn validate(&self) -> Result<(), InteropError> {
        if self.compliance_claim {
            return Err(InteropError::new(
                "standards reference cannot assert compliance",
            ));
        }
        validate_text(
            "standards document identifier",
            &self.document_id,
            MAX_STANDARD_DOCUMENT_ID_BYTES,
        )?;
        validate_text(
            "standards version",
            &self.version,
            MAX_STANDARD_VERSION_BYTES,
        )?;
        if let Some(stage) = &self.release_or_stage {
            validate_text("standards release or stage", stage, MAX_STANDARD_STAGE_BYTES)?;
        }
        validate_reference_date(&self.reference_date)
    }
}

/// Lossless CloudEvents 1.0 structured event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CloudEvent {
    /// CloudEvents version.
    pub specversion: String,
    /// RuField event identifier.
    pub id: String,
    /// Stable producer URI.
    pub source: String,
    /// Event type.
    #[serde(rename = "type")]
    pub event_type: String,
    /// Device identifier used as the event subject.
    pub subject: String,
    /// Native RuField payload content type.
    pub datacontenttype: String,
    /// Source standard profile extension.
    pub sourceprofile: String,
    /// Optional non-compliance references to evolving standards documents.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub standardsreferences: Vec<StandardsReference>,
    /// Integer capture time extension preserving nanosecond precision.
    pub timeunixnano: u64,
    /// Lossless native event.
    pub data: FieldEvent,
}

/// JSON LD context used by [`SosaObservation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SosaContext {
    /// W3C SOSA namespace.
    pub sosa: String,
    /// RuField extension namespace.
    pub rufield: String,
}

/// JSON LD IRI node represented with `@id`, not a string literal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IriNode {
    /// Absolute IRI identifier.
    #[serde(rename = "@id")]
    pub id: String,
}

/// Lossless SOSA observation projection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SosaObservation {
    /// JSON LD context.
    #[serde(rename = "@context")]
    pub context: SosaContext,
    /// Observation URI.
    #[serde(rename = "@id")]
    pub id: String,
    /// SOSA observation type.
    #[serde(rename = "@type")]
    pub kind: String,
    /// Sensor URI.
    #[serde(rename = "sosa:madeBySensor")]
    pub made_by_sensor: IriNode,
    /// Stable modality property URI.
    #[serde(rename = "sosa:observedProperty")]
    pub observed_property: IriNode,
    /// Nanosecond capture time preserved by the RuField extension.
    #[serde(rename = "rufield:resultTimeUnixNano")]
    pub result_time_unix_nano: u64,
    /// Source standard profile identifier.
    #[serde(rename = "rufield:sourceProfile")]
    pub source_profile: String,
    /// Optional non-compliance references to evolving standards documents.
    #[serde(
        rename = "rufield:standardsReferences",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub standards_references: Vec<StandardsReference>,
    /// Lossless native event payload.
    #[serde(rename = "rufield:event")]
    pub event: FieldEvent,
}

/// Projection or validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteropError(String);

impl InteropError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for InteropError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InteropError {}

/// Project a native event into CloudEvents without changing its payload.
#[must_use]
pub fn to_cloud_event(event: &FieldEvent, profile: SourceProfile) -> CloudEvent {
    CloudEvent {
        specversion: CLOUD_EVENTS_SPEC_VERSION.into(),
        id: event.event_id.clone(),
        source: format!("urn:rufield:device:{}", event.sensor.device_id),
        event_type: "net.ruv.rufield.observation.v1".into(),
        subject: event.sensor.device_id.clone(),
        datacontenttype: "application/vnd.rufield.event+json".into(),
        sourceprofile: profile.identifier().into(),
        standardsreferences: Vec::new(),
        timeunixnano: event.timestamp_ns,
        data: event.clone(),
    }
}

/// Project a native event into CloudEvents and attach validated standards
/// references that cannot assert certification or compliance.
pub fn to_cloud_event_with_references(
    event: &FieldEvent,
    profile: SourceProfile,
    standards_references: Vec<StandardsReference>,
) -> Result<CloudEvent, InteropError> {
    validate_standards_references(&standards_references)?;
    let mut envelope = to_cloud_event(event, profile);
    envelope.standardsreferences = standards_references;
    Ok(envelope)
}

/// Validate and recover the lossless native event from CloudEvents.
pub fn from_cloud_event(envelope: CloudEvent) -> Result<FieldEvent, InteropError> {
    if envelope.specversion != CLOUD_EVENTS_SPEC_VERSION {
        return Err(InteropError::new("unsupported CloudEvents version"));
    }
    if envelope.event_type != "net.ruv.rufield.observation.v1" {
        return Err(InteropError::new("unsupported CloudEvents event type"));
    }
    validate_standards_references(&envelope.standardsreferences)?;
    let expected_source = format!("urn:rufield:device:{}", envelope.data.sensor.device_id);
    if envelope.id != envelope.data.event_id
        || envelope.subject != envelope.data.sensor.device_id
        || envelope.source != expected_source
        || envelope.datacontenttype != "application/vnd.rufield.event+json"
        || !known_source_profile(&envelope.sourceprofile)
        || envelope.timeunixnano != envelope.data.timestamp_ns
    {
        return Err(InteropError::new(
            "CloudEvents attributes disagree with native payload",
        ));
    }
    envelope
        .data
        .tensor
        .validate()
        .map_err(|error| InteropError::new(error.to_string()))?;
    Ok(envelope.data)
}

/// Project a native event into a lossless SOSA JSON LD observation.
#[must_use]
pub fn to_sosa_observation(event: &FieldEvent, profile: SourceProfile) -> SosaObservation {
    SosaObservation {
        context: SosaContext {
            sosa: SOSA_NAMESPACE.into(),
            rufield: RUFIELD_NAMESPACE.into(),
        },
        id: format!("urn:rufield:observation:{}", event.event_id),
        kind: "sosa:Observation".into(),
        made_by_sensor: IriNode {
            id: format!("urn:rufield:sensor:{}", event.sensor.device_id),
        },
        observed_property: IriNode {
            id: format!(
                "urn:rufield:modality:{}",
                modality_name(event.tensor.modality)
            ),
        },
        result_time_unix_nano: event.timestamp_ns,
        source_profile: profile.identifier().into(),
        standards_references: Vec::new(),
        event: event.clone(),
    }
}

/// Project a native event into SOSA JSON LD and attach validated standards
/// references that cannot assert certification or compliance.
pub fn to_sosa_observation_with_references(
    event: &FieldEvent,
    profile: SourceProfile,
    standards_references: Vec<StandardsReference>,
) -> Result<SosaObservation, InteropError> {
    validate_standards_references(&standards_references)?;
    let mut envelope = to_sosa_observation(event, profile);
    envelope.standards_references = standards_references;
    Ok(envelope)
}

/// Validate and recover the lossless native event from SOSA JSON LD.
pub fn from_sosa_observation(envelope: SosaObservation) -> Result<FieldEvent, InteropError> {
    if envelope.context.sosa != SOSA_NAMESPACE
        || envelope.context.rufield != RUFIELD_NAMESPACE
        || envelope.kind != "sosa:Observation"
    {
        return Err(InteropError::new("unsupported SOSA context or type"));
    }
    validate_standards_references(&envelope.standards_references)?;
    let expected_id = format!("urn:rufield:observation:{}", envelope.event.event_id);
    let expected_sensor = format!("urn:rufield:sensor:{}", envelope.event.sensor.device_id);
    let expected_property = format!(
        "urn:rufield:modality:{}",
        modality_name(envelope.event.tensor.modality)
    );
    if envelope.id != expected_id
        || envelope.made_by_sensor.id != expected_sensor
        || envelope.observed_property.id != expected_property
        || !known_source_profile(&envelope.source_profile)
        || envelope.result_time_unix_nano != envelope.event.timestamp_ns
    {
        return Err(InteropError::new(
            "SOSA attributes disagree with native payload",
        ));
    }
    envelope
        .event
        .tensor
        .validate()
        .map_err(|error| InteropError::new(error.to_string()))?;
    Ok(envelope.event)
}

/// Serialize with stable struct field ordering for fixtures and signatures.
pub fn deterministic_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(value)
}

fn validate_standards_references(references: &[StandardsReference]) -> Result<(), InteropError> {
    if references.len() > MAX_STANDARDS_REFERENCES {
        return Err(InteropError::new(format!(
            "too many standards references: {} > {MAX_STANDARDS_REFERENCES}",
            references.len()
        )));
    }
    for reference in references {
        reference.validate()?;
    }
    Ok(())
}

fn validate_text(field: &str, value: &str, maximum_bytes: usize) -> Result<(), InteropError> {
    if value.is_empty() || value.len() > maximum_bytes || value.trim() != value {
        return Err(InteropError::new(format!("invalid {field}")));
    }
    if value.chars().any(char::is_control) {
        return Err(InteropError::new(format!("invalid {field}")));
    }
    Ok(())
}

fn validate_reference_date(value: &str) -> Result<(), InteropError> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return Err(InteropError::new("invalid standards reference date"));
    }
    let month = value[5..7]
        .parse::<u8>()
        .map_err(|_| InteropError::new("invalid standards reference date"))?;
    let day = value[8..10]
        .parse::<u8>()
        .map_err(|_| InteropError::new("invalid standards reference date"))?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(InteropError::new("invalid standards reference date"));
    }
    Ok(())
}

fn modality_name(modality: Modality) -> &'static str {
    match modality {
        Modality::WifiCsi => "wifi_csi",
        Modality::WifiCir => "wifi_cir",
        Modality::WifiBfld => "wifi_bfld",
        Modality::UwbHrp => "uwb_hrp",
        Modality::BleAdvertisementRssi => "ble_advertisement_rssi",
        Modality::QuantumRf => "quantum_rf",
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

fn known_source_profile(value: &str) -> bool {
    [
        SourceProfile::Ieee80211bf2025,
        SourceProfile::BluetoothCore60ChannelSounding,
        SourceProfile::RufieldNativeV01,
    ]
    .into_iter()
    .any(|profile| profile.identifier() == value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_event() -> FieldEvent {
        serde_json::from_str(include_str!("../../../fixtures/interop/field-event.json")).unwrap()
    }

    fn isac_references() -> Vec<StandardsReference> {
        vec![
            StandardsReference::new(
                StandardsOrganization::ThreeGpp,
                "TS 23.138",
                "0.2.0",
                Some("Release 20 draft".into()),
                "2026-09-02",
                StandardsRole::VerticalExposure,
            )
            .unwrap(),
            StandardsReference::new(
                StandardsOrganization::ThreeGpp,
                "TS 29.545",
                "0.2.0",
                Some("Release 20 draft".into()),
                "2026-09-04",
                StandardsRole::SensingService,
            )
            .unwrap(),
            StandardsReference::new(
                StandardsOrganization::Etsi,
                "GR ISC 009",
                "0.0.3",
                Some("Early draft".into()),
                "2026-09-02",
                StandardsRole::EvaluationProfile,
            )
            .unwrap(),
        ]
    }

    #[test]
    fn cloud_event_matches_golden_and_round_trips() {
        let event = fixture_event();
        let envelope = to_cloud_event(&event, SourceProfile::Ieee80211bf2025);
        let expected = include_str!("../../../fixtures/interop/cloudevent.json").trim();
        assert_eq!(deterministic_json(&envelope).unwrap(), expected);
        assert_eq!(from_cloud_event(envelope).unwrap(), event);
    }

    #[test]
    fn sosa_matches_golden_and_round_trips() {
        let event = fixture_event();
        let envelope = to_sosa_observation(&event, SourceProfile::Ieee80211bf2025);
        let expected = include_str!("../../../fixtures/interop/sosa-observation.json").trim();
        let json = deterministic_json(&envelope).unwrap();
        assert_eq!(json, expected);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value["sosa:madeBySensor"]["@id"].is_string());
        assert!(value["sosa:observedProperty"]["@id"].is_string());
        assert_eq!(from_sosa_observation(envelope).unwrap(), event);
    }

    #[test]
    fn evolving_standards_references_are_additive_and_round_trip() {
        let event = fixture_event();
        let references = isac_references();
        let envelope = to_cloud_event_with_references(
            &event,
            SourceProfile::Ieee80211bf2025,
            references.clone(),
        )
        .unwrap();
        assert_eq!(envelope.standardsreferences, references);
        let json = deterministic_json(&envelope).unwrap();
        assert!(json.contains("TS 23.138"));
        assert!(json.contains("GR ISC 009"));
        assert_eq!(from_cloud_event(envelope).unwrap(), event);

        let sosa = to_sosa_observation_with_references(
            &event,
            SourceProfile::Ieee80211bf2025,
            isac_references(),
        )
        .unwrap();
        let json = deterministic_json(&sosa).unwrap();
        assert!(json.contains("rufield:standardsReferences"));
        assert_eq!(from_sosa_observation(sosa).unwrap(), event);
    }

    #[test]
    fn standards_metadata_cannot_manufacture_compliance() {
        let event = fixture_event();
        let mut reference = isac_references().remove(0);
        reference.compliance_claim = true;
        let err = to_cloud_event_with_references(
            &event,
            SourceProfile::RufieldNativeV01,
            vec![reference],
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "standards reference cannot assert compliance");
    }

    #[test]
    fn external_standards_metadata_is_bounded_and_sanitized() {
        let event = fixture_event();
        let oversized = "x".repeat(MAX_STANDARD_DOCUMENT_ID_BYTES + 1);
        let reference = StandardsReference {
            organization: StandardsOrganization::Etsi,
            document_id: oversized,
            version: "0.0.3".into(),
            release_or_stage: None,
            reference_date: "2026-09-02".into(),
            role: StandardsRole::EvaluationProfile,
            compliance_claim: false,
        };
        assert!(to_cloud_event_with_references(
            &event,
            SourceProfile::RufieldNativeV01,
            vec![reference]
        )
        .is_err());

        assert!(StandardsReference::new(
            StandardsOrganization::ThreeGpp,
            "TS 29.545\nforged",
            "0.2.0",
            None,
            "2026-09-04",
            StandardsRole::SensingService,
        )
        .is_err());
        assert!(StandardsReference::new(
            StandardsOrganization::ThreeGpp,
            "TS 29.545",
            "0.2.0",
            None,
            "2026-13-04",
            StandardsRole::SensingService,
        )
        .is_err());
    }

    #[test]
    fn too_many_standards_references_are_rejected() {
        let event = fixture_event();
        let reference = isac_references().remove(0);
        let references = vec![reference; MAX_STANDARDS_REFERENCES + 1];
        assert!(to_cloud_event_with_references(
            &event,
            SourceProfile::RufieldNativeV01,
            references
        )
        .is_err());
    }

    #[test]
    fn radio_profiles_are_identifiers_not_protocol_claims() {
        assert_eq!(
            SourceProfile::Ieee80211bf2025.identifier(),
            "ieee.802.11bf.2025"
        );
        assert_eq!(
            SourceProfile::BluetoothCore60ChannelSounding.identifier(),
            "bluetooth.core.6.0.channel_sounding"
        );
    }
}
