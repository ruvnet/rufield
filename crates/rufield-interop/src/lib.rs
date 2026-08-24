//! Lossless interoperability projections for RuField field events.
//!
//! IEEE 802.11bf and Bluetooth Channel Sounding appear only as source profile
//! identifiers. This crate does not reimplement either radio protocol. It maps
//! an already normalized [`rufield_core::FieldEvent`] to CloudEvents 1.0 and a
//! compact SOSA observation envelope while preserving the native event as the
//! lossless payload.

use rufield_core::{FieldEvent, Modality};
use serde::{Deserialize, Serialize};
use std::fmt;

/// CloudEvents profile version supported by this projection.
pub const CLOUD_EVENTS_SPEC_VERSION: &str = "1.0";
/// SOSA namespace used by the JSON LD projection.
pub const SOSA_NAMESPACE: &str = "http://www.w3.org/ns/sosa/";
/// RuField namespace used by the JSON LD projection.
pub const RUFIELD_NAMESPACE: &str = "https://github.com/ruvnet/rufield/spec/";

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
        timeunixnano: event.timestamp_ns,
        data: event.clone(),
    }
}

/// Validate and recover the lossless native event from CloudEvents.
pub fn from_cloud_event(envelope: CloudEvent) -> Result<FieldEvent, InteropError> {
    if envelope.specversion != CLOUD_EVENTS_SPEC_VERSION {
        return Err(InteropError::new("unsupported CloudEvents version"));
    }
    if envelope.event_type != "net.ruv.rufield.observation.v1" {
        return Err(InteropError::new("unsupported CloudEvents event type"));
    }
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
        event: event.clone(),
    }
}

/// Validate and recover the lossless native event from SOSA JSON LD.
pub fn from_sosa_observation(envelope: SosaObservation) -> Result<FieldEvent, InteropError> {
    if envelope.context.sosa != SOSA_NAMESPACE
        || envelope.context.rufield != RUFIELD_NAMESPACE
        || envelope.kind != "sosa:Observation"
    {
        return Err(InteropError::new("unsupported SOSA context or type"));
    }
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
