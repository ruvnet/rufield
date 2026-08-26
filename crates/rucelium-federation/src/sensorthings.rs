//! **SensorThings-inspired projection** (ADR-264 §7): typed serde structs
//! modelled on the OGC SensorThings API 1.1 entity JSON shapes (`@iot.id`,
//! camelCase field names) so every accepted observation is externally
//! consumable (§14 criterion 6).
//!
//! Honest label: this is *inspired by* the SensorThings data model, not a
//! conformant implementation — it must not be described as OGC-conformant
//! until it passes an external OGC conformance suite. Known deliberate
//! deviations are documented on the fields involved (see
//! [`Sensor::encoding_type`]).
//!
//! v0.1 implements the biome → entity *projection*; serving these entities
//! over HTTP is a follow-up.

use rucelium_core::{EnvSample, GeoPoint};
use serde::{Deserialize, Serialize};

/// GeoJSON `Point` geometry as embedded in `Location.location` and
/// `FeatureOfInterest.feature`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoJsonPoint {
    /// Always `"Point"`.
    #[serde(rename = "type")]
    pub r#type: String,
    /// `[longitude_deg, latitude_deg]` — GeoJSON axis order.
    pub coordinates: [f64; 2],
}

impl GeoJsonPoint {
    /// Project a [`GeoPoint`] to GeoJSON (longitude first).
    #[must_use]
    pub fn from_geo(geo: &GeoPoint) -> Self {
        GeoJsonPoint {
            r#type: "Point".into(),
            coordinates: [geo.longitude_deg(), geo.latitude_deg()],
        }
    }
}

/// SensorThings-inspired `Thing` — one per device.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Thing {
    /// Stable entity id: `thing:node:<node_id>`.
    #[serde(rename = "@iot.id")]
    pub iot_id: String,
    /// Human-readable name.
    pub name: String,
    /// Description.
    pub description: String,
}

/// SensorThings-inspired `Location` of a Thing (GeoJSON encoded).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    /// Stable entity id: `location:node:<node_id>`.
    #[serde(rename = "@iot.id")]
    pub iot_id: String,
    /// Human-readable name.
    pub name: String,
    /// Always `"application/geo+json"`.
    pub encoding_type: String,
    /// GeoJSON point geometry.
    pub location: GeoJsonPoint,
}

/// SensorThings-inspired `Sensor` — the measuring procedure/instrument.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sensor {
    /// Stable entity id: `sensor:node:<node_id>:<modality>`.
    #[serde(rename = "@iot.id")]
    pub iot_id: String,
    /// Human-readable name.
    pub name: String,
    /// Description (mandatory in the SensorThings data model).
    pub description: String,
    /// Always `"text/plain"`.
    ///
    /// **Deliberate deviation** from SensorThings 1.1, which enumerates only
    /// `application/pdf` and SensorML encodings here: our `metadata` field
    /// carries a firmware measurement-implementation hash string, which is
    /// plain text, not PDF content — labelling it `application/pdf` would be
    /// a lie about the bytes. This deviation is part of why this module is a
    /// SensorThings-*inspired* projection rather than a conformant one.
    pub encoding_type: String,
    /// Sensor metadata: the firmware measurement-implementation hash.
    pub metadata: String,
}

/// SensorThings-inspired `ObservedProperty` — what is being measured.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservedProperty {
    /// Stable entity id: `observedproperty:<observed_property>`.
    #[serde(rename = "@iot.id")]
    pub iot_id: String,
    /// Property name (e.g. `air_temperature`).
    pub name: String,
    /// Definition URI.
    pub definition: String,
    /// Description.
    pub description: String,
}

/// SensorThings-inspired `unitOfMeasurement` value object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnitOfMeasurement {
    /// Unit name.
    pub name: String,
    /// Unit symbol (the UCUM code).
    pub symbol: String,
    /// Definition URI.
    pub definition: String,
}

/// SensorThings-inspired `Datastream` — the series linking Thing, Sensor,
/// and ObservedProperty.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Datastream {
    /// Stable entity id: `datastream:<node_id>:<observed_property>`.
    #[serde(rename = "@iot.id")]
    pub iot_id: String,
    /// Human-readable name.
    pub name: String,
    /// Description (mandatory in the SensorThings data model).
    pub description: String,
    /// Observation type URI (mandatory in the SensorThings data model);
    /// always the O&M measurement type,
    /// `http://www.opengis.net/def/observationType/OGC-OM/2.0/OM_Measurement`.
    #[serde(rename = "observationType")]
    pub observation_type: String,
    /// Unit of measurement for all observations in this stream.
    pub unit_of_measurement: UnitOfMeasurement,
    /// Linked [`ObservedProperty`] id.
    pub observed_property_id: String,
    /// Linked [`Sensor`] id.
    pub sensor_id: String,
    /// Linked [`Thing`] id.
    pub thing_id: String,
}

/// SensorThings-inspired `Observation` — one measured value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    /// Stable entity id: `obs:<node_id>:<sequence>`.
    #[serde(rename = "@iot.id")]
    pub iot_id: String,
    /// Measurement time (RFC 3339, from `measured_ns`).
    pub phenomenon_time: String,
    /// Result availability time (RFC 3339, from `received_ns`).
    pub result_time: String,
    /// Calibrated value.
    pub result: f64,
    /// Quality score `0.0..=1.0` (ADR-264 §12 public quality scores).
    pub result_quality: f32,
    /// Linked [`Datastream`] id.
    pub datastream_id: String,
}

/// SensorThings-inspired `FeatureOfInterest` — where the observation
/// applies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeatureOfInterest {
    /// Stable entity id: `foi:node:<node_id>`.
    #[serde(rename = "@iot.id")]
    pub iot_id: String,
    /// Human-readable name.
    pub name: String,
    /// Always `"application/geo+json"`.
    pub encoding_type: String,
    /// GeoJSON point geometry.
    pub feature: GeoJsonPoint,
}

/// A fully linked SensorThings-inspired entity set for one observation —
/// every accepted observation must be projectable (ADR-264 §14 criterion 6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SensorThingsBundle {
    /// The producing device.
    pub thing: Thing,
    /// Its location.
    pub location: Location,
    /// The measuring sensor.
    pub sensor: Sensor,
    /// The observed property.
    pub observed_property: ObservedProperty,
    /// The datastream linking them.
    pub datastream: Datastream,
    /// The observation itself.
    pub observation: Observation,
    /// The feature of interest.
    pub feature_of_interest: FeatureOfInterest,
}

/// The O&M measurement observation type URI stamped on every
/// [`Datastream`].
const OM_MEASUREMENT: &str = "http://www.opengis.net/def/observationType/OGC-OM/2.0/OM_Measurement";

/// Project one normalized [`EnvSample`] into a fully linked
/// SensorThings-inspired entity set with stable, deterministic ids.
#[must_use]
pub fn project_sample(sample: &EnvSample) -> SensorThingsBundle {
    let thing_id = format!("thing:node:{}", sample.node_id);
    let sensor_id = format!(
        "sensor:node:{}:{}",
        sample.node_id,
        sample.modality.as_str()
    );
    let observed_property_id = format!("observedproperty:{}", sample.observed_property);
    let datastream_id = format!("datastream:{}:{}", sample.node_id, sample.observed_property);
    let point = GeoJsonPoint::from_geo(&sample.geo);

    SensorThingsBundle {
        thing: Thing {
            iot_id: thing_id.clone(),
            name: format!("spore-node-{}", sample.node_id),
            description: format!(
                "RuCelium spore node {} ({})",
                sample.node_id,
                sample.modality.as_str()
            ),
        },
        location: Location {
            iot_id: format!("location:node:{}", sample.node_id),
            name: format!("location of spore-node-{}", sample.node_id),
            encoding_type: "application/geo+json".into(),
            location: point.clone(),
        },
        sensor: Sensor {
            iot_id: sensor_id.clone(),
            name: format!(
                "{} sensor on node {}",
                sample.modality.as_str(),
                sample.node_id
            ),
            description: format!(
                "{} sensor on RuCelium spore node {}, described by its firmware \
                 measurement-implementation hash",
                sample.modality.as_str(),
                sample.node_id
            ),
            encoding_type: "text/plain".into(),
            metadata: sample.provenance.firmware_hash.clone(),
        },
        observed_property: ObservedProperty {
            iot_id: observed_property_id.clone(),
            name: sample.observed_property.clone(),
            definition: format!("urn:rucelium:property:{}", sample.observed_property),
            description: format!(
                "{} observed by the {} modality",
                sample.observed_property,
                sample.modality.as_str()
            ),
        },
        datastream: Datastream {
            iot_id: datastream_id.clone(),
            name: format!("{} from node {}", sample.observed_property, sample.node_id),
            description: format!(
                "{} measurements from RuCelium spore node {}",
                sample.observed_property, sample.node_id
            ),
            observation_type: OM_MEASUREMENT.into(),
            unit_of_measurement: UnitOfMeasurement {
                name: sample.unit.clone(),
                symbol: sample.unit.clone(),
                definition: format!("https://ucum.org/ucum#{}", sample.unit),
            },
            observed_property_id,
            sensor_id,
            thing_id,
        },
        observation: Observation {
            iot_id: format!("obs:{}:{}", sample.node_id, sample.sequence),
            phenomenon_time: rfc3339_from_ns(sample.measured_ns),
            result_time: rfc3339_from_ns(sample.received_ns),
            result: sample.value,
            result_quality: sample.quality,
            datastream_id,
        },
        feature_of_interest: FeatureOfInterest {
            iot_id: format!("foi:node:{}", sample.node_id),
            name: format!("measurement site of spore-node-{}", sample.node_id),
            encoding_type: "application/geo+json".into(),
            feature: point,
        },
    }
}

/// Format nanoseconds since the Unix epoch as RFC 3339 UTC with millisecond
/// precision: `YYYY-MM-DDTHH:MM:SS.mmmZ`.
///
/// Pure integer math via the inverse of Howard Hinnant's `days_from_civil`
/// (`civil_from_days`) — no `chrono`, no clocks.
#[must_use]
pub fn rfc3339_from_ns(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    let millis = (ns % 1_000_000_000) / 1_000_000;
    let days = secs / 86_400;
    let second_of_day = secs % 86_400;
    let (hour, minute, second) = (
        second_of_day / 3_600,
        (second_of_day % 3_600) / 60,
        second_of_day % 60,
    );

    // civil_from_days (Hinnant): days since 1970-01-01 → (y, m, d).
    // All values are non-negative here (u64 input), so plain division works.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097; // day of era [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    if month <= 2 {
        year += 1;
    }

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::sample;

    #[test]
    fn rfc3339_known_vectors() {
        // Epoch.
        assert_eq!(rfc3339_from_ns(0), "1970-01-01T00:00:00.000Z");
        // Millisecond precision.
        assert_eq!(rfc3339_from_ns(1_000_000), "1970-01-01T00:00:00.001Z");
        assert_eq!(rfc3339_from_ns(999_999), "1970-01-01T00:00:00.000Z");
        // 1_754_006_400 s = 20_301 d since epoch = 2025-08-01 (hand check:
        // 20_089 d to 2025-01-01, +212 d = Aug 1).
        assert_eq!(
            rfc3339_from_ns(1_754_006_400_000_000_000),
            "2025-08-01T00:00:00.000Z"
        );
        // 1_785_542_400 s = 20_666 d = 2026-08-01 (20_454 d to 2026-01-01,
        // +212 d = Aug 1).
        assert_eq!(
            rfc3339_from_ns(1_785_542_400_000_000_000),
            "2026-08-01T00:00:00.000Z"
        );
        // Leap-year date: 1_709_164_800 s = 2024-02-29T00:00:00Z
        // (2024-03-01T00:00:00Z = 1_709_251_200 minus one day).
        assert_eq!(
            rfc3339_from_ns(1_709_164_800_000_000_000),
            "2024-02-29T00:00:00.000Z"
        );
        // End of that leap day.
        assert_eq!(
            rfc3339_from_ns(1_709_251_199_999_000_000),
            "2024-02-29T23:59:59.999Z"
        );
        // Sub-day time components.
        assert_eq!(
            rfc3339_from_ns(3_661_500_000_000),
            "1970-01-01T01:01:01.500Z"
        );
    }

    #[test]
    fn projection_json_has_sensorthings_shapes() {
        let s = sample(7, 42, 1_754_006_400_000_000_000, 21.5);
        let bundle = project_sample(&s);
        let json = serde_json::to_string(&bundle).unwrap();
        assert!(json.contains("\"@iot.id\""));
        assert!(json.contains("\"phenomenonTime\":\"2025-08-01T00:00:00.000Z\""));
        assert!(json.contains("\"resultTime\""));
        assert!(json.contains("\"result\":21.5"));
        assert!(json.contains("\"resultQuality\""));
        assert!(json.contains("\"unitOfMeasurement\""));
        assert!(json.contains("\"encodingType\":\"application/geo+json\""));
        // Sensor metadata is a firmware hash string, not PDF content.
        assert!(json.contains("\"encodingType\":\"text/plain\""));
        assert!(!json.contains("application/pdf"));
        // Mandatory-per-spec fields are present.
        assert!(json.contains(
            "\"observationType\":\
             \"http://www.opengis.net/def/observationType/OGC-OM/2.0/OM_Measurement\""
        ));
        assert!(json.contains("\"description\""));
        assert!(json.contains("\"type\":\"Point\""));
        // Round trips.
        let back: SensorThingsBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, back);
    }

    #[test]
    fn mandatory_descriptions_are_nonempty() {
        let b = project_sample(&sample(7, 42, 1_000, 21.5));
        assert!(!b.thing.description.is_empty());
        assert!(!b.sensor.description.is_empty());
        assert!(!b.observed_property.description.is_empty());
        assert!(!b.datastream.description.is_empty());
        assert_eq!(b.datastream.observation_type, OM_MEASUREMENT);
        assert_eq!(b.sensor.encoding_type, "text/plain");
    }

    #[test]
    fn ids_are_stable_and_linked() {
        let s = sample(7, 42, 1_000, 21.5);
        let b1 = project_sample(&s);
        let b2 = project_sample(&s);
        assert_eq!(b1, b2); // deterministic

        assert_eq!(b1.thing.iot_id, "thing:node:7");
        assert_eq!(b1.location.iot_id, "location:node:7");
        assert_eq!(b1.sensor.iot_id, "sensor:node:7:weather");
        assert_eq!(
            b1.observed_property.iot_id,
            "observedproperty:air_temperature"
        );
        assert_eq!(b1.datastream.iot_id, "datastream:7:air_temperature");
        assert_eq!(b1.observation.iot_id, "obs:7:42");
        assert_eq!(b1.feature_of_interest.iot_id, "foi:node:7");

        // Entity linkage is consistent.
        assert_eq!(b1.datastream.thing_id, b1.thing.iot_id);
        assert_eq!(b1.datastream.sensor_id, b1.sensor.iot_id);
        assert_eq!(
            b1.datastream.observed_property_id,
            b1.observed_property.iot_id
        );
        assert_eq!(b1.observation.datastream_id, b1.datastream.iot_id);

        // Unit and firmware metadata carried through.
        assert_eq!(b1.datastream.unit_of_measurement.symbol, "Cel");
        assert_eq!(b1.sensor.metadata, "sha256:fw-test");
    }

    #[test]
    fn geojson_axis_order_is_lon_lat() {
        let s = sample(7, 1, 1_000, 21.5);
        let b = project_sample(&s);
        let [lon, lat] = b.location.location.coordinates;
        assert!((lon - s.geo.longitude_deg()).abs() < 1e-12);
        assert!((lat - s.geo.latitude_deg()).abs() < 1e-12);
        assert_eq!(b.feature_of_interest.feature, b.location.location);
    }
}
