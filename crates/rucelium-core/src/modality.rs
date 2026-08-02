//! Sensor modality registry and the three-tier data-class model
//! (ADR-264 §5.2 / §10).

use serde::{Deserialize, Serialize};

/// Environmental sensor modalities (ADR-264 §5.2). Extends the ADR-139
/// WorldGraph modality set rather than creating a second registry: `WifiCsi`
/// is the RuView RF-context modality; the rest are physical environmental
/// sensors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorModality {
    /// RuView-compatible RF observation (contextual evidence, ADR-264 §8).
    WifiCsi,
    /// CO₂, volatile organic compounds, PM1 / PM2.5 / PM10.
    AirQuality,
    /// Soil moisture and conductivity.
    SoilMoisture,
    /// Water level, flow, and quality.
    WaterQuality,
    /// Acoustic biodiversity.
    Acoustic,
    /// Temperature, humidity, leaf wetness, rainfall.
    Weather,
    /// Mycelial bioelectric potential.
    Bioelectric,
    /// Ionizing radiation.
    Radiation,
    /// Light, UV, and infrared.
    Optical,
    /// Chemical concentration probes.
    Chemical,
}

impl SensorModality {
    /// All modalities in wire-code order.
    pub const ALL: [SensorModality; 10] = [
        SensorModality::WifiCsi,
        SensorModality::AirQuality,
        SensorModality::SoilMoisture,
        SensorModality::WaterQuality,
        SensorModality::Acoustic,
        SensorModality::Weather,
        SensorModality::Bioelectric,
        SensorModality::Radiation,
        SensorModality::Optical,
        SensorModality::Chemical,
    ];

    /// Stable `u8` wire code used by the C ABI (`rv_env_sample_v1.sensor_type`).
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            SensorModality::WifiCsi => 0,
            SensorModality::AirQuality => 1,
            SensorModality::SoilMoisture => 2,
            SensorModality::WaterQuality => 3,
            SensorModality::Acoustic => 4,
            SensorModality::Weather => 5,
            SensorModality::Bioelectric => 6,
            SensorModality::Radiation => 7,
            SensorModality::Optical => 8,
            SensorModality::Chemical => 9,
        }
    }

    /// Decode a wire code; `None` for unknown codes (reject, never guess).
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        SensorModality::ALL.get(code as usize).copied()
    }

    /// Stable string code (matches the serde representation).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SensorModality::WifiCsi => "wifi_csi",
            SensorModality::AirQuality => "air_quality",
            SensorModality::SoilMoisture => "soil_moisture",
            SensorModality::WaterQuality => "water_quality",
            SensorModality::Acoustic => "acoustic",
            SensorModality::Weather => "weather",
            SensorModality::Bioelectric => "bioelectric",
            SensorModality::Radiation => "radiation",
            SensorModality::Optical => "optical",
            SensorModality::Chemical => "chemical",
        }
    }

    /// Default observed property + UCUM unit for samples arriving over the
    /// C ABI, which carries only a modality code (ADR-264 §11). Gateways may
    /// override via device metadata; these are the registry defaults.
    #[must_use]
    pub fn default_property_unit(self) -> (&'static str, &'static str) {
        match self {
            SensorModality::WifiCsi => ("rf_channel_feature", "1"),
            SensorModality::AirQuality => ("pm2_5_mass_concentration", "ug/m3"),
            SensorModality::SoilMoisture => ("soil_volumetric_water_content", "%"),
            SensorModality::WaterQuality => ("water_level", "m"),
            SensorModality::Acoustic => ("acoustic_activity_index", "1"),
            SensorModality::Weather => ("air_temperature", "Cel"),
            SensorModality::Bioelectric => ("bioelectric_potential", "mV"),
            SensorModality::Radiation => ("ambient_dose_rate", "uSv/h"),
            SensorModality::Optical => ("illuminance", "lx"),
            SensorModality::Chemical => ("analyte_concentration", "umol/L"),
        }
    }
}

/// Where data of a given class is allowed to live (ADR-264 §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Residency {
    /// Never leaves the producing gateway.
    GatewayOnly,
    /// May move within the owning biome.
    Biome,
    /// May federate globally.
    Global,
}

/// The three data classes of the fabric's data economics (ADR-264 §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    /// Raw signal data (raw CSI, raw acoustic waveforms). Hours–days,
    /// gateway-local only.
    RawSignal,
    /// Derived features and model outputs. Weeks–months, biome-resident.
    DerivedFeature,
    /// Signed events and statistical aggregates. Years, globally federable.
    FederatedEvent,
}

const NS_PER_DAY: u64 = 86_400_000_000_000;

impl DataClass {
    /// Where this class is allowed to reside.
    #[must_use]
    pub fn residency(self) -> Residency {
        match self {
            DataClass::RawSignal => Residency::GatewayOnly,
            DataClass::DerivedFeature => Residency::Biome,
            DataClass::FederatedEvent => Residency::Global,
        }
    }

    /// Default retention in nanoseconds (biomes may tighten, never loosen
    /// residency; retention itself is biome policy — these are defaults).
    #[must_use]
    pub fn default_retention_ns(self) -> u64 {
        match self {
            DataClass::RawSignal => 2 * NS_PER_DAY,
            DataClass::DerivedFeature => 90 * NS_PER_DAY,
            DataClass::FederatedEvent => 3650 * NS_PER_DAY,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip() {
        for m in SensorModality::ALL {
            assert_eq!(SensorModality::from_code(m.code()), Some(m));
        }
        assert_eq!(SensorModality::from_code(10), None);
        assert_eq!(SensorModality::from_code(255), None);
    }

    #[test]
    fn serde_uses_snake_case() {
        let j = serde_json::to_string(&SensorModality::SoilMoisture).unwrap();
        assert_eq!(j, "\"soil_moisture\"");
        let back: SensorModality = serde_json::from_str("\"wifi_csi\"").unwrap();
        assert_eq!(back, SensorModality::WifiCsi);
    }

    #[test]
    fn raw_signal_never_leaves_gateway() {
        assert_eq!(DataClass::RawSignal.residency(), Residency::GatewayOnly);
        assert_eq!(DataClass::DerivedFeature.residency(), Residency::Biome);
        assert_eq!(DataClass::FederatedEvent.residency(), Residency::Global);
        // Retention ordering: raw << derived << federated.
        assert!(
            DataClass::RawSignal.default_retention_ns()
                < DataClass::DerivedFeature.default_retention_ns()
        );
        assert!(
            DataClass::DerivedFeature.default_retention_ns()
                < DataClass::FederatedEvent.default_retention_ns()
        );
    }
}
