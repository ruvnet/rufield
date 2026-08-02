//! `rv_env_sample_v1`: packed little-endian wire struct, bounds-checked
//! allocation-free parse, field validation, and domain conversion
//! (ADR-264 §11.1).

use core::fmt;
#[cfg(feature = "std")]
use rucelium_core::{EnvSample, GeoPoint, SampleProvenance, SensorModality, Uncertainty};

/// Maximum valid latitude in 1e-7 degree units. Defined locally so the wire
/// layer stays `no_std`; a std-only test pins it to `rucelium_core::geo`.
pub const LAT_E7_MAX: i32 = 900_000_000;
/// Maximum valid longitude in 1e-7 degree units (see [`LAT_E7_MAX`]).
pub const LON_E7_MAX: i32 = 1_800_000_000;
/// Highest valid `sensor_type` wire code. Pinned to
/// `rucelium_core::SensorModality::ALL` by a std-only test.
pub const SENSOR_TYPE_MAX: u8 = 9;

/// Wire schema version 1.
pub const RV_ENV_SCHEMA_V1: u8 = 1;

/// Exact serialized length of `rv_env_sample_v1` (packed, little-endian).
pub const RV_ENV_SAMPLE_V1_WIRE_LEN: usize = 48;

/// Flags bit 0: ring-buffer retransmit after an outage (store-and-forward
/// recovery, distinct from a replay attack — the sequence window still
/// deduplicates either way).
pub const RV_ENV_FLAG_RETRANSMIT: u16 = 1;

/// Maximum `quality_q15` value (Q0.15 encoding of 1.0).
pub const Q15_ONE: u16 = 0x8000;

/// One Q16.16 unit.
const Q16_ONE_F64: f64 = 65_536.0;

/// Errors raised at the ABI boundary. Every failure is a rejection — the
/// boundary never repairs or guesses (ADR-264 §11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbiError {
    /// The byte slice was not exactly 48 bytes.
    WrongLength {
        /// Expected length (48).
        expected: usize,
        /// Actual length received.
        actual: usize,
    },
    /// Unknown schema version.
    BadSchemaVersion(u8),
    /// Unknown sensor modality code.
    UnknownModality(u8),
    /// Latitude/longitude outside valid range.
    GeoOutOfRange(&'static str, i32),
    /// `quality_q15` above `Q15_ONE`.
    QualityOutOfRange(u16),
    /// Zero measurement timestamp.
    ZeroTimestamp,
    /// Domain validation failed after conversion (std only — conversion into
    /// the domain model requires `rucelium-core`).
    #[cfg(feature = "std")]
    Domain(String),
}

impl fmt::Display for AbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AbiError::WrongLength { expected, actual } => {
                write!(
                    f,
                    "wire record must be exactly {expected} bytes, got {actual}"
                )
            }
            AbiError::BadSchemaVersion(v) => write!(f, "unknown schema version {v}"),
            AbiError::UnknownModality(c) => write!(f, "unknown sensor modality code {c}"),
            AbiError::GeoOutOfRange(field, v) => write!(f, "{field} out of range: {v}"),
            AbiError::QualityOutOfRange(q) => {
                write!(f, "quality_q15 {q:#06x} above Q15 1.0 ({:#06x})", Q15_ONE)
            }
            AbiError::ZeroTimestamp => write!(f, "zero measurement timestamp"),
            #[cfg(feature = "std")]
            AbiError::Domain(m) => write!(f, "domain validation failed: {m}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AbiError {}

/// Rust mirror of the C `rv_env_sample_v1` struct (ADR-264 §11.1). `repr(C)`
/// documents the field contract; parsing never transmutes — it reads each
/// little-endian field from the byte slice after a single bounds check.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RvEnvSampleV1 {
    /// Must equal [`RV_ENV_SCHEMA_V1`].
    pub schema_version: u8,
    /// [`SensorModality`] wire code.
    pub sensor_type: u8,
    /// Flag bits ([`RV_ENV_FLAG_RETRANSMIT`], …).
    pub flags: u16,
    /// Device identity.
    pub node_id: u64,
    /// Measurement time, ns since Unix epoch.
    pub timestamp_ns: u64,
    /// Per-device monotonic sequence number.
    pub sequence: u32,
    /// Latitude, degrees × 1e7.
    pub latitude_e7: i32,
    /// Longitude, degrees × 1e7.
    pub longitude_e7: i32,
    /// Altitude, millimetres.
    pub altitude_mm: i32,
    /// Measurement value, Q16.16.
    pub value_q16: i32,
    /// Quality score, Q0.15 (`0x0000..=0x8000`).
    pub quality_q15: u16,
    /// Battery level, millivolts.
    pub battery_mv: u16,
    /// Applied calibration record id (0 = uncalibrated).
    pub calibration_id: u32,
}

// Little-endian field readers over a length-checked 48-byte slice. The
// `expect`s are unreachable: offsets are compile-time constants inside the
// checked length.
fn rd_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().expect("checked length"))
}
fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().expect("checked length"))
}
fn rd_i32(b: &[u8], off: usize) -> i32 {
    i32::from_le_bytes(b[off..off + 4].try_into().expect("checked length"))
}
fn rd_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().expect("checked length"))
}

impl RvEnvSampleV1 {
    /// Parse a packed little-endian wire record. Exactly one bounds check
    /// (the length), no allocation, no `unsafe`, no panics on any input.
    /// Parsing does **not** validate field semantics — call [`Self::validate`]
    /// (or [`Self::parse_validated`]) before trusting the contents.
    pub fn parse(bytes: &[u8]) -> Result<Self, AbiError> {
        if bytes.len() != RV_ENV_SAMPLE_V1_WIRE_LEN {
            return Err(AbiError::WrongLength {
                expected: RV_ENV_SAMPLE_V1_WIRE_LEN,
                actual: bytes.len(),
            });
        }
        Ok(RvEnvSampleV1 {
            schema_version: bytes[0],
            sensor_type: bytes[1],
            flags: rd_u16(bytes, 2),
            node_id: rd_u64(bytes, 4),
            timestamp_ns: rd_u64(bytes, 12),
            sequence: rd_u32(bytes, 20),
            latitude_e7: rd_i32(bytes, 24),
            longitude_e7: rd_i32(bytes, 28),
            altitude_mm: rd_i32(bytes, 32),
            value_q16: rd_i32(bytes, 36),
            quality_q15: rd_u16(bytes, 40),
            battery_mv: rd_u16(bytes, 42),
            calibration_id: rd_u32(bytes, 44),
        })
    }

    /// Parse and validate in one step — the form gateways use.
    pub fn parse_validated(bytes: &[u8]) -> Result<Self, AbiError> {
        let s = Self::parse(bytes)?;
        s.validate()?;
        Ok(s)
    }

    /// Serialize to the packed little-endian wire layout. Used by the
    /// synthetic spore-node simulator and by tests; real nodes serialize
    /// in C per `rucelium_env.h`.
    #[must_use]
    pub fn encode(&self) -> [u8; RV_ENV_SAMPLE_V1_WIRE_LEN] {
        let mut b = [0u8; RV_ENV_SAMPLE_V1_WIRE_LEN];
        b[0] = self.schema_version;
        b[1] = self.sensor_type;
        b[2..4].copy_from_slice(&self.flags.to_le_bytes());
        b[4..12].copy_from_slice(&self.node_id.to_le_bytes());
        b[12..20].copy_from_slice(&self.timestamp_ns.to_le_bytes());
        b[20..24].copy_from_slice(&self.sequence.to_le_bytes());
        b[24..28].copy_from_slice(&self.latitude_e7.to_le_bytes());
        b[28..32].copy_from_slice(&self.longitude_e7.to_le_bytes());
        b[32..36].copy_from_slice(&self.altitude_mm.to_le_bytes());
        b[36..40].copy_from_slice(&self.value_q16.to_le_bytes());
        b[40..42].copy_from_slice(&self.quality_q15.to_le_bytes());
        b[42..44].copy_from_slice(&self.battery_mv.to_le_bytes());
        b[44..48].copy_from_slice(&self.calibration_id.to_le_bytes());
        b
    }

    /// Validate every field before any domain conversion (ADR-264 §11.1:
    /// "every value is validated before conversion into the domain model").
    pub fn validate(&self) -> Result<(), AbiError> {
        if self.schema_version != RV_ENV_SCHEMA_V1 {
            return Err(AbiError::BadSchemaVersion(self.schema_version));
        }
        if self.sensor_type > SENSOR_TYPE_MAX {
            return Err(AbiError::UnknownModality(self.sensor_type));
        }
        if self.latitude_e7.abs() > LAT_E7_MAX {
            return Err(AbiError::GeoOutOfRange("latitude_e7", self.latitude_e7));
        }
        if self.longitude_e7.abs() > LON_E7_MAX {
            return Err(AbiError::GeoOutOfRange("longitude_e7", self.longitude_e7));
        }
        if self.quality_q15 > Q15_ONE {
            return Err(AbiError::QualityOutOfRange(self.quality_q15));
        }
        if self.timestamp_ns == 0 {
            return Err(AbiError::ZeroTimestamp);
        }
        Ok(())
    }

    /// The modality, if the code is known (std only — the registry lives in
    /// `rucelium-core`).
    #[cfg(feature = "std")]
    #[must_use]
    pub fn modality(&self) -> Option<SensorModality> {
        SensorModality::from_code(self.sensor_type)
    }

    /// Raw measurement value as `f64` (Q16.16 → float).
    #[must_use]
    pub fn value_f64(&self) -> f64 {
        f64::from(self.value_q16) / Q16_ONE_F64
    }

    /// Quality as `f32` (Q0.15 → float, `0x8000` ⇒ 1.0).
    #[must_use]
    pub fn quality_f32(&self) -> f32 {
        f32::from(self.quality_q15) / f32::from(Q15_ONE)
    }

    /// Convert a **validated** wire record into an *uncalibrated* domain
    /// [`EnvSample`] (std only — requires `rucelium-core`). The uncertainty starts at the Q16.16 quantization
    /// half-step; `rucelium-calibration` widens it with the calibration's
    /// stated uncertainty. Provenance identity comes from the verified wire
    /// envelope, supplied by the ingest pipeline.
    #[cfg(feature = "std")]
    pub fn to_env_sample(
        &self,
        received_ns: u64,
        firmware_hash: &str,
        signer_pubkey_hex: &str,
        verified: bool,
    ) -> Result<EnvSample, AbiError> {
        self.validate()?;
        let modality = self
            .modality()
            .ok_or(AbiError::UnknownModality(self.sensor_type))?;
        let (property, unit) = modality.default_property_unit();
        let value = self.value_f64();
        let sample = EnvSample {
            node_id: self.node_id,
            sequence: self.sequence,
            measured_ns: self.timestamp_ns,
            received_ns,
            geo: GeoPoint {
                latitude_e7: self.latitude_e7,
                longitude_e7: self.longitude_e7,
                altitude_mm: self.altitude_mm,
            },
            modality,
            observed_property: property.to_string(),
            unit: unit.to_string(),
            value,
            quality: self.quality_f32(),
            uncertainty: Uncertainty::symmetric(value, 0.5 / Q16_ONE_F64),
            calibration_id: self.calibration_id,
            flags: self.flags,
            battery_mv: self.battery_mv,
            provenance: SampleProvenance {
                firmware_hash: firmware_hash.to_string(),
                signer_pubkey_hex: signer_pubkey_hex.to_string(),
                verified,
                lineage: vec!["abi:rv_env_sample_v1".to_string()],
            },
        };
        sample
            .validate()
            .map_err(|e| AbiError::Domain(e.to_string()))?;
        Ok(sample)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn wire_sample() -> RvEnvSampleV1 {
        RvEnvSampleV1 {
            schema_version: RV_ENV_SCHEMA_V1,
            sensor_type: SensorModality::SoilMoisture.code(),
            flags: 0,
            node_id: 0xDEAD_BEEF_0000_0007,
            timestamp_ns: 1_754_000_000_000_000_000,
            sequence: 42,
            latitude_e7: 514_778_216,
            longitude_e7: -14_767,
            altitude_mm: 46_000,
            value_q16: 27 * 65_536 + 32_768, // 27.5 %VWC
            quality_q15: 0x7000,
            battery_mv: 3_612,
            calibration_id: 3,
        }
    }

    #[test]
    fn encode_parse_round_trip() {
        let s = wire_sample();
        let bytes = s.encode();
        assert_eq!(bytes.len(), RV_ENV_SAMPLE_V1_WIRE_LEN);
        let back = RvEnvSampleV1::parse_validated(&bytes).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn wrong_length_rejected() {
        let s = wire_sample().encode();
        assert!(matches!(
            RvEnvSampleV1::parse(&s[..47]),
            Err(AbiError::WrongLength {
                expected: 48,
                actual: 47
            })
        ));
        let mut long = s.to_vec();
        long.push(0);
        assert!(RvEnvSampleV1::parse(&long).is_err());
        assert!(RvEnvSampleV1::parse(&[]).is_err());
    }

    #[test]
    fn every_invalid_field_rejected() {
        let mut s = wire_sample();
        s.schema_version = 2;
        assert!(matches!(s.validate(), Err(AbiError::BadSchemaVersion(2))));

        let mut s = wire_sample();
        s.sensor_type = 10;
        assert!(matches!(s.validate(), Err(AbiError::UnknownModality(10))));

        let mut s = wire_sample();
        s.latitude_e7 = LAT_E7_MAX + 1;
        assert!(matches!(s.validate(), Err(AbiError::GeoOutOfRange(..))));

        let mut s = wire_sample();
        s.longitude_e7 = -(LON_E7_MAX + 1);
        assert!(matches!(s.validate(), Err(AbiError::GeoOutOfRange(..))));

        let mut s = wire_sample();
        s.quality_q15 = 0x8001;
        assert!(matches!(s.validate(), Err(AbiError::QualityOutOfRange(_))));

        let mut s = wire_sample();
        s.timestamp_ns = 0;
        assert!(matches!(s.validate(), Err(AbiError::ZeroTimestamp)));
    }

    #[test]
    fn fixed_point_conversions() {
        let s = wire_sample();
        assert!((s.value_f64() - 27.5).abs() < 1e-9);
        assert!((s.quality_f32() - 0.875).abs() < 1e-6);
    }

    #[test]
    fn domain_conversion_carries_all_twelve_attributes() {
        let s = wire_sample();
        let env = s
            .to_env_sample(s.timestamp_ns + 1_000_000, "sha256:fw", "aabb", true)
            .unwrap();
        env.validate().unwrap();
        assert_eq!(env.node_id, s.node_id);
        assert_eq!(env.sequence, 42);
        assert_eq!(env.observed_property, "soil_volumetric_water_content");
        assert_eq!(env.unit, "%");
        assert_eq!(env.calibration_id, 3);
        assert!(env.provenance.verified);
        assert_eq!(env.provenance.lineage, vec!["abi:rv_env_sample_v1"]);
        // Quantization uncertainty brackets the value.
        assert!(env.uncertainty.lower <= env.value && env.value <= env.uncertainty.upper);
    }

    #[test]
    fn local_constants_pin_the_core_registry() {
        // The no_std wire layer duplicates these so it can drop rucelium-core;
        // this std-only test keeps the copies honest.
        assert_eq!(LAT_E7_MAX, rucelium_core::geo::LAT_E7_MAX);
        assert_eq!(LON_E7_MAX, rucelium_core::geo::LON_E7_MAX);
        assert_eq!(
            usize::from(SENSOR_TYPE_MAX) + 1,
            SensorModality::ALL.len(),
            "SENSOR_TYPE_MAX must track the SensorModality registry"
        );
        assert!(SensorModality::from_code(SENSOR_TYPE_MAX).is_some());
        assert!(SensorModality::from_code(SENSOR_TYPE_MAX + 1).is_none());
    }

    #[test]
    fn parse_never_panics_on_arbitrary_bytes() {
        // Deterministic pseudo-fuzz over lengths and contents.
        let mut x: u64 = 0x1234_5678_9ABC_DEF0;
        for len in 0..96usize {
            let mut buf = vec![0u8; len];
            for b in &mut buf {
                x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                *b = (x >> 56) as u8;
            }
            let _ = RvEnvSampleV1::parse_validated(&buf); // must not panic
        }
    }
}
