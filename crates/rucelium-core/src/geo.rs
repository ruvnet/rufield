//! Geospatial references with fixed-point storage and privacy coarsening
//! (ADR-264 §6 / §11).

use crate::error::EnvError;
use serde::{Deserialize, Serialize};

/// Maximum valid latitude in 1e-7 degree units.
pub const LAT_E7_MAX: i32 = 900_000_000;
/// Maximum valid longitude in 1e-7 degree units.
pub const LON_E7_MAX: i32 = 1_800_000_000;

/// A geospatial reference in the fixed-point encoding the C ABI carries:
/// degrees × 1e7 and altitude in millimetres. Fixed point keeps spore nodes
/// float-free and makes coarsening exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GeoPoint {
    /// Latitude in 1e-7 degrees (`-900_000_000..=900_000_000`).
    pub latitude_e7: i32,
    /// Longitude in 1e-7 degrees (`-1_800_000_000..=1_800_000_000`).
    pub longitude_e7: i32,
    /// Altitude above the reference ellipsoid, millimetres.
    pub altitude_mm: i32,
}

impl GeoPoint {
    /// Construct and validate.
    pub fn new(latitude_e7: i32, longitude_e7: i32, altitude_mm: i32) -> Result<Self, EnvError> {
        let p = GeoPoint {
            latitude_e7,
            longitude_e7,
            altitude_mm,
        };
        p.validate()?;
        Ok(p)
    }

    /// Range-check both coordinates.
    pub fn validate(&self) -> Result<(), EnvError> {
        if self.latitude_e7.abs() > LAT_E7_MAX {
            return Err(EnvError::GeoOutOfRange {
                field: "latitude_e7",
                value: i64::from(self.latitude_e7),
            });
        }
        if self.longitude_e7.abs() > LON_E7_MAX {
            return Err(EnvError::GeoOutOfRange {
                field: "longitude_e7",
                value: i64::from(self.longitude_e7),
            });
        }
        Ok(())
    }

    /// Latitude in degrees.
    #[must_use]
    pub fn latitude_deg(&self) -> f64 {
        f64::from(self.latitude_e7) / 1e7
    }

    /// Longitude in degrees.
    #[must_use]
    pub fn longitude_deg(&self) -> f64 {
        f64::from(self.longitude_e7) / 1e7
    }

    /// Privacy coarsening for sensitive locations (ADR-264 §6): snap both
    /// coordinates to a grid of `keep_decimals` decimal degrees (0..=7).
    /// `keep_decimals = 2` ≈ 1.1 km cells; altitude is dropped to 0.
    /// Coarsening is exact integer arithmetic — no float round-trip.
    #[must_use]
    pub fn coarsen(&self, keep_decimals: u32) -> GeoPoint {
        let d = keep_decimals.min(7);
        let step = 10_i32.pow(7 - d);
        GeoPoint {
            latitude_e7: (self.latitude_e7.div_euclid(step)) * step,
            longitude_e7: (self.longitude_e7.div_euclid(step)) * step,
            altitude_mm: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_ranges_accepted_invalid_rejected() {
        assert!(GeoPoint::new(LAT_E7_MAX, LON_E7_MAX, -5_000).is_ok());
        assert!(GeoPoint::new(-LAT_E7_MAX, -LON_E7_MAX, 8_848_000).is_ok());
        assert!(matches!(
            GeoPoint::new(LAT_E7_MAX + 1, 0, 0),
            Err(EnvError::GeoOutOfRange {
                field: "latitude_e7",
                ..
            })
        ));
        assert!(matches!(
            GeoPoint::new(0, -(LON_E7_MAX + 1), 0),
            Err(EnvError::GeoOutOfRange {
                field: "longitude_e7",
                ..
            })
        ));
    }

    #[test]
    fn coarsen_snaps_to_grid_and_drops_altitude() {
        // 51.4778216°N, -0.0014767°E (Greenwich), altitude 46 m.
        let p = GeoPoint::new(514_778_216, -14_767, 46_000).unwrap();
        let c = p.coarsen(2);
        assert_eq!(c.latitude_e7, 514_700_000); // 51.47
        assert_eq!(c.longitude_e7, -100_000); // -0.01 (floor, exact grid)
        assert_eq!(c.altitude_mm, 0);
        // Coarsening is idempotent.
        assert_eq!(c.coarsen(2), c);
        // keep_decimals = 7 is the identity on coordinates.
        let full = p.coarsen(7);
        assert_eq!(full.latitude_e7, p.latitude_e7);
        assert_eq!(full.longitude_e7, p.longitude_e7);
    }

    #[test]
    fn degrees_conversion() {
        let p = GeoPoint::new(514_778_216, -14_767, 0).unwrap();
        assert!((p.latitude_deg() - 51.4778216).abs() < 1e-9);
        assert!((p.longitude_deg() + 0.0014767).abs() < 1e-9);
    }
}
