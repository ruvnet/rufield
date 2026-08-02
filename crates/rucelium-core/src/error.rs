//! Core error type for RuCelium data-model validation (ADR-264 §7.1).

use std::fmt;

/// Errors raised by the core environmental data model.
#[derive(Debug, Clone, PartialEq)]
pub enum EnvError {
    /// A geospatial reference was outside valid latitude/longitude ranges.
    GeoOutOfRange {
        /// Which coordinate failed (`"latitude_e7"` / `"longitude_e7"`).
        field: &'static str,
        /// The offending fixed-point value.
        value: i64,
    },
    /// Quality score was outside `0.0..=1.0`.
    QualityOutOfRange(f32),
    /// The uncertainty interval did not bracket the value
    /// (`lower <= value <= upper` violated).
    UncertaintyInverted {
        /// Interval lower bound.
        lower: f64,
        /// Measured value.
        value: f64,
        /// Interval upper bound.
        upper: f64,
    },
    /// Reception time preceded measurement time.
    TimeInverted {
        /// Measurement time (ns since Unix epoch).
        measured_ns: u64,
        /// Reception time (ns since Unix epoch).
        received_ns: u64,
    },
    /// A required field (ADR-264 §7.1 twelve requirements) was empty.
    MissingField(&'static str),
    /// A generic validation failure with a message.
    Invalid(String),
}

impl fmt::Display for EnvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvError::GeoOutOfRange { field, value } => {
                write!(f, "geospatial reference out of range: {field} = {value}")
            }
            EnvError::QualityOutOfRange(q) => {
                write!(f, "quality score {q} outside 0.0..=1.0")
            }
            EnvError::UncertaintyInverted {
                lower,
                value,
                upper,
            } => write!(
                f,
                "uncertainty interval [{lower}, {upper}] does not bracket value {value}"
            ),
            EnvError::TimeInverted {
                measured_ns,
                received_ns,
            } => write!(
                f,
                "reception time {received_ns} precedes measurement time {measured_ns}"
            ),
            EnvError::MissingField(name) => write!(f, "missing required field: {name}"),
            EnvError::Invalid(m) => write!(f, "invalid environmental data: {m}"),
        }
    }
}

impl std::error::Error for EnvError {}
