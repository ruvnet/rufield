//! Core error type for RuField MFS data-model validation.

use std::fmt;

/// Errors raised by the core data model (validation failures, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// `shape.product()` did not equal `values.len()`.
    ShapeMismatch {
        /// Element count implied by `shape`.
        expected: usize,
        /// Actual `values.len()`.
        actual: usize,
    },
    /// `axes.len()` did not equal `shape.len()`.
    AxisRankMismatch {
        /// Number of axes provided.
        axes: usize,
        /// Rank of the shape.
        rank: usize,
    },
    /// A generic validation failure with a message.
    Invalid(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::ShapeMismatch { expected, actual } => write!(
                f,
                "field tensor shape mismatch: shape implies {expected} values but got {actual}"
            ),
            CoreError::AxisRankMismatch { axes, rank } => write!(
                f,
                "field tensor axis/rank mismatch: {axes} axes for rank-{rank} shape"
            ),
            CoreError::Invalid(m) => write!(f, "invalid field data: {m}"),
        }
    }
}

impl std::error::Error for CoreError {}
