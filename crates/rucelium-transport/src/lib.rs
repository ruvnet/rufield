//! # rucelium-transport
//!
//! Constrained-link transport for the RuCelium fabric: a compact signed
//! envelope and an MTU fragmentation layer (companion to the ADR-264 §11
//! ABI boundary).
//!
//! ## Motivation: the LoRaWAN DR0 budget
//!
//! The v1 signed envelope ([`rucelium_abi::SignedEnvRecordV1`], deterministic
//! CBOR `[payload, pubkey, signature]`) encodes to **151 bytes** — but
//! LoRaWAN DR0 caps the application payload at **51 bytes** per datagram.
//! Two fixes, composable:
//!
//! - **(a) Compact envelope v2** ([`envelope`]): drop the 32-byte pubkey from
//!   the wire — the gateway already holds the device registry keyed by the
//!   `node_id` inside the 48-byte payload, so the key travels *by reference*.
//!   A packed 2-byte header replaces the CBOR framing:
//!   `2 + 48 + 64 = 114` bytes vs v1's 151.
//! - **(b) Fragmentation** ([`frag`]): 114 bytes still exceeds one DR0
//!   datagram, so a 6-byte-header fragment/reassembly layer splits any
//!   message across up to 255 datagrams. A compact envelope at the DR0 MTU
//!   is exactly **3 frames** ([`frag::fragment_compact`]).
//!
//! Rehydration via [`envelope::to_v1`] turns a verified compact envelope back
//! into a [`rucelium_abi::SignedEnvRecordV1`], so the existing ingest
//! pipeline downstream of the gateway is unchanged.
//!
//! The arithmetic, pinned:
//!
//! ```
//! use rucelium_abi::SignedEnvRecordV1;
//! use rucelium_transport::{COMPACT_ENV_V2_LEN, LORAWAN_DR0_MTU};
//!
//! let v1 = SignedEnvRecordV1 { payload: [0; 48], pubkey: [0; 32], signature: [0; 64] };
//! assert_eq!(v1.encode().len(), 151); // v1: CBOR framing + embedded pubkey
//! assert_eq!(COMPACT_ENV_V2_LEN, 2 + 48 + 64); // v2: 114 bytes
//! // ...but 114 still exceeds one DR0 datagram — hence the frag layer.
//! assert!(COMPACT_ENV_V2_LEN > LORAWAN_DR0_MTU);
//! ```
//!
//! Everything here is deterministic (callers pass `now_ns`), allocation-light,
//! bounds-checked, and free of `unsafe` and panics on untrusted input.

#![doc(html_root_url = "https://docs.rs/rucelium-transport/0.1.0")]

pub mod envelope;
pub mod frag;

pub use envelope::{
    sign_compact, to_v1, verify_compact, CompactEnvV2, COMPACT_ENV_MAGIC, COMPACT_ENV_V2_LEN,
    COMPACT_ENV_VERSION,
};
pub use frag::{
    fragment, fragment_compact, Fragment, Reassembler, FRAG_HEADER_LEN, FRAG_MAGIC, FRAG_VERSION,
    LORAWAN_DR0_MTU,
};

use std::fmt;

/// Errors raised by the transport layer. Every failure is a rejection — the
/// transport never repairs or guesses (same posture as the ABI boundary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// A buffer had the wrong length for the structure being parsed.
    WrongLength {
        /// Expected length in bytes (for fragments: the minimum).
        expected: usize,
        /// Actual length received.
        actual: usize,
    },
    /// The leading magic byte did not match.
    BadMagic(u8),
    /// The version byte did not match.
    BadVersion(u8),
    /// The public key bytes were not a valid ed25519 point.
    BadKey,
    /// The ed25519 signature did not verify over the payload.
    BadSignature,
    /// The requested MTU cannot carry a fragment header plus one chunk byte.
    MtuTooSmall(usize),
    /// The message does not fit in 255 fragments at the requested MTU.
    TooLarge {
        /// Message length in bytes.
        len: usize,
        /// Maximum message length at this MTU.
        max: usize,
    },
    /// A fragment header was structurally invalid.
    BadFragment(String),
    /// Fragments for the same `(from, msg_id)` disagreed about the message
    /// shape; the pending entry was dropped.
    Inconsistent,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::WrongLength { expected, actual } => {
                write!(f, "wrong length: expected {expected} bytes, got {actual}")
            }
            TransportError::BadMagic(b) => write!(f, "bad magic byte {b:#04x}"),
            TransportError::BadVersion(v) => write!(f, "bad version byte {v}"),
            TransportError::BadKey => write!(f, "invalid ed25519 public key"),
            TransportError::BadSignature => write!(f, "signature verification failed"),
            TransportError::MtuTooSmall(mtu) => {
                write!(f, "mtu {mtu} too small: need header plus one chunk byte")
            }
            TransportError::TooLarge { len, max } => {
                write!(
                    f,
                    "message of {len} bytes exceeds {max}-byte fragment limit"
                )
            }
            TransportError::BadFragment(m) => write!(f, "bad fragment: {m}"),
            TransportError::Inconsistent => {
                write!(
                    f,
                    "inconsistent fragments for message; pending entry dropped"
                )
            }
        }
    }
}

impl std::error::Error for TransportError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_is_informative() {
        let cases: Vec<(TransportError, &str)> = vec![
            (
                TransportError::WrongLength {
                    expected: 114,
                    actual: 3,
                },
                "expected 114",
            ),
            (TransportError::BadMagic(0x00), "0x00"),
            (TransportError::BadVersion(9), "9"),
            (TransportError::BadKey, "public key"),
            (TransportError::BadSignature, "verification failed"),
            (TransportError::MtuTooSmall(6), "6"),
            (TransportError::TooLarge { len: 999, max: 45 }, "999"),
            (TransportError::BadFragment("x".to_string()), "x"),
            (TransportError::Inconsistent, "inconsistent"),
        ];
        for (err, needle) in cases {
            let s = err.to_string();
            assert!(s.contains(needle), "{s:?} should contain {needle:?}");
        }
    }
}
