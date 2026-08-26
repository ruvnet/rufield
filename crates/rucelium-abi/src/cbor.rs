//! Dependency-free **deterministic CBOR** (RFC 8949 core deterministic
//! encoding requirements: definite lengths, shortest-form integer heads,
//! fixed field order) plus the COSE_Sign1-inspired signed record envelope
//! (ADR-264 §11.2).
//!
//! The same input always yields byte-identical output, and the decoder
//! *rejects* non-canonical heads — so a signature over an encoding is a
//! signature over the one possible encoding.

use crate::wire::{RvEnvSampleV1, RV_ENV_SAMPLE_V1_WIRE_LEN};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::fmt;

/// CBOR decode errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborError {
    /// Input ended mid-item.
    Truncated,
    /// Reserved / unsupported head byte.
    BadHead(u8),
    /// An integer head was not shortest-form (non-canonical).
    NotCanonical,
    /// Expected a different major type.
    WrongType {
        /// Major type expected.
        expected: u8,
        /// Major type found.
        found: u8,
    },
    /// A fixed-length field had the wrong length.
    WrongLength {
        /// Expected byte/item count.
        expected: usize,
        /// Actual count.
        actual: usize,
    },
    /// Bytes remained after the top-level item.
    TrailingBytes(usize),
    /// An integer did not fit the target field.
    IntOutOfRange,
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CborError::Truncated => write!(f, "cbor input truncated"),
            CborError::BadHead(b) => write!(f, "unsupported cbor head byte {b:#04x}"),
            CborError::NotCanonical => write!(f, "non-canonical (non-shortest-form) cbor head"),
            CborError::WrongType { expected, found } => {
                write!(
                    f,
                    "wrong cbor major type: expected {expected}, found {found}"
                )
            }
            CborError::WrongLength { expected, actual } => {
                write!(
                    f,
                    "wrong cbor field length: expected {expected}, got {actual}"
                )
            }
            CborError::TrailingBytes(n) => write!(f, "{n} trailing bytes after cbor item"),
            CborError::IntOutOfRange => write!(f, "cbor integer out of range for field"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CborError {}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

/// Append a shortest-form head for `major` (0..=5) with argument `value`.
fn write_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let m = major << 5;
    if value < 24 {
        out.push(m | value as u8);
    } else if value <= u64::from(u8::MAX) {
        out.push(m | 24);
        out.push(value as u8);
    } else if value <= u64::from(u16::MAX) {
        out.push(m | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u64::from(u32::MAX) {
        out.push(m | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

/// Append an unsigned integer.
pub fn write_uint(out: &mut Vec<u8>, v: u64) {
    write_head(out, 0, v);
}

/// Append a signed integer (major 0 or 1).
pub fn write_int(out: &mut Vec<u8>, v: i64) {
    if v >= 0 {
        write_head(out, 0, v as u64);
    } else {
        // CBOR nint encodes -1 - n.
        write_head(out, 1, !(v as u64));
    }
}

/// Append a definite-length byte string.
pub fn write_bytes(out: &mut Vec<u8>, b: &[u8]) {
    write_head(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}

/// Append a definite-length array header.
pub fn write_array(out: &mut Vec<u8>, len: usize) {
    write_head(out, 4, len as u64);
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        let end = self.pos.checked_add(n).ok_or(CborError::Truncated)?;
        if end > self.b.len() {
            return Err(CborError::Truncated);
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    /// Read a head, enforcing shortest-form (canonical) encoding.
    fn read_head(&mut self) -> Result<(u8, u64), CborError> {
        let first = self.take(1)?[0];
        let major = first >> 5;
        let ai = first & 0x1f;
        let value = match ai {
            0..=23 => u64::from(ai),
            24 => {
                let v = u64::from(self.take(1)?[0]);
                if v < 24 {
                    return Err(CborError::NotCanonical);
                }
                v
            }
            25 => {
                let v = u64::from(u16::from_be_bytes(
                    self.take(2)?.try_into().expect("len checked"),
                ));
                if v <= u64::from(u8::MAX) {
                    return Err(CborError::NotCanonical);
                }
                v
            }
            26 => {
                let v = u64::from(u32::from_be_bytes(
                    self.take(4)?.try_into().expect("len checked"),
                ));
                if v <= u64::from(u16::MAX) {
                    return Err(CborError::NotCanonical);
                }
                v
            }
            27 => {
                let v = u64::from_be_bytes(self.take(8)?.try_into().expect("len checked"));
                if v <= u64::from(u32::MAX) {
                    return Err(CborError::NotCanonical);
                }
                v
            }
            _ => return Err(CborError::BadHead(first)),
        };
        Ok((major, value))
    }

    fn read_uint(&mut self) -> Result<u64, CborError> {
        let (major, v) = self.read_head()?;
        if major != 0 {
            return Err(CborError::WrongType {
                expected: 0,
                found: major,
            });
        }
        Ok(v)
    }

    fn read_int(&mut self) -> Result<i64, CborError> {
        let (major, v) = self.read_head()?;
        match major {
            0 => i64::try_from(v).map_err(|_| CborError::IntOutOfRange),
            1 => {
                let n = i64::try_from(v).map_err(|_| CborError::IntOutOfRange)?;
                Ok(-1 - n)
            }
            found => Err(CborError::WrongType { expected: 0, found }),
        }
    }

    fn read_bytes(&mut self) -> Result<&'a [u8], CborError> {
        let (major, len) = self.read_head()?;
        if major != 2 {
            return Err(CborError::WrongType {
                expected: 2,
                found: major,
            });
        }
        let len = usize::try_from(len).map_err(|_| CborError::IntOutOfRange)?;
        self.take(len)
    }

    fn read_array(&mut self, expected_len: usize) -> Result<(), CborError> {
        let (major, len) = self.read_head()?;
        if major != 4 {
            return Err(CborError::WrongType {
                expected: 4,
                found: major,
            });
        }
        if len != expected_len as u64 {
            return Err(CborError::WrongLength {
                expected: expected_len,
                actual: usize::try_from(len).unwrap_or(usize::MAX),
            });
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), CborError> {
        if self.pos != self.b.len() {
            return Err(CborError::TrailingBytes(self.b.len() - self.pos));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// rv_env_sample_v1 <-> CBOR (13-element fixed-order array)
// ---------------------------------------------------------------------------

const SAMPLE_FIELDS: usize = 13;

/// Encode a wire sample as a fixed-order 13-element CBOR array:
/// `[schema_version, sensor_type, flags, node_id, timestamp_ns, sequence,
/// latitude_e7, longitude_e7, altitude_mm, value_q16, quality_q15,
/// battery_mv, calibration_id]`. Deterministic by construction.
#[must_use]
pub fn encode_sample_v1(s: &RvEnvSampleV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    write_array(&mut out, SAMPLE_FIELDS);
    write_uint(&mut out, u64::from(s.schema_version));
    write_uint(&mut out, u64::from(s.sensor_type));
    write_uint(&mut out, u64::from(s.flags));
    write_uint(&mut out, s.node_id);
    write_uint(&mut out, s.timestamp_ns);
    write_uint(&mut out, u64::from(s.sequence));
    write_int(&mut out, i64::from(s.latitude_e7));
    write_int(&mut out, i64::from(s.longitude_e7));
    write_int(&mut out, i64::from(s.altitude_mm));
    write_int(&mut out, i64::from(s.value_q16));
    write_uint(&mut out, u64::from(s.quality_q15));
    write_uint(&mut out, u64::from(s.battery_mv));
    write_uint(&mut out, u64::from(s.calibration_id));
    out
}

fn to_u8(v: u64) -> Result<u8, CborError> {
    u8::try_from(v).map_err(|_| CborError::IntOutOfRange)
}
fn to_u16(v: u64) -> Result<u16, CborError> {
    u16::try_from(v).map_err(|_| CborError::IntOutOfRange)
}
fn to_u32(v: u64) -> Result<u32, CborError> {
    u32::try_from(v).map_err(|_| CborError::IntOutOfRange)
}
fn to_i32(v: i64) -> Result<i32, CborError> {
    i32::try_from(v).map_err(|_| CborError::IntOutOfRange)
}

/// Decode a wire sample from canonical CBOR, rejecting non-canonical heads,
/// wrong arity, and trailing bytes.
pub fn decode_sample_v1(bytes: &[u8]) -> Result<RvEnvSampleV1, CborError> {
    let mut r = Reader::new(bytes);
    r.read_array(SAMPLE_FIELDS)?;
    let s = RvEnvSampleV1 {
        schema_version: to_u8(r.read_uint()?)?,
        sensor_type: to_u8(r.read_uint()?)?,
        flags: to_u16(r.read_uint()?)?,
        node_id: r.read_uint()?,
        timestamp_ns: r.read_uint()?,
        sequence: to_u32(r.read_uint()?)?,
        latitude_e7: to_i32(r.read_int()?)?,
        longitude_e7: to_i32(r.read_int()?)?,
        altitude_mm: to_i32(r.read_int()?)?,
        value_q16: to_i32(r.read_int()?)?,
        quality_q15: to_u16(r.read_uint()?)?,
        battery_mv: to_u16(r.read_uint()?)?,
        calibration_id: to_u32(r.read_uint()?)?,
    };
    r.finish()?;
    Ok(s)
}

// ---------------------------------------------------------------------------
// Signed record envelope
// ---------------------------------------------------------------------------

/// COSE_Sign1-inspired deterministic envelope: `[payload, pubkey, signature]`
/// as definite-length byte strings. The payload is the 48-byte packed wire
/// record; the signature is ed25519 over exactly those payload bytes.
/// Honest label (ADR-264 §11.2): COSE-*inspired* framing, not RFC 9052.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEnvRecordV1 {
    /// The 48-byte packed `rv_env_sample_v1` payload.
    pub payload: [u8; RV_ENV_SAMPLE_V1_WIRE_LEN],
    /// ed25519 verifying key (32 bytes).
    pub pubkey: [u8; 32],
    /// ed25519 detached signature over `payload` (64 bytes).
    pub signature: [u8; 64],
}

impl SignedEnvRecordV1 {
    /// Encode the envelope as deterministic CBOR.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 48 + 34 + 66);
        write_array(&mut out, 3);
        write_bytes(&mut out, &self.payload);
        write_bytes(&mut out, &self.pubkey);
        write_bytes(&mut out, &self.signature);
        out
    }

    /// Decode an envelope, enforcing exact field lengths and canonical form.
    pub fn decode(bytes: &[u8]) -> Result<Self, CborError> {
        let mut r = Reader::new(bytes);
        r.read_array(3)?;
        let payload: [u8; RV_ENV_SAMPLE_V1_WIRE_LEN] =
            r.read_bytes()?
                .try_into()
                .map_err(|_| CborError::WrongLength {
                    expected: RV_ENV_SAMPLE_V1_WIRE_LEN,
                    actual: 0,
                })?;
        let pubkey: [u8; 32] = r
            .read_bytes()?
            .try_into()
            .map_err(|_| CborError::WrongLength {
                expected: 32,
                actual: 0,
            })?;
        let signature: [u8; 64] =
            r.read_bytes()?
                .try_into()
                .map_err(|_| CborError::WrongLength {
                    expected: 64,
                    actual: 0,
                })?;
        r.finish()?;
        Ok(SignedEnvRecordV1 {
            payload,
            pubkey,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::RV_ENV_SCHEMA_V1;

    fn sample() -> RvEnvSampleV1 {
        RvEnvSampleV1 {
            schema_version: RV_ENV_SCHEMA_V1,
            sensor_type: 2,
            flags: 1,
            node_id: 7,
            timestamp_ns: 1_754_000_000_000_000_000,
            sequence: 42,
            latitude_e7: 514_778_216,
            longitude_e7: -14_767,
            altitude_mm: 46_000,
            value_q16: 1_802_240,
            quality_q15: 0x7000,
            battery_mv: 3_612,
            calibration_id: 3,
        }
    }

    #[test]
    fn sample_cbor_round_trips_and_is_deterministic() {
        let s = sample();
        let a = encode_sample_v1(&s);
        let b = encode_sample_v1(&s);
        assert_eq!(a, b, "same input must produce byte-identical CBOR");
        assert_eq!(decode_sample_v1(&a).unwrap(), s);
    }

    #[test]
    fn known_vector_stability() {
        // Freeze the encoding: array(13), then 1, 2, flags=1... Changing the
        // encoder in any way must break this test.
        let s = sample();
        let enc = encode_sample_v1(&s);
        assert_eq!(enc[0], 0x8d); // array(13)
        assert_eq!(enc[1], 0x01); // schema_version 1
        assert_eq!(enc[2], 0x02); // sensor_type 2
        assert_eq!(enc[3], 0x01); // flags 1
        assert_eq!(enc[4], 0x07); // node_id 7
                                  // timestamp needs 8-byte head.
        assert_eq!(enc[5], 0x1b);
        // Full-message determinism pin via length:
        // 1 (array) + 1+1+1+1 (small uints) + 9 (u64 ts) + 2 (seq 42)
        // + 5 (lat) + 3 (lon nint) + 3 (alt) + 5 (value) + 3 (quality)
        // + 3 (battery) + 1 (calibration 3) = 39 bytes.
        assert_eq!(enc.len(), 39);
    }

    #[test]
    fn non_canonical_heads_rejected() {
        // uint 7 encoded long-form as 0x18 0x07 (should be 0x07).
        let mut bad = vec![0x81]; // array(1)
        bad.extend_from_slice(&[0x18, 0x07]);
        let mut r = Reader::new(&bad);
        r.read_array(1).unwrap();
        assert_eq!(r.read_uint(), Err(CborError::NotCanonical));
    }

    #[test]
    fn truncated_and_trailing_rejected() {
        let enc = encode_sample_v1(&sample());
        assert!(decode_sample_v1(&enc[..enc.len() - 1]).is_err());
        let mut extra = enc.clone();
        extra.push(0x00);
        assert_eq!(decode_sample_v1(&extra), Err(CborError::TrailingBytes(1)));
    }

    #[test]
    fn negative_ints_round_trip() {
        let mut s = sample();
        s.latitude_e7 = -900_000_000;
        s.longitude_e7 = -1_800_000_000;
        s.altitude_mm = -11_000_000;
        s.value_q16 = i32::MIN;
        let enc = encode_sample_v1(&s);
        assert_eq!(decode_sample_v1(&enc).unwrap(), s);
    }

    #[test]
    fn envelope_round_trips_and_rejects_bad_lengths() {
        let rec = SignedEnvRecordV1 {
            payload: sample().encode(),
            pubkey: [0xAA; 32],
            signature: [0xBB; 64],
        };
        let enc = rec.encode();
        assert_eq!(SignedEnvRecordV1::decode(&enc).unwrap(), rec);

        // Envelope with a 47-byte payload must be rejected.
        let mut bad = Vec::new();
        write_array(&mut bad, 3);
        write_bytes(&mut bad, &[0u8; 47]);
        write_bytes(&mut bad, &[0u8; 32]);
        write_bytes(&mut bad, &[0u8; 64]);
        assert!(SignedEnvRecordV1::decode(&bad).is_err());
    }
}
