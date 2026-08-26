//! # rucelium-abi
//!
//! The versioned C ABI boundary of the RuCelium fabric (ADR-264 §11).
//!
//! This crate is the Rust side of the ADR-096 posture: the C world (spore
//! nodes) produces a **packed, little-endian, 48-byte** `rv_env_sample_v1`
//! record (header of record: [`include/rucelium_env.h`]); this crate parses
//! it with **bounds-checked, allocation-free** field reads — the workspace
//! forbids `unsafe`, so no transmute ever happens — and validates every field
//! before conversion into the `rucelium-core` domain model.
//!
//! Above the fixed struct sits **deterministic CBOR** (definite lengths,
//! fixed field order, shortest-form integers) and a COSE_Sign1-*inspired*
//! signed envelope `[payload, pubkey, signature]` with real ed25519
//! signatures. Honest label: this is deterministic COSE-inspired framing,
//! not a full RFC 9052 implementation (stated follow-up in ADR-264 §11.2).
//!
//! [`include/rucelium_env.h`]:
//!     https://github.com/ruvnet/rufield/blob/main/crates/rucelium-abi/include/rucelium_env.h

#![doc(html_root_url = "https://docs.rs/rucelium-abi/0.1.0")]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod cbor;
#[cfg(feature = "std")]
pub mod sign;
pub mod wire;

#[cfg(feature = "alloc")]
pub use cbor::{CborError, SignedEnvRecordV1};
#[cfg(feature = "std")]
pub use sign::{sign_payload, verify_record, NodeSigner};
pub use wire::{
    AbiError, RvEnvSampleV1, RV_ENV_FLAG_RETRANSMIT, RV_ENV_SAMPLE_V1_WIRE_LEN, RV_ENV_SCHEMA_V1,
};
