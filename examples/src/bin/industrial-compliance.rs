//! # industrial-compliance — deployment wedge #3 (ADR-266 §3.1)
//!
//! Industrial environmental compliance is the wedge that **monetizes signed
//! provenance**: device identity, calibration lineage, location, quality, and
//! transformation lineage are not internal plumbing here, they *are* the
//! product. A regulator does not want a dashboard — a regulator wants an
//! evidence bundle they can check themselves, months later, without trusting
//! the operator, the gateway, or this program.
//!
//! So this example builds one exceedance at a plant's discharge point and
//! packages it as a **regulator-verifiable evidence bundle**:
//!
//! * the accepted observations (each with `provenance.verified`, the signer
//!   key, and the transformation lineage that produced the reported value),
//! * the **signed calibration lineage chain** resolving to a reference-grade
//!   anchor — held in a STRICT [`CalibrationStore`] where an anchor cannot be
//!   declared by writing a method string,
//! * the biome-signed [`EnvironmentalEvent`], whose signed `message` binds
//!   the consent limit, the calibration head, and a digest of the exact
//!   observations.
//!
//! Then it runs [`verify_bundle`] — an **independent verifier** that sees only
//! the bundle's JSON and the public keys a regulator would hold — and shows it
//! passing on the genuine bundle and failing on every field mutation tried.
//!
//! ```bash
//! cargo run  -p rucelium-examples --bin industrial-compliance
//! cargo test -p rucelium-examples --bin industrial-compliance
//! ```

use rucelium_abi::{NodeSigner, RvEnvSampleV1, RV_ENV_SCHEMA_V1};
use rucelium_calibration::{
    sha256_hex, verify_record_signature, AuthorityRegistry, CalibrationAuthority, CalibrationError,
    CalibrationSigner, CalibrationStore, Calibrator,
};
use rucelium_core::calibration::Q16_ONE;
use rucelium_core::{
    CalibrationRecord, EnvSample, EnvironmentalEvent, EventKind, EvidenceRef, GeoPoint,
    SensorModality, Severity, SPEC_VERSION,
};
use rucelium_examples::{banner, line, synthetic_footer, Gateway, Node, Rng, EPOCH_NS, NS_PER_S};
use rucelium_federation::{verify_event, AcceptOutcome, Biome, BiomeConfig};
use rucelium_ingest::RejectReason;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Site constants
// ---------------------------------------------------------------------------

/// The regulated site's biome.
pub const BIOME_ID: &str = "biome/tees-works-outfall";

/// Deterministic seed for the biome's federated identity key.
pub const BIOME_SEED: &[u8; 32] = b"rucelium-example-compliance-bio!";

/// Deterministic seed for the accredited chemistry laboratory's key.
pub const CONSENT_LAB_SEED: &[u8; 32] = b"rucelium-example-consent-lab-key";

/// Deterministic seed for the site metrology team's key.
pub const SITE_METROLOGY_SEED: &[u8; 32] = b"rucelium-example-site-metrology!";

/// Deterministic seed for a key nobody registered as an authority.
pub const ROGUE_AUTHORITY_SEED: &[u8; 32] = b"rucelium-example-rogue-authority";

/// Deterministic seed for an attacker's *device* key.
pub const ROGUE_DEVICE_SEED: &[u8; 32] = b"rucelium-example-rogue-device-k!";

/// Discharge consent limit for the regulated analyte, µmol/L.
pub const CONSENT_LIMIT_UMOL_L: f64 = 250.0;

/// Seconds between the three discharge grab samples (15 minutes).
pub const SAMPLE_INTERVAL_S: u64 = 900;

/// One day in nanoseconds.
pub const NS_PER_DAY: u64 = 86_400 * NS_PER_S;

// Node-table indices.
/// The consented discharge point.
pub const DISCHARGE: usize = 0;
/// Particulate-matter monitor at the site boundary.
pub const PM: usize = 1;
/// Noise monitor at the nearest receptor.
pub const NOISE: usize = 2;
/// Boundary-activity (optical) monitor.
pub const BOUNDARY: usize = 3;

/// The four plant monitors and their calibration identities.
const SPEC: [(u64, SensorModality, &str, f64, u32, u32); 4] = [
    (
        0x00C3_0000_0000_0001,
        SensorModality::Chemical,
        "discharge point DP-1 (consented outfall)",
        0.0,
        100,
        101,
    ),
    (
        0x00C3_0000_0000_0002,
        SensorModality::AirQuality,
        "PM-1 boundary particulate monitor",
        38.0,
        102,
        103,
    ),
    (
        0x00C3_0000_0000_0003,
        SensorModality::Acoustic,
        "NM-1 nearest-receptor noise monitor",
        0.62,
        104,
        105,
    ),
    (
        0x00C3_0000_0000_0004,
        SensorModality::Optical,
        "BA-1 boundary activity monitor",
        780.0,
        106,
        107,
    ),
];

/// The three raw discharge readings, µmol/L before calibration.
pub const DISCHARGE_RAW: [f64; 3] = [405.0, 418.0, 431.0];

// ---------------------------------------------------------------------------
// The evidence bundle and its independent verifier
// ---------------------------------------------------------------------------

/// A regulator-verifiable evidence bundle for one exceedance.
///
/// Everything a third party needs is inside: the observations, the signed
/// calibration lineage that produced their values, and the biome-signed event
/// that asserts the exceedance. Nothing in it has to be taken on trust —
/// [`verify_bundle`] re-derives every claim from the bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    /// Owning biome.
    pub biome_id: String,
    /// Every observation in the evidence window, post-calibration.
    pub observations: Vec<EnvSample>,
    /// The discharge point's calibration lineage, child first, anchor last.
    pub calibration_chain: Vec<CalibrationRecord>,
    /// The biome-signed exceedance event.
    pub event: EnvironmentalEvent,
}

/// What [`verify_bundle`] managed to prove from the bundle alone.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedClaim {
    /// Biome that signed the event.
    pub biome_id: String,
    /// Number of cited observations above the consent limit.
    pub exceedances: usize,
    /// The consent limit carried inside the signed message.
    pub limit: f64,
    /// The calibration record the cited observations were produced with.
    pub calibration_head: u32,
    /// The anchor the lineage chain resolves to.
    pub anchor_id: u32,
    /// The anchor's method (`factory` or `anchor_reference`).
    pub anchor_method: String,
}

/// Extract a `name=value` token from the event's signed message.
fn signed_field<'a>(message: &'a str, name: &str) -> Result<&'a str, String> {
    message
        .split(" | ")
        .find_map(|part| part.trim().strip_prefix(name))
        .ok_or_else(|| format!("signed message carries no `{name}` field"))
}

/// **The independent verifier.**
///
/// Takes only the serialized bundle and the public keys a regulator holds —
/// no access to this program's state, the gateway, or the operator — and
/// re-checks every signature and every binding:
///
/// 1. the event is signed by the trusted biome key and the signature verifies;
/// 2. the observations hash to the digest inside the *signed* message, so no
///    observation can be edited, added, or removed;
/// 3. every calibration record's signature verifies under a trusted
///    calibration authority;
/// 4. the lineage chain is parent-linked and terminates at an anchored root;
/// 5. every cited observation is verified at ingest, carries the chain head in
///    both `calibration_id` and its transformation lineage, and really does
///    exceed the consent limit named in the signed message.
///
/// Any failure returns `Err` with the reason. Nothing is repaired.
pub fn verify_bundle(
    bundle_json: &str,
    trusted_biome_pubkey_hex: &str,
    trusted_calibration_authorities: &[String],
) -> Result<VerifiedClaim, String> {
    let bundle: EvidenceBundle =
        serde_json::from_str(bundle_json).map_err(|e| format!("bundle does not parse: {e}"))?;

    // (1) Event authenticity.
    bundle
        .event
        .validate()
        .map_err(|e| format!("event is not structurally valid: {e}"))?;
    if bundle.event.signer_pubkey_hex.as_deref() != Some(trusted_biome_pubkey_hex) {
        return Err("event was not signed by the trusted biome key".to_string());
    }
    if !verify_event(&bundle.event) {
        return Err("event signature does not verify over its canonical bytes".to_string());
    }
    if bundle.event.biome_id != bundle.biome_id {
        return Err("bundle biome_id does not match the signed event".to_string());
    }

    // (2) The signed message binds limit, calibration head, and observations.
    let message = &bundle.event.message;
    let limit: f64 = signed_field(message, "limit=")?
        .parse()
        .map_err(|e| format!("signed limit is not a number: {e}"))?;
    let calibration_head: u32 = signed_field(message, "cal_head=")?
        .parse()
        .map_err(|e| format!("signed calibration head is not a number: {e}"))?;
    // Prefer the structured, signed field; fall back to the legacy
    // message-embedded digest for events minted before the schema gained it.
    let (signed_digest, observed_digest) = match bundle.event.evidence_digest.as_deref() {
        // Structured, signed, content-binding (rucelium_core::evidence_digest).
        Some(d) => (
            d.to_string(),
            rucelium_core::evidence_digest(&bundle.observations.iter().collect::<Vec<_>>()),
        ),
        // Legacy events that predate the schema field carried the digest
        // inside the signed message string.
        None => (
            signed_field(message, "obs_digest=")?.to_string(),
            sha256_hex(
                &serde_json::to_vec(&bundle.observations)
                    .map_err(|e| format!("observations do not serialize: {e}"))?,
            ),
        ),
    };
    if observed_digest != signed_digest {
        return Err(
            "observation digest mismatch: the observations are not the signed ones".to_string(),
        );
    }

    // (3) + (4) Calibration lineage: signed, trusted, parent-linked, anchored.
    if bundle.calibration_chain.is_empty() {
        return Err("bundle carries no calibration lineage".to_string());
    }
    for record in &bundle.calibration_chain {
        verify_record_signature(record)
            .map_err(|e| format!("calibration {} fails signature: {e}", record.calibration_id))?;
        let signer = record.signer_pubkey_hex.as_deref().unwrap_or_default();
        if !trusted_calibration_authorities.iter().any(|k| k == signer) {
            return Err(format!(
                "calibration {} signed by an untrusted authority",
                record.calibration_id
            ));
        }
    }
    if bundle.calibration_chain[0].calibration_id != calibration_head {
        return Err("lineage head does not match the signed calibration head".to_string());
    }
    for link in bundle.calibration_chain.windows(2) {
        if link[0].parent_id != Some(link[1].calibration_id) {
            return Err(format!(
                "lineage break: calibration {} does not point at {}",
                link[0].calibration_id, link[1].calibration_id
            ));
        }
    }
    let anchor = bundle
        .calibration_chain
        .last()
        .expect("chain is non-empty here");
    if anchor.parent_id.is_some() {
        return Err("lineage does not terminate: the root still has a parent".to_string());
    }
    if anchor.method != "factory" && anchor.method != "anchor_reference" {
        return Err(format!(
            "lineage root uses unanchored method `{}`",
            anchor.method
        ));
    }

    // (5) Every cited observation.
    let mut exceedances = 0usize;
    for cited in &bundle.event.evidence {
        let observation = bundle
            .observations
            .iter()
            .find(|o| o.node_id == cited.node_id && o.sequence == cited.sequence)
            .ok_or_else(|| {
                format!(
                    "event cites observation ({}, {}) that is not in the bundle",
                    cited.node_id, cited.sequence
                )
            })?;
        observation
            .validate()
            .map_err(|e| format!("cited observation is not valid: {e}"))?;
        if !observation.provenance.verified {
            return Err("cited observation was never verified at ingest".to_string());
        }
        if observation.calibration_id != calibration_head {
            return Err(
                "cited observation was not produced with the signed calibration".to_string(),
            );
        }
        let expected_lineage = format!("cal:{calibration_head}");
        if !observation.provenance.lineage.contains(&expected_lineage) {
            return Err("cited observation's lineage does not record the calibration".to_string());
        }
        if observation.value <= limit {
            return Err("cited observation does not exceed the consent limit".to_string());
        }
        exceedances += 1;
    }

    Ok(VerifiedClaim {
        biome_id: bundle.biome_id,
        exceedances,
        limit,
        calibration_head,
        anchor_id: anchor.calibration_id,
        anchor_method: anchor.method.clone(),
    })
}

// ---------------------------------------------------------------------------
// Building the bundle
// ---------------------------------------------------------------------------

/// Build a geo point, panicking on a coordinate the example itself got wrong.
fn geo(latitude_e7: i32, longitude_e7: i32, altitude_mm: i32) -> GeoPoint {
    GeoPoint::new(latitude_e7, longitude_e7, altitude_mm).expect("example coordinates are in range")
}

/// Provision the four plant monitors, in node-table order.
#[must_use]
pub fn provision() -> Vec<Node> {
    SPEC.iter()
        .enumerate()
        .map(|(i, (node_id, modality, label, _, _, _))| {
            Node::new(
                *node_id,
                *modality,
                geo(
                    546_000_000 + (i as i32) * 1_300,
                    -11_200_000 - (i as i32) * 900,
                    8_000,
                ),
                label,
            )
        })
        .collect()
}

/// An unsigned calibration record template.
fn record(
    calibration_id: u32,
    node_id: u64,
    modality: SensorModality,
    method: &str,
    parent_id: Option<u32>,
    created_ns: u64,
    expires_ns: u64,
    scale_q16: i32,
    offset_q16: i32,
) -> CalibrationRecord {
    CalibrationRecord {
        calibration_id,
        node_id,
        modality,
        method: method.to_string(),
        reference_station: Some("ukas-anchor-04".to_string()),
        parent_id,
        created_ns,
        expires_ns,
        scale_q16,
        offset_q16,
        uncertainty_q16: 6 * Q16_ONE,
        data_hash: sha256_hex(format!("calibration-source-data:{calibration_id}").as_bytes()),
        signature_hex: None,
        signer_pubkey_hex: None,
    }
}

/// An envelope signed by a key the gateway never provisioned.
fn forged_envelope(
    node_id: u64,
    modality: SensorModality,
    at: GeoPoint,
    value: f64,
    measured_ns: u64,
    sequence: u32,
) -> Vec<u8> {
    let wire = RvEnvSampleV1 {
        schema_version: RV_ENV_SCHEMA_V1,
        sensor_type: modality.code(),
        flags: 0,
        node_id,
        timestamp_ns: measured_ns,
        sequence,
        latitude_e7: at.latitude_e7,
        longitude_e7: at.longitude_e7,
        altitude_mm: at.altitude_mm,
        value_q16: (value * 65_536.0) as i32,
        quality_q15: 32_112,
        battery_mv: 3_600,
        calibration_id: 0,
    };
    NodeSigner::for_node(ROGUE_DEVICE_SEED, node_id)
        .sign_sample(&wire)
        .encode()
}

/// Everything one compliance run produced.
#[derive(Debug)]
pub struct ComplianceRun {
    /// The genuine evidence bundle.
    pub bundle: EvidenceBundle,
    /// Its serialized form — the only thing the verifier ever sees.
    pub bundle_json: String,
    /// The biome's federated public key (a regulator holds this).
    pub biome_pubkey_hex: String,
    /// Public keys of the registered calibration authorities.
    pub trusted_authorities: Vec<String>,
    /// The discharge point's verified lineage, child first.
    pub lineage: Vec<u32>,
    /// Why an unsigned calibration record was refused.
    pub unsigned_refusal: CalibrationError,
    /// Why a record signed by an unregistered key was refused.
    pub rogue_refusal: CalibrationError,
    /// Why a registered authority signing outside its modality scope was
    /// refused.
    pub out_of_scope_refusal: CalibrationError,
    /// Why an envelope signed with an unregistered device key was refused.
    pub forged_sensor_refusal: RejectReason,
    /// Observations the biome accepted.
    pub accepted: usize,
}

/// Run the exceedance and package the evidence.
///
/// # Panics
///
/// Panics if the scenario's own inputs are inconsistent (a signed envelope
/// that will not ingest, or a calibration the strict store refuses) — the
/// example is the specification of what must work.
#[must_use]
pub fn run_compliance() -> ComplianceRun {
    // --- calibration authorities -------------------------------------------
    let consent_lab = CalibrationSigner::from_seed(CONSENT_LAB_SEED);
    let site_metrology = CalibrationSigner::from_seed(SITE_METROLOGY_SEED);
    let rogue = CalibrationSigner::from_seed(ROGUE_AUTHORITY_SEED);

    let mut registry = AuthorityRegistry::new();
    registry.add(CalibrationAuthority {
        name: "UKAS-accredited discharge chemistry laboratory".to_string(),
        pubkey_hex: consent_lab.public_hex(),
        modalities: BTreeSet::from([SensorModality::Chemical]),
    });
    registry.add(CalibrationAuthority {
        name: "site metrology team".to_string(),
        pubkey_hex: site_metrology.public_hex(),
        modalities: BTreeSet::from([
            SensorModality::AirQuality,
            SensorModality::Acoustic,
            SensorModality::Optical,
        ]),
    });
    // STRICT mode: signatures required, signers checked per modality.
    let mut store = CalibrationStore::with_authorities(registry);

    for (i, (node_id, modality, _, _, anchor_id, child_id)) in SPEC.iter().enumerate() {
        let signer = if i == DISCHARGE {
            &consent_lab
        } else {
            &site_metrology
        };
        let mut anchor = record(
            *anchor_id,
            *node_id,
            *modality,
            "anchor_reference",
            None,
            EPOCH_NS - 90 * NS_PER_DAY,
            EPOCH_NS + 275 * NS_PER_DAY,
            Q16_ONE,
            0,
        );
        signer
            .sign_record(&mut anchor)
            .expect("record canonicalizes");
        store.insert(anchor).expect("signed anchor is accepted");

        let mut child = record(
            *child_id,
            *node_id,
            *modality,
            "colocation",
            Some(*anchor_id),
            EPOCH_NS - 7 * NS_PER_DAY,
            EPOCH_NS + 358 * NS_PER_DAY,
            66_847,   // ≈ 1.020
            -196_608, // -3.0
        );
        signer
            .sign_record(&mut child)
            .expect("record canonicalizes");
        store.insert(child).expect("signed child is accepted");
    }

    // What the strict store refuses. Each of these would silently succeed in a
    // permissive store — which is exactly why compliance evidence needs one.
    let unsigned_refusal = store
        .insert(record(
            900,
            SPEC[DISCHARGE].0,
            SensorModality::Chemical,
            "anchor_reference",
            None,
            EPOCH_NS,
            EPOCH_NS + NS_PER_DAY,
            Q16_ONE,
            0,
        ))
        .expect_err("an unsigned record must be refused");
    let rogue_refusal = {
        let mut forged = record(
            901,
            SPEC[DISCHARGE].0,
            SensorModality::Chemical,
            "anchor_reference",
            None,
            EPOCH_NS,
            EPOCH_NS + NS_PER_DAY,
            Q16_ONE,
            0,
        );
        rogue.sign_record(&mut forged).expect("canonicalizes");
        store
            .insert(forged)
            .expect_err("an unregistered signer must be refused")
    };
    let out_of_scope_refusal = {
        let mut wrong_scope = record(
            902,
            SPEC[DISCHARGE].0,
            SensorModality::Chemical,
            "anchor_reference",
            None,
            EPOCH_NS,
            EPOCH_NS + NS_PER_DAY,
            Q16_ONE,
            0,
        );
        site_metrology
            .sign_record(&mut wrong_scope)
            .expect("canonicalizes");
        store
            .insert(wrong_scope)
            .expect_err("an authority may not sign outside its modality scope")
    };

    // --- sensing ------------------------------------------------------------
    let mut nodes = provision();
    let mut gateway = Gateway::with_nodes(&nodes);
    let mut biome = Biome::new(BiomeConfig::new(BIOME_ID), BIOME_SEED);
    let calibrator = Calibrator::default();
    let mut rng = Rng::new(0x00C3_0FF1_0000_2026);
    let mut observations: Vec<EnvSample> = Vec::new();
    let mut cited: Vec<EvidenceRef> = Vec::new();
    let mut accepted = 0usize;

    for (k, raw_value) in DISCHARGE_RAW.iter().enumerate() {
        let measured = EPOCH_NS + (k as u64) * SAMPLE_INTERVAL_S * NS_PER_S;
        let raw = raw_value + rng.noise(0.4);
        let envelope = nodes[DISCHARGE].emit(raw, measured, SPEC[DISCHARGE].5);
        let mut sealed = gateway
            .ingest(&envelope, measured + 1_000_000)
            .expect("the plant's own signed envelope must ingest");
        // The calibration is a *transformation*: it is applied to the sealed
        // sample and recorded in `provenance.lineage`, never applied silently.
        sealed
            .modify(|s| calibrator.apply(&store, s, measured))
            .expect("calibrated sample still validates")
            .expect("the discharge calibration applies");
        let sample = sealed.sample().clone();
        cited.push(EvidenceRef {
            node_id: sample.node_id,
            sequence: sample.sequence,
        });
        observations.push(sample);
        assert_eq!(biome.accept(sealed), AcceptOutcome::Accepted);
        accepted += 1;
    }

    // Context monitors: one observation each, same calibration discipline.
    let context_ns = EPOCH_NS + 2 * SAMPLE_INTERVAL_S * NS_PER_S;
    for idx in [PM, NOISE, BOUNDARY] {
        let (_, _, _, truth, _, child_id) = SPEC[idx];
        let envelope = nodes[idx].emit(truth + rng.noise(0.05), context_ns, child_id);
        let mut sealed = gateway
            .ingest(&envelope, context_ns + 1_000_000)
            .expect("the plant's own signed envelope must ingest");
        sealed
            .modify(|s| calibrator.apply(&store, s, context_ns))
            .expect("calibrated sample still validates")
            .expect("the context calibration applies");
        observations.push(sealed.sample().clone());
        assert_eq!(biome.accept(sealed), AcceptOutcome::Accepted);
        accepted += 1;
    }

    // A tampering attempt on the sensor itself: same node id, attacker's key.
    let forged_sensor_refusal = gateway
        .ingest(
            &forged_envelope(
                SPEC[DISCHARGE].0,
                SensorModality::Chemical,
                nodes[DISCHARGE].geo,
                12.0, // "we were well inside consent, honest"
                context_ns + SAMPLE_INTERVAL_S * NS_PER_S,
                99,
            ),
            context_ns + SAMPLE_INTERVAL_S * NS_PER_S + 1_000_000,
        )
        .expect_err("an unregistered device key must be refused at ingest");

    // --- the signed event ---------------------------------------------------
    let calibration_head = SPEC[DISCHARGE].5;
    let lineage = store
        .verify_lineage(calibration_head)
        .expect("the discharge lineage resolves to an anchor");
    let digest = sha256_hex(&serde_json::to_vec(&observations).expect("observations serialize"));
    let mut event = EnvironmentalEvent {
        // The schema now binds observation CONTENT into the signature
        // (rucelium_core::evidence_digest). Previously this example had to
        // smuggle a digest through the signed `message` string because
        // EvidenceRef pins identity only — that gap is closed.
        evidence_digest: Some(rucelium_core::evidence_digest(
            &observations.iter().collect::<Vec<_>>(),
        )),
        spec_version: SPEC_VERSION.to_string(),
        event_id: "compliance:dp1-exceedance-2026-001".to_string(),
        biome_id: BIOME_ID.to_string(),
        kind: EventKind::ThresholdExceeded,
        severity: Severity::Warning,
        modality: SensorModality::Chemical,
        geo: nodes[DISCHARGE].geo,
        window_start_ns: observations[0].measured_ns,
        window_end_ns: context_ns,
        detected_ns: context_ns + NS_PER_S,
        evidence: cited,
        confidence: 0.99,
        message: format!(
            "discharge consent exceedance at DP-1 | limit={CONSENT_LIMIT_UMOL_L} \
             | cal_head={calibration_head} | obs_digest={digest}"
        ),
        signature_hex: None,
        signer_pubkey_hex: None,
    };
    event.validate().expect("the event is well-formed");
    biome.sign_event(&mut event);

    let bundle = EvidenceBundle {
        biome_id: BIOME_ID.to_string(),
        observations,
        calibration_chain: lineage
            .iter()
            .map(|id| store.get(*id).expect("chain member is stored").clone())
            .collect(),
        event,
    };
    let bundle_json = serde_json::to_string(&bundle).expect("bundle serializes");

    ComplianceRun {
        bundle,
        bundle_json,
        biome_pubkey_hex: biome.public_key_hex(),
        trusted_authorities: vec![consent_lab.public_hex(), site_metrology.public_hex()],
        lineage,
        unsigned_refusal,
        rogue_refusal,
        out_of_scope_refusal,
        forged_sensor_refusal,
        accepted,
    }
}

/// Re-serialize a bundle after applying `mutate`, so the verifier sees only
/// the altered bytes.
#[must_use]
pub fn mutated_json(bundle: &EvidenceBundle, mutate: impl FnOnce(&mut EvidenceBundle)) -> String {
    let mut copy = bundle.clone();
    mutate(&mut copy);
    serde_json::to_string(&copy).expect("bundle serializes")
}

/// A named field mutation applied to a bundle before re-verification.
pub type TamperCase = (&'static str, fn(&mut EvidenceBundle));

/// The field mutations a regulator's verifier must catch.
#[must_use]
pub fn tamper_cases() -> Vec<TamperCase> {
    vec![
        ("observation value edited down", |b| {
            b.observations[0].value = 12.0;
        }),
        ("calibration scale edited", |b| {
            b.calibration_chain[0].scale_q16 += 1;
        }),
        ("anchor method downgraded", |b| {
            b.calibration_chain[1].method = "self_declared".to_string();
        }),
        ("event severity downgraded", |b| {
            b.event.severity = Severity::Advisory;
        }),
        ("cited observation swapped out", |b| {
            b.event.evidence[0].sequence = 42;
        }),
        ("consent limit raised in the message", |b| {
            b.event.message = b.event.message.replace("limit=250", "limit=500");
        }),
        ("an observation removed from the bundle", |b| {
            b.observations.pop();
        }),
    ]
}

// ---------------------------------------------------------------------------
// Narrative
// ---------------------------------------------------------------------------

fn main() {
    banner(
        "INDUSTRIAL ENVIRONMENTAL COMPLIANCE — ADR-266 wedge #3",
        "one exceedance, packaged so a regulator can verify it without trusting us",
    );

    let run = run_compliance();

    println!("  Site monitors");
    for node in provision() {
        line(
            &format!("  {}", node.label),
            format!("{} / node {:#018x}", node.modality.as_str(), node.node_id),
        );
    }
    line("observations accepted by the biome", run.accepted);
    line("consent limit", format!("{CONSENT_LIMIT_UMOL_L} umol/L"));

    println!("\n  1. Calibration lineage — STRICT store, signatures required");
    line(
        "discharge lineage (child -> anchor)",
        format!("{:?}", run.lineage),
    );
    for record in &run.bundle.calibration_chain {
        line(
            &format!("  calibration {}", record.calibration_id),
            format!(
                "method={} parent={:?} signer={}…",
                record.method,
                record.parent_id,
                &record.signer_pubkey_hex.as_deref().unwrap_or("")[..16]
            ),
        );
    }
    line(
        "unsigned record",
        format!("REFUSED — {}", run.unsigned_refusal),
    );
    line(
        "record signed by an unregistered key",
        format!("REFUSED — {}", run.rogue_refusal),
    );
    line(
        "authority signing outside its modality",
        format!("REFUSED — {}", run.out_of_scope_refusal),
    );

    println!("\n  2. Transformation lineage on the evidence");
    let first = &run.bundle.observations[0];
    line(
        "cited observation",
        format!("node {:#018x} seq {}", first.node_id, first.sequence),
    );
    line(
        "reported value",
        format!("{:.2} {}", first.value, first.unit),
    );
    line(
        "uncertainty",
        format!("± {:.2}", first.uncertainty.width() / 2.0),
    );
    line("verified at ingest", first.provenance.verified);
    line("signer key", &first.provenance.signer_pubkey_hex);
    line(
        "provenance.lineage",
        format!("{:?}", first.provenance.lineage),
    );

    println!("\n  3. Sensor tampering (attacker's device key)");
    line(
        "forged envelope for node DP-1",
        format!("REJECTED at ingest — {}", run.forged_sensor_refusal),
    );

    println!("\n  4. Independent verification of the bundle");
    line(
        "bundle size",
        format!("{} bytes of JSON", run.bundle_json.len()),
    );
    match verify_bundle(
        &run.bundle_json,
        &run.biome_pubkey_hex,
        &run.trusted_authorities,
    ) {
        Ok(claim) => {
            line("verdict", "PASS");
            line(
                "proved",
                format!(
                    "{} observations above {} umol/L in biome {}",
                    claim.exceedances, claim.limit, claim.biome_id
                ),
            );
            line(
                "lineage",
                format!(
                    "calibration {} resolves to anchor {} ({})",
                    claim.calibration_head, claim.anchor_id, claim.anchor_method
                ),
            );
        }
        Err(why) => line("verdict", format!("FAIL — guarantee broken: {why}")),
    }

    println!("\n  5. The same verifier against tampered bundles");
    for (name, mutate) in tamper_cases() {
        let json = mutated_json(&run.bundle, mutate);
        let verdict = match verify_bundle(&json, &run.biome_pubkey_hex, &run.trusted_authorities) {
            Ok(_) => "PASS — guarantee broken".to_string(),
            Err(why) => format!("REJECTED — {why}"),
        };
        line(&format!("  {name}"), verdict);
    }
    let verdict = match verify_bundle(&run.bundle_json, &"00".repeat(32), &run.trusted_authorities)
    {
        Ok(_) => "PASS — guarantee broken".to_string(),
        Err(why) => format!("REJECTED — {why}"),
    };
    line("  verified against the wrong biome key", verdict);

    synthetic_footer(
        "Discharge chemistry is simulated; the calibration authority, lineage, \
         event signing, and the independent verifier are the production code.",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_genuine_bundle_verifies() {
        let run = run_compliance();
        let claim = verify_bundle(
            &run.bundle_json,
            &run.biome_pubkey_hex,
            &run.trusted_authorities,
        )
        .expect("the genuine bundle must verify");
        assert_eq!(claim.biome_id, BIOME_ID);
        assert_eq!(claim.exceedances, DISCHARGE_RAW.len());
        assert_eq!(claim.limit, CONSENT_LIMIT_UMOL_L);
        assert_eq!(claim.calibration_head, SPEC[DISCHARGE].5);
        assert_eq!(claim.anchor_id, SPEC[DISCHARGE].4);
        assert_eq!(claim.anchor_method, "anchor_reference");
    }

    #[test]
    fn every_field_mutation_breaks_verification() {
        let run = run_compliance();
        let cases = tamper_cases();
        assert!(cases.len() >= 3, "at least three distinct mutations");
        for (name, mutate) in cases {
            let json = mutated_json(&run.bundle, mutate);
            assert!(
                verify_bundle(&json, &run.biome_pubkey_hex, &run.trusted_authorities).is_err(),
                "mutation `{name}` must break verification"
            );
        }
    }

    #[test]
    fn verification_is_bound_to_the_trusted_keys() {
        let run = run_compliance();
        // Wrong biome key.
        assert!(
            verify_bundle(&run.bundle_json, &"00".repeat(32), &run.trusted_authorities).is_err()
        );
        // No trusted calibration authorities at all.
        assert!(verify_bundle(&run.bundle_json, &run.biome_pubkey_hex, &[]).is_err());
        // Garbage in, error out — never a panic.
        assert!(verify_bundle("{}", &run.biome_pubkey_hex, &run.trusted_authorities).is_err());
    }

    #[test]
    fn the_strict_store_refuses_unsigned_and_untrusted_records() {
        let run = run_compliance();
        assert_eq!(
            run.unsigned_refusal,
            CalibrationError::MissingSignature(900)
        );
        assert!(
            matches!(
                run.rogue_refusal,
                CalibrationError::UntrustedSigner { id: 901, .. }
            ),
            "got {:?}",
            run.rogue_refusal
        );
        // A registered authority is still refused outside its modality scope:
        // a method string can never declare an anchor.
        assert!(
            matches!(
                run.out_of_scope_refusal,
                CalibrationError::UntrustedSigner { id: 902, .. }
            ),
            "got {:?}",
            run.out_of_scope_refusal
        );
    }

    #[test]
    fn lineage_resolves_to_an_anchor_and_is_carried_on_the_sample() {
        let run = run_compliance();
        assert_eq!(run.lineage, vec![SPEC[DISCHARGE].5, SPEC[DISCHARGE].4]);
        let anchor = run
            .bundle
            .calibration_chain
            .last()
            .expect("chain is non-empty");
        assert_eq!(anchor.parent_id, None);
        assert_eq!(anchor.method, "anchor_reference");
        for observation in run.bundle.observations.iter().take(DISCHARGE_RAW.len()) {
            assert!(observation
                .provenance
                .lineage
                .contains(&format!("cal:{}", SPEC[DISCHARGE].5)));
            assert!(observation
                .provenance
                .lineage
                .contains(&"abi:rv_env_sample_v1".to_string()));
            assert!(observation.value > CONSENT_LIMIT_UMOL_L);
        }
    }

    #[test]
    fn an_unregistered_device_key_never_reaches_the_evidence() {
        let run = run_compliance();
        assert_eq!(
            run.forged_sensor_refusal,
            RejectReason::KeyMismatch(SPEC[DISCHARGE].0)
        );
        // The forged reading is nowhere in the bundle.
        assert!(!run
            .bundle
            .observations
            .iter()
            .any(|o| (o.value - 12.0).abs() < 1.0));
        assert_eq!(run.accepted, DISCHARGE_RAW.len() + 3);
    }
}
