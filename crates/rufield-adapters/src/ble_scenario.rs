//! Deterministic two-person crossing scenario for BLE and WiFi CSI fusion
//! contract tests.
//!
//! The scenario emits anonymous CSI tracks, enrolled RSSI identity evidence,
//! and coherent Channel Sounding respiration features. It also injects a
//! simultaneous conflicting-track claim and a late expired replay. Both are
//! retained only as adapter abstentions and never appear in the event stream.

use crate::ble::{
    derive_ble_pseudonym, BleAbstention, BleAdapterConfig, BleAnchorTrust,
    BleChannelSoundingAdapter, BleChannelSoundingSample, BleIdentityEvidenceAdapter,
    BleIdentitySample,
};
use rufield_core::{
    FieldAdapter, FieldAxis, FieldEvent, FieldTensor, GatewayEnvelopeProvenance, Modality,
    Observation, PrivacyClass, ProvenanceRef, PseudonymousId, SensorDescriptor,
};
use rufield_provenance::{sha256_hex, Signer};

/// Fixed base timestamp for the crossing scenario.
pub const CROSSING_BASE_TS_NS: u64 = 1_790_000_000_000_000_000;

/// Scenario tick period: 100 ms.
pub const CROSSING_TICK_NS: u64 = 100_000_000;

/// Complete scenario output. Only validated events are present in `events`;
/// policy failures are explicit in `identity_abstentions`.
#[derive(Debug, Clone, PartialEq)]
pub struct BleCrossingScenario {
    /// Time-ordered, validated CSI, RSSI evidence, and Channel Sounding events.
    pub events: Vec<FieldEvent>,
    /// Fail-closed identity decisions, including spoof and expiry cases.
    pub identity_abstentions: Vec<BleAbstention>,
    /// Pseudonym assigned to the first enrolled subject.
    pub subject_a: PseudonymousId,
    /// Pseudonym assigned to the second enrolled subject.
    pub subject_b: PseudonymousId,
}

/// Build the canonical deterministic crossing scenario.
#[must_use]
pub fn two_person_ble_crossing_scenario() -> BleCrossingScenario {
    let ephemeral_a = [0xa1; 8];
    let ephemeral_b = [0xb2; 8];
    let token_epoch = 42;
    let pseudonym_key = [0x19; 32];
    let subject_a = derive_ble_pseudonym(&pseudonym_key, &ephemeral_a, token_epoch);
    let subject_b = derive_ble_pseudonym(&pseudonym_key, &ephemeral_b, token_epoch);
    let signing_seed = [0x73; 32];
    let signer = Signer::from_seed(&signing_seed);
    let mut events = Vec::new();
    let mut identity_samples = Vec::new();
    let mut channel_samples = Vec::new();

    for tick in 0..5u64 {
        let timestamp_ns = CROSSING_BASE_TS_NS + tick * CROSSING_TICK_NS;
        let ax = tick as i32 - 2;
        let bx = 2 - tick as i32;
        events.push(csi_track_event(
            &signer,
            timestamp_ns,
            tick,
            "track_a",
            [ax, 0, 1],
        ));
        events.push(csi_track_event(
            &signer,
            timestamp_ns,
            tick,
            "track_b",
            [bx, 0, 1],
        ));

        identity_samples.push(identity_sample(
            timestamp_ns,
            ephemeral_a,
            token_epoch,
            u32::try_from(tick + 1).unwrap_or(u32::MAX),
            "track_a",
            [ax, 0, 1],
            -48 - i16::try_from(ax.abs()).unwrap_or(0) * 4,
            "enrollment_a",
        ));
        identity_samples.push(identity_sample(
            timestamp_ns,
            ephemeral_b,
            token_epoch,
            u32::try_from(tick + 1).unwrap_or(u32::MAX),
            "track_b",
            [bx, 0, 1],
            -50 - i16::try_from(bx.abs()).unwrap_or(0) * 4,
            "enrollment_b",
        ));

        channel_samples.extend(channel_procedure_steps(
            timestamp_ns,
            tick,
            0x0000_a001,
            0x0000_a100,
            0,
            "track_a",
            [ax, 0, 1],
            0.78,
            0.0,
        ));
        channel_samples.extend(channel_procedure_steps(
            timestamp_ns,
            tick,
            0x0000_b002,
            0x0000_b200,
            1,
            "track_b",
            [bx, 0, 1],
            0.66,
            0.7,
        ));

        // A cloned or mis-associated advertisement claims another live track
        // while the legitimate binding remains current. The identity adapter
        // must abstain rather than silently rebinding it.
        if tick == 2 {
            identity_samples.push(identity_sample(
                timestamp_ns,
                ephemeral_a,
                token_epoch,
                u32::try_from(tick + 2).unwrap_or(u32::MAX),
                "track_b",
                [bx, 0, 1],
                -35,
                "forged_binding",
            ));
        }
    }

    // Late replay delivered after the stream watermark has advanced. Its
    // requested TTL ended three ticks ago, so it must never become an event.
    let mut expired = identity_sample(
        CROSSING_BASE_TS_NS,
        ephemeral_a,
        token_epoch,
        1,
        "track_a",
        [-2, 0, 1],
        -42,
        "enrollment_a",
    );
    expired.ttl_ns = CROSSING_TICK_NS;
    identity_samples.push(expired);

    let common = BleAdapterConfig {
        device_id: "ble_sim_gateway".into(),
        vendor: "rufield_ble_sim".into(),
        placement: "crossing_zone_edge".into(),
        clock_domain: "sim_clock".into(),
        signer_seed: signing_seed,
        pseudonym_key,
        ..BleAdapterConfig::synthetic_fixture()
    };

    let mut identity_adapter = BleIdentityEvidenceAdapter::new(common.clone(), identity_samples)
        .expect("synthetic BLE identity configuration is valid");
    while let Some(event) = identity_adapter
        .next_event()
        .expect("deterministic identity scenario is structurally valid")
    {
        events.push(event);
    }
    let identity_abstentions = identity_adapter.abstentions().to_vec();

    let mut channel_adapter = BleChannelSoundingAdapter::new(common, channel_samples)
        .expect("synthetic BLE Channel Sounding configuration is valid");
    while let Some(event) = channel_adapter
        .next_event()
        .expect("deterministic Channel Sounding scenario is structurally valid")
    {
        events.push(event);
    }

    events.sort_by(|left, right| {
        left.timestamp_ns
            .cmp(&right.timestamp_ns)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });

    BleCrossingScenario {
        events,
        identity_abstentions,
        subject_a,
        subject_b,
    }
}

fn identity_sample(
    timestamp_ns: u64,
    ephemeral_id: [u8; 8],
    token_epoch: u64,
    sequence: u32,
    track_id: &str,
    space_cell: [i32; 3],
    rssi_dbm: i16,
    binding_receipt_id: &str,
) -> BleIdentitySample {
    BleIdentitySample {
        timestamp_ns,
        ephemeral_id,
        token_epoch,
        sequence,
        track_id: track_id.into(),
        zone_id: "crossing_zone".into(),
        space_cell: Some(space_cell),
        rssi_dbm,
        confidence: 0.91,
        ttl_ns: 350_000_000,
        trust: BleAnchorTrust::Enrolled {
            binding_receipt_id: binding_receipt_id.into(),
        },
    }
}

fn channel_procedure_steps(
    timestamp_ns: u64,
    tick: u64,
    source_id: u32,
    source_session_id: u32,
    source_lane: u32,
    track_id: &str,
    space_cell: [i32; 3],
    breathing_band: f32,
    phase_offset: f32,
) -> Vec<BleChannelSoundingSample> {
    let breath = ((tick as f32) * 0.17 + phase_offset).sin() * 0.025;
    (0..8u16)
        .map(|step_index| {
            let sequence = u32::try_from(tick)
                .unwrap_or(u32::MAX)
                .saturating_mul(16)
                .saturating_add(source_lane.saturating_mul(8))
                .saturating_add(u32::from(step_index))
                .saturating_add(1);
            let phase_rad = phase_offset + f32::from(step_index) * 0.21 + breath;
            BleChannelSoundingSample {
                timestamp_ns,
                source_id,
                source_session_id,
                procedure_id: u32::try_from(tick).unwrap_or(u32::MAX).saturating_add(1),
                declared_step_count: 8,
                step_index,
                channel_index: 4 + step_index * 3,
                companion_key_id: 3,
                companion_sequence: sequence,
                sample_age_us: 250 + u32::from(step_index),
                companion_timing_uncertainty_us: 18,
                gateway: GatewayEnvelopeProvenance {
                    node_id: 7,
                    key_id: 11,
                    boot_nonce: 0xaabb_ccdd_1020_3040,
                    sequence: 10_000u32.saturating_add(sequence),
                    received_at_boot_us: tick
                        .saturating_mul(100_000)
                        .saturating_add(u64::from(source_lane) * 1_000)
                        .saturating_add(u64::from(step_index) * 10),
                    timing_uncertainty_us: 30,
                },
                zone_id: "crossing_zone".into(),
                track_id: Some(track_id.into()),
                space_cell: Some(space_cell),
                phase_millirad: (phase_rad * 1_000.0).round() as i32,
                rtt_picoseconds: 75_000 + space_cell[0].abs() * 1_000,
                frequency_offset_hz: i32::from(step_index) * 25 - 75,
                quality_permille: 880,
                breathing_band,
                companion_firmware_hash: sha256_hex(b"external_ble_cs_companion_sim_v1"),
                calibration_id: "ble_cs_crossing_cal_v1".into(),
            }
        })
        .collect()
}

fn csi_track_event(
    signer: &Signer,
    timestamp_ns: u64,
    tick: u64,
    track_id: &str,
    space_cell: [i32; 3],
) -> FieldEvent {
    let range_m = 1.0 + f32::from(space_cell[0].abs() as i16) * 0.5;
    let values = vec![
        0.4 + tick as f32 * 0.01,
        0.5 + f32::from(space_cell[0] as i16) * 0.01,
        0.6,
        0.7,
    ];
    let raw_bytes: Vec<u8> = values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    let tensor = FieldTensor::new(
        timestamp_ns,
        Modality::WifiCsi,
        vec![FieldAxis::Frequency],
        vec![values.len()],
        values,
        0.90,
        0.03,
        Some("csi_crossing_cal_v1".into()),
        PrivacyClass::P0,
    )
    .expect("scenario CSI tensor is valid");
    let mut observation = Observation::occupancy(0.92, PrivacyClass::P2);
    observation.zone_id = Some("crossing_zone".into());
    observation.track_id = Some(track_id.into());
    observation.space_cell = Some(space_cell);
    observation.range_m = Some(range_m);
    observation.motion_vector = Some([if track_id == "track_a" { 1.0 } else { -1.0 }, 0.0, 0.0]);
    observation.features.insert("presence".into(), 0.92);
    observation.features.insert("motion_energy".into(), 0.58);
    observation.features.insert("range_m".into(), range_m);
    observation.features.insert("track_confidence".into(), 0.90);

    let mut event = FieldEvent::new(
        format!("csi-crossing-{track_id}-{timestamp_ns}"),
        timestamp_ns,
        SensorDescriptor {
            modality: Modality::WifiCsi.as_str().into(),
            vendor: "esp32_s3_sim".into(),
            device_id: "csi_sim_gateway".into(),
            placement: "crossing_zone_edge".into(),
            clock_domain: "sim_clock".into(),
        },
        tensor,
        observation,
        ProvenanceRef {
            raw_hash: sha256_hex(&raw_bytes),
            firmware_hash: sha256_hex(b"rufield_crossing_sim_v1"),
            model_id: "csi_anonymous_tracker_v1".into(),
            calibration_id: "csi_crossing_cal_v1".into(),
            synthetic: true,
            signature_hex: None,
            signer_pubkey_hex: None,
        },
    );
    signer
        .sign_event(&mut event)
        .expect("scenario CSI event signs");
    event
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BleAbstentionReason;
    use std::collections::BTreeSet;

    #[test]
    fn scenario_is_deterministic() {
        assert_eq!(
            two_person_ble_crossing_scenario(),
            two_person_ble_crossing_scenario()
        );
    }

    #[test]
    fn crossing_keeps_tracks_and_pseudonyms_separate() {
        let scenario = two_person_ble_crossing_scenario();
        let mut bindings = BTreeSet::new();
        for event in &scenario.events {
            if let Some(evidence) = &event.observation.identity_evidence {
                bindings.insert((evidence.pseudonym.clone(), evidence.track_id.clone()));
            }
        }
        assert_eq!(bindings.len(), 2);
        assert!(bindings.contains(&(scenario.subject_a.clone(), "track_a".into())));
        assert!(bindings.contains(&(scenario.subject_b.clone(), "track_b".into())));
    }

    #[test]
    fn scenario_contains_spoof_and_expiry_abstentions() {
        let scenario = two_person_ble_crossing_scenario();
        assert!(scenario
            .identity_abstentions
            .iter()
            .any(|item| item.reason == BleAbstentionReason::ConflictingTrack));
        assert!(scenario
            .identity_abstentions
            .iter()
            .any(|item| item.reason == BleAbstentionReason::Expired));
    }
}
