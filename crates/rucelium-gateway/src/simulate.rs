//! **SYNTHETIC traffic generator** (ADR-265 §4, `--simulate N`).
//!
//! Spawns N make-believe spore nodes that sign *real* envelopes with real
//! per-node ed25519 keys and send them to the gateway's own UDP socket over
//! loopback — the full production pipeline is exercised with zero hardware.
//! Every value produced here is SYNTHETIC: a diurnal sine plus a small
//! deterministic wobble, with a periodic water-level spike so the alert path
//! demonstrably fires. Nothing here claims field-validated accuracy.

use crate::state::{now_ns, GatewayState};
use rucelium_abi::{sign_payload, NodeSigner, RvEnvSampleV1, RV_ENV_SCHEMA_V1};
use rucelium_core::{CalibrationRecord, SensorModality};
use rucelium_transport::{fragment_compact, CompactEnvV2};
use std::f64::consts::TAU;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Base node id for synthetic nodes (`0x5C` = "SC", spore-node class).
pub const SIM_NODE_ID_BASE: u64 = 0x5C00_0000_0000_0100;

/// Nanoseconds per day.
const NS_PER_DAY: u64 = 86_400_000_000_000;
/// Seconds per day.
const S_PER_DAY: f64 = 86_400.0;
/// Synthetic wire quality (Q0.15 ≈ 0.9).
const SIM_QUALITY_Q15: u16 = 0x7333;
/// Every this many ticks, one water node spikes over the alert threshold.
const SPIKE_EVERY_TICKS: u32 = 60;
/// Spiked water level (metres) — above the 1.6 m flood threshold.
const SPIKE_WATER_LEVEL_M: f64 = 1.8;

/// One synthetic node: identity, key, modality, calibration record id.
struct SimNode {
    /// Provisioned device id.
    node_id: u64,
    /// Round-robin physical modality (WifiCsi is skipped — it is the RF
    /// context modality, not a spore-node sensor).
    modality: SensorModality,
    /// The node's signing key.
    signer: NodeSigner,
    /// The node's colocation calibration record id.
    calibration_id: u32,
    /// Index (drives encoding rotation and value phase).
    index: usize,
    /// Whether this node produces the periodic alert spike.
    spiker: bool,
}

/// Derive the 32-byte synthetic provisioning seed from the numeric config
/// seed (deterministic; strength is irrelevant for synthetic keys).
fn provision_seed(seed: u64) -> [u8; 32] {
    let sb = seed.to_le_bytes();
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = sb[i % 8] ^ (i as u8).wrapping_mul(0x35) ^ 0x5C;
    }
    out
}

/// Baseline and diurnal amplitude per physical modality (in the modality's
/// default unit). Chosen to look plausible on a dashboard, nothing more.
fn profile(modality: SensorModality) -> (f64, f64) {
    match modality {
        SensorModality::AirQuality => (12.0, 4.0),
        SensorModality::SoilMoisture => (27.0, 3.0),
        SensorModality::WaterQuality => (1.0, 0.3),
        SensorModality::Acoustic => (0.5, 0.2),
        SensorModality::Weather => (16.0, 6.0),
        SensorModality::Bioelectric => (40.0, 10.0),
        SensorModality::Radiation => (0.10, 0.02),
        SensorModality::Optical => (400.0, 300.0),
        SensorModality::Chemical => (5.0, 1.0),
        // Never provisioned by the simulator.
        SensorModality::WifiCsi => (0.0, 0.0),
    }
}

/// SYNTHETIC value model: diurnal sine (phase-shifted per node) plus a small
/// deterministic wobble, with the periodic water spike for the spiker node.
fn sim_value(node: &SimNode, ts_ns: u64, tick: u32) -> f64 {
    if node.spiker && tick.is_multiple_of(SPIKE_EVERY_TICKS) {
        return SPIKE_WATER_LEVEL_M;
    }
    let (base, amp) = profile(node.modality);
    let day_frac = (ts_ns % NS_PER_DAY) as f64 / 1e9 / S_PER_DAY;
    let phase = node.index as f64 * 0.7;
    let wobble = 0.05 * amp * (f64::from(tick) * 0.9 + phase).sin();
    base + amp * (TAU * day_frac + phase).sin() + wobble
}

/// Provision `n` synthetic nodes into the gateway: register their keys,
/// insert identity calibration records (one anchor per physical modality,
/// one colocation child per node — the ADR-264 benchmark shape), and return
/// the node list.
async fn provision(state: &GatewayState, n: u32, seed: u64) -> Vec<SimNode> {
    let seed32 = provision_seed(seed);
    let now = now_ns();
    let created = now.saturating_sub(NS_PER_DAY);
    let expires = now.saturating_add(3650 * NS_PER_DAY);
    let mut inner = state.inner.lock().await;

    // Anchor records: ids 1..=9 by modality code (skip 0 = WifiCsi). The
    // store runs in STRICT mode, so every record is signed by the gateway's
    // calibration authority before insertion — an unsigned "anchor_reference"
    // root would be refused (ADR-264 §12 items 1–3).
    for m in SensorModality::ALL {
        if m == SensorModality::WifiCsi {
            continue;
        }
        let _ = inner.insert_signed_calibration(CalibrationRecord {
            calibration_id: u32::from(m.code()),
            node_id: 0, // the reference anchor station
            modality: m,
            method: "anchor_reference".into(),
            reference_station: Some(format!("anchor/{}", m.as_str())),
            parent_id: None,
            created_ns: created,
            expires_ns: expires,
            scale_q16: 65_536,
            offset_q16: 0,
            uncertainty_q16: 6_554, // ±0.1 in-unit
            data_hash: format!("sha256:sim-anchor-{}", m.as_str()),
            signature_hex: None,
            signer_pubkey_hex: None,
        });
    }

    let mut nodes = Vec::with_capacity(n as usize);
    let mut spiker_chosen = false;
    for i in 0..n as usize {
        let node_id = SIM_NODE_ID_BASE + i as u64;
        // Round-robin over the 9 physical modalities (codes 1..=9).
        let modality = SensorModality::ALL[1 + (i % 9)];
        let signer = NodeSigner::for_node(&seed32, node_id);
        inner.ingest.registry_mut().register(
            node_id,
            signer.public_key(),
            format!("sha256:sim-fw-{i}"),
        );
        let calibration_id = 1000 + i as u32;
        let _ = inner.insert_signed_calibration(CalibrationRecord {
            calibration_id,
            node_id,
            modality,
            method: "colocation".into(),
            reference_station: Some(format!("anchor/{}", modality.as_str())),
            parent_id: Some(u32::from(modality.code())),
            created_ns: created + 1,
            expires_ns: expires,
            scale_q16: 65_536, // identity: synthetic nodes left the factory true
            offset_q16: 0,
            uncertainty_q16: 19_661, // ±0.3 in-unit
            data_hash: format!("sha256:sim-colo-{node_id}"),
            signature_hex: None,
            signer_pubkey_hex: None,
        });
        let spiker = !spiker_chosen && modality == SensorModality::WaterQuality;
        spiker_chosen |= spiker;
        nodes.push(SimNode {
            node_id,
            modality,
            signer,
            calibration_id,
            index: i,
            spiker,
        });
    }
    nodes
}

/// Run the synthetic traffic loop forever: every `interval_ms`, each node
/// signs one envelope for the current wall-clock instant and sends it to
/// `127.0.0.1:udp_port`, rotating encodings to exercise all three transport
/// paths — `i % 3 == 0` v1 CBOR, `1` compact v2, `2` compact v2 fragmented
/// at the LoRaWAN DR0 MTU (3 datagrams).
pub async fn run_simulator(
    state: GatewayState,
    n: u32,
    seed: u64,
    interval_ms: u64,
    udp_port: u16,
) {
    let nodes = provision(&state, n, seed).await;
    let socket = match UdpSocket::bind(("127.0.0.1", 0)).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("gateway: simulator disabled, socket bind failed: {e}");
            return;
        }
    };
    let target = (std::net::Ipv4Addr::LOCALHOST, udp_port);
    let mut tick_timer = tokio::time::interval(Duration::from_millis(interval_ms.max(10)));
    let mut tick: u32 = 0;
    let mut msg_id: u16 = 0;
    loop {
        tick_timer.tick().await;
        tick = tick.wrapping_add(1);
        for node in &nodes {
            let ts_ns = now_ns();
            let value = sim_value(node, ts_ns, tick);
            let wire = RvEnvSampleV1 {
                schema_version: RV_ENV_SCHEMA_V1,
                sensor_type: node.modality.code(),
                flags: 0,
                node_id: node.node_id,
                timestamp_ns: ts_ns,
                sequence: tick,
                latitude_e7: 514_778_216 + node.index as i32 * 1_000,
                longitude_e7: -14_767 + node.index as i32 * 1_000,
                altitude_mm: 46_000,
                value_q16: (value * 65_536.0).round() as i32,
                quality_q15: SIM_QUALITY_Q15,
                battery_mv: 3_600,
                calibration_id: node.calibration_id,
            };
            let payload = wire.encode();
            match node.index % 3 {
                0 => {
                    // v1 CBOR envelope (151 bytes).
                    let env = sign_payload(&node.signer, &payload).encode();
                    let _ = socket.send_to(&env, target).await;
                }
                1 => {
                    // Compact envelope v2 (114 bytes).
                    let env = compact(&node.signer, &payload);
                    let _ = socket.send_to(&env.encode(), target).await;
                }
                _ => {
                    // Compact v2 fragmented at the DR0 MTU: 3 datagrams. The
                    // gateway reassembles with sender hint 0, so msg_ids are
                    // globally unique via one counter (see `pipeline`).
                    msg_id = msg_id.wrapping_add(1);
                    let env = compact(&node.signer, &payload);
                    for frame in fragment_compact(&env, msg_id) {
                        let _ = socket.send_to(&frame, target).await;
                    }
                }
            }
        }
    }
}

/// Sign a payload into a compact v2 envelope.
fn compact(signer: &NodeSigner, payload: &[u8; 48]) -> CompactEnvV2 {
    rucelium_transport::sign_compact(signer, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provision_seed_is_deterministic_and_seed_sensitive() {
        assert_eq!(provision_seed(1), provision_seed(1));
        assert_ne!(provision_seed(1), provision_seed(2));
    }

    #[test]
    fn value_model_is_bounded_and_spikes_on_schedule() {
        let spiker = SimNode {
            node_id: SIM_NODE_ID_BASE + 2,
            modality: SensorModality::WaterQuality,
            signer: NodeSigner::for_node(&provision_seed(1), SIM_NODE_ID_BASE + 2),
            calibration_id: 1002,
            index: 2,
            spiker: true,
        };
        let ts = 1_754_000_000_000_000_000;
        // Normal ticks stay well under the flood threshold.
        for tick in 1..SPIKE_EVERY_TICKS {
            let v = sim_value(&spiker, ts, tick);
            assert!(v < crate::pipeline::WATER_ALERT_LEVEL_M, "tick {tick}: {v}");
            assert!(v > 0.0);
        }
        // The 60th tick spikes above it.
        let v = sim_value(&spiker, ts, SPIKE_EVERY_TICKS);
        assert!(v > crate::pipeline::WATER_ALERT_LEVEL_M, "{v}");
    }

    #[test]
    fn all_physical_modalities_have_positive_profiles() {
        for m in SensorModality::ALL {
            if m == SensorModality::WifiCsi {
                continue;
            }
            let (base, amp) = profile(m);
            assert!(base > 0.0 && amp > 0.0, "{m:?}");
        }
    }
}
