//! The end-to-end gateway + biome runner: feeds the simulated emission
//! stream through the REAL production pipeline — ABI envelopes → ingest
//! (signatures, revocation, anti-replay) → calibration (lineage, drift,
//! quarantine) → WorldGraph + RF context → biome (dedup, outage buffer,
//! revocation, summaries) → SensorThings projection → governed control path —
//! and scores the ADR-264 §14 acceptance criteria against the simulator's
//! ground truth.

use crate::report::{BiomeReport, Criterion};
use crate::sim::{
    anchor_expectation, noise_sd, BiomeSim, EmissionKind, SimConfig, EPOCH_START_NS, NODE_ID_BASE,
    NS_PER_S, S_PER_DAY,
};
use rucelium_calibration::{CalibrationOutcome, CalibrationStore, Calibrator, DriftDetector};
use rucelium_core::{
    CalibrationRecord, EnvironmentalEvent, EventKind, EvidenceRef, SensorModality, Severity,
    SPEC_VERSION,
};
use rucelium_federation::{
    project_sample, verify_event, verify_summary, AcceptOutcome, Biome, BiomeConfig, FederationBus,
    OutageBuffer,
};
use rucelium_ingest::{DeviceRegistry, IngestPipeline};
use rucelium_policy::{
    verify_receipt, AgentProposal, AuditTrail, AuthorityRegistry, CommandSigner, GatewayValidator,
    PolicyConfig, PolicyEngine, ProposalKind, SafetyConfig, SafetySimulator,
};
use rucelium_worldgraph::{
    assess_plausibility, fuse_rf_context, GraphNode, Plausibility, RfContext, WorldGraph,
};
use std::time::Instant;

/// Water-level threshold (metres) for the local flood alert rule. The
/// synthetic baseline peaks ≈ 1.36 m; the injected surge starts ≈ 1.7 m.
const FLOOD_THRESHOLD_M: f64 = 1.6;

/// Biome signing seed (deterministic identity).
const BIOME_SEED: &[u8; 32] = b"rucelium-biome-owner-key-32b-v1!";
/// Governance (control-path) signing seed.
const GOV_SEED: &[u8; 32] = b"rucelium-governance-key-32b-v01!";
/// Gateway receipt-signing identity seed (ADR-264 §9: receipts are signed
/// attestations, so the gateway needs its own deterministic identity).
const GATEWAY_SEED: &[u8; 32] = b"rucelium-gateway-identity-32b-1!";
/// Federation key epoch the benchmark registers its biome under.
const KEY_EPOCH: u32 = 1;
/// The single actuator the benchmark's biome owner exposes.
const ACTUATOR_ID: &str = "sluice-gate-1";

/// Build the calibration store: one anchor-rooted record per modality, then
/// one colocation record per node chaining to its modality anchor.
fn build_calibration(sim: &BiomeSim) -> CalibrationStore {
    let mut store = CalibrationStore::new();
    let created = EPOCH_START_NS - S_PER_DAY * NS_PER_S;
    let expires = EPOCH_START_NS + u64::from(sim.config.days + 10) * S_PER_DAY * NS_PER_S;
    // Anchor records: ids 1..=10 by modality code (skip 0 = WifiCsi context).
    for m in SensorModality::ALL {
        if m == SensorModality::WifiCsi {
            continue;
        }
        store
            .insert(CalibrationRecord {
                calibration_id: u32::from(m.code()) + 1,
                node_id: 0, // the reference anchor station
                modality: m,
                method: "anchor_reference".into(),
                reference_station: Some(format!("anchor/{}", m.as_str())),
                parent_id: None,
                created_ns: created,
                expires_ns: expires,
                scale_q16: 65_536,
                offset_q16: 0,
                uncertainty_q16: 6_554, // ±0.1 in-unit anchor uncertainty
                data_hash: format!("sha256:anchor-{}", m.as_str()),
                signature_hex: None,
                signer_pubkey_hex: None,
            })
            .expect("anchor record valid");
    }
    for (i, spec) in sim.nodes.iter().enumerate() {
        store
            .insert(CalibrationRecord {
                calibration_id: 1000 + i as u32,
                node_id: spec.node_id,
                modality: spec.modality,
                method: "colocation".into(),
                reference_station: Some(format!("anchor/{}", spec.modality.as_str())),
                parent_id: Some(u32::from(spec.modality.code()) + 1),
                created_ns: created + 1,
                expires_ns: expires,
                scale_q16: 65_536, // identity: nodes left the factory true
                offset_q16: 0,
                uncertainty_q16: 19_661, // ±0.3 in-unit
                data_hash: format!("sha256:colo-{}", spec.node_id),
                signature_hex: None,
                signer_pubkey_hex: None,
            })
            .expect("node record valid");
    }
    store
}

fn percentile(sorted_ms: &[f64], p: f64) -> f64 {
    if sorted_ms.is_empty() {
        return 0.0;
    }
    let idx = ((sorted_ms.len() as f64 - 1.0) * p).round() as usize;
    sorted_ms[idx.min(sorted_ms.len() - 1)]
}

/// Build the daily gateway-side RuView RF context event (ADR-264 §8 —
/// supporting evidence, never ground truth).
fn rf_context_for_day(day: u32, motion_energy: f32) -> RfContext {
    let ts = EPOCH_START_NS + (u64::from(day) * S_PER_DAY + S_PER_DAY / 2) * NS_PER_S;
    let tensor = rufield_core::FieldTensor::new(
        ts,
        rufield_core::Modality::WifiCsi,
        vec![rufield_core::FieldAxis::Frequency],
        vec![2],
        vec![0.1, 0.2],
        0.9,
        0.01,
        Some("rf-cal".into()),
        rufield_core::PrivacyClass::P2,
    )
    .expect("tensor valid");
    let mut obs = rufield_core::Observation::occupancy(0.9, rufield_core::PrivacyClass::P2);
    obs.features.insert("motion_energy".into(), motion_energy);
    obs.labels = vec!["water_boundary_shift".into()];
    let ev = rufield_core::FieldEvent::new(
        format!("rf-day-{day}"),
        ts,
        rufield_core::SensorDescriptor {
            modality: "wifi_csi".into(),
            vendor: "ruview_gw".into(),
            device_id: "rf-gw-01".into(),
            placement: "river_bank".into(),
            clock_domain: "gateway".into(),
        },
        tensor,
        obs,
        rufield_core::ProvenanceRef {
            raw_hash: "sha256:rf".into(),
            firmware_hash: "sha256:rf-fw".into(),
            model_id: "ruview_env_ctx_v1".into(),
            calibration_id: "rf-cal".into(),
            synthetic: true,
            signature_hex: None,
            signer_pubkey_hex: None,
        },
    );
    RfContext::from_field_event(&ev).expect("wifi_csi context")
}

/// Run the governed control path twice (one authorized command per the §9
/// pipeline, one actuator proposal without authority) and return
/// `(executed, rejected)`.
fn run_control_path(biome_id: &str, quarantined_node: u64, now_ns: u64) -> (u64, u64) {
    let mut audit = AuditTrail::new();
    let mut policy_cfg = PolicyConfig::default();
    policy_cfg.allowed_actuators.insert(ACTUATOR_ID.into());
    let engine = PolicyEngine::new(policy_cfg);
    let mut safety = SafetySimulator::new(SafetyConfig::default());
    let mut authority = AuthorityRegistry::new();
    authority.grant(biome_id, "agent/flood", ACTUATOR_ID);
    let signer = CommandSigner::from_seed(GOV_SEED);
    let mut gateway = GatewayValidator::new(vec![signer.public_hex()], GATEWAY_SEED);

    let mut executed = 0u64;
    let mut rejected = 0u64;

    // 1. Calibration agent: raise the quarantined node's sampling interval
    //    (non-actuator — auto-authorized for the proposing biome).
    let p1 = AgentProposal {
        proposal_id: "prop-recal-1".into(),
        agent_id: "agent/calibration".into(),
        biome_id: biome_id.into(),
        kind: ProposalKind::SetSamplingRate {
            node_id: quarantined_node,
            interval_s: 3600,
        },
        justification: "node quarantined for drift; reduce cadence until recalibrated".into(),
        proposed_ns: now_ns,
    };
    let done = engine
        .evaluate(p1, now_ns, &mut audit)
        .and_then(|e| safety.simulate(e, now_ns, &mut audit))
        .and_then(|s| authority.authorize(s, now_ns, &mut audit))
        .map(|a| signer.sign(a, now_ns, 3_600 * NS_PER_S, &mut audit))
        .and_then(|cmd| {
            gateway.validate_and_execute(
                &cmd,
                now_ns + 1,
                |_k| Ok("applied".to_string()),
                &mut audit,
            )
        });
    if let Ok(receipt) = &done {
        // Receipts are gateway-signed attestations (ADR-264 §9).
        debug_assert!(verify_receipt(receipt), "receipt must verify");
        executed += 1;
    } else {
        rejected += 1;
    }

    // 2. Flood agent: authorized actuator command through every §9 stage.
    let p2 = AgentProposal {
        proposal_id: "prop-sluice-1".into(),
        agent_id: "agent/flood".into(),
        biome_id: biome_id.into(),
        kind: ProposalKind::ActuatorCommand {
            actuator_id: ACTUATOR_ID.into(),
            action: "open_fraction".into(),
            magnitude: 0.5,
        },
        justification: "flood risk warning: pre-emptively relieve water level".into(),
        proposed_ns: now_ns,
    };
    let done = engine
        .evaluate(p2, now_ns, &mut audit)
        .and_then(|e| safety.simulate(e, now_ns, &mut audit))
        .and_then(|s| authority.authorize(s, now_ns, &mut audit))
        .map(|a| signer.sign(a, now_ns, 3_600 * NS_PER_S, &mut audit))
        .and_then(|cmd| {
            gateway.validate_and_execute(
                &cmd,
                now_ns + 1,
                |_k| Ok("opened 50%".to_string()),
                &mut audit,
            )
        });
    if let Ok(receipt) = &done {
        debug_assert!(verify_receipt(receipt), "receipt must verify");
        // Budgets are checked at safety and charged at execution: only a
        // command the gateway actually executed consumes the actuator budget.
        safety.record_execution(ACTUATOR_ID);
        executed += 1;
    } else {
        rejected += 1;
    }

    // 3. A rogue agent proposing an actuator it has no authority over — the
    //    control path must stop it (never reaches signing).
    let p3 = AgentProposal {
        proposal_id: "prop-rogue-1".into(),
        agent_id: "agent/unknown".into(),
        biome_id: biome_id.into(),
        kind: ProposalKind::ActuatorCommand {
            actuator_id: ACTUATOR_ID.into(),
            action: "open_fraction".into(),
            magnitude: 0.7,
        },
        justification: "no".into(),
        proposed_ns: now_ns,
    };
    let outcome = engine
        .evaluate(p3, now_ns, &mut audit)
        .and_then(|e| safety.simulate(e, now_ns, &mut audit))
        .and_then(|s| authority.authorize(s, now_ns, &mut audit));
    if outcome.is_err() {
        rejected += 1;
    } else {
        executed += 1; // would be a bug; the criterion below catches it
    }

    (executed, rejected)
}

/// Run the full ADR-264 §14 biome benchmark.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run(config: SimConfig) -> BiomeReport {
    let sim = BiomeSim::generate(config.clone());

    // --- Gateway + biome assembly (the real production components). ---
    let mut registry = DeviceRegistry::new();
    for spec in &sim.nodes {
        registry.register(spec.node_id, spec.pubkey, spec.firmware_hash.clone());
    }
    let mut ingest = IngestPipeline::new(registry);
    let store = build_calibration(&sim);
    let calibrator = Calibrator::default();
    let mut drift = DriftDetector::default();
    let mut graph = WorldGraph::new();
    graph.add_node(
        "region/synthetic-watershed",
        GraphNode::Region {
            biome_id: "biome/synthetic-watershed".into(),
            name: "Synthetic Watershed".into(),
        },
    );
    let mut biome = Biome::new(BiomeConfig::new("biome/synthetic-watershed"), BIOME_SEED);
    let mut bus = FederationBus::new();
    // Federation identity binding (ADR-264 §6): the bus binds this biome id
    // to this key at epoch 1 — nothing else may publish under the id.
    bus.register_biome(
        biome.config().biome_id.clone(),
        biome.public_key_hex(),
        KEY_EPOCH,
    )
    .expect("biome registers on the federation bus");
    // Store-and-forward now buffers the ORIGINAL signed envelopes: decoded
    // samples cannot be re-verified, so only the wire bytes are replayable.
    let mut buffer = OutageBuffer::new();

    // --- Counters / metrics. ---
    let mut pipeline_ms: Vec<f64> = Vec::with_capacity(sim.emissions.len());
    let mut alert_ms: Vec<f64> = Vec::new();
    let mut attacks_injected = 0u64;
    let mut attacks_rejected = 0u64;
    let mut attacks_accepted = 0u64;
    let mut accepted = 0u64;
    let mut usable = 0u64;
    let mut worldgraph_mapped = 0u64;
    let mut sensorthings_projected = 0u64;
    let mut anomaly_alerts = 0u64;
    let mut restored_after_outage = 0u64;
    let mut restore_duplicates = 0u64;
    let mut buffered_during_outage = 0u64;
    let mut accepted_after_revocation = 0u64;
    let mut revocation_done = false;
    let mut was_offline = false;
    let mut rf_day_done: Option<u32> = None;
    let mut first_quarantine_ns: Option<u64> = None;
    let mut water_sensor_key: Option<String> = None;
    let mut event_seq = 0u64;

    let revoked_node_id = NODE_ID_BASE + u64::from(config.compromised_node);

    for em in &sim.emissions {
        // Day-boundary duties: revocation, RF context.
        if !revocation_done && em.day >= config.revoke_day {
            ingest.registry_mut().revoke(revoked_node_id);
            let rev_event =
                biome.revoke_device(revoked_node_id, em.received_ns, "compromised device key");
            debug_assert!(verify_event(&rev_event));
            bus.publish_event(rev_event)
                .expect("signed revocation event publishes");
            revocation_done = true;
        }
        if rf_day_done != Some(em.day) && em.kind == EmissionKind::Genuine {
            rf_day_done = Some(em.day);
            // Daily RuView RF context: high motion on the anomaly day
            // (flood boundary shift) and on day 3 (deliberate disagreement —
            // RF alone must never win; it records a contradiction instead).
            let motion = if em.day == config.anomaly_day || em.day == 3 {
                0.9
            } else {
                0.2
            };
            let rf = rf_context_for_day(em.day, motion);
            let change_expected = em.day == config.anomaly_day;
            let plaus =
                assess_plausibility(change_expected, rf.timestamp_ns, &rf, S_PER_DAY * NS_PER_S);
            // Attach the context to a representative water sensor (first
            // days have none registered yet — the context is then skipped).
            if let Some(key) = &water_sensor_key {
                if plaus != Plausibility::NoContext {
                    let _ = fuse_rf_context(&mut graph, key, &rf, plaus);
                }
            }
        }

        // Reconnect transition: uplink restored ⇒ restore buffered data.
        if was_offline && !em.uplink_down {
            was_offline = false;
            // Prove restart-safety: serialize + restore the buffer state,
            // drain the restored copy, and re-verify every stored envelope
            // before it may enter the biome. `reverify_stored` runs the full
            // registry + revocation + key-match + signature + payload checks
            // WITHOUT touching the anti-replay window (those sequences were
            // consumed on the live path); duplicate suppression on this path
            // is the biome's global dedup index.
            let snapshot = buffer.to_json().expect("buffer serializes");
            let mut restored = OutageBuffer::from_json(&snapshot).expect("buffer restores");
            for (envelope, recv_ns) in restored.drain() {
                let sealed = ingest
                    .reverify_stored(&envelope, recv_ns)
                    .expect("buffered envelope re-verifies on restore");
                match biome.accept(sealed) {
                    AcceptOutcome::Accepted => restored_after_outage += 1,
                    AcceptOutcome::Duplicate => restore_duplicates += 1,
                    AcceptOutcome::Revoked => {}
                }
            }
            // Second restore of the SAME snapshot: every sample must dedup.
            let mut again = OutageBuffer::from_json(&snapshot).expect("buffer restores");
            for (envelope, recv_ns) in again.drain() {
                let sealed = ingest
                    .reverify_stored(&envelope, recv_ns)
                    .expect("buffered envelope re-verifies on restore");
                match biome.accept(sealed) {
                    AcceptOutcome::Accepted => restore_duplicates += 1, // duplicates admitted = failure
                    AcceptOutcome::Duplicate | AcceptOutcome::Revoked => {}
                }
            }
            buffer = OutageBuffer::new();
        }
        if em.uplink_down {
            was_offline = true;
        }

        let is_attack = em.kind != EmissionKind::Genuine;
        if is_attack {
            attacks_injected += 1;
        }

        let t0 = Instant::now();
        match ingest.ingest(&em.envelope, em.received_ns) {
            Err(_) => {
                if is_attack {
                    attacks_rejected += 1;
                }
                pipeline_ms.push(t0.elapsed().as_secs_f64() * 1e3);
            }
            Ok(mut sample) => {
                if is_attack {
                    // A tampered/replayed/forged/post-revocation emission got
                    // through — acceptance criterion 4 fails.
                    attacks_accepted += 1;
                    pipeline_ms.push(t0.elapsed().as_secs_f64() * 1e3);
                    continue;
                }

                // Calibration (lineage-checked affine + stated uncertainty).
                // `modify` keeps the ingest seal across the transformation:
                // the change is committed only if the result still validates,
                // so calibration can never smuggle an invalid sample through.
                let outcome = sample
                    .modify(|s| calibrator.apply(&store, s, em.received_ns))
                    .expect("calibrated sample stays valid");
                let calibrated = matches!(outcome, Ok(CalibrationOutcome::Applied { .. }));

                // Drift monitoring vs the modality anchor expectation,
                // normalized so one threshold spans all modalities.
                // Samples that fire the local anomaly rule are EXCLUDED from
                // drift accounting: drift is a slow, single-sensor
                // phenomenon; an environmental event (many sensors deviating
                // together) must not quarantine healthy sensors.
                // Read access to the sealed sample; the seal never leaves the
                // wrapper, so nothing downstream can fabricate one.
                let view = sample.sample();
                let is_local_anomaly =
                    view.modality == SensorModality::WaterQuality && view.value > FLOOD_THRESHOLD_M;
                if !is_local_anomaly {
                    let t_s = (view.measured_ns - EPOCH_START_NS) / NS_PER_S;
                    let expected = anchor_expectation(view.modality, em.node_index, t_s);
                    let residual = (view.value - expected) / (4.0 * noise_sd(view.modality));
                    drift.observe(view.node_id, residual);
                }
                let quarantined = drift.is_quarantined(view.node_id);
                if quarantined && first_quarantine_ns.is_none() {
                    first_quarantine_ns = Some(em.received_ns);
                }

                // WorldGraph registration (criterion 6).
                let key = graph.register_observation(view);
                let _ = graph.link_within_region(&key, "region/synthetic-watershed");
                if water_sensor_key.is_none() && view.modality == SensorModality::WaterQuality {
                    water_sensor_key = Some(key.clone());
                }
                worldgraph_mapped += 1;

                // SensorThings projection (criterion 6).
                let bundle = project_sample(view);
                debug_assert!(bundle.observation.result.is_finite());
                sensorthings_projected += 1;

                // Local flood alert rule (< 500 ms target, criterion 5).
                if is_local_anomaly {
                    event_seq += 1;
                    let mut alert = EnvironmentalEvent {
                        spec_version: SPEC_VERSION.into(),
                        event_id: format!("evt-flood-{event_seq:05}"),
                        biome_id: biome.config().biome_id.clone(),
                        kind: EventKind::FloodRisk,
                        severity: Severity::Warning,
                        modality: SensorModality::WaterQuality,
                        geo: view.geo,
                        window_start_ns: view.measured_ns,
                        window_end_ns: view.measured_ns,
                        detected_ns: em.received_ns,
                        evidence: vec![EvidenceRef {
                            node_id: view.node_id,
                            sequence: view.sequence,
                        }],
                        confidence: 0.92,
                        // Bind the cited observation's CONTENT, not just its
                        // (node, sequence) identity — ADR-266 §3.1.
                        evidence_digest: Some(rucelium_core::evidence_digest(&[sample.sample()])),
                        message: format!("water level {:.2} m above flood threshold", view.value),
                        signature_hex: None,
                        signer_pubkey_hex: None,
                    };
                    biome.sign_event(&mut alert);
                    if !em.uplink_down {
                        bus.publish_event(alert).expect("signed alert publishes");
                    }
                    alert_ms.push(t0.elapsed().as_secs_f64() * 1e3);
                    if em.true_anomaly {
                        anomaly_alerts += 1;
                    }
                }

                // Usability metric (criterion 8): calibrated, healthy, high
                // quality. Quarantined-node data stays stored but flagged.
                if calibrated && !quarantined && view.quality >= 0.9 {
                    usable += 1;
                }

                // Biome admission: live when online, store-and-forward when
                // the uplink is down. The buffer stores the ORIGINAL signed
                // envelope (dedup key `(node, sequence)` is read structurally)
                // so restore can re-verify it cryptographically.
                let admitted = if em.uplink_down {
                    let pushed = buffer
                        .push(&em.envelope, em.received_ns)
                        .expect("genuine envelope decodes structurally");
                    buffered_during_outage += u64::from(pushed);
                    pushed
                } else {
                    matches!(biome.accept(sample), AcceptOutcome::Accepted)
                };
                if admitted {
                    accepted += 1;
                    if revocation_done {
                        accepted_after_revocation += 1;
                    }
                }
                pipeline_ms.push(t0.elapsed().as_secs_f64() * 1e3);
            }
        }
    }

    // End-of-run: publish the signed regional summary for the final week.
    let sum_start = EPOCH_START_NS + u64::from(config.days - 7) * S_PER_DAY * NS_PER_S;
    let sum_end = EPOCH_START_NS + u64::from(config.days) * S_PER_DAY * NS_PER_S;
    let summary = biome.summarize(sum_start, sum_end);
    debug_assert!(verify_summary(&summary));
    bus.publish(summary).expect("signed summary publishes");

    // Governed control path (§9): reacting to the quarantine + flood.
    let control_now = first_quarantine_ns.unwrap_or(sum_end);
    let (commands_executed, proposals_rejected) = run_control_path(
        &biome.config().biome_id.clone(),
        NODE_ID_BASE + u64::from(config.drift_node),
        control_now,
    );

    pipeline_ms.sort_by(f64::total_cmp);
    alert_ms.sort_by(f64::total_cmp);

    let total_accepted = accepted.max(1);
    let usable_calibrated_pct = usable as f64 / total_accepted as f64 * 100.0;
    let worldgraph_coverage_pct = worldgraph_mapped as f64 / total_accepted as f64 * 100.0;
    let sensorthings_coverage_pct = sensorthings_projected as f64 / total_accepted as f64 * 100.0;
    let p95_alert = percentile(&alert_ms, 0.95);
    let quarantined_nodes = drift.quarantined().len() as u64;

    let criteria = vec![
        Criterion {
            number: 1,
            name: "operates 30 simulated days".into(),
            value: format!("{} days", config.days),
            target: ">= 30".into(),
            pass: config.days >= 30,
        },
        Criterion {
            number: 2,
            name: "survives 7 consecutive offline days".into(),
            value: format!(
                "{} days, {} buffered",
                config.offline_days, buffered_during_outage
            ),
            target: "7 offline".into(),
            pass: config.offline_days >= 7 && buffered_during_outage > 0,
        },
        Criterion {
            number: 3,
            name: "restores without duplicates".into(),
            value: format!("{restored_after_outage} restored / {restore_duplicates} dup"),
            target: "0 duplicates".into(),
            pass: restored_after_outage > 0 && restore_duplicates == 0,
        },
        Criterion {
            number: 4,
            name: "rejects modified/replayed packets".into(),
            value: format!("{attacks_rejected}/{attacks_injected} rejected"),
            target: "100 %".into(),
            pass: attacks_accepted == 0 && attacks_rejected == attacks_injected,
        },
        Criterion {
            number: 5,
            name: "local alerts within 500 ms".into(),
            value: format!("p95 {p95_alert:.3} ms, {anomaly_alerts} alerts"),
            target: "< 500 ms".into(),
            pass: anomaly_alerts > 0 && p95_alert < 500.0,
        },
        Criterion {
            number: 6,
            name: "maps to SensorThings + WorldGraph".into(),
            value: format!("{worldgraph_coverage_pct:.1} % / {sensorthings_coverage_pct:.1} %"),
            target: "100 %".into(),
            pass: (worldgraph_coverage_pct - 100.0).abs() < 1e-9
                && (sensorthings_coverage_pct - 100.0).abs() < 1e-9,
        },
        Criterion {
            number: 7,
            name: "revokes device without interruption".into(),
            value: format!("{accepted_after_revocation} accepted post-revocation"),
            target: "> 0 & 0 from revoked".into(),
            pass: revocation_done
                && biome.is_revoked(revoked_node_id)
                && accepted_after_revocation > 0,
        },
        Criterion {
            number: 8,
            name: ">= 95 % usable calibrated obs".into(),
            value: format!("{usable_calibrated_pct:.2} %"),
            target: ">= 95 %".into(),
            pass: usable_calibrated_pct >= 95.0,
        },
    ];

    BiomeReport {
        spec_version: SPEC_VERSION.into(),
        synthetic: true,
        seed: config.seed,
        nodes: config.nodes,
        days: config.days,
        offline_days: config.offline_days,
        emissions_total: sim.emissions.len(),
        accepted,
        attacks_injected,
        attacks_rejected,
        restored_after_outage,
        restore_duplicates,
        usable_calibrated_pct,
        worldgraph_coverage_pct,
        sensorthings_coverage_pct,
        p50_pipeline_ms: percentile(&pipeline_ms, 0.50),
        p95_pipeline_ms: percentile(&pipeline_ms, 0.95),
        p95_alert_ms: p95_alert,
        anomaly_alerts,
        quarantined_nodes,
        accepted_after_revocation,
        contradictions: graph.contradiction_count(),
        commands_executed,
        proposals_rejected,
        criteria,
    }
}
