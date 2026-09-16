//! Deterministic signed SDK fixture; measures verification + compact preparation.
use rufield_core::FieldEvent;
use rufield_provenance::{Signer, TrustPolicy, TrustVerifier, TrustedKeyRegistry};
use rufield_ruvector::routing::prepare_routing_event;
use std::time::Instant;
fn main() {
    let mut event: FieldEvent =
        serde_json::from_str(include_str!("../tests/fixtures/ruview.json")).unwrap();
    // Large deterministic tensor makes serialization savings visible. This is
    // generated evidence, not a measured RF capture or road benchmark.
    event.tensor.shape = vec![4096];
    event.tensor.values = vec![0.25; 4096];
    let signer = Signer::from_seed(&[17; 32]);
    let mut registry = TrustedKeyRegistry::new();
    registry
        .enroll_sensor_key(&event.sensor.device_id, signer.public_hex())
        .unwrap();
    let mut verifier = TrustVerifier::new(TrustPolicy::production(), registry);
    let mut times = Vec::new();
    let mut bytes = 0;
    let mut serialize_times = Vec::new();
    let mut compact_times = Vec::new();
    for i in 1..=1100u64 {
        event.timestamp_ns = i;
        event.tensor.timestamp_ns = i;
        event.event_id = format!("bench-{i}");
        signer.sign_event(&mut event).unwrap();
        let start = Instant::now();
        let prepared = prepare_routing_event(&event, &mut verifier, i).unwrap();
        let elapsed = start.elapsed().as_nanos();
        let start = Instant::now();
        let full = serde_json::to_vec(&event).unwrap();
        std::hint::black_box(&full);
        let serialize = start.elapsed().as_nanos();
        let start = Instant::now();
        prepared
            .deliver(i, |payload, _, _| {
                std::hint::black_box(payload);
                Ok::<_, ()>(())
            })
            .unwrap()
            .unwrap();
        let delivery = start.elapsed().as_nanos();
        bytes = prepared.payload_bytes();
        if i > 100 {
            times.push(elapsed);
            serialize_times.push(serialize);
            compact_times.push(delivery);
        }
    }
    times.sort_unstable();
    serialize_times.sort_unstable();
    compact_times.sort_unstable();
    println!("{{\"samples\":1000,\"tensor_values\":4096,\"full_bytes\":{},\"routing_bytes\":{bytes},\"verify_prepare_p50_ns\":{},\"verify_prepare_p95_ns\":{},\"full_serialize_p50_ns\":{},\"prepared_delivery_p50_ns\":{}}}",serde_json::to_vec(&event).unwrap().len(), times[499],times[949],serialize_times[499],compact_times[499]);
}
