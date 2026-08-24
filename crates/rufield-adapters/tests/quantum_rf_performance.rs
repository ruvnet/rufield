use std::hint::black_box;
use std::time::{Duration, Instant};

use rufield_adapters::{RydbergFrame, RydbergReplayAdapter, RydbergReplayConfig};
use rufield_core::FieldAdapter;

const MEASURED_FRAMES: usize = 10_000;
const TRIALS: usize = 3;

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "performance gate requires an optimized release build"
)]
fn replay_exceeds_ten_thousand_frames_per_second_with_submillisecond_p95() {
    let frames = frames(MEASURED_FRAMES);
    warm_up();

    let mut results = Vec::with_capacity(TRIALS);
    for _ in 0..TRIALS {
        let mut adapter = RydbergReplayAdapter::from_frames_with_config(
            frames.clone(),
            RydbergReplayConfig::default(),
        )
        .expect("benchmark frames pass every gate");
        let mut latencies = Vec::with_capacity(MEASURED_FRAMES);
        let trial_start = Instant::now();
        for _ in 0..MEASURED_FRAMES {
            let event_start = Instant::now();
            let event = adapter
                .next_event()
                .expect("event conversion succeeds")
                .expect("benchmark stream has expected length");
            latencies.push(event_start.elapsed());
            black_box(event);
        }
        let elapsed = trial_start.elapsed();
        latencies.sort_unstable();
        let p95 = latencies[(MEASURED_FRAMES * 95).div_ceil(100) - 1];
        let throughput = MEASURED_FRAMES as f64 / elapsed.as_secs_f64();
        results.push((throughput, p95));
    }

    results.sort_by(|a, b| a.0.total_cmp(&b.0));
    let median_throughput = results[TRIALS / 2].0;
    let mut p95s: Vec<Duration> = results.iter().map(|result| result.1).collect();
    p95s.sort_unstable();
    let median_p95 = p95s[TRIALS / 2];
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    eprintln!(
        "quantum_rf_replay_perf host={}-{} profile={} frames={} trials={} median_fps={:.0} median_p95_us={:.1}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        profile,
        MEASURED_FRAMES,
        TRIALS,
        median_throughput,
        median_p95.as_secs_f64() * 1_000_000.0,
    );

    assert!(
        median_throughput >= 10_000.0,
        "median replay throughput {median_throughput:.0} frames/s is below 10,000"
    );
    assert!(
        median_p95 < Duration::from_millis(1),
        "median p95 replay conversion latency {median_p95:?} is not below 1 ms"
    );
}

fn warm_up() {
    let mut adapter =
        RydbergReplayAdapter::from_frames_with_config(frames(256), RydbergReplayConfig::default())
            .unwrap();
    while let Some(event) = adapter.next_event().unwrap() {
        black_box(event);
    }
}

fn frames(count: usize) -> Vec<RydbergFrame> {
    let mut frames = Vec::with_capacity(count);
    for index in 0..count {
        frames.push(RydbergFrame {
            timestamp_ns: 10_000_000_000 + index as u64 * 1_000_000,
            sensor_position_m: [1.0, 2.0, 3.0],
            sensor_orientation_xyzw: [0.0, 0.0, 0.0, 1.0],
            coordinate_frame: "perf_world".into(),
            signal_id: "perf-signal".into(),
            carrier_hz: 6_640_000_000.0,
            e_field_sensor_vpm: [[0.04, 0.0], [0.0, 0.03], [0.0, 0.0]],
            k_hat_sensor: [0.0, 0.0, 1.0],
            sign_ambiguous: true,
            ellipticity: 0.96,
            snr_db: 30.0,
            integration_ms: 0.1,
            angular_covariance_rad2: [[0.001, 0.0002], [0.0002, 0.002]],
            calibration_id: "perf-calibration".into(),
            calibration_created_ns: 9_000_000_000,
            calibration_expires_ns: 21_000_000_000,
            calibration_quality: 0.95,
            lock_quality: 0.98,
        });
    }
    frames
}
