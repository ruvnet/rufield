use rufield_adapters::{
    RydbergFrame, RydbergGateFailure, RydbergQualityThresholds, RydbergReplayAdapter,
    RydbergReplayConfig,
};

const CASES: usize = 10_000;

fn base_frame() -> RydbergFrame {
    RydbergFrame {
        timestamp_ns: 2_000_000_000,
        sensor_position_m: [0.0, 0.0, 0.0],
        sensor_orientation_xyzw: [0.0, 0.0, 0.0, 1.0],
        coordinate_frame: "property_world".into(),
        signal_id: "property-signal".into(),
        carrier_hz: 6_640_000_000.0,
        e_field_sensor_vpm: [[0.04, 0.0], [0.0, 0.03], [0.0, 0.0]],
        k_hat_sensor: [0.0, 0.0, 1.0],
        sign_ambiguous: true,
        ellipticity: 0.96,
        snr_db: 30.0,
        integration_ms: 1.0,
        angular_covariance_rad2: [[0.001, 0.0001], [0.0001, 0.002]],
        calibration_id: "property-calibration".into(),
        calibration_created_ns: 1_000_000_000,
        calibration_expires_ns: 3_000_000_000,
        calibration_quality: 0.99,
        lock_quality: 0.99,
    }
}

#[test]
fn ten_thousand_physics_cases_preserve_axis_under_scale_and_global_phase() {
    let quality = RydbergQualityThresholds::default();
    let golden_angle = std::f64::consts::PI * (3.0 - 5.0_f64.sqrt());

    for case in 0..CASES {
        let z = 1.0 - 2.0 * (case as f64 + 0.5) / CASES as f64;
        let radial = (1.0 - z * z).sqrt();
        let azimuth = case as f64 * golden_angle;
        let k = [radial * azimuth.cos(), radial * azimuth.sin(), z];
        let reference = if z.abs() < 0.9 {
            [0.0, 0.0, 1.0]
        } else {
            [0.0, 1.0, 0.0]
        };
        let u = normalize(cross(reference, k));
        let v = cross(k, u);

        let amplitude = 0.001 + 0.099 * ((case % 997) as f64 + 1.0) / 998.0;
        let ratio = 0.2 + 0.8 * ((case % 991) as f64 + 1.0) / 992.0;
        let phase = std::f64::consts::TAU * ((case * 7_919) % CASES) as f64 / CASES as f64;
        let (cos_phase, sin_phase) = (phase.cos(), phase.sin());
        let major = u.map(|value| amplitude * value);
        let minor = v.map(|value| amplitude * ratio * value);
        let real = array3(|axis| major[axis] * cos_phase - minor[axis] * sin_phase);
        let imaginary = array3(|axis| major[axis] * sin_phase + minor[axis] * cos_phase);
        let q_axis = 2.0 * ratio / (1.0 + ratio * ratio);

        let mut frame = base_frame();
        frame.k_hat_sensor = k;
        frame.e_field_sensor_vpm = array3(|axis| [real[axis], imaginary[axis]]);
        frame.ellipticity = q_axis;
        frame
            .validate(quality)
            .unwrap_or_else(|error| panic!("valid transformed case {case} rejected: {error}"));

        let derived = normalize(cross(real, imaginary));
        assert!(
            dot(derived, k) > 1.0 - 1.0e-10,
            "axis changed in case {case}"
        );
        let observed_q =
            2.0 * norm(cross(real, imaginary)) / (dot(real, real) + dot(imaginary, imaginary));
        assert!((observed_q - q_axis).abs() < 1.0e-12);

        let mut linear = frame;
        linear.e_field_sensor_vpm = array3(|axis| [major[axis], major[axis] * 0.5]);
        linear.ellipticity = 0.5;
        assert_eq!(
            linear.validate(quality),
            Err(RydbergGateFailure::EllipticityDegenerate),
            "degenerate case {case} escaped"
        );
    }
}

#[test]
fn covariance_and_noise_share_the_same_emitted_symmetric_matrix() {
    let mut frame = base_frame();
    frame.angular_covariance_rad2 = [[0.001, 0.000_2], [0.000_200_000_5, 0.002]];
    let event =
        &RydbergReplayAdapter::from_frames_with_config(vec![frame], RydbergReplayConfig::default())
            .unwrap()
            .collect_events()
            .unwrap()[0];
    let a = f64::from(event.observation.features["angle_cov_00_rad2"]);
    let b = f64::from(event.observation.features["angle_cov_01_rad2"]);
    let d = f64::from(event.observation.features["angle_cov_11_rad2"]);
    let lambda_max = (a + d + ((a - d).powi(2) + 4.0 * b.powi(2)).sqrt()) / 2.0;
    let expected_noise = lambda_max.sqrt();
    let actual_noise = f64::from(event.tensor.noise_floor);
    assert!((actual_noise - expected_noise).abs() <= expected_noise * 1.0e-6);
}

fn array3<T>(mut make: impl FnMut(usize) -> T) -> [T; 3] {
    [make(0), make(1), make(2)]
}

fn dot(a: [f64; 3], b: [f64; 3]) -> f64 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

fn norm(vector: [f64; 3]) -> f64 {
    dot(vector, vector).sqrt()
}

fn normalize(vector: [f64; 3]) -> [f64; 3] {
    let length = norm(vector);
    vector.map(|value| value / length)
}

fn cross(a: [f64; 3], b: [f64; 3]) -> [f64; 3] {
    [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]
}
