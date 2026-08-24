//! Small dependency-free linear algebra helpers for bearing fusion.

use crate::bearing::BearingObservation;

pub(crate) fn weighted_system(
    observations: &[BearingObservation],
    weights: &[f64],
) -> ([[f64; 3]; 3], [f64; 3]) {
    let mut a = [[0.0; 3]; 3];
    let mut b = [0.0; 3];
    for (observation, weight) in observations.iter().zip(weights) {
        let p = projector(observation.direction_axis);
        for row in 0..3 {
            for col in 0..3 {
                a[row][col] += weight * p[row][col];
                b[row] += weight * p[row][col] * observation.sensor_position_m[col];
            }
        }
    }
    (a, b)
}

pub(crate) fn dot(a: [f64; 3], b: [f64; 3]) -> f64 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

pub(crate) fn rotate_vector_xyzw(vector: [f64; 3], quaternion: [f64; 4]) -> [f64; 3] {
    let q = [quaternion[0], quaternion[1], quaternion[2]];
    let t = scale(cross(q, vector), 2.0);
    add(add(vector, scale(t, quaternion[3])), cross(q, t))
}

fn cross(a: [f64; 3], b: [f64; 3]) -> [f64; 3] {
    [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]
}

fn add(a: [f64; 3], b: [f64; 3]) -> [f64; 3] {
    [a[0] + b[0], a[1] + b[1], a[2] + b[2]]
}

fn scale(vector: [f64; 3], factor: f64) -> [f64; 3] {
    [vector[0] * factor, vector[1] * factor, vector[2] * factor]
}

pub(crate) fn sub(a: [f64; 3], b: [f64; 3]) -> [f64; 3] {
    [a[0] - b[0], a[1] - b[1], a[2] - b[2]]
}

pub(crate) fn projector(k: [f64; 3]) -> [[f64; 3]; 3] {
    let mut p = [[0.0; 3]; 3];
    for row in 0..3 {
        for col in 0..3 {
            p[row][col] = f64::from(row == col) - k[row] * k[col];
        }
    }
    p
}

pub(crate) fn mat_vec(matrix: [[f64; 3]; 3], vector: [f64; 3]) -> [f64; 3] {
    [
        dot(matrix[0], vector),
        dot(matrix[1], vector),
        dot(matrix[2], vector),
    ]
}

pub(crate) fn scale_matrix(mut matrix: [[f64; 3]; 3], scale: f64) -> [[f64; 3]; 3] {
    for row in &mut matrix {
        for value in row {
            *value *= scale;
        }
    }
    matrix
}

pub(crate) fn max_axis_separation(observations: &[BearingObservation]) -> f64 {
    let mut max_angle = 0.0_f64;
    for i in 0..observations.len() {
        for j in i + 1..observations.len() {
            let cosine = dot(
                observations[i].direction_axis,
                observations[j].direction_axis,
            )
            .abs()
            .clamp(0.0, 1.0);
            max_angle = max_angle.max(cosine.acos());
        }
    }
    max_angle
}

pub(crate) fn max_sensor_baseline(observations: &[BearingObservation]) -> f64 {
    let mut baseline = 0.0_f64;
    for i in 0..observations.len() {
        for j in i + 1..observations.len() {
            let delta = sub(
                observations[i].sensor_position_m,
                observations[j].sensor_position_m,
            );
            baseline = baseline.max(dot(delta, delta).sqrt());
        }
    }
    baseline
}

pub(crate) fn condition_number_inf(matrix: [[f64; 3]; 3], inverse: [[f64; 3]; 3]) -> f64 {
    matrix_inf_norm(matrix) * matrix_inf_norm(inverse)
}

fn matrix_inf_norm(matrix: [[f64; 3]; 3]) -> f64 {
    matrix
        .iter()
        .map(|row| row.iter().map(|value| value.abs()).sum::<f64>())
        .fold(0.0, f64::max)
}

pub(crate) fn invert_3x3(matrix: [[f64; 3]; 3]) -> Option<[[f64; 3]; 3]> {
    let mut augmented = [[0.0; 6]; 3];
    let scale = matrix
        .iter()
        .flatten()
        .map(|v| v.abs())
        .fold(0.0_f64, f64::max)
        .max(1.0);
    for row in 0..3 {
        augmented[row][..3].copy_from_slice(&matrix[row]);
        augmented[row][row + 3] = 1.0;
    }
    for col in 0..3 {
        let pivot = (col..3)
            .max_by(|&a, &b| augmented[a][col].abs().total_cmp(&augmented[b][col].abs()))?;
        if augmented[pivot][col].abs() <= scale * 1.0e-10 {
            return None;
        }
        augmented.swap(col, pivot);
        let divisor = augmented[col][col];
        for value in &mut augmented[col] {
            *value /= divisor;
        }
        let pivot_values = augmented[col];
        for (row_index, row_values) in augmented.iter_mut().enumerate() {
            if row_index == col {
                continue;
            }
            let factor = row_values[col];
            for (value, pivot_value) in row_values.iter_mut().zip(&pivot_values) {
                *value -= factor * pivot_value;
            }
        }
    }
    let mut inverse = [[0.0; 3]; 3];
    for row in 0..3 {
        inverse[row].copy_from_slice(&augmented[row][3..]);
    }
    Some(inverse)
}
