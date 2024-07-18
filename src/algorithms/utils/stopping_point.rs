use cached::proc_macro::cached;

const PROBABILITY_DEFINITION: f64 = 1_000.0;

const PRE_COMPUTE_SIZE: usize = 64;
const PRE_COMPUTE_MAX_IDX: usize = PRE_COMPUTE_SIZE - 1;

const STOPPING_POINT_95: [usize; PRE_COMPUTE_SIZE] = [
    0, 1, 6, 11, 16, 21, 27, 33, 38, 44, 51, 57, 63, 70, 76, 83, 90, 96, 103, 110, 117, 124, 131,
    138, 145, 152, 159, 167, 174, 181, 189, 196, 203, 211, 218, 226, 233, 241, 248, 256, 264, 271,
    279, 287, 294, 302, 310, 318, 326, 333, 341, 349, 357, 365, 373, 381, 389, 397, 405, 413, 421,
    429, 437, 445,
];

const STOPPING_POINT_99: [usize; PRE_COMPUTE_SIZE] = [
    0, 1, 8, 15, 21, 28, 36, 43, 51, 58, 66, 74, 82, 90, 98, 106, 115, 123, 132, 140, 149, 157,
    166, 175, 183, 192, 201, 210, 219, 228, 237, 246, 255, 264, 273, 282, 291, 300, 309, 319, 328,
    337, 347, 356, 365, 375, 384, 393, 403, 412, 422, 431, 441, 450, 460, 470, 479, 489, 499, 508,
    518, 528, 537, 547,
];

fn chooses(n: usize, k: usize) -> f64 {
    // computes n choose k
    if n < k {
        return 0.0;
    }
    if n == k {
        return 1.0;
    }

    (1..=k).fold(1.0, |acc, j| acc * (n - j + 1) as f64 / j as f64)
}

fn _stirling2_fact(n: usize, k: usize) -> f64 {
    if n == 0 && k == 0 {
        return 1.0;
    }
    if n == 0 || k == 0 {
        return 0.0;
    }

    (0..=k).fold(0.0, |acc, j| {
        acc + if (k - j) % 2 == 0 {
            chooses(k, j) * (j as f64).powf(n as f64)
        } else {
            -chooses(k, j) * (j as f64).powf(n as f64)
        }
    })
}

#[cached]
pub fn general_prob(total_interfaces: usize, n_probes: usize, reached_interfaces: usize) -> f64 {
    let stirling = _stirling2_fact(n_probes, reached_interfaces);
    let binom = chooses(total_interfaces, reached_interfaces);
    stirling * binom / (total_interfaces as f64).powf(n_probes as f64)
}

#[cached]
fn reach_prob(total_interfaces: usize, n_probes: usize, target_interfaces: usize) -> f64 {
    // Initialization:
    //   We can reach 0 interfaces with probability 1.0, only if we send 0 probes.
    //   We cannot reach 0 interfaces with 1 or more probes.
    //   With 0 probes, we cannot reach n > 0 interfaces.

    match (n_probes, target_interfaces) {
        (0, 0) => return 1.0,
        (0, _) | (_, 0) => return 0.0,
        _ => {}
    };

    // We now define our recursion primarily on the number of sent probes.
    // We suppose we already sent (n_probes - 1) probes and distinguish between
    // the two following cases:
    //
    // - A: we already reached our target number of interfaces with (n_probes - 1) probes ; or
    // - B: we still need to reach one new interface with our last probe.
    //
    // A :  [x] [x] [x] [ ] ------> [x] [x] [x] [ ]
    //     (after n-1 probes)      (after n probes)
    //
    // B :  [x] [x] [ ] [ ] ------> [x] [x] [X] [ ]
    //     (after n-1 probes)      (after n probes)

    let prob_discovered_all_targets = reach_prob(total_interfaces, n_probes - 1, target_interfaces);
    let prob_hit_discovered_interface = target_interfaces as f64 / total_interfaces as f64;

    let prob_one_target_left = reach_prob(total_interfaces, n_probes - 1, target_interfaces - 1);
    let prob_hit_new_interface =
        (total_interfaces - (target_interfaces - 1)) as f64 / total_interfaces as f64;

    prob_discovered_all_targets * prob_hit_discovered_interface
        + prob_one_target_left * prob_hit_new_interface
}

#[cached]
fn _cached_stopping_point(n_interfaces: usize, failure_probability_proxy: u64) -> usize {
    (0..)
        .find(|&n_probes| {
            reach_prob(n_interfaces, n_probes, n_interfaces)
                >= (1.0 - (failure_probability_proxy as f64 / PROBABILITY_DEFINITION))
        })
        .unwrap()
}

pub fn stopping_point(n_interfaces: usize, failure_probability: f64) -> usize {
    match (
        n_interfaces,
        (failure_probability * PROBABILITY_DEFINITION) as u64,
    ) {
        (0..=PRE_COMPUTE_MAX_IDX, 50) => STOPPING_POINT_95[n_interfaces],
        (0..=PRE_COMPUTE_MAX_IDX, 10) => STOPPING_POINT_99[n_interfaces],
        _ => _cached_stopping_point(
            n_interfaces,
            (failure_probability * PROBABILITY_DEFINITION) as u64,
        ),
    }
}

pub fn general_stopping_point(n_interfaces: usize, failure_probability: f64) -> usize {
    let mut n_probes = 1;
    // let growth_factor = 3;
    // let mut previous_n_probes = 0;
    while general_prob(n_interfaces, n_probes, n_interfaces) < (1.0 - failure_probability) {
        n_probes += 1;
    }
    n_probes
    // while general_prob(n_interfaces, n_probes, n_interfaces) < (1.0 - failure_probability) {
    //     previous_n_probes = n_probes;
    //     n_probes *= growth_factor;
    // }

    // Vec::from_iter(previous_n_probes..n_probes).partition_point(|&n| {
    //     general_prob(n_interfaces, n, n_interfaces) < (1.0 - failure_probability)
    // }) + previous_n_probes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn general_stopping_point_0_95() {
        assert_eq!(
            (0..PRE_COMPUTE_SIZE)
                .map(|n| general_stopping_point(n, 0.05))
                .collect::<Vec<usize>>(),
            STOPPING_POINT_95
        )
    }

    // #[test]
    // fn stopping_point_0_95() {
    //     // Using _cached_stopping_point to prove equivalence of the hard coded arrays
    //     let prob_proxy = (0.05 * PROBABILITY_DEFINITION) as u64;
    //     assert_eq!(
    //         (0..PRE_COMPUTE_SIZE)
    //             .map(|n| _cached_stopping_point(n, prob_proxy))
    //             .collect::<Vec<usize>>(),
    //         STOPPING_POINT_95
    //     )
    // }

    // #[test]
    // fn stopping_point_0_99() {
    //     // Using _cached_stopping_point to prove equivalence of the hard coded arrays
    //     let prob_proxy = (0.01 * PROBABILITY_DEFINITION) as u64;
    //     assert_eq!(
    //         (0..PRE_COMPUTE_SIZE)
    //             .map(|n| _cached_stopping_point(n, prob_proxy))
    //             .collect::<Vec<usize>>(),
    //         STOPPING_POINT_99
    //     )
    // }
}
