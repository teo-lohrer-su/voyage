use core::panic;

use once_cell::sync::Lazy;
use stirling_numbers::stirling2_ratio_table;

// consider using f128 for higher precision once it's stable
type Probability = f64;

// see https://github.com/10XGenomics/rust-toolbox/blob/6856c585a918e183fc4b3bd902b9e4f22e1f3d5f/stirling_numbers/src/lib.rs#L98
const MAX_N_PROBES: usize = 722;
const MAX_N_INTERFACES: usize = 1024;

pub const LIKELIHOOD_THRESHOLD: Probability = 0.95;

// using a Lazy to avoid recomputing the table every time
// Stirling_2 ratios are defined as the S(n, k) / (k^n * k!)
// see the link above for more details
// the table at index n contains the probabilities of finding k interfaces after n probes
static STIRLING2_RATIOS: Lazy<Vec<Vec<Probability>>> = Lazy::new(|| {
    let ratios = stirling2_ratio_table::<Probability>(MAX_N_PROBES);
    ratios
});

pub fn stopping_point(n_interfaces: usize, failure_probability: f64) -> usize {
    // the stopping point is defined as the smallest number of probes such that
    // the probability of finding (n_interfaces + 1) interfaces is at least (1 - failure_probability)
    STIRLING2_RATIOS
        .iter()
        .enumerate()
        .skip(n_interfaces + 1)
        .find(|(_, ratios_for_n)| {
            ratios_for_n[n_interfaces + 1] >= ((1.0 - failure_probability) as Probability)
        })
        .map(|(idx, _)| idx)
        .unwrap_or(MAX_N_PROBES)
}

fn binomial(n: usize, k: usize) -> Probability {
    (0..k).fold(1.0, |result, i| {
        result * (n - i) as Probability / (k - i) as Probability
    })
}

pub fn event_prob(
    total_interfaces: usize,
    n_probes: usize,
    observed_interfaces: usize,
) -> Probability {
    // the probability of finding exactly observed_interfaces interfaces after n_probes given total_interfaces
    if total_interfaces < observed_interfaces {
        panic!("observed_interfaces must be less than or equal to total_interfaces");
    }
    if n_probes < observed_interfaces {
        return 0.0;
    }
    // SR * k^n / K^n
    // SR * (k / K)^n
    // then multiply by the number of ways to choose k interfaces from n_interfaces

    let k_ratio = observed_interfaces as Probability / total_interfaces as Probability;
    let mut current_ratio = STIRLING2_RATIOS[n_probes][observed_interfaces];
    for _ in 0..n_probes {
        current_ratio *= k_ratio;
    }
    // mult by binomial coefficient
    let binom = binomial(total_interfaces, observed_interfaces);
    current_ratio * binom
}

pub fn estimate_total_interfaces(
    n_probes: usize,
    observed_interfaces: usize,
    likelihood_threshold: Probability,
) -> usize {
    if n_probes < observed_interfaces {
        panic!(
            "observed_interfaces must be less than or equal to n_probes. {} < {}",
            n_probes, observed_interfaces
        );
    }

    if n_probes == observed_interfaces {
        for total_interfaces in observed_interfaces..=MAX_N_INTERFACES {
            if event_prob(total_interfaces, n_probes, observed_interfaces) > likelihood_threshold {
                return total_interfaces;
            }
        }
        return observed_interfaces;
    }
    let mut prev_prob = 0.0;

    for total_interfaces in observed_interfaces..=MAX_N_INTERFACES {
        let prob = event_prob(total_interfaces, n_probes, observed_interfaces);
        if prob > likelihood_threshold {
            return total_interfaces;
        }
        if prob < prev_prob {
            return total_interfaces - 1;
        }
        prev_prob = prob;
    }
    observed_interfaces
}

#[cfg(test)]
mod tests {

    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;

    #[test]
    fn general_stopping_point_0_95() {
        let stopping_point_95: [usize; 63] = [
            1, 6, 11, 16, 21, 27, 33, 38, 44, 51, 57, 63, 70, 76, 83, 90, 96, 103, 110, 117, 124,
            131, 138, 145, 152, 159, 167, 174, 181, 189, 196, 203, 211, 218, 226, 233, 241, 248,
            256, 264, 271, 279, 287, 294, 302, 310, 318, 326, 333, 341, 349, 357, 365, 373, 381,
            389, 397, 405, 413, 421, 429, 437, 445,
        ];
        assert_eq!(
            (0..63)
                .map(|n| (n, stopping_point(n, 0.05)))
                .collect::<Vec<(usize, usize)>>(),
            (0..63)
                .map(|n| (n, stopping_point_95[n]))
                .collect::<Vec<(usize, usize)>>()
        )
    }

    #[test]
    fn general_stopping_point_0_99() {
        let stopping_point_99: [usize; 63] = [
            1, 8, 15, 21, 28, 36, 43, 51, 58, 66, 74, 82, 90, 98, 106, 115, 123, 132, 140, 149,
            157, 166, 175, 183, 192, 201, 210, 219, 228, 237, 246, 255, 264, 273, 282, 291, 300,
            309, 319, 328, 337, 347, 356, 365, 375, 384, 393, 403, 412, 422, 431, 441, 450, 460,
            470, 479, 489, 499, 508, 518, 528, 537, 547,
        ];
        assert_eq!(
            (0..63)
                .map(|n| (n, stopping_point(n, 0.01)))
                .collect::<Vec<(usize, usize)>>(),
            (0..63)
                .map(|n| (n, stopping_point_99[n]))
                .collect::<Vec<(usize, usize)>>()
        )
    }

    fn simulate_draw(rng: &mut ChaCha8Rng, n_interfaces: usize, n_probes: usize) -> usize {
        // compute the size of the distinct values set
        // after n_probes samples with replacement
        // from a uniform distribution of n_interfaces values

        let mut distinct_values = std::collections::HashSet::new();
        for _ in 0..n_probes {
            distinct_values.insert(rng.gen_range(0..n_interfaces));
        }
        distinct_values.len()
    }

    #[test]
    fn general_prob_simulation() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        for n_interfaces in 1..=7 {
            for n_probes in 1..=7 {
                for target_interfaces in 1..=n_interfaces.min(n_probes) {
                    let n_samples = 1_000;
                    let simulated_prob = (0..n_samples)
                        .map(|_| simulate_draw(&mut rng, n_interfaces, n_probes))
                        .filter(|&x| x == target_interfaces)
                        .count() as f64
                        / n_samples as f64;
                    let computed_prob = event_prob(n_interfaces, n_probes, target_interfaces);
                    let diff = (simulated_prob - computed_prob).abs();
                    assert!(
                        diff <= 0.05,
                        "n_interfaces: {} n_probes: {} target_interfaces: {} simulated: {} computed: {}", 
                        n_interfaces,
                        n_probes,
                        target_interfaces,
                        simulated_prob,
                        computed_prob
                    );
                }
            }
        }
    }

    #[test]
    fn estimate_total_interfaces_range() {
        // (n_probes, observed_interfaces, estimate)
        let expected = [
            (2, 1, 1),
            (3, 1, 1),
            (3, 2, 2),
            (4, 1, 1),
            (4, 2, 2),
            (4, 3, 5),
            (5, 1, 1),
            (5, 2, 2),
            (5, 3, 3),
            (5, 4, 8),
            (6, 1, 1),
            (6, 2, 2),
            (6, 3, 3),
            (6, 4, 6),
            (6, 5, 13),
            (7, 1, 1),
            (7, 2, 2),
            (7, 3, 3),
            (7, 4, 5),
            (7, 5, 8),
            (7, 6, 19),
            (8, 1, 1),
            (8, 2, 2),
            (8, 3, 3),
            (8, 4, 4),
            (8, 5, 7),
            (8, 6, 11),
            (8, 7, 25),
            (9, 1, 1),
            (9, 2, 2),
            (9, 3, 3),
            (9, 4, 4),
            (9, 5, 6),
            (9, 6, 9),
            (9, 7, 15),
            (9, 8, 33),
        ];
        for (n_probes, observed_interfaces, estimate) in expected.iter() {
            let result =
                estimate_total_interfaces(*n_probes, *observed_interfaces, LIKELIHOOD_THRESHOLD);
            assert_eq!(
                result, *estimate,
                "n_probes: {} observed_interfaces: {}, expected: {}, got {}",
                n_probes, observed_interfaces, estimate, result,
            );
        }
    }
}
