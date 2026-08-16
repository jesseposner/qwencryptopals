//! Shannon entropy over a byte histogram, normalized to `[0, 1]`.
//!
//! Used by the repeating-key level: at the true key length, each key position forms its own
//! column of mostly-English bytes (low entropy); at any other length the columns interleave
//! several key positions and scatter into a wider, higher-entropy value range.

/// Normalized Shannon entropy of `data`, in `[0.0, 1.0]`.
///
/// `0.0` when `data` is empty or holds a single repeated byte; `1.0` when every one of the 256
/// byte values is present in equal proportions. Computed from the byte-value histogram, so the
/// result depends only on the relative frequencies of the distinct byte values, not on the
/// order or the absolute length of `data`.
///
/// # Examples
///
/// ```
/// assert_eq!(cryptopals::util::entropy::normalized_shannon_entropy(b"\x01\x01"), 0.0);
/// ```
pub fn normalized_shannon_entropy(data: &[u8]) -> f64 {
    let n = data.len() as f64;
    if n == 0.0 {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let mut h = 0.0;
    for &c in &counts {
        let c = c as f64;
        if c > 0.0 {
            let p = c / n;
            h -= p * p.log2();
        }
    }
    h / 8.0 // log2(256): the maximum entropy a byte value distribution can carry.
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    #[test]
    fn empty_input_is_zero() {
        assert_eq!(normalized_shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn a_single_repeated_byte_is_zero() {
        assert_eq!(normalized_shannon_entropy(b"\x80\x80\x80"), 0.0);
    }

    #[test]
    fn two_distinct_equal_values_is_one_quarter_bit_of_an_byte() {
        assert!((normalized_shannon_entropy(b"\x00\xff") - 0.125).abs() < 1e-12);
    }

    #[test]
    fn the_uniform_byte_distribution_reaches_one() {
        let all: Vec<u8> = (0u8..=255).collect();
        assert!((normalized_shannon_entropy(&all) - 1.0).abs() < 1e-12);
    }

    proptest! {
        #[test]
        fn the_result_lies_in_the_unit_interval(data in any::<Vec<u8>>()) {
            let x = normalized_shannon_entropy(&data);
            prop_assert!((0.0_f64..=1.0).contains(&x));
        }

        #[test]
        fn repeating_a_sample_leaves_its_entropy_unchanged(
            sample in prop::collection::vec(any::<u8>(), 1..=32),
            times in 1..=16usize,
        ) {
            let repeated: Vec<u8> = sample.iter().cycle().take(sample.len() * times).copied().collect();
            prop_assert!(
                (normalized_shannon_entropy(&sample) - normalized_shannon_entropy(&repeated)).abs() < 1e-12,
                "repetition must not change relative frequencies"
            );
        }

        #[test]
        fn a_two_item_pair_is_zero_only_when_both_bytes_agree(x in any::<u8>(), y in any::<u8>()) {
            let pair = [x, y];
            if x == y {
                prop_assert_eq!(normalized_shannon_entropy(&pair), 0.0);
            } else {
                prop_assert!((normalized_shannon_entropy(&pair) - 0.125).abs() < 1e-12);
            }
        }
    }
}
