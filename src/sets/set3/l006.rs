//! Set 3, Challenge 22 - Crack an MT19937 seed.
//!
//! An MT19937 seeded with a Unix timestamp is a vulnerability in waiting: the seed space is
//! "seconds since 1970", so an attacker who sees one output and roughly knows when it was
//! produced brute-forces the candidate timestamps in that window, matches the first draw of
//! each candidate against the observed word, and recovers the exact seed. The whole future
//! stream is then predictable. [`solve`] is that brute force: it works backward from the
//! observation time and returns the seed whose first output is the observed one.

use crate::util::err::CpalError;
use crate::util::mt19937::Mt19937;

/// The seconds searched back from the observation time: the challenge's 40-1000 s wait.
const WINDOW: u32 = 1000;

/// Crack an MT19937 seed: given the Unix time the output was observed at and the first 32-bit
/// word an MT19937 produced, recover the seed.
///
/// Seeds the [Mt19937](crate::util::mt19937::Mt19937) with each candidate Unix timestamp from
/// `current_unix_time` back `WINDOW` seconds and returns the first candidate whose first draw
/// matches `first_output`. The MT19937's seed-stretch plus first temper is deterministic, so
/// matching first words means matching seeds. Yields [`NoSeedFound`](crate::util::err::CpalError::NoSeedFound)
/// when no candidate in the window matches.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set3::l006;
///
/// // An MT19937 seeded with Unix time 1700000000 first outputs 1001043830.
/// let seed = l006::solve(1_700_000_040, 1_001_043_830).unwrap();
/// assert_eq!(seed, 1_700_000_000);
/// ```
pub fn solve(current_unix_time: u32, first_output: u32) -> Result<u32, CpalError> {
    (0..=WINDOW)
        .map(|back| current_unix_time.wrapping_sub(back))
        .find(|&seed| Mt19937::new(seed).next_u32() == first_output)
        .ok_or(CpalError::NoSeedFound)
}

#[cfg(test)]
mod solve {
    use super::*;

    #[test]
    fn recovers_a_seed_inside_the_window() {
        let seed = solve(1_700_000_040, 1_001_043_830).expect("the seed is 40 s back");
        assert_eq!(seed, 1_700_000_000);
    }

    #[test]
    fn recovers_a_seed_at_the_edge_of_the_window() {
        let seed = solve(1_717_001_000, 2_345_588_813).expect("the seed is WINDOW s back");
        assert_eq!(seed, 1_717_000_000);
    }

    #[test]
    fn a_seed_outside_the_window_is_not_found() {
        let err = solve(1_700_005_000, 1_001_043_830).expect_err("the seed is 5000 s back");
        assert_eq!(err, CpalError::NoSeedFound);
    }
}
