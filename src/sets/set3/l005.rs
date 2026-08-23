//! Set 3, Challenge 21 - Implement the Mersenne Twister RNG.
//!
//! Most languages' `rand()` is the Mersenne Twister, and the challenge is to hand-roll the
//! machine instead of calling the library: the 624-word `u32` state, the seed-stretch
//! recurrence, the twist every 624 draws, the tempered output. The machine lives in
//! [`crate::util::mt19937`]; this level is the surface the challenge asks for: [`solve`]
//! stretches a seed and draws `count` consecutive 32-bit words, the "bunch of keys" the
//! challenge's follow-up builds on.
//!
//! The reference values the tests pin come from the canonical MT19937 stream (Matsumoto's
//! `mt19937ar.c`, the form `std::mt19937` runs: the state starts at index 624, so the very
//! first draw twists before it produces a word), so this implementation agrees word for word
//! with any reference, and with the state-recovery challenge that follows it.

use crate::util::mt19937::Mt19937;

/// Draw `count` consecutive 32-bit words from an MT19937 seeded with `seed`: the hand-rolled
/// replacement for the language's `rand()`, one draw at a time.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set3::l005;
///
/// let words = l005::solve(5489, 2);
/// assert_eq!(words, vec![3499211612, 581869302]);
/// ```
pub fn solve(seed: u32, count: u32) -> Vec<u32> {
    let mut rng = Mt19937::new(seed);
    (0..count).map(|_| rng.next_u32()).collect()
}

#[cfg(test)]
mod solve {
    use super::*;
    use proptest::prelude::*;

    /// The first 5 words of seed 5489, pinned against the reference `std::mt19937` stream.
    const REF_5489: [u32; 5] = [
        3_499_211_612,
        581_869_302,
        3_890_346_734,
        3_586_334_585,
        545_404_204,
    ];

    #[test]
    fn the_official_seed_reproduces_the_reference_stream() {
        assert_eq!(solve(5489, 5), REF_5489);
    }

    #[test]
    fn zero_draws_yield_an_empty_stream() {
        assert!(solve(5489, 0).is_empty());
    }

    proptest! {
        #[test]
        fn the_stream_has_exactly_the_requested_length(
            seed in any::<u32>(),
            count in 0..=1024u32,
        ) {
            prop_assert_eq!(solve(seed, count).len(), count as usize);
        }
    }
}
