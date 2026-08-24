//! Set 3, Challenge 23 - Clone an MT19937 RNG from its output.
//!
//! MT19937's 624-word internal state is never exposed directly: every output is a
//! *tempered* state word, not the word itself. The temper is invertible, so one full
//! batch of 624 consecutive outputs that begins at a twist boundary is exactly enough
//! to reconstruct the whole state: untemper each output back into its state word,
//! splice the 624 words into a fresh generator, and the clone is bit-for-bit the
//! original, producing every word the original would have produced from that point
//! on. The untemper and the splice live in [`crate::util::mt19937`]; this level is
//! the attack the challenge describes.
//!
//! The challenge's stop-and-think is what real deployments do about it: hash each
//! output before releasing it. One hash per draw destroys the invertibility and
//! with it the attack; the price is a hash per word.

use crate::util::mt19937::Mt19937;

/// Clone an MT19937 from its output: given one full batch of 624 consecutive outputs
/// that begins at a twist boundary, untemper each to recover the generator's state
/// and return a fresh generator spliced with that state.
///
/// The batch must be one complete pass, 624 draws from a freshly twisted state, so
/// the spliced state is exactly the generator's state after the batch and the
/// clone's next draw is the original's next output.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set3::l007;
/// use cryptopals::util::mt19937::Mt19937;
///
/// let mut original = Mt19937::new(5489);
/// let batch: [u32; 624] = (0..624).map(|_| original.next_u32()).collect::<Vec<_>>().try_into().unwrap();
/// let mut clone = l007::solve(&batch);
/// assert_eq!(clone.next_u32(), original.next_u32());
/// ```
pub fn solve(outputs: &[u32; 624]) -> Mt19937 {
    Mt19937::from_outputs(outputs)
}
#[cfg(test)]
mod solve {
    use super::*;
    use proptest::prelude::*;

    /// The first 5 words of seed 5489 after its first twist (stream words 624-628),
    /// pinned against the reference `std::mt19937` stream.
    const AFTER_FIRST_TWIST: [u32; 5] = [
        4_178_893_912,
        610_818_241,
        2_787_397_224,
        2_762_441_380,
        3_437_393_657,
    ];

    fn batch_of(seed: u32) -> [u32; 624] {
        let mut rng = Mt19937::new(seed);
        (0..624)
            .map(|_| rng.next_u32())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    #[test]
    fn a_clone_of_seed_5489_predicts_the_reference_second_pass() {
        let mut clone = solve(&batch_of(5489));
        let next: Vec<u32> = (0..5).map(|_| clone.next_u32()).collect();
        assert_eq!(next.as_slice(), AFTER_FIRST_TWIST);
    }

    #[test]
    fn a_clone_of_seed_0_tracks_a_fresh_generator() {
        let mut original = Mt19937::new(0);
        let batch: [u32; 624] = (0..624)
            .map(|_| original.next_u32())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let mut clone = solve(&batch);
        // 640 draws span the clone's own twist boundary, so its twist loop must agree
        // with the original's, not just its tempering.
        for _ in 0..640 {
            assert_eq!(clone.next_u32(), original.next_u32());
        }
    }

    proptest! {
        #[test]
        fn a_clone_stays_in_sync_across_the_next_twist(seed in any::<u32>()) {
            let mut original = Mt19937::new(seed);
            let batch: [u32; 624] = (0..624).map(|_| original.next_u32()).collect::<Vec<_>>().try_into().unwrap();
            let mut clone = solve(&batch);
            // 625 words span the clone's own twist boundary, so its twist loop must
            // agree with the original's, not just its tempering.
            for _ in 0..625 {
                prop_assert_eq!(clone.next_u32(), original.next_u32());
            }
        }
    }
}
