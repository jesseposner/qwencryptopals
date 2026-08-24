//! MT19937, the Mersenne Twister: the 624-word `u32` PRNG behind most languages' `rand()`.
//!
//! A single 32-bit seed stretches across the whole state with a multiply-xor-shift
//! recurrence (the `init_genrand` form, multiplier 1812433253). Every 624 draws the state is
//! *twisted*: each word is XORed with a mix of the word 397 ahead, and that mix's low bit
//! selects `MATRIX_A`. Each drawn word is then *tempered* with four shift/XOR passes that
//! spread any low-bit correlation across all 32 bits. The period is 2^19937 - 1, the
//! Mersenne prime the family is named for; 624 words of 32 bits give 19968 bits of state,
//! just past the period, which is what makes the distribution good.
//!
//! This is the reference form of Matsumoto's `mt19937ar.c`, the one C++'s `std::mt19937`
//! runs: the state starts at index `N`, so the very first draw twists before it produces a
//! word. It is not the older real-number `sgenrand` with its 69069 multiplier.
//!
//! [C21](crate::sets::set3::l005) hand-rolls this machine instead of calling a library, and
//! [C23](crate::sets::set3::l007) exploits it: the four-pass temper is invertible, so one
//! batch of 624 outputs reconstructs the whole 624-word state, and every later word falls out
//! of the clone. `untemper` and [`Mt19937::from_outputs`] carry that recovery; [C24](crate::sets::set3::l008)
//! wraps the same machine in a keystream cipher and brute-forces its 16-bit seed off a known tail.

/// The number of state words: 624 = 12 x 52, just past the 19937 bits of the 2^19937 - 1 period.
const N: usize = 624;

/// The twist lag: each word mixes with the word this many places ahead.
const M: usize = 397;

/// The matrix constant, XORed in when the twist mix's low bit is set.
const MATRIX_A: u32 = 0x9908_B0DF;

/// The seed-stretch multiplier of the `init_genrand` recurrence.
const SEED_MUL: u32 = 1_812_433_253;

/// The twist mix takes the high bit of one word and the low 31 of the next.
const UPPER: u32 = 0x8000_0000;
const LOWER: u32 = 0x7FFF_FFFF;

/// MT19937, the Mersenne Twister: a 624-word `u32` state machine with a 2^19937 - 1 period,
/// stretched from a single 32-bit seed.
///
/// # Examples
///
/// ```
/// let mut rng = cryptopals::util::mt19937::Mt19937::new(5489);
/// assert_eq!(rng.next_u32(), 3499211612);
/// ```
pub struct Mt19937 {
    state: [u32; N],
    idx: usize,
}

impl Mt19937 {
    /// Stretch `seed` across the 624-word state with the `init_genrand` recurrence.
    ///
    /// The reference convention: the state starts at index `N`, so the very first
    /// [`next_u32`] twists before it produces a word, exactly as `std::mt19937` does.
    pub fn new(seed: u32) -> Self {
        let mut state = [0u32; N];
        state[0] = seed;
        for i in 1..N {
            state[i] = SEED_MUL
                .wrapping_mul(state[i - 1] ^ (state[i - 1] >> 30))
                .wrapping_add(i as u32);
        }
        Self { state, idx: N }
    }

    /// The next 32-bit output: the next state word, tempered; when the 624 words are
    /// exhausted the state is twisted and the draw index restarts.
    pub fn next_u32(&mut self) -> u32 {
        if self.idx >= N {
            for k in 0..N {
                let y = (self.state[k] & UPPER) | (self.state[(k + 1) % N] & LOWER);
                self.state[k] =
                    self.state[(k + M) % N] ^ (y >> 1) ^ if y & 1 != 0 { MATRIX_A } else { 0 };
            }
            self.idx = 0;
        }
        let word = self.state[self.idx];
        self.idx += 1;
        temper(word)
    }

    /// Clone a generator from 624 consecutive outputs that begin at a twist boundary: untemper
    /// each to recover the raw state word, splice the 624 into a fresh state array, and position
    /// the instance to twist on its next draw. The captured block is one full pass (624 draws
    /// starting at the first word after a twist), so the spliced state is exactly the
    /// generator's current state and the clone's next draw is the original's next output.
    pub fn from_outputs(outputs: &[u32; 624]) -> Self {
        let mut state = [0u32; N];
        for i in 0..N {
            state[i] = untemper(outputs[i]);
        }
        Self { state, idx: N }
    }
}

/// The four-pass temper of one drawn word: each XOR-with-shift spreads the low-bit
/// correlation of the raw state word across all 32 bits.
fn temper(mut word: u32) -> u32 {
    word ^= word >> 11;
    word ^= (word << 7) & 0x9D2C5680;
    word ^= (word << 15) & 0xEFC60000;
    word ^= word >> 18;
    word
}
/// The inverse of the four-pass temper: recover a raw state word from a drawn output,
/// undoing the temper's operations in reverse order. A right shift inverts by cascading
/// until it runs past the word: `>> 11` needs a second `>> 22` step, but `>> 18` does
/// not (36 is past 32 bits). The masked left shifts are not self-inverse: the `<< 15`
/// step inverts with one reapplication, but the `<< 7` step is an order-8 permutation,
/// so its inverse is seven more.
pub fn untemper(mut word: u32) -> u32 {
    word ^= word >> 18;
    word ^= (word << 15) & 0xEFC60000;
    for _ in 0..7 {
        word ^= (word << 7) & 0x9D2C5680;
    }
    word ^= word >> 11;
    word ^= word >> 22;
    word
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    /// The first 10 words of seed 5489, pinned against the reference `std::mt19937` stream.
    const KAT_5489: [u32; 10] = [
        3_499_211_612,
        581_869_302,
        3_890_346_734,
        3_586_334_585,
        545_404_204,
        4_161_255_391,
        3_922_919_429,
        949_333_985,
        2_715_962_298,
        1_323_567_403,
    ];

    /// The first 5 words of seed 0.
    const KAT_0: [u32; 5] = [
        2_357_136_044,
        2_546_248_239,
        3_071_714_933,
        3_626_093_760,
        2_588_848_963,
    ];

    /// Words 623..625 of seed 5489: word 623 is the last of the first twisted pass, 624-625
    /// the first two of the second, so the triple straddles the twist boundary.
    const KAT_5489_BOUNDARY: [u32; 3] = [4_020_325_887, 4_178_893_912, 610_818_241];

    /// The 10 words of seed 5489 that follow the first twist: the second-pass stream, words
    /// 624-633. Pinned against a fresh build of the reference C.
    const KAT_5489_AFTER_TWIST: [u32; 10] = [
        4_178_893_912,
        610_818_241,
        2_787_397_224,
        2_762_441_380,
        3_437_393_657,
        2_030_369_078,
        1_949_046_312,
        1_876_612_561,
        1_857_107_382,
        1_049_344_864,
    ];

    /// The post-first-twist state of seed 5489, words 0-3, exactly as the reference C holds
    /// them after drawing 624 words.
    const STATE_5489_AFTER_TWIST: [u32; 4] = [0x9B0AFA27, 0xE99DE361, 0x87532B73, 0xC1FB51E3];

    fn stream(seed: u32, count: usize) -> Vec<u32> {
        let mut rng = Mt19937::new(seed);
        (0..count).map(|_| rng.next_u32()).collect()
    }

    #[test]
    fn the_seed_5489_stream_matches_the_reference() {
        assert_eq!(stream(5489, 10), KAT_5489);
    }

    #[test]
    fn the_seed_0_stream_matches_the_reference() {
        assert_eq!(stream(0, 5), KAT_0);
    }

    #[test]
    fn the_twist_boundary_of_seed_5489_is_pinned() {
        assert_eq!(stream(5489, 626)[623..], KAT_5489_BOUNDARY);
    }

    #[test]
    fn untempering_the_seed_5489_outputs_recovers_the_post_twist_state() {
        for i in 0..4 {
            assert_eq!(untemper(KAT_5489[i]), STATE_5489_AFTER_TWIST[i]);
        }
    }

    #[test]
    fn a_clone_from_the_first_batch_predicts_the_second_batch() {
        let captured: [u32; 624] = stream(5489, 624).try_into().unwrap();
        let mut spliced = Mt19937::from_outputs(&captured);
        let predicted: Vec<u32> = (0..10).map(|_| spliced.next_u32()).collect();
        assert_eq!(predicted.as_slice(), KAT_5489_AFTER_TWIST);
    }

    proptest! {
        #[test]
        fn two_instances_with_the_same_seed_are_identical(seed in any::<u32>()) {
            prop_assert_eq!(stream(seed, 64), stream(seed, 64));
        }

        #[test]
        fn different_seeds_diverge_at_the_first_output(a in any::<u32>(), b in any::<u32>()) {
            prop_assume!(a != b);
            let mut ra = Mt19937::new(a);
            let mut rb = Mt19937::new(b);
            prop_assert_ne!(ra.next_u32(), rb.next_u32());
        }
        #[test]
        fn untemper_inverts_temper(x in any::<u32>()) {
            prop_assert_eq!(untemper(temper(x)), x);
        }

        #[test]
        fn a_clone_stays_in_sync_across_a_batch(seed in any::<u32>()) {
            let stream = stream(seed, 640);
            let captured: [u32; 624] = stream[..624].try_into().unwrap();
            let mut spliced = Mt19937::from_outputs(&captured);
            for i in 0..16 {
                prop_assert_eq!(spliced.next_u32(), stream[624 + i]);
            }
        }

        #[test]
        fn the_top_byte_spreads_roughly_uniformly(seed in any::<u32>()) {
            let mut counts = [0u32; 256];
            for &word in &stream(seed, 4096) {
                counts[(word >> 24) as usize] += 1;
            }
            let expected = 4096.0 / 256.0;
            let chi2: f64 = counts
                .iter()
                .map(|&c| {
                    let c = c as f64;
                    (c - expected) * (c - expected) / expected
                })
                .sum();
            // chi-square with 255 degrees of freedom, mean 255; 600 is far in the tail,
            // so a genuine stream cannot reach it on 4096 draws.
            prop_assert!(chi2 <= 600.0, "chi2 {chi2}");
        }
    }
}
