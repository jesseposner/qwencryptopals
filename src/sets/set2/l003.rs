//! Set 2, Challenge 11 — An ECB/CBC detection oracle.
//!
//! The "black box" picks a random AES-128 key, prepends 5–10 random bytes and appends 5–10
//! random bytes to the caller's input, then encrypts the whole thing under either ECB or CBC
//! (chosen at random; CBC uses a fresh random IV). The key and IV are thrown away, so all the
//! caller is handed is ciphertext. The trick (from Set 1 / L8) is that ECB is deterministic: two
//! identical 16-byte plaintext blocks yield two identical 16-byte ciphertext blocks, whereas CBC's
//! fresh IV and chaining scatter them. So the detector just looks for the repeated-block signature.
//!
//! The oracle's random 5–10-byte prefix shifts where block boundaries fall, but feeding the box a
//! message with a long run of identical plaintext still lines up at least two blocks under ECB no
//! matter the shift — enough to spot it for sure.

use crate::util::aes;
use crate::util::cbc;
use crate::util::pad;

use rand::Rng;

/// The AES block size in bytes.
const BLOCK: usize = 16;

/// Which block mode a piece of ciphertext was produced under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockMode {
    /// Electronic Codebook: stateless, deterministic per block.
    Ecb,
    /// Cipher Block Chaining: stateful, a fresh IV per message.
    Cbc,
}

/// The challenge's black box: encrypt `input` under a random key, wrapping it in 5–10 random bytes
/// of padding on each side, under a randomly chosen block mode (CBC with a fresh random IV).
///
/// Only the ciphertext is returned — the key and IV never leak, so the caller cannot decrypt it or
/// re-encrypt it themselves.
pub fn oracle(input: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    build(input, rng).0
}

/// Point [`oracle`] at `input` and call out which block mode it used this round.
///
/// This is the headline answer to the challenge: given only the black box's output, decide ECB or
/// CBC. Feeding `input` a long run of identical bytes guarantees a repeat under ECB, so the call
/// is reliable for either mode.
pub fn solve(input: &[u8], rng: &mut impl Rng) -> BlockMode {
    detect_mode(&oracle(input, rng))
}

/// The detection core (Set 1 / L8's repeated-block rule, generalized to a single ciphertext): it
/// reports [`BlockMode::Ecb`] when the ciphertext carries two identical 16-byte blocks, and
/// [`BlockMode::Cbc`] otherwise.
pub fn detect_mode(ct: &[u8]) -> BlockMode {
    if has_repeated_block(ct) {
        BlockMode::Ecb
    } else {
        BlockMode::Cbc
    }
}

/// True when any 16-byte block of `ct` occurs two or more times.
fn has_repeated_block(ct: &[u8]) -> bool {
    let mut seen = std::collections::HashSet::new();
    for block in ct.chunks_exact(BLOCK) {
        if !seen.insert(block) {
            return true;
        }
    }
    false
}

/// Run [`oracle`] and hand back the mode it chose, alongside the ciphertext.
fn build(input: &[u8], rng: &mut impl Rng) -> (Vec<u8>, BlockMode) {
    let key = random_block(rng);
    let prefix_len = rng.gen_range(5..=10);
    let suffix_len = rng.gen_range(5..=10);
    let prefix: Vec<u8> = (0..prefix_len).map(|_| rng.gen()).collect();
    let suffix: Vec<u8> = (0..suffix_len).map(|_| rng.gen()).collect();
    let mode = if rng.gen::<bool>() {
        BlockMode::Ecb
    } else {
        BlockMode::Cbc
    };

    let mut plain = Vec::with_capacity(prefix_len + input.len() + suffix_len + BLOCK);
    plain.extend_from_slice(&prefix);
    plain.extend_from_slice(input);
    plain.extend_from_slice(&suffix);
    let padded = pad::pkcs7_pad(&plain, BLOCK).expect("block size is 16, well inside 1..=255");

    let ct = match mode {
        BlockMode::Ecb => aes::ecb_encrypt(&padded, &key).expect("padded, 16-byte key"),
        BlockMode::Cbc => {
            let iv = random_block(rng);
            cbc::encrypt(&padded, &key, &iv).expect("padded, 16-byte key and iv")
        }
    };
    (ct, mode)
}

/// A random 16-byte block, used for the AES key and the CBC IV.
fn random_block(rng: &mut impl Rng) -> [u8; BLOCK] {
    std::array::from_fn(|_| rng.gen())
}

#[cfg(test)]
mod solve {
    use super::*;

    use proptest::prelude::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn seeded(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    /// A long run of a single byte: under ECB it forces a repeated 16-byte block for any of the
    /// oracle's 5–10-byte prefix shifts; under CBC it never does.
    const REPEATED_INPUT: [u8; 256] = [b'A'; 256];

    #[test]
    fn an_ecb_ciphertext_with_a_repeat_is_detected_as_ecb() {
        let key = [0u8; 16];
        let plain = vec![0x07u8; 64]; // four identical 16-byte blocks
        let ct = aes::ecb_encrypt(&plain, &key).expect("aligned, 16-byte key");
        assert_eq!(detect_mode(&ct), BlockMode::Ecb);
    }

    #[test]
    fn the_same_run_under_cbc_is_detected_as_cbc() {
        let key = [0u8; 16];
        let iv = [1u8; 16];
        let plain = vec![0x07u8; 64]; // four identical 16-byte blocks
        let ct = cbc::encrypt(&plain, &key, &iv).expect("aligned, 16-byte key and iv");
        assert_eq!(detect_mode(&ct), BlockMode::Cbc);
    }

    #[test]
    fn a_ciphertext_shorter_than_two_blocks_is_cbc() {
        // One block can never contain a repeat.
        assert_eq!(detect_mode(&[0u8; 16]), BlockMode::Cbc);
        assert_eq!(detect_mode(&[]), BlockMode::Cbc);
    }

    #[test]
    fn the_oracle_emits_valid_block_aligned_ciphertexts() {
        for seed in 0..64 {
            let mut rng = seeded(seed);
            let ct = oracle(b"hello world", &mut rng);
            assert!(!ct.is_empty(), "seed {seed}");
            assert_eq!(ct.len() % BLOCK, 0, "seed {seed}");
        }
    }

    #[test]
    fn solve_calls_out_the_oracles_actual_mode_across_seeds() {
        // `oracle` is `build(...).0`, so two streams from the same seed pick the same mode. Compare
        // the mode the oracle chose against what `solve` concludes from its ciphertext.
        for seed in 0..256 {
            let mode = {
                let mut probe = seeded(seed);
                build(&REPEATED_INPUT, &mut probe).1
            };
            let mut rng = seeded(seed);
            let detected = solve(&REPEATED_INPUT, &mut rng);
            assert_eq!(detected, mode, "seed {seed}");
        }
    }

    proptest! {
        #[test]
        fn detection_matches_the_oracle_for_any_long_repeated_input(
            seed in any::<u64>(),
            len in 64usize..=512,
        ) {
            let input = vec![b'B'; len];
            let mut rng = StdRng::seed_from_u64(seed);
            let (ct, mode) = build(&input, &mut rng);
            prop_assert!(detect_mode(&ct) == mode, "mode mismatch at seed {seed}, len {len}");
        }
    }
}
