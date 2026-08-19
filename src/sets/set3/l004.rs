//! Set 3, Challenge 20 — Detect block cipher mode.
//!
//! The challenge is a batch: eighty 64-byte AES-128 ciphertexts, some encrypted in ECB and some
//! in CBC, each under a random key. There is no live oracle and no key — the ciphertext is all
//! that can be seen. The same signal [C11](crate::sets::set2::l003) used decides it. ECB is a
//! pure block function of the plaintext, so two identical 16-byte plaintext blocks yield two
//! identical 16-byte ciphertext blocks; a CBC chain with a fresh IV scatters identical plaintext
//! blocks into different ciphertext blocks. So each ciphertext is classified on a single rule:
//! does any 16-byte block repeat? Repeat means ECB, otherwise CBC.
//!
//! The batch is minted in the crate, the way [C17](crate::sets::set3::l001) mints its cookies and
//! [C19](crate::sets::set3::l003) mints its ciphertexts: for an ECB line the 64-byte plaintext
//! repeats one 16-byte block, guaranteeing a repeated ciphertext block, and for a CBC line the
//! four blocks are all distinct under a random IV so no ciphertext block can realistically
//! repeat. The tests then confirm [`classify_batch`] recovers exactly the mode each line was
//! built under.

use crate::util::aes;
use crate::util::cbc;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;

/// The AES block size in bytes.
const BLOCK: usize = 16;

/// The ciphertext length of every minted line: four 16-byte blocks.
const LINE: usize = 64;

/// Which block mode a piece of ciphertext was produced under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockMode {
    /// Electronic Codebook: a deterministic per-block function of the plaintext.
    Ecb,
    /// Cipher Block Chaining: stateful; with a fresh IV, identical plaintext blocks never repeat
    /// in the ciphertext.
    Cbc,
}

/// Mint `batch` 64-byte AES-128 ciphertexts, seeded so they are reproducible: even-indexed lines
/// are ECB and odd-indexed lines are CBC.
///
/// This mirrors [C17](crate::sets::set3::l001)'s `make_cookie` and
/// [C19](crate::sets::set3::l003)'s in-memory ciphertexts: the batch lives in the crate, so the
/// tests can assert against it without a data file.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set3::l004::{mint, classify_batch, BlockMode};
///
/// let cts = mint(10, 0);
/// let refs: Vec<&[u8]> = cts.iter().map(|c| c.as_slice()).collect();
/// let modes = classify_batch(&refs);
/// assert!(modes.contains(&BlockMode::Ecb));
/// assert!(modes.contains(&BlockMode::Cbc));
/// ```
pub fn mint(batch: usize, seed: u64) -> Vec<Vec<u8>> {
    build(batch, seed).0
}

/// The headline answer to the challenge: classify each ciphertext in `cts` by the repeated-block
/// one line at a time, in order.
///
/// For a [`mint`]ed batch this returns exactly the mode each line was built under.
pub fn classify_batch(cts: &[&[u8]]) -> Vec<BlockMode> {
    cts.iter().map(|ct| classify(ct)).collect()
}

/// Classify a single ciphertext by the repeated-block rule: [`BlockMode::Ecb`] when two of its
/// 16-byte blocks are identical, [`BlockMode::Cbc`] otherwise.
pub fn classify(ct: &[u8]) -> BlockMode {
    if has_repeated_block(ct) {
        BlockMode::Ecb
    } else {
        BlockMode::Cbc
    }
}

/// True when any 16-byte block of `ct` appears two or more times — the ECB signature C11/L8 named.
fn has_repeated_block(ct: &[u8]) -> bool {
    let mut seen = std::collections::HashSet::new();
    for block in ct.chunks_exact(BLOCK) {
        if !seen.insert(block) {
            return true;
        }
    }
    false
}

/// Mint the batch and hand back the ciphertexts *and* the mode each was encrypted under, so the
/// tests can verify classification without a solver ever touching the keys or IVs.
fn build(batch: usize, seed: u64) -> (Vec<Vec<u8>>, Vec<BlockMode>) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut cts = Vec::with_capacity(batch);
    let mut modes = Vec::with_capacity(batch);

    for i in 0..batch {
        let key: [u8; BLOCK] = std::array::from_fn(|_| rng.gen());
        let ecb = i % 2 == 0;

        let plain = if ecb {
            // One 16-byte block repeated four times: its ECB image is four identical blocks.
            let shared: [u8; BLOCK] = std::array::from_fn(|_| rng.gen());
            let mut p = Vec::with_capacity(LINE);
            for _ in 0..4 {
                p.extend_from_slice(&shared);
            }
            p
        } else {
            // Four distinct 16-byte blocks; no ciphertext block will realistically repeat under a
            // fresh-IV CBC chain.
            let mut p = Vec::with_capacity(LINE);
            for _ in 0..4 {
                let block: [u8; BLOCK] = std::array::from_fn(|_| rng.gen());
                p.extend_from_slice(&block);
            }
            p
        };

        let ct = if ecb {
            aes::ecb_encrypt(&plain, &key).expect("64 aligned bytes, 16-byte key")
        } else {
            let iv: [u8; BLOCK] = std::array::from_fn(|_| rng.gen());
            cbc::encrypt(&plain, &key, &iv).expect("64 aligned bytes, 16-byte key and iv")
        };

        debug_assert_eq!(
            classify(&ct),
            (if ecb { BlockMode::Ecb } else { BlockMode::Cbc })
        );
        cts.push(ct);
        modes.push(if ecb { BlockMode::Ecb } else { BlockMode::Cbc });
    }

    (cts, modes)
}

#[cfg(test)]
mod solve {
    use super::*;

    use crate::util::entropy;
    use proptest::prelude::*;

    #[test]
    fn a_repeated_block_is_ecb_and_a_distinct_one_is_cbc() {
        let key = [9u8; 16];

        let mut ecb_plain = Vec::new();
        for _ in 0..4 {
            ecb_plain.extend_from_slice(&[3u8; 16]); // one block, repeated
        }
        let ecb_ct = aes::ecb_encrypt(&ecb_plain, &key).expect("64 bytes, 16-byte key");
        assert_eq!(classify(&ecb_ct), BlockMode::Ecb);

        let mut cbc_plain = Vec::new();
        for i in 0..4u8 {
            cbc_plain.extend_from_slice(&[i; 16]); // four distinct blocks
        }
        let cbc_ct =
            cbc::encrypt(&cbc_plain, &key, &[7u8; 16]).expect("64 bytes, 16-byte key + iv");
        assert_eq!(classify(&cbc_ct), BlockMode::Cbc);
    }

    #[test]
    fn a_ciphertext_shorter_than_two_blocks_is_cbc() {
        // One block can never contain a repeat.
        assert_eq!(classify(&[0u8; 16]), BlockMode::Cbc);
        assert_eq!(classify(&[]), BlockMode::Cbc);
    }

    #[test]
    fn classify_batch_recovers_the_minted_modes_for_all_eighty() {
        let (cts, modes) = build(80, 0);
        let refs: Vec<&[u8]> = cts.iter().map(|c| c.as_slice()).collect();
        assert_eq!(classify_batch(&refs), modes);
        let ecb = modes.iter().filter(|m| **m == BlockMode::Ecb).count();
        assert_eq!(ecb, 40);
    }

    #[test]
    fn the_mint_produces_sixty_four_byte_lines() {
        for seed in 0..32u64 {
            let cts = mint(80, seed);
            assert_eq!(cts.len(), 80, "seed {seed}");
            for (i, ct) in cts.iter().enumerate() {
                assert_eq!(ct.len(), LINE, "seed {seed}, line {i}");
                assert_eq!(ct.len() % BLOCK, 0, "seed {seed}, line {i}");
            }
        }
    }

    #[test]
    fn ecb_lines_carry_lower_entropy_than_cbc_lines() {
        // An ECB line is four identical 16-byte blocks, a narrow byte-value histogram; a fresh-IV
        // CBC line spreads near-uniformly. The entropy gap is the "why this works" behind the test.
        let (cts, modes) = build(400, 1);
        let avg = |xs: &[&[u8]]| {
            xs.iter()
                .map(|c| entropy::normalized_shannon_entropy(c))
                .sum::<f64>()
                / xs.len() as f64
        };
        let (mut ecb, mut cbc) = (Vec::new(), Vec::new());
        for (ct, mode) in cts.iter().zip(&modes) {
            match mode {
                BlockMode::Ecb => ecb.push(ct.as_slice()),
                BlockMode::Cbc => cbc.push(ct.as_slice()),
            }
        }
        assert!(
            avg(&ecb) < avg(&cbc),
            "ECB lines must be lower-entropy than CBC lines"
        );
    }

    proptest! {
        #[test]
        fn classification_matches_the_minted_mode_for_any_batch(
            seed in any::<u64>(),
            batch in 1usize..=128,
        ) {
            let (cts, modes) = build(batch, seed);
            let refs: Vec<&[u8]> = cts.iter().map(|c| c.as_slice()).collect();
            prop_assert_eq!(classify_batch(&refs), modes);
        }
    }
}
