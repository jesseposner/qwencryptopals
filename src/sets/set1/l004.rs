//! Set 1, Challenge 4 — Detect single-character XOR.
//!
//! A long hex dump mixes one `single-char-xored English` line with random
//! noise; `solve` finds that line by brute-forcing the 256 keys on every line
//! and keeping the candidate whose plaintext is the most English-ish.

use crate::util::err::CpalError;
use crate::util::freq;
use crate::util::hex;

/// Scan `lines` (one hex-encoded ciphertext per line) for the line that is
/// single-byte-XOR-encrypted English and return its `(index, key, plaintext)`.
///
/// `index` is the 0-based position of the winning line. The winner is the line
/// whose [`freq::best_single_byte_key`] plaintext carries the highest
/// [`freq::english_score`]; exact ties go to the earlier line.
///
/// # Errors
///
/// [`CpalError::NoLines`] when `lines` is empty, or a
/// [`crate::util::hex::from_hex`] error when a line is not valid hex.
pub fn solve(lines: &[&str]) -> Result<(usize, u8, Vec<u8>), CpalError> {
    let mut best: Option<(usize, u8, Vec<u8>, u32)> = None;

    for (i, line) in lines.iter().enumerate() {
        let ct = hex::from_hex(line)?;
        let (key, plain) = freq::best_single_byte_key(&ct);
        let score = freq::english_score(&plain);
        if best.as_ref().is_none_or(|b| score > b.3) {
            best = Some((i, key, plain, score));
        }
    }

    match best {
        Some((i, key, plain, _)) => Ok((i, key, plain)),
        None => Err(CpalError::NoLines),
    }
}

#[cfg(test)]
mod solve {
    use super::*;

    use proptest::prelude::*;

    const PANGRAMS: [&str; 4] = [
        "The quick brown fox jumps over the lazy dog",
        "Pack my box with five dozen liquor jugs",
        "Now that the party is jumping",
        "How vexingly quick daft zebras jump",
    ];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn empty_input_is_an_error() {
        assert_eq!(solve(&[]), Err(CpalError::NoLines));
    }

    #[test]
    fn invalid_hex_on_any_line_is_an_error() {
        let lines: Vec<&str> = vec!["0011", "zz"];
        assert_eq!(solve(&lines), Err(CpalError::InvalidHexChar('z')));
    }

    #[test]
    fn the_official_dump_yields_the_party_line() {
        let data = include_str!("../../../data/challenge_04.txt");
        let lines: Vec<&str> = data.lines().collect();
        let (idx, key, plain) = solve(&lines).expect("official dump has a winner");
        assert_eq!(idx, 170);
        assert_eq!(key, 0x35);
        assert_eq!(plain, "Now that the party is jumping\n".as_bytes());
    }

    proptest! {
        #[test]
        fn recovers_the_planted_line_among_noise(
            key in any::<u8>(),
            idx in 0..PANGRAMS.len(),
            noise in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 1..=64),
                3..=40,
            ),
            slot in 0usize..=40,
        ) {
            // Plant one xored-English line at `slot` among `n` random lines,
            // then check solve recovers that slot's index, key and exact plaintext.
            let n = noise.len();
            let slot = slot % (n + 1);
            let plain: Vec<u8> = PANGRAMS[idx].as_bytes().to_vec();
            let ct: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
            let mut lines = noise.clone();
            lines.insert(slot, ct);

            let strs: Vec<String> = lines.iter().map(|b| hex(b)).collect();
            let refs: Vec<&str> = strs.iter().map(|s| s.as_str()).collect();

            let (got_idx, got_key, got_plain) = solve(&refs).expect("valid hex never errors");
            prop_assert_eq!(got_idx, slot);
            prop_assert_eq!(got_key, key);
            prop_assert_eq!(got_plain, plain);
        }
    }
}
