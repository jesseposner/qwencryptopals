//! Set 1, Challenge 8 — Detect AES in ECB mode.
//!
//! ECB is deterministic and stateless, so an identical 16-byte plaintext block always produces
//! an identical 16-byte ciphertext block. A ciphertext that was encrypted under ECB therefore
//! carries at least one repeated 16-byte block; a ciphertext under CBC (the other mode in play)
//! essentially never does. Scanning for a duplicated block exposes the ECB line.

use crate::util::err::CpalError;
use crate::util::hex;

/// The AES block size in bytes.
const BLOCK_SIZE: usize = 16;

/// Return the 0-based index of the first line (hex-encoded ciphertext) that contains a repeated
/// 16-byte block — the signature of ECB.
///
/// `index` is the 0-based position of the winning line within `lines`; the first matching line
/// wins when several do.
///
/// # Errors
///
/// [`CpalError::NoLines`] when `lines` is empty, a
/// [`crate::util::hex::from_hex`] error when a line is not valid hex, or
/// [`CpalError::NoRepeatedBlock`] when no line contains a repeated block.
pub fn solve(lines: &[&str]) -> Result<usize, CpalError> {
    if lines.is_empty() {
        return Err(CpalError::NoLines);
    }
    for (i, line) in lines.iter().enumerate() {
        let ct = hex::from_hex(line)?;
        if has_repeated_block(&ct) {
            return Ok(i);
        }
    }
    Err(CpalError::NoRepeatedBlock)
}

/// True when any 16-byte block of `ct` occurs two or more times.
fn has_repeated_block(ct: &[u8]) -> bool {
    let mut seen = std::collections::HashSet::new();
    for block in ct.chunks_exact(BLOCK_SIZE) {
        if !seen.insert(block) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod solve {
    use super::*;

    use proptest::prelude::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn empty_input_is_an_error() {
        assert_eq!(solve(&[]), Err(CpalError::NoLines));
    }

    #[test]
    fn a_single_block_has_no_repeat() {
        assert_eq!(
            solve(&["00112233445566778899aabbccddeeff"]),
            Err(CpalError::NoRepeatedBlock)
        );
    }

    #[test]
    fn the_official_set_flags_the_one_ecb_line() {
        let data = include_str!("../../../data/challenge_08.txt");
        let lines: Vec<&str> = data.lines().collect();
        let idx = solve(&lines).expect("the official set has one ECB line");
        assert_eq!(idx, 132);

        // No other line may carry the signature, or the detection would be a guess.
        let flagged: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| has_repeated_block(&hex::from_hex(line).expect("official hex")))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(flagged, vec![idx]);
    }

    proptest! {
        #[test]
        fn plants_one_ecb_line_and_recovers_its_index(
            n in 3..=40usize,
            slot in 0..=40usize,
            salt in 0u8..255,
            blocks_in_line in 3..=10usize,
        ) {
            let slot = slot % (n + 1);

            // `id` seeds each line's block bytes so that, for a fixed block index, no two lines
            // (and no two blocks within a line) collide; the planted line copies a block to force
            // exactly one duplicate.
            let line = |id: u8, dup: bool| {
                let mut out = Vec::new();
                for bl in 0..blocks_in_line {
                    let mut block = [0u8; 16];
                    let base = id.wrapping_mul(31).wrapping_add(bl as u8).wrapping_add(salt);
                    for (i, byte) in block.iter_mut().enumerate() {
                        *byte = base.wrapping_add(i as u8);
                    }
                    out.extend_from_slice(&block);
                }
                if dup {
                    for k in 0..BLOCK_SIZE {
                        out[BLOCK_SIZE + k] = out[k];
                    }
                }
                out
            };

            let mut strings: Vec<String> =
                (0..n as u8).map(|id| hex(&line(id, false))).collect();
            strings.insert(slot, hex(&line(n as u8, true)));
            let refs: Vec<&str> = strings.iter().map(|s| s.as_str()).collect();

            let got = solve(&refs).expect("valid hex never errors");
            prop_assert_eq!(got, slot);
        }
    }
}
