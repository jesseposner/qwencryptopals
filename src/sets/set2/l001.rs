//! Set 2 / Level 1 — Implement PKCS#7 padding.
//!
//! A block cipher eats a fixed-size block but the messages we hand it are irregularly sized, so
//! we fill the final block out to a whole multiple of the block length. PKCS#7 does this by
//! appending `n` identical bytes, each of value `n`, where `n` is exactly enough to reach the
//! next block boundary; an already-aligned message still costs a full block. This is transport,
//! not cryptography: no confidentiality is in play yet.
//!
//! The canonical example pads `"YELLOW SUBMARINE"` (16 bytes) to a 20-byte block:
//! `{ 59 45 46 4c 4c 4f 57 20 53 55 42 4d 41 52 49 4e 45, 04, 04, 04, 04 }`.

use crate::util::err::CpalError;
use crate::util::pad;

/// Solve Level 1 (Set 2): PKCS#7-pad the ASCII `plaintext` to `block_size` and return the padded
/// bytes.
///
/// # Errors
///
/// Returns [`CpalError::InvalidBlockSize`] when `block_size` is not in `1..=255`.
pub fn solve(plaintext: &str, block_size: usize) -> Result<Vec<u8>, CpalError> {
    pad::pkcs7_pad(plaintext.as_bytes(), block_size)
}

#[cfg(test)]
mod tests {
    use super::solve;
    use crate::util::err::CpalError;
    use crate::util::pad::pkcs7_unpad;

    use proptest::prelude::*;

    #[test]
    fn yellow_submarine_padded_to_20_matches_the_official_example() {
        assert_eq!(
            solve("YELLOW SUBMARINE", 20).unwrap(),
            b"YELLOW SUBMARINE\x04\x04\x04\x04"
        );
    }

    #[test]
    fn an_already_aligned_message_gains_a_whole_block() {
        let padded = solve("YELLOW SUBMARINE", 16).unwrap();
        assert_eq!(padded.len(), 32);
        assert!(padded[16..].iter().all(|&b| b == 0x10));
    }

    #[test]
    fn out_of_range_block_sizes_are_rejected() {
        assert_eq!(solve("ab", 0), Err(CpalError::InvalidBlockSize(0)));
        assert_eq!(solve("ab", 256), Err(CpalError::InvalidBlockSize(256)));
    }

    proptest! {
        #[test]
        fn padded_then_unpadded_is_a_roundtrip(
            plaintext in any::<String>(),
            block_size in 1usize..=255,
        ) {
            let padded = solve(&plaintext, block_size).unwrap();
            prop_assert_eq!(padded.len() % block_size, 0);
            prop_assert_eq!(pkcs7_unpad(&padded, block_size), Ok(plaintext.into_bytes()));
        }

        #[test]
        fn out_of_range_block_sizes_rejected_for_arbitrary_input(
            plaintext in any::<String>(),
            block_size in prop_oneof![Just(0usize), Just(256)],
        ) {
            prop_assert_eq!(
                solve(&plaintext, block_size),
                Err(CpalError::InvalidBlockSize(block_size))
            );
        }
    }
}
