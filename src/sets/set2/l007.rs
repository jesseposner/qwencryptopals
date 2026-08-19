//! Set 2, Challenge 15 — PKCS#7 padding validation.
//!
//! Padding is transport, not cryptography, but the boundary between **valid** and **malformed**
//! padding is the exact leak the Set 3 oracle exploits: a server that distinguishes the two cases
//! in its error response has just handed an attacker a padding bit. This level only nails the rule
//! down for the 16-byte AES block — a buffer is well-padded when its last byte `n` satisfies
//! `1 <= n <= 16` and its final `n` bytes are all `n` — and treats anything else as malformed.
//!
//! The canonical vectors, at a 16-byte block: `"ICE ICE BABY\x04\x04\x04\x04"` validates to
//! `"ICE ICE BABY"`; `"ICE ICE BABY\x05\x05\x05\x05"` is malformed (the last byte claims five pad
//! bytes, but only four trail it, and claiming five overruns the block); and
//! `"ICE ICE BABY\x01\x02\x03\x04"` is malformed (the four trailing bytes are not all equal).

use crate::util::err::CpalError;
use crate::util::pad;

/// The AES block size in bytes.
const BLOCK: usize = 16;

/// Unpad `data` and report its validity for the 16-byte AES block.
///
/// Returns `Ok(plaintext)` — the bytes with the pad run stripped — when `data` is a whole number
/// of blocks ending in legal PKCS#7, or `Err(CpalError::BadPadding(len))` when the padding is
/// malformed.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set2::l007;
/// assert_eq!(l007::solve(b"ICE ICE BABY\x04\x04\x04\x04"), Ok(b"ICE ICE BABY".to_vec()));
/// ```
pub fn solve(data: &[u8]) -> Result<Vec<u8>, CpalError> {
    pad::pkcs7_unpad(data, BLOCK)
}

#[cfg(test)]
mod padding_validation {
    use super::*;

    use crate::util::pad::pkcs7_pad;
    use proptest::prelude::*;

    #[test]
    fn four_matching_pad_bytes_validate_and_are_stripped() {
        assert_eq!(
            solve(b"ICE ICE BABY\x04\x04\x04\x04"),
            Ok(b"ICE ICE BABY".to_vec())
        );
    }

    #[test]
    fn a_pad_run_claimed_longer_than_present_is_malformed() {
        // Last byte 0x05 claims five pad bytes, but only four trail it in the 16-byte block.
        assert_eq!(
            solve(b"ICE ICE BABY\x05\x05\x05\x05"),
            Err(CpalError::BadPadding(16))
        );
    }

    #[test]
    fn non_identical_trailing_bytes_are_malformed() {
        // Four trailing bytes 01 02 03 04: not all equal, so not legal PKCS#7.
        assert_eq!(
            solve(b"ICE ICE BABY\x01\x02\x03\x04"),
            Err(CpalError::BadPadding(16))
        );
    }

    proptest! {
        #[test]
        fn pads_then_validates_roundtrip(
            data in prop::collection::vec(any::<u8>(), 0..=14),
        ) {
            let padded = pkcs7_pad(&data, BLOCK).expect("pads to a 16-byte block");
            prop_assert_eq!(solve(&padded).expect("freshly-padded data is valid"), data);
        }
    }
}
