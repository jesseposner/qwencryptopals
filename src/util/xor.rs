//! Byte-wise XOR — the "fixed XOR" primitive reused across levels.
//!
//! Per the Cryptopals rule this is real cryptography on raw bytes, not a transport layer.

use crate::util::err::CpalError;

/// XOR two equal-length byte buffers byte-wise.
///
/// # Errors
///
/// Returns [`CpalError::LengthMismatch`] when the buffers differ in length.
///
/// # Examples
///
/// ```
/// assert_eq!(
///     cryptopals::util::xor::xor(b"abc", b"abb").unwrap(),
///     vec![0u8, 0, 1]
/// );
/// ```
pub fn xor(a: &[u8], b: &[u8]) -> Result<Vec<u8>, CpalError> {
    if a.len() != b.len() {
        return Err(CpalError::LengthMismatch {
            a: a.len(),
            b: b.len(),
        });
    }
    Ok(a.iter().zip(b).map(|(&x, &y)| x ^ y).collect())
}

#[cfg(test)]
mod xor_fn {
    use super::*;

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn is_commutative(pairs in prop::collection::vec((any::<u8>(), any::<u8>()), 0..=128)) {
            let (a, b): (Vec<u8>, Vec<u8>) = pairs.into_iter().unzip();
            prop_assert_eq!(xor(&a, &b), xor(&b, &a));
        }

        #[test]
        fn zeros_are_the_identity(a in prop::collection::vec(any::<u8>(), 0..=128)) {
            let zeros = vec![0u8; a.len()];
            prop_assert_eq!(xor(&a, &zeros), Ok(a));
        }

        #[test]
        fn a_byte_xorred_with_itself_is_zero(a in prop::collection::vec(any::<u8>(), 0..=128)) {
            let zeros = vec![0u8; a.len()];
            prop_assert_eq!(xor(&a, &a), Ok(zeros));
        }

        #[test]
        fn xor_twice_returns_the_first_input(pairs in prop::collection::vec((any::<u8>(), any::<u8>()), 0..=128)) {
            let (a, b): (Vec<u8>, Vec<u8>) = pairs.into_iter().unzip();
            let a_xor_b = xor(&a, &b).unwrap();
            prop_assert_eq!(xor(&a_xor_b, &b), Ok(a));
        }

        #[test]
        fn length_mismatch_is_reported(a in prop::collection::vec(any::<u8>(), 0..=128)) {
            let mut b = a.clone();
            b.push(0u8);
            prop_assert_eq!(xor(&a, &b), Err(CpalError::LengthMismatch { a: a.len(), b: a.len() + 1 }));
        }
    }
}
