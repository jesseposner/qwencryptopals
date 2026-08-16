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

/// Repeating-key XOR (a.k.a. XORE): XOR `plain` with `key`, cycling back to the start of
/// `key` after each of its bytes has been applied.
///
/// Unlike [`xor`], the inputs need not be the same length: `key` repeats as far as it takes
/// to cover `plain`.
///
/// # Errors
///
/// Returns [`CpalError::EmptyKey`] when `key` is empty.
///
/// # Examples
///
/// ```
/// assert_eq!(
///     cryptopals::util::xor::xore(b"abcd", b"a").unwrap(),
///     vec![0u8, 3, 2, 5]
/// );
/// ```
pub fn xore(plain: &[u8], key: &[u8]) -> Result<Vec<u8>, CpalError> {
    if key.is_empty() {
        return Err(CpalError::EmptyKey);
    }
    let len = key.len();
    Ok(plain
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % len])
        .collect())
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

#[cfg(test)]
mod xore_fn {
    use super::*;

    use proptest::prelude::*;

    #[test]
    fn cycles_the_key_back_to_its_start() {
        assert_eq!(xore(b"abcdef", b"ab").unwrap(), vec![0, 0, 2, 6, 4, 4]);
    }

    #[test]
    fn an_empty_key_is_an_error() {
        assert_eq!(xore(b"abc", b""), Err(CpalError::EmptyKey));
    }

    #[test]
    fn an_empty_plain_gives_an_empty_result() {
        assert_eq!(xore(b"", b"abc").unwrap(), Vec::<u8>::new());
    }

    proptest! {
        #[test]
        fn xoring_twice_recovers_the_plaintext(
            plain in prop::collection::vec(any::<u8>(), 0..=64),
            key in prop::collection::vec(any::<u8>(), 1..=64),
        ) {
            let ct = xore(&plain, &key).expect("non-empty key");
            prop_assert_eq!(xore(&ct, &key), Ok(plain));
        }

        #[test]
        fn matches_explicitly_repeated_fixed_xor(
            plain in prop::collection::vec(any::<u8>(), 0..=64),
            key in prop::collection::vec(any::<u8>(), 1..=64),
        ) {
            // Independent oracle: repeat the key to plain's length, then use the fixed xor.
            let repeated: Vec<u8> = key.iter().cycle().take(plain.len()).copied().collect();
            prop_assert_eq!(xore(&plain, &key), xor(&plain, &repeated));
        }
    }
}
