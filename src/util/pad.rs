//! PKCS#7 padding — fill a message out to a whole multiple of the block size.
//!
//! Padding is transport, not cryptography: it merely makes an irregularly-sized message whole
//! blocks long so a block cipher will eat it. [`pkcs7_pad`] and [`pkcs7_unpad`] are exact
//! inverses.

use crate::util::err::CpalError;

/// Pad `data` to the next multiple of `block_size` using PKCS#7.
///
/// `n = block_size - data.len() % block_size` bytes, each of value `n`, are appended. Because a
/// zero byte is not a legal pad value, an already-aligned `data` gains a *full* block of value
/// `block_size`.
///
/// # Errors
///
/// Returns [`CpalError::InvalidBlockSize`] when `block_size` is not in `1..=255`.
///
/// # Examples
///
/// ```
/// let padded = cryptopals::util::pad::pkcs7_pad(b"YELLOW SUBMARINE", 20).unwrap();
/// assert_eq!(&padded[..], b"YELLOW SUBMARINE\x04\x04\x04\x04");
/// ```
pub fn pkcs7_pad(data: &[u8], block_size: usize) -> Result<Vec<u8>, CpalError> {
    if !(1..=255).contains(&block_size) {
        return Err(CpalError::InvalidBlockSize(block_size));
    }
    let n = block_size - data.len() % block_size;
    let mut out = data.to_vec();
    out.resize(out.len() + n, n as u8);
    Ok(out)
}

/// Remove PKCS#7 padding from `data`, the inverse of [`pkcs7_pad`].
///
/// Reads the last byte `n`, requires `1 <= n <= block_size` and that the final `n` bytes are all
/// `n`, then returns `data` without those `n` bytes.
///
/// # Errors
///
/// - [`CpalError::InvalidBlockSize`] when `block_size` is not in `1..=255`.
/// - [`CpalError::BadPadding`] when `data` is empty, not a multiple of `block_size`, or its
///   padding bytes are malformed.
///
/// # Examples
///
/// ```
/// use cryptopals::util::pad::{pkcs7_pad, pkcs7_unpad};
/// let padded = pkcs7_pad(b"YELLOW SUBMARINE", 20).unwrap();
/// assert_eq!(pkcs7_unpad(&padded, 20).unwrap(), b"YELLOW SUBMARINE");
/// ```
pub fn pkcs7_unpad(data: &[u8], block_size: usize) -> Result<Vec<u8>, CpalError> {
    if !(1..=255).contains(&block_size) {
        return Err(CpalError::InvalidBlockSize(block_size));
    }
    if data.is_empty() || !data.len().is_multiple_of(block_size) {
        return Err(CpalError::BadPadding(data.len()));
    }
    let n = data[data.len() - 1] as usize;
    if n == 0 || n > block_size || !data[data.len() - n..].iter().all(|&b| b as usize == n) {
        return Err(CpalError::BadPadding(data.len()));
    }
    Ok(data[..data.len() - n].to_vec())
}

#[cfg(test)]
mod pkcs7_pad_fn {
    use super::*;

    use proptest::prelude::*;

    #[test]
    fn pads_to_the_next_multiple_of_the_block_size() {
        assert_eq!(
            pkcs7_pad(b"YELLOW SUBMARINE", 20).unwrap(),
            b"YELLOW SUBMARINE\x04\x04\x04\x04"
        );
    }

    #[test]
    fn already_aligned_data_gains_a_full_block() {
        let padded = pkcs7_pad(b"YELLOW SUBMARINE", 16).unwrap();
        assert_eq!(padded.len(), 32);
        assert!(padded[16..].iter().all(|&b| b == 0x10));
    }

    #[test]
    fn empty_data_pads_to_one_full_block() {
        assert_eq!(pkcs7_pad(b"", 8).unwrap(), vec![8u8; 8]);
    }

    proptest! {
        #[test]
        fn padded_length_is_a_multiple_of_and_at_least_the_input_length(
            data in prop::collection::vec(any::<u8>(), 0..=512),
            block_size in 1usize..=255,
        ) {
            let padded = pkcs7_pad(&data, block_size).unwrap();
            prop_assert_eq!(padded.len() % block_size, 0);
            prop_assert!(padded.len() >= data.len());
        }

        #[test]
        fn every_padding_byte_equals_the_number_of_padding_bytes(
            data in prop::collection::vec(any::<u8>(), 0..=512),
            block_size in 1usize..=255,
        ) {
            let padded = pkcs7_pad(&data, block_size).unwrap();
            let n = padded.len() - data.len();
            prop_assert!((1..=block_size).contains(&n));
            prop_assert!(padded[data.len()..].iter().all(|&b| b as usize == n));
        }

        #[test]
        fn invalid_block_sizes_are_reported(
            data in prop::collection::vec(any::<u8>(), 0..=16),
            block_size in prop_oneof![Just(0usize), Just(256), Just(1024)],
        ) {
            prop_assert_eq!(
                pkcs7_pad(&data, block_size),
                Err(CpalError::InvalidBlockSize(block_size))
            );
        }
    }
}

#[cfg(test)]
mod pkcs7_unpad_fn {
    use super::*;

    use proptest::prelude::*;

    #[test]
    fn removes_a_correct_full_block() {
        let mut buf = b"YELLOW SUBMARINE".to_vec();
        buf.extend(vec![0x10u8; 16]);
        assert_eq!(pkcs7_unpad(&buf, 16).unwrap(), b"YELLOW SUBMARINE");
    }

    #[test]
    fn empty_is_malformed() {
        assert_eq!(pkcs7_unpad(&[], 16), Err(CpalError::BadPadding(0)));
    }

    #[test]
    fn a_zero_last_byte_is_malformed() {
        assert_eq!(pkcs7_unpad(&[0u8; 16], 16), Err(CpalError::BadPadding(16)));
    }

    #[test]
    fn inconsistent_padding_bytes_are_malformed() {
        let mut buf = vec![0u8; 14];
        buf.extend_from_slice(&[3, 2]); // claims 2 bytes of padding, but the second-to-last is 3
        assert_eq!(pkcs7_unpad(&buf, 16), Err(CpalError::BadPadding(16)));
    }

    proptest! {
        #[test]
        fn roundtrips_pad(
            data in prop::collection::vec(any::<u8>(), 0..=512),
            block_size in 1usize..=255,
        ) {
            let padded = pkcs7_pad(&data, block_size).unwrap();
            prop_assert_eq!(pkcs7_unpad(&padded, block_size), Ok(data));
        }
    }
}
