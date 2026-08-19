//! AES in ECB mode — the raw, block-at-a-time form.
//!
//! ECB has no chaining and no padding of its own: `plain` must already be a whole number of
//! 16-byte blocks (a caller pads with [`crate::util::pad`] first). Every block is encrypted
//! independently by the AES-128 core, which is exactly what makes ECB leak structure — identical
//! 16-byte inputs give identical 16-byte outputs.
//!
//! This is the encrypt half that the Set 2 oracle needs; the matching decrypt primitive already
//! lives in [`crate::sets::set1::l007`]. Only what a level has asked for is exposed here.

use crate::util::err::CpalError;

use aes::cipher::BlockEncrypt;
use aes::cipher::KeyInit;
use aes::Aes128;
use generic_array::GenericArray;

/// The AES block size in bytes.
const BLOCK: usize = 16;

/// AES-128-ECB-encrypt the already block-aligned `plain` under `key`.
///
/// `key` must be 16 bytes and `plain` a whole number of 16-byte blocks — pass PKCS#7-padded
/// plaintext, not a raw message.
///
/// # Errors
///
/// - [`CpalError::InvalidKeyLength`] when `key` is not 16 bytes, or
/// - [`CpalError::PlaintextNotBlockAligned`] when `plain` is not a multiple of 16.
///
/// # Examples
///
/// ```
/// use cryptopals::util::aes;
/// let key: [u8; 16] = *b"YELLOW SUBMARINE";
/// let plain = vec![0u8; 16];
/// // ECB is deterministic: the same padded block always gives the same ciphertext.
/// assert_eq!(aes::ecb_encrypt(&plain, &key).unwrap(), aes::ecb_encrypt(&plain, &key).unwrap());
/// ```
pub fn ecb_encrypt(plain: &[u8], key: &[u8]) -> Result<Vec<u8>, CpalError> {
    if key.len() != BLOCK {
        return Err(CpalError::InvalidKeyLength(key.len()));
    }
    if !plain.len().is_multiple_of(BLOCK) {
        return Err(CpalError::PlaintextNotBlockAligned(plain.len()));
    }

    let cipher = Aes128::new_from_slice(key).map_err(|_| CpalError::InvalidKeyLength(key.len()))?;

    let mut out = Vec::with_capacity(plain.len());
    for chunk in plain.chunks_exact(BLOCK) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(block.as_slice());
    }
    Ok(out)
}

#[cfg(test)]
mod ecb_encrypt_fn {
    use super::*;

    use crate::util::hex;

    const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";

    /// SP 800-38A F.2.1 AES-128 block-encryption known-answer.
    #[test]
    fn the_sp800_38a_block_vector_encrypts_to_its_known_ciphertext() {
        let key = hex::from_hex(KEY).unwrap();
        let plain = hex::from_hex("6bc1bee22e409f96e93d7e117393172a").unwrap();
        assert_eq!(
            ecb_encrypt(&plain, &key).unwrap(),
            hex::from_hex("3ad77bb40d7a3660a89ecaf32466ef97").unwrap()
        );
    }

    #[test]
    fn ecb_is_deterministic_and_repeats_identical_blocks() {
        let key = hex::from_hex(KEY).unwrap();
        let plain = vec![0u8; 48]; // three identical 16-byte zero blocks
        let ct = ecb_encrypt(&plain, &key).unwrap();
        let first = hex::from_hex("7df76b0c1ab899b33e42f047b91b546f").unwrap();
        assert_eq!(
            ct,
            first.iter().copied().cycle().take(48).collect::<Vec<_>>()
        );
        // The hallmark ECB leak: three identical plaintext blocks -> three identical ciphertext blocks.
        assert_eq!(&ct[0..16], &ct[16..32]);
    }

    #[test]
    fn a_key_that_is_not_sixteen_bytes_is_rejected() {
        let plain = [0u8; 16];
        assert_eq!(
            ecb_encrypt(&plain, &[0u8; 8]),
            Err(CpalError::InvalidKeyLength(8))
        );
    }

    #[test]
    fn a_ragged_plaintext_is_rejected() {
        let key = hex::from_hex(KEY).unwrap();
        assert_eq!(
            ecb_encrypt(&[0u8; 7], &key),
            Err(CpalError::PlaintextNotBlockAligned(7))
        );
    }
}
