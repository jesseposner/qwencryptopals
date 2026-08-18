//! AES in CBC mode — a block cipher chained over the ciphertext so that blocks depend on each
//! other. A block cipher turns one fixed-size block at a time; a real message is longer, so the
//! blocks are chained so each ciphertext block depends on the one before it.
//!
//! In CBC the chaining is done with XOR: before the first block is handed to the AES core it is
//! XORed with the *initialization vector* (IV), and from then on each plaintext block is XORed
//! with the *previous ciphertext block* before decryption. Decryption is the mirror image — each
//! ciphertext block is decrypted by the AES core, then XORed with the ciphertext block that
//! precedes it (or the IV for the first block). The payoff is that identical plaintext blocks no
//! longer map to identical ciphertext blocks the way they do under ECB.
//!
//! This builds straight on the AES-128 block core that Set 1 / L7 wrapped into the ECB primitive;
//! the chaining plus XOR is the part we hand-roll here. Only decryption is exposed, since that is
//! what the levels hand us to recover plaintext; the level adds the PKCS#7 unpad on top.

use crate::util::err::CpalError;

use aes::cipher::BlockDecrypt;
use aes::cipher::KeyInit;
use aes::Aes128;
use generic_array::GenericArray;

/// The AES block size in bytes.
const BLOCK: usize = 16;

/// AES-128-CBC-decrypt `ct` under `key` and `iv`, without touching any padding.
///
/// `key` must be 16 bytes and `iv` 16 bytes; `ct` must be a whole number of 16-byte blocks. Each
/// block is decrypted by the AES core and XORed with the ciphertext block that precedes it (the
/// IV for the first block). PKCS#7 padding, if the caller padded before encrypting, is left in
/// place; callers strip it with [`crate::util::pad::pkcs7_unpad`].
///
/// # Errors
///
/// - [`CpalError::InvalidIvLength`] when `iv` is not 16 bytes,
/// - [`CpalError::InvalidKeyLength`] when `key` is not 16 bytes, or
/// - [`CpalError::CiphertextNotBlockAligned`] when `ct` is not a multiple of 16.
///
/// # Examples
///
/// ```
/// use cryptopals::util::{cbc, hex};
/// let key = hex::from_hex("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
/// let iv = hex::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
/// let ct = hex::from_hex("7649abac8119b246cee98e9b12e9197d").unwrap();
///
/// assert_eq!(
///     cbc::decrypt(&ct, &key, &iv).unwrap(),
///     hex::from_hex("6bc1bee22e409f96e93d7e117393172a").unwrap()
/// );
/// ```
pub fn decrypt(ct: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CpalError> {
    if iv.len() != BLOCK {
        return Err(CpalError::InvalidIvLength(iv.len()));
    }
    if key.len() != BLOCK {
        return Err(CpalError::InvalidKeyLength(key.len()));
    }
    if !ct.len().is_multiple_of(BLOCK) {
        return Err(CpalError::CiphertextNotBlockAligned(ct.len()));
    }

    let cipher = Aes128::new_from_slice(key).map_err(|_| CpalError::InvalidKeyLength(key.len()))?;

    let mut out = Vec::with_capacity(ct.len());
    let mut prev = <[u8; BLOCK]>::try_from(iv).expect("iv is exactly 16 bytes");
    for block in ct.chunks_exact(BLOCK) {
        let mut buf = GenericArray::<u8, _>::clone_from_slice(block);
        cipher.decrypt_block(&mut buf);
        for (i, &b) in buf.iter().enumerate() {
            out.push(b ^ prev[i]);
        }
        prev = <[u8; BLOCK]>::try_from(block).expect("each chunk is exactly 16 bytes");
    }
    Ok(out)
}

#[cfg(test)]
mod cbc_decrypt_fn {
    use super::*;

    use crate::util::hex;

    const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
    const IV: &str = "000102030405060708090a0b0c0d0e0f";

    /// A single block's worth of the SP 800-38A vector, the reference chaining step.
    #[test]
    fn sp800_38a_first_block_roundtrips() {
        let key = hex::from_hex(KEY).unwrap();
        let iv = hex::from_hex(IV).unwrap();
        let ct = hex::from_hex("7649abac8119b246cee98e9b12e9197d").unwrap();
        assert_eq!(
            decrypt(&ct, &key, &iv).unwrap(),
            hex::from_hex("6bc1bee22e409f96e93d7e117393172a").unwrap()
        );
    }

    #[test]
    fn sp800_38a_four_blocks_decrypt_to_the_full_plaintext() {
        let key = hex::from_hex(KEY).unwrap();
        let iv = hex::from_hex(IV).unwrap();
        let ct = hex::from_hex(
            "7649abac8119b246cee98e9b12e9197d\
             5086cb9b507219ee95db113a917678b2\
             73bed6b8e3c1743b7116e69e22229516\
             cb23d7e6eb6ecdaf6a755dadd0d4de5a",
        )
        .unwrap();
        let pt = decrypt(&ct, &key, &iv).unwrap();
        assert_eq!(pt.len(), 64);
        assert_eq!(
            &pt[..16],
            &hex::from_hex("6bc1bee22e409f96e93d7e117393172a").unwrap()
        );
        assert_eq!(
            &pt[48..],
            &hex::from_hex("f6d9f03e3c1df715e3232eae6b0b4e22").unwrap()
        );
    }

    #[test]
    fn a_short_iv_is_rejected() {
        let key = hex::from_hex(KEY).unwrap();
        let ct = vec![0u8; 32];
        assert_eq!(
            decrypt(&ct, &key, &[0u8; 8]),
            Err(CpalError::InvalidIvLength(8))
        );
    }

    #[test]
    fn a_key_that_is_not_sixteen_bytes_is_rejected() {
        let key = vec![0u8; 8];
        let ct = vec![0u8; 32];
        let iv = vec![0u8; 16];
        assert_eq!(decrypt(&ct, &key, &iv), Err(CpalError::InvalidKeyLength(8)));
    }

    #[test]
    fn a_ragged_ciphertext_is_rejected() {
        let key = hex::from_hex(KEY).unwrap();
        let iv = vec![0u8; 16];
        assert_eq!(
            decrypt(&[0u8; 7], &key, &iv),
            Err(CpalError::CiphertextNotBlockAligned(7))
        );
    }
}
