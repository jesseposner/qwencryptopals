//! Set 1, Challenge 7 — AES-128 in ECB mode.
//!
//! The base64 blob is AES-128-ECB ciphertext under a 16-byte key. ECB is a block mode: every
//! 16-byte block encrypts/independently decrypts with no chaining, so the ciphertext is just
//! `n` back-to-back decrypted blocks.

use crate::util::b64;
use crate::util::err::CpalError;

use aes::cipher::BlockDecrypt;
use aes::cipher::KeyInit;
use aes::Aes128;
use generic_array::GenericArray;

/// The AES block size in bytes.
const AES_BLOCK_SIZE: usize = 16;

/// Decrypt a base64-encoded AES-128 ECB ciphertext under `key` and return the plaintext.
///
/// `key` must be exactly 16 bytes; the decoded ciphertext must be a whole number of 16-byte
/// blocks. The base64 payload may be wrapped across lines.
///
/// # Errors
///
/// - a [`crate::util::b64::b64_decode`] error,
/// - [`CpalError::CiphertextNotBlockAligned`] when the ciphertext is not 16-byte aligned, or
/// - [`CpalError::InvalidKeyLength`] when `key.len() != 16`.
pub fn solve(encrypted_b64: &str, key: &[u8]) -> Result<Vec<u8>, CpalError> {
    let ct = b64::b64_decode(encrypted_b64)?;
    if ct.len() % AES_BLOCK_SIZE != 0 {
        return Err(CpalError::CiphertextNotBlockAligned(ct.len()));
    }
    if key.len() != AES_BLOCK_SIZE {
        return Err(CpalError::InvalidKeyLength(key.len()));
    }

    let cipher = Aes128::new_from_slice(key).map_err(|_| CpalError::InvalidKeyLength(key.len()))?;

    let mut out = Vec::with_capacity(ct.len());
    for chunk in ct.chunks_exact(AES_BLOCK_SIZE) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        out.extend_from_slice(block.as_slice());
    }
    Ok(out)
}

#[cfg(test)]
mod solve {
    use super::*;

    use crate::util::b64;
    use crate::util::hex;

    use aes::cipher::BlockEncrypt;
    use proptest::prelude::*;

    const KEY: [u8; 16] = *b"YELLOW SUBMARINE";

    /// AES-128-ECB encrypt, used only here to synthesise inputs for the round-trip property;
    /// it mirrors how the official blob was produced so `solve` is never tested against its own
    /// decrypt path alone.
    fn encrypt_ecb(key: &[u8], data: &[u8]) -> Vec<u8> {
        let cipher = Aes128::new_from_slice(key).expect("16-byte test key");
        data.chunks_exact(AES_BLOCK_SIZE)
            .flat_map(|chunk| {
                let mut block = GenericArray::clone_from_slice(chunk);
                cipher.encrypt_block(&mut block);
                block.to_vec()
            })
            .collect()
    }

    #[test]
    fn the_fips_197_vector_decrypts_to_its_known_plaintext() {
        let key = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let ciphertext =
            hex::from_hex("69c4e0d86a7b0430d8cdb78070b4c55a").expect("FIPS-197 vector");
        let plain = solve(&b64::b64_encode(&ciphertext), &key).expect("valid input must not error");
        assert_eq!(
            plain,
            [
                0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );
    }

    #[test]
    fn recovers_the_official_plaintext() {
        let blob = include_str!("../../../data/challenge_07.txt");
        let plain = solve(blob, &KEY).expect("the official blob is solvable");
        assert!(plain.starts_with(b"I'm back and I'm ringin' the bell"));
    }

    #[test]
    fn a_key_that_is_not_sixteen_bytes_is_rejected() {
        let aligned = b64::b64_encode(&[0u8; 16]);
        assert_eq!(
            solve(&aligned, &[0u8; 8]),
            Err(CpalError::InvalidKeyLength(8))
        );
    }

    #[test]
    fn a_ciphertext_that_is_not_block_aligned_is_rejected() {
        let ragged = b64::b64_encode(&[0u8; 5]);
        assert_eq!(
            solve(&ragged, &KEY),
            Err(CpalError::CiphertextNotBlockAligned(5))
        );
    }

    proptest! {
        #[test]
        fn decryptions_invert_encryptions(
            key in prop::collection::vec(any::<u8>(), 16),
            plain in prop::collection::vec(any::<u8>(), 16..=320),
        ) {
            let align = plain.len() - plain.len() % AES_BLOCK_SIZE;
            let plain: Vec<u8> = plain.into_iter().take(align).collect();
            let ciphertext = encrypt_ecb(key.as_slice(), &plain);
            let got = solve(&b64::b64_encode(&ciphertext), key.as_slice()).expect("valid input must not error");
            prop_assert_eq!(got, plain);
        }
    }
}
