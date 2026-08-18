//! Set 2 / Level 2 — Implement CBC mode.
//!
//! A block cipher can only transform one block at a time, so to move a real message we chain
//! blocks: each plaintext block is XORed with the *previous ciphertext* block before it is handed
//! to the cipher core, with the initialization vector (IV) standing in for the "previous" block of
//! the very first one. That chaining — the XOR plus the AES block core — is the whole of CBC; the
//! reusable piece lives in [`crate::util::cbc`]. This level just adds the transport around it: base64
//! decode on the way in, and a PKCS#7 unpad on the way out.
//!
//! The official blob is AES-128-CBC under the 16-byte key `b"YELLOW SUBMARINE"` with an IV of
//! sixteen zero bytes, and it is padded, so the recovered plaintext is the un-padded stream.

use crate::util::b64;
use crate::util::cbc;
use crate::util::err::CpalError;
use crate::util::pad;

/// The AES block size in bytes.
const AES_BLOCK_SIZE: usize = 16;

/// Decrypt a base64-encoded AES-128-CBC ciphertext under `key` and `iv`, then strip its PKCS#7
/// padding, returning the plaintext.
///
/// `key` must be 16 bytes and `iv` 16 bytes; the decoded ciphertext must be a whole number of
/// 16-byte blocks. The base64 payload may be wrapped across lines.
///
/// # Errors
///
/// - a [`crate::util::b64::b64_decode`] error,
/// - a [`crate::util::cbc::decrypt`] error (bad IV, key, or block alignment), or
/// - [`CpalError::BadPadding`] when the final PKCS#7 padding is malformed.
pub fn solve(encrypted_b64: &str, key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CpalError> {
    let ct = b64::b64_decode(encrypted_b64)?;
    let raw = cbc::decrypt(&ct, key, iv)?;
    pad::pkcs7_unpad(&raw, AES_BLOCK_SIZE)
}

#[cfg(test)]
mod solve {
    use super::*;

    use crate::util::b64;
    use crate::util::pad::pkcs7_pad;

    use aes::cipher::BlockEncrypt;
    use aes::cipher::KeyInit;
    use aes::Aes128;
    use generic_array::GenericArray;
    use proptest::prelude::*;

    /// AES-128-CBC-encrypt with PKCS#7 padding — the inverse of [`solve`]. Used only in tests to
    /// synthesise inputs so the level's decrypt is never verified against itself.
    fn encrypt_cbc(plain: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
        let cipher = Aes128::new_from_slice(key).expect("16-byte key");
        let padded = pkcs7_pad(plain, AES_BLOCK_SIZE).expect("block size 16");
        let mut out = Vec::with_capacity(padded.len());
        let mut prev: [u8; AES_BLOCK_SIZE] = iv.try_into().expect("16-byte iv");
        for block in padded.chunks_exact(AES_BLOCK_SIZE) {
            let mut xored = [0u8; AES_BLOCK_SIZE];
            for i in 0..AES_BLOCK_SIZE {
                xored[i] = block[i] ^ prev[i];
            }
            let mut buf = GenericArray::<u8, _>::clone_from_slice(&xored);
            cipher.encrypt_block(&mut buf);
            out.extend_from_slice(buf.as_slice());
            prev = buf
                .as_slice()
                .try_into()
                .expect("block is exactly 16 bytes");
        }
        out
    }

    const KEY: [u8; 16] = *b"YELLOW SUBMARINE";
    const IV: [u8; 16] = [0u8; 16];

    #[test]
    fn recovers_the_official_plaintext() {
        let blob = include_str!("../../../data/challenge_10.txt");
        let plain = solve(blob, &KEY, &IV).expect("the official blob is solvable");
        assert_eq!(plain.len(), 2876);
        assert!(plain.starts_with(b"I'm back and I'm ringin' the bell "));
        assert!(plain.ends_with(b"Play that funky music \n"));
    }

    #[test]
    fn a_short_iv_is_rejected() {
        let aligned = b64::b64_encode(&[0u8; 32]);
        assert_eq!(
            solve(&aligned, &KEY, &[0u8; 8]),
            Err(CpalError::InvalidIvLength(8))
        );
    }

    #[test]
    fn a_ragged_ciphertext_is_rejected() {
        let ragged = b64::b64_encode(&[0u8; 5]);
        assert_eq!(
            solve(&ragged, &KEY, &IV),
            Err(CpalError::CiphertextNotBlockAligned(5))
        );
    }

    #[test]
    fn malformed_padding_in_the_final_block_is_rejected() {
        // Craft a single ciphertext block whose decrypted (and IV-XORed) final byte is 0, an
        // illegal PKCS#7 pad value.
        let iv = [0u8; 16];
        let mut target = [0u8; 16];
        target[15] = 0; // last plaintext byte = 00 -> illegal pad
        let mut xored = [0u8; 16];
        for i in 0..AES_BLOCK_SIZE {
            xored[i] = target[i] ^ iv[i];
        }
        let cipher = Aes128::new_from_slice(&KEY).expect("16-byte key");
        let mut c = GenericArray::<u8, _>::clone_from_slice(&xored);
        cipher.encrypt_block(&mut c);

        let got = solve(&b64::b64_encode(&c), &KEY, &iv);
        assert_eq!(got, Err(CpalError::BadPadding(16)));
    }

    proptest! {
        #[test]
        fn decryption_inverts_encryption(
            key in prop::collection::vec(any::<u8>(), 16),
            iv in prop::collection::vec(any::<u8>(), 16),
            plain in prop::collection::vec(any::<u8>(), 1..=300),
        ) {
            let ct = encrypt_cbc(&plain, &key, &iv);
            let got = solve(&b64::b64_encode(&ct), &key, &iv)
                .expect("a well-formed CBC ciphertext must decrypt");
            prop_assert_eq!(got, plain);
        }
    }
}
