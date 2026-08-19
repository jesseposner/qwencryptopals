//! AES in CTR mode — the stream-cipher way to use a block cipher.
//!
//! Instead of encrypting the plaintext, CTR encrypts a running 16-byte *counter*: each counter
//! block is fed through the AES core to produce a 16-byte block of *keystream*, which is XORed
//! byte-for-byte against the plaintext. No chaining between blocks, no padding — when the message
//! runs out of bytes you simply stop, so the output is exactly as long as the input. Because XOR is
//! its own inverse, the very same function that encrypts also decrypts: generate the identical
//! keystream and XOR again.
//!
//! The 16-byte counter is a 64-bit nonce in the half, and a 64-bit little-endian block index in
//! the other half, so the keystream depends on both the key and the chosen nonce. This builds on
//! the AES-128 block core exactly as [`crate::util::cbc`] does, just XORing a counter instead of
//! the previous ciphertext block.

use crate::util::err::CpalError;

use aes::cipher::BlockEncrypt;
use aes::cipher::KeyInit;
use aes::Aes128;
use generic_array::GenericArray;

/// The AES block size in bytes.
const BLOCK: usize = 16;

/// AES-128-CTR-encrypt or -decrypt `stream` under `key`, using `nonce` as the 8-byte counter
/// prefix. Encrypting and decrypting are the identical operation: XOR the stream against the AES
/// keystream generated from `(nonce, block index)` blocks. The output has exactly the same length
/// as `stream` — CTR never pads.
///
/// `key` must be 16 bytes. `stream` may be any length, including empty; the final partial block is
/// XORed against the corresponding keystream bytes only.
///
/// # Errors
///
/// - [`CpalError::InvalidKeyLength`] when `key` is not 16 bytes.
///
/// # Examples
///
/// ```
/// use cryptopals::util::ctr;
/// let key: [u8; 16] = *b"YELLOW SUBMARINE";
/// let data = b"hello, CTR - a stream, not a stack of blocks";
/// let enc = ctr::ctr(data, &key, 0).unwrap();
/// assert!(enc.len() == data.len() && enc != data.to_vec());
/// assert_eq!(ctr::ctr(&enc, &key, 0).unwrap(), data.to_vec());
/// ```
pub fn ctr(stream: &[u8], key: &[u8], nonce: u64) -> Result<Vec<u8>, CpalError> {
    if key.len() != BLOCK {
        return Err(CpalError::InvalidKeyLength(key.len()));
    }

    let cipher = Aes128::new_from_slice(key).map_err(|_| CpalError::InvalidKeyLength(key.len()))?;
    let prefix = nonce.to_le_bytes();

    let mut out = Vec::with_capacity(stream.len());
    for (i, chunk) in stream.chunks(BLOCK).enumerate() {
        let mut counter = [0u8; BLOCK];
        counter[..8].copy_from_slice(&prefix);
        counter[8..].copy_from_slice(&(i as u64).to_le_bytes());

        let mut keystream = GenericArray::clone_from_slice(&counter);
        cipher.encrypt_block(&mut keystream);
        for (j, &b) in chunk.iter().enumerate() {
            out.push(b ^ keystream[j]);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod ctr_fn {
    use super::*;

    use crate::util::aes;
    use crate::util::hex;

    use proptest::prelude::*;

    const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";

    #[test]
    fn applying_ctr_twice_recovers_the_original_stream() {
        let key = hex::from_hex(KEY).unwrap();
        let stream = b"apply it, get some bytes back, apply it again - same bytes";
        let enc = ctr(stream, &key, 0).unwrap();
        assert_ne!(enc, stream.to_vec());
        assert_eq!(ctr(&enc, &key, 0).unwrap(), stream.to_vec());
    }

    /// With an all-zero stream and nonce 0, the first counter block is 16 zero bytes, so the first
    /// output block must equal plain AES-ECB encryption of that block — a cross-check on the
    /// counter layout against the already-vetted AES primitive.
    #[test]
    fn a_zero_nonce_block_agrees_with_ebc_on_the_same_zero_block() {
        let key = hex::from_hex(KEY).unwrap();
        let zeros = [0u8; BLOCK];
        let enc = ctr(&zeros, &key, 0).unwrap();
        assert_eq!(enc, aes::ecb_encrypt(&zeros, &key).unwrap());
    }

    #[test]
    fn the_output_is_exactly_as_long_as_the_input() {
        let key = hex::from_hex(KEY).unwrap();
        for len in [0usize, 1, 15, 16, 17, 47, 48, 49] {
            let stream = vec![0x42u8; len];
            assert_eq!(ctr(&stream, &key, 7).unwrap().len(), len, "length {len}");
        }
    }

    #[test]
    fn ctr_is_deterministic_for_fixed_inputs() {
        let key = hex::from_hex(KEY).unwrap();
        let stream = b"the same stream, the same key, the same nonce";
        assert_eq!(
            ctr(stream, &key, 42).unwrap(),
            ctr(stream, &key, 42).unwrap()
        );
    }

    #[test]
    fn a_different_nonce_yields_a_different_keystream() {
        let key = hex::from_hex(KEY).unwrap();
        let stream = b"a stream long enough that the whole keystream block matters";
        assert_ne!(ctr(stream, &key, 0).unwrap(), ctr(stream, &key, 1).unwrap());
    }

    #[test]
    fn a_key_that_is_not_sixteen_bytes_is_rejected() {
        assert_eq!(
            ctr(b"hello world", &[0u8; 8], 0),
            Err(CpalError::InvalidKeyLength(8))
        );
    }

    proptest! {
        #[test]
        fn ctr_is_involutive_at_any_length(
            key in prop::collection::vec(any::<u8>(), 16),
            stream in prop::collection::vec(any::<u8>(), 0..=400),
            nonce in any::<u64>(),
        ) {
            let enc = ctr(&stream, &key, nonce).unwrap();
            prop_assert_eq!(enc.len(), stream.len());
            prop_assert_eq!(ctr(&enc, &key, nonce).unwrap(), stream);
        }
    }
}
