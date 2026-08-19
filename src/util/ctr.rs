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
//!
//! A fixed nonce is a serious error: when the counter restarts for every message, each message is
//! XORed against the *leading* bytes of the very same keystream, so `ct_a ^ ct_b == pt_a ^ pt_b`
//! and one known `(ciphertext, plaintext)` pair pins the shared prefix used by every message. This
//! module also carries the primitives that attack that misconfiguration:
//! [`shared_keystream`] and [`recover`].

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

/// The shared keystream pinned down by one known `(ciphertext, plaintext)` pair, recovered by
/// XORing the two over their length.
///
/// This is the whole point of the fixed-nonce CTR misconfiguration: because the counter restarts
/// for every message, every ciphertext's first bytes were XORed against this same keystream, so a
/// single known plaintext leaks the leading keystream those ciphertexts all depend on.
///
/// # Examples
///
/// ```
/// use cryptopals::util::ctr;
/// // A known pair pins the keystream: ciphertext XOR plaintext = keystream.
/// assert_eq!(
///     ctr::shared_keystream(&[3u8, 0, 7, 0, 1, 0], &[1, 0, 1, 0, 1, 0]),
///     vec![2, 0, 6, 0, 0, 0]
/// );
/// ```
pub fn shared_keystream(known_ct: &[u8], known_pt: &[u8]) -> Vec<u8> {
    known_ct
        .iter()
        .zip(known_pt)
        .map(|(&c, &p)| c ^ p)
        .collect()
}

/// Recover the plaintext bytes of each of `ciphertexts` from a single known
/// `(known_ct, known_pt)` pair, for a CTR stream where the nonce is fixed and the counter restarts
/// for each message.
///
/// The known pair yields the shared keystream via [`shared_keystream`]; that keystream is then
/// XORed into every ciphertext. The result keeps each ciphertext's length: a byte at position `i`
/// is decoded to plaintext only while the keystream still has a byte — `keystream[i]` — and bytes
/// past the keystream are left as ciphertext. So a known line as long as the longest target
/// recovers every target in full, and a shorter known line recovers only the overlapping prefix.
///
/// # Examples
///
/// ```
/// use cryptopals::util::ctr;
/// // A known (ciphertext, plaintext) pair pins the shared keystream.
/// let known = [3u8, 0, 7, 0, 1, 0];
/// let clear = [1u8, 0, 1, 0, 1, 0];
/// let ciphers = vec![known.to_vec(), vec![9, 0, 1, 0, 1, 0, 6, 0]];
/// let out = ctr::recover(&ciphers, &known, &clear);
/// // The known ciphertext recovers to its own plaintext...
/// assert_eq!(out[0], clear.to_vec());
/// // ...and the longer ciphertext is decoded over the shared prefix, its tail left as ciphertext.
/// assert_eq!(&out[1][0..6], [11, 0, 7, 0, 1, 0]); // 9^2, 0^0, 1^6, 0, 1, 0
/// assert_eq!(&out[1][6..], [6, 0]);
/// ```
pub fn recover(ciphertexts: &[Vec<u8>], known_ct: &[u8], known_pt: &[u8]) -> Vec<Vec<u8>> {
    let ks = shared_keystream(known_ct, known_pt);
    ciphertexts
        .iter()
        .map(|ct| {
            ct.iter()
                .enumerate()
                .map(|(i, &b)| match ks.get(i) {
                    Some(&k) => b ^ k,
                    None => b,
                })
                .collect()
        })
        .collect()
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

#[cfg(test)]
mod reuse_fn {
    use super::*;

    use crate::util::xor::xor;

    use proptest::prelude::*;

    #[test]
    fn the_known_pair_gives_ciphertext_xor_plaintext() {
        // The shared keystream is simply the byte-wise XOR of a known ciphertext and its plaintext;
        // check it matches the standalone xor primitive on an equal-length pair.
        let ct = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let pt = [8u8, 7, 6, 5, 4, 3, 2, 1];
        assert_eq!(shared_keystream(&ct, &pt), xor(&ct, &pt).unwrap());
    }

    #[test]
    fn a_known_ciphertext_recovers_to_its_own_plaintext() {
        // known_ct is the known plaintext with a constant mask applied, so the shared keystream is
        // that mask over the whole length and the recovery of the pair is exactly the plaintext.
        let known_pt: Vec<u8> = b"a message written in plaintext".to_vec();
        let known_ct: Vec<u8> = known_pt.iter().map(|&b| b ^ 0x5a).collect();
        let cts = vec![known_ct.clone()];
        assert_eq!(recover(&cts, &known_ct, &known_pt), vec![known_pt]);
    }

    #[test]
    fn bytes_past_the_keystream_are_left_as_ciphertext() {
        // The known pair pins a keystream the length of `known_ct`. A longer target is decoded over
        // that shared prefix and left as ciphertext from there on.
        let known_pt: Vec<u8> = b"short shared prefix".to_vec();
        let known_ct: Vec<u8> = known_pt.iter().map(|&b| b ^ 0x5a).collect();
        let long_ct: Vec<u8> = b"a much longer ciphered line, well past the shared prefix".to_vec();
        let cts = vec![known_ct.clone(), long_ct.clone()];
        let out = recover(&cts, &known_ct, &known_pt);

        // The known ciphertext always recovers to its own plaintext.
        assert_eq!(out[0], known_pt);

        let shared = known_ct.len();
        // Over the shared prefix the target decodes to plaintext: c ^ (kc ^ kp).
        let decoded: Vec<u8> = (0..shared)
            .map(|i| long_ct[i] ^ known_ct[i] ^ known_pt[i])
            .collect();
        assert_eq!(&out[1][0..shared], &decoded[..]);
        // Past the keystream the bytes are still the raw ciphertext.
        assert_eq!(&out[1][shared..], &long_ct[shared..]);
        assert!(long_ct.len() > shared);
    }

    proptest! {
        #[test]
        fn a_fixed_keystream_makes_pair_xor_linear(
            key in prop::collection::vec(any::<u8>(), 16),
            a in prop::collection::vec(any::<u8>(), 0..=300),
            b in prop::collection::vec(any::<u8>(), 0..=300),
        ) {
            // Fixed nonce 0, counter restarts: each message is its own CTR(., nonce 0) run.
            let ca = ctr(&a, &key, 0).unwrap();
            let cb = ctr(&b, &key, 0).unwrap();
            let n = a.len().min(b.len());
            let xor_cts: Vec<u8> = (0..n).map(|i| ca[i] ^ cb[i]).collect();
            let xor_pts: Vec<u8> = (0..n).map(|i| a[i] ^ b[i]).collect();
            // The shared keystream cancels, leaving plaintext XOR plaintext.
            prop_assert_eq!(xor_cts, xor_pts);
        }

        #[test]
        fn the_longest_known_line_covers_every_target(
            key in prop::collection::vec(any::<u8>(), 16),
            msgs in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..=300), 1..=12),
        ) {
            let cts: Vec<Vec<u8>> = msgs.iter().map(|m| ctr(m, &key, 0).unwrap()).collect();
            let longest = cts
                .iter()
                .enumerate()
                .max_by(|x, y| x.1.len().cmp(&y.1.len()))
                .map(|(i, _)| i)
                .unwrap();
            let out = recover(&cts, &cts[longest], &msgs[longest]);
            for (i, m) in msgs.iter().enumerate() {
                prop_assert_eq!(&out[i], m);
            }
        }
    }
}
