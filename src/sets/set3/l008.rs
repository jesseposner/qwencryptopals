//! Set 3, Challenge 24 - Create an MT19937 stream cipher and break it.
//!
//! Any PRNG makes a trivial stream cipher: generate 8-bit outputs, call them
//! the keystream, and XOR the plaintext against it byte by byte. This level
//! does that with the Mersenne Twister from [L21](crate::sets::set3::l005),
//! seeded with 16 bits instead of 32: each 32-bit word contributes four
//! keystream bytes, low byte first. The cipher is one XOR, and XOR is its
//! own inverse, so `encrypt` is both the encrypt and the decrypt, the same
//! shape as the CTR code of [L18](crate::sets::set3::l002).
//!
//! The break is the seed size, not the machine. A 16-bit seed is 65536
//! candidates, and the challenge's known plaintext pins the check: encrypt
//! fourteen `A` bytes behind a random prefix of random characters, and the
//! ciphertext's last 14 bytes are those `A` bytes XORed with the last 14
//! keystream bytes. The attacker holds the whole ciphertext and the known
//! tail, so the recovery is a deterministic ascending scan of all 65536
//! seeds: decrypt the ciphertext with each candidate and keep the one whose
//! plaintext still ends in the known tail. A wrong seed XORs two different
//! keystreams into those 14 positions and looks random, so exactly one
//! seed matches. The challenge's "password reset token" half is the same
//! attack with a smaller candidate set: a token seeded from the current time
//! only ever took one of a few thousand seeds, and
//! [L22](crate::sets::set3::l006) scans that window.

use crate::util::err::CpalError;
use crate::util::mt19937::Mt19937;

/// The MT19937 stream cipher: XOR `plain` with the MT19937 keystream seeded
/// with `seed`, four bytes per word, low byte first. The result is the
/// ciphertext; XORing it again with the same seed recovers `plain`, exactly
/// like the AES-CTR cipher of [L18](crate::sets::set3::l002), so this single
/// function serves as both the encrypt and the decrypt.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set3::l008;
///
/// let ct = l008::encrypt(b"AAAA", 1234);
/// assert_eq!(ct, vec![110, 42, 70, 112]);
/// ```
pub fn encrypt(plain: &[u8], seed: u16) -> Vec<u8> {
    let mut rng = Mt19937::new(seed as u32);
    let mut out = Vec::with_capacity(plain.len());
    let mut word = 0u32;
    let mut byte_in_word = 4u32; // force a fresh word before the first byte
    for &b in plain {
        if byte_in_word == 4 {
            word = rng.next_u32();
            byte_in_word = 0;
        }
        out.push(b ^ ((word >> (8 * byte_in_word)) as u8));
        byte_in_word += 1;
    }
    out
}

/// Recover the 16-bit seed of a ciphertext produced by [`encrypt`]: the
/// known plaintext tail is what the attacker saw, and every candidate seed
/// is tried against it. Decrypt `ciphertext` with each of the 65536
/// candidate seeds and return the one whose plaintext ends with
/// `known_tail`. A wrong seed scrambles the tail with a different keystream,
/// so the match is essentially unique, and the ascending scan makes the
/// result deterministic.
///
/// # Errors
///
/// Returns [`CpalError::CiphertextTooShort`] when `ciphertext` is shorter
/// than `known_tail`, and [`CpalError::NoSeedFound`] when no 16-bit seed
/// reproduces the tail.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set3::l008;
///
/// let ct = l008::encrypt(b"qwencryptopalsAAAAAAAAAAAAAA", 0x5432);
/// assert_eq!(l008::solve(&ct, b"AAAAAAAAAAAAAA").unwrap(), 0x5432);
/// ```
pub fn solve(ciphertext: &[u8], known_tail: &[u8]) -> Result<u16, CpalError> {
    if ciphertext.len() < known_tail.len() {
        return Err(CpalError::CiphertextTooShort(ciphertext.len()));
    }
    for seed in 0..=u16::MAX {
        if encrypt(ciphertext, seed).ends_with(known_tail) {
            return Ok(seed);
        }
    }
    Err(CpalError::NoSeedFound)
}

#[cfg(test)]
mod solve {
    use super::*;
    use proptest::prelude::*;

    /// The first 16 keystream bytes of seed 0, low byte of each word first.
    const KSTREAM_0: [u8; 16] = [
        172, 10, 127, 140, 47, 170, 196, 151, 117, 166, 22, 183, 192, 204, 33, 216,
    ];

    /// The first 16 keystream bytes of seed 1.
    const KSTREAM_1: [u8; 16] = [
        37, 244, 193, 106, 235, 128, 71, 255, 140, 47, 103, 184, 72, 20, 188, 238,
    ];

    /// The known plaintext tail the challenge mints: fourteen `A` bytes.
    const TAIL: [u8; 14] = *b"AAAAAAAAAAAAAA";

    /// A deterministic plaintext that ends in the known tail but has no run
    /// of fourteen `A` bytes anywhere else, so no wrong seed's keystream can
    /// fake the tail.
    fn plaintext() -> Vec<u8> {
        let mut pt = b"qwencryptopals".to_vec();
        pt.extend_from_slice(&TAIL);
        pt
    }

    #[test]
    fn the_cipher_is_pinned() {
        assert_eq!(encrypt(b"AAAA", 1234), vec![110, 42, 70, 112]);
        // encrypting sixteen zero bytes is the raw keystream itself.
        assert_eq!(encrypt(&[0u8; 16], 0), KSTREAM_0.to_vec());
        assert_eq!(encrypt(&[0u8; 16], 1), KSTREAM_1.to_vec());
    }

    #[test]
    fn the_cipher_is_its_own_inverse() {
        let pt = plaintext();
        for seed in [0u16, 1, 0x5432, 0xFFFF] {
            assert_eq!(encrypt(&encrypt(&pt, seed), seed), pt);
        }
    }

    #[test]
    fn a_known_tail_reveals_the_16_bit_seed() {
        let ct = encrypt(&plaintext(), 0x5432);
        assert_eq!(solve(&ct, &TAIL).unwrap(), 0x5432);
    }

    #[test]
    fn a_ciphertext_without_the_known_tail_has_no_seed() {
        // No run of fourteen `A` bytes anywhere in this plaintext, so no
        // seed's keystream can turn the ciphertext's tail into the known one.
        let ct = encrypt(b"qwencryptopalsB", 0xBEEF);
        assert_eq!(solve(&ct, &TAIL), Err(CpalError::NoSeedFound));
    }

    #[test]
    fn a_ciphertext_shorter_than_the_known_tail_is_an_error() {
        let ct = encrypt(b"AAAA", 0x1234);
        assert_eq!(solve(&ct, &TAIL), Err(CpalError::CiphertextTooShort(4)));
    }

    proptest! {
        #[test]
        fn encrypting_twice_returns_the_plaintext(seed in any::<u16>(), plain in prop::collection::vec(any::<u8>(), 0..=64)) {
            let ct = encrypt(&plain, seed);
            prop_assert_eq!(encrypt(&ct, seed), plain);
        }
    }
}
