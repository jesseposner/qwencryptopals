//! Set 2, Challenge 12 — Byte-at-a-time AES-ECB decryption.
//!
//! The oracle mirrors [L11's black box](crate::sets::set2::l003) but locks the mode to ECB and
//! hands it a *consistent* key — a single key that is assigned once, never changes, yet is never
//! revealed to the caller. Before encrypting, it appends a fixed secret string to whatever input
//! you supply, so every call returns
//!
//! ```text
//! AES-128-ECB(your-input || unknown-string, KEY)
//! ```
//!
//! The secret is stored as a base64 blob; the oracle decodes it in code (never by hand), so its
//! contents are "unknown." The attack leans on the exact flaw L8 exposed: ECB is per-block and
//! deterministic, so identical 16-byte plaintext blocks map to the same 16-byte ciphertext block,
//! wherever they sit. To read the unknown string, line each next unknown byte up as the final byte
//! of a 16-byte block whose other fifteen bytes you already know (controlled filler for the first
//! block, earlier recovered bytes thereafter), then brute-force that byte 0–255 by re-invoking the
//! oracle — whichever candidate reproduces the observed block is the byte. Slide the window
//! forward one byte at a time and the whole unknown string falls out.
//!
//! The block size (16) and padding (PKCS#7) are "discovered" here the way the challenge prescribes
//! — see [`unknown_len`] — but since it is AES-128 the values are already known, matching L9 and
//! L11's handling.
//!
//! [`oracle`] is the black box; [`solve`] runs the byte-at-a-time attack against it and returns the
//! fully recovered unknown string.

use crate::util::aes;
use crate::util::b64;
use crate::util::pad;

/// The AES block size in bytes.
const BLOCK: usize = 16;

/// The oracle's AES key: consistent (fixed once, used by every call) but unknown to the solver.
/// It is a fixed value only so the challenge is reproducible — never exposed or read back.
const KEY: [u8; 16] = [7, 3, 9, 5, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];

/// The filler byte the attack sends to align block boundaries.
const FILLER: u8 = b'A';

/// The challenge's secret, kept base64-encoded so its contents are not read here. The oracle
/// decodes this and appends it before encrypting; the solver must recover it byte by byte.
const TARGET: &str = "\
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
";

/// The L12 oracle: append the (base64-decoded) unknown string to `input`, PKCS#7-pad the result to
/// 16-byte blocks, and encrypt the whole thing under the fixed ECB [`KEY`].
///
/// Only ciphertext is returned — the key and the unknown string both stay inside the box.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set2::l004;
/// // ECB is deterministic, so the same input always yields the same ciphertext.
/// assert_eq!(l004::oracle(b"hi"), l004::oracle(b"hi"));
/// ```
pub fn oracle(input: &[u8]) -> Vec<u8> {
    let mut plain = input.to_vec();
    plain.extend_from_slice(&target_bytes());
    let padded = pad::pkcs7_pad(&plain, BLOCK).expect("block size 16 is inside 1..=255");
    aes::ecb_encrypt(&padded, &KEY).expect("padded, 16-byte key")
}

/// Run the byte-at-a-time attack against [`oracle`] and return the recovered unknown string.
///
/// This is the headline answer: given only the black box's ciphertexts, read off, one byte at a
/// time, the exact secret the oracle keeps appending.
pub fn solve() -> Vec<u8> {
    recover(unknown_len(), &|input| oracle(input))
}

/// How many bytes the oracle appends after its own input.
///
/// `oracle`-ciphertext length is always `(len(input) + unknown_len)` PKCS#7-rounded up to a whole
/// multiple of 16. Feeding `0..=16` distinct input lengths walks every residue mod 16, so the
/// padding added ranges over `1..=16`; the minimum of `ciphertext_len - input_len` is therefore
/// `unknown_len + 1`.
fn unknown_len() -> usize {
    (0..=BLOCK)
        .map(|len| oracle(&vec![FILLER; len]).len() - len)
        .min()
        .expect("at least one sample")
        - 1
}

/// The byte-at-a-time core.
///
/// `total` is the number of unknown bytes to recover and `enc` is any block-aligned 16-byte ECB
/// black box that appends a fixed secret before encrypting (here, [`oracle`]).
///
/// For the byte at position `k`, the 15 known bytes immediately before it are: `15 - k` filler
/// bytes plus `k` already-recovered bytes (while `k < 16`), or the last 15 recovered bytes (once
/// `k >= 16`). Lining byte `k` up as the final byte of a block is just a matter of feeding `15 -
/// (k % 16)` filler bytes, which drops that block onto index `(left + k) / 16`. The candidate
/// bytes are then probed one at a time; the one whose encryption matches the observed block is
/// the byte.
fn recover(total: usize, enc: &dyn Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let mut recovered = Vec::with_capacity(total);
    for k in 0..total {
        let mut known15 = if k < BLOCK {
            vec![FILLER; BLOCK - 1 - k]
        } else {
            Vec::with_capacity(BLOCK - 1)
        };
        if k < BLOCK {
            known15.extend_from_slice(&recovered[..k]);
        } else {
            known15.extend_from_slice(&recovered[k - (BLOCK - 1)..k]);
        }

        // Feed `left` filler bytes: they place the unknown byte `k` as the final byte of block
        // `block`, whose other fifteen bytes are `known15`.
        let left = BLOCK - 1 - k % BLOCK;
        let block = (left + k) / BLOCK;
        let observed = enc(&vec![FILLER; left]);
        let observed_block = &observed[block * BLOCK..block * BLOCK + BLOCK];

        // Probe every possible value for the final byte; exactly one reproduces `observed_block`.
        let mut cand = known15;
        cand.push(0);
        for c in 0..=u8::MAX {
            cand[BLOCK - 1] = c;
            if enc(&cand)[..BLOCK] == *observed_block {
                recovered.push(c);
                break;
            }
        }
    }
    recovered
}

/// The base64-decoded unknown string, used only to set up the oracle — never read by the solver.
fn target_bytes() -> Vec<u8> {
    b64::b64_decode(TARGET).expect("the challenge constant is valid base64")
}

#[cfg(test)]
mod solve {
    use super::*;

    use proptest::prelude::*;

    /// A faithful `oracle` with the secret and key injected, so the property test can verify the
    /// attack against freshly generated values.
    fn encrypt_ecb_with(input: &[u8], secret: &[u8], key: &[u8]) -> Vec<u8> {
        let mut plain = input.to_vec();
        plain.extend_from_slice(secret);
        let padded = pad::pkcs7_pad(&plain, BLOCK).expect("block size is 16");
        aes::ecb_encrypt(&padded, key).expect("padded, 16-byte key")
    }

    #[test]
    fn the_oracle_is_deterministic_and_block_aligned() {
        let a = oracle(b"hello, world");
        let b = oracle(b"hello, world");
        assert_eq!(a, b);
        assert!(!a.is_empty());
        assert_eq!(a.len() % BLOCK, 0);
        // A longer input yields strictly more ciphertext.
        assert!(oracle(b"hello, world, and again").len() > a.len());
    }

    #[test]
    fn the_oracle_is_ecb_so_identical_blocks_repeat() {
        // With no random prefix here, two identical plaintext blocks inside `input` produce two
        // identical ciphertext blocks — the L8 signature that this box is ECB.
        let input = [0x42u8; 2 * BLOCK];
        let ct = oracle(&input);
        assert_eq!(&ct[..BLOCK], &ct[BLOCK..2 * BLOCK]);
    }

    #[test]
    fn unknown_len_matches_the_secret() {
        assert_eq!(unknown_len(), target_bytes().len());
    }

    #[test]
    fn the_official_secret_is_recovered_byte_for_byte() {
        assert_eq!(solve(), target_bytes());
    }

    #[test]
    fn the_recovered_secret_is_the_expected_prose() {
        let out = solve();
        assert!(out.starts_with(b"Rollin' in my 5.0\nWith my rag-top down"));
        assert!(out.ends_with(b"just drove by\n"));
        assert_eq!(out.len(), 138);
    }

    #[test]
    fn a_single_byte_secret_is_recovered() {
        let secret = [0x42];
        let key = [5u8; 16];
        let enc = |input: &[u8]| encrypt_ecb_with(input, &secret, &key);
        assert_eq!(recover(1, &enc), secret);
    }

    proptest! {
        #[test]
        fn the_attack_recovers_any_secret_of_any_len(
            secret in prop::collection::vec(any::<u8>(), 1..=48),
            key in prop::collection::vec(any::<u8>(), 16),
        ) {
            let enc = |input: &[u8]| encrypt_ecb_with(input, &secret, &key);
            prop_assert_eq!(recover(secret.len(), &enc), secret);
        }
    }
}
