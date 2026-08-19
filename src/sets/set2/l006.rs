//! Set 2, Challenge 14 — Byte-at-a-time AES-ECB decryption, with an unknown random prefix.
//!
//! This box is the L12 oracle [`l004`] with one twist: before encrypting it prepends a random
//! number of random bytes to every plaintext. The contents of the target are still the same
//! base64 blob, and it is still encrypted under one fixed ECB key, so every call returns
//!
//! ```text
//! AES-128-ECB(random-prefix || your-input || unknown-string, KEY)
//! ```
//!
//! The random prefix is the whole difficulty. In L12 the filler you send sits at the very front of
//! the plaintext, so you can count the unknown string's length straight from the ciphertext length
//! and line each byte up against controlled filler. Here the prefix shifts every block boundary by
//! an opaque offset, so the solver must first *discover* where the prefix ends before the byte-at-a-
//! time machinery from L12 can be run at all.
//!
//! [`oracle`] is the black box; [`solve`] recovers the unknown string.

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

/// The random prefix the box prepends to every plaintext. A "random count of random bytes," made a
/// fixed constant only so the challenge is reproducible. Its length is not a multiple of 16 so it
/// genuinely shifts where the target's block boundaries fall; the solver must discover that shift,
/// never read this value.
const PREFIX: [u8; 15] = [
    0x5a, 0x2f, 0x41, 0x09, 0x88, 0x3c, 0x1b, 0xd7, 0xe0, 0x66, 0x14, 0x92, 0x38, 0x05, 0x4c,
];

/// The challenge's secret, kept base64-encoded so its contents are not read here. The oracle
/// decodes this and appends it before encrypting; the solver must recover it byte by byte. The
/// solver *does* get the blob (as the challenge prescribes), so it knows how long the secret is.
const TARGET: &str = "\
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
";

/// The L14 oracle: prepend the fixed random prefix and append the base64-decoded unknown string to
/// `input`, PKCS#7-pad to 16-byte blocks, and encrypt the whole thing under the fixed ECB [`KEY`].
///
/// Only ciphertext is returned — the key, the prefix, and the unknown string all stay inside the
/// box.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set2::l006;
/// // The prefix is consistent, so the same input always yields the same ciphertext.
/// assert_eq!(l006::oracle(b"hi"), l006::oracle(b"hi"));
/// ```
pub fn oracle(input: &[u8]) -> Vec<u8> {
    let mut plain = Vec::with_capacity(PREFIX.len() + input.len() + target_bytes().len());
    plain.extend_from_slice(&PREFIX);
    plain.extend_from_slice(input);
    plain.extend_from_slice(&target_bytes());
    let padded = pad::pkcs7_pad(&plain, BLOCK).expect("block size 16 is inside 1..=255");
    aes::ecb_encrypt(&padded, &KEY).expect("padded, 16-byte key")
}

/// Run the byte-at-a-time attack against [`oracle`] and return the recovered unknown string.
///
/// This is the headline answer: given only the black box's ciphertexts — and that box hides a
/// random prefix of unknown length — read off, one byte at a time, the exact secret it keeps
/// appending to every plaintext.
pub fn solve() -> Vec<u8> {
    let unknown = target_bytes().len();
    let prefix = prefix_len(&unknown);
    recover(unknown, prefix, &|input| oracle(input))
}

/// How many random bytes the box prepends before your own input.
///
/// Ciphertext length is always `(prefix + input + unknown)` PKCS#7-rounded up to a multiple of 16.
/// Feeding `0..=16` input lengths walks every residue mod 16, so the minimum of
/// `ciphertext_len - input_len` is `prefix + unknown + 1`. The solver independently knows
/// `unknown` (it was handed the blob), so the prefix length is `that minimum - 1 - unknown`.
fn prefix_len(unknown: &usize) -> usize {
    let total = (0..=BLOCK)
        .map(|len| oracle(&vec![FILLER; len]).len() - len)
        .min()
        .expect("at least one sample")
        - 1;
    total - unknown
}

/// The byte-at-a-time core, run past an unknown random prefix of length `prefix_len`.
///
/// `total` is the number of unknown bytes to recover and `enc` is any black box that returns
/// `ecb(prefix || input || secret)` for a fixed `prefix` of length `prefix_len` and a `secret`
/// (`secret.len() == total`).
///
/// The prefix is the difficulty: it pushes the secret off every block boundary by `prefix_len`, so
/// the L12 trick of counting filler from the front no longer lines bytes up. For the byte at
/// position `k` the attack picks a filler length `left` such that the byte lands on the final
/// position of a block — i.e. `(prefix_len + left + k) % 16 == 15` — while `left` is long enough
/// that the fifteen bytes before it fall inside the attacker's own filler plus already-recovered
/// bytes (`FILLER^(15-m)` ++ `recovered[k-m..k]`, `m = min(k, 15)`), never the unknown prefix. It
/// then reads that block off the observed ciphertext and probes every candidate final byte: the
/// candidate whose re-encryption reproduces the block is the byte.
fn recover(total: usize, prefix_len: usize, enc: &dyn Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let mut recovered = Vec::with_capacity(total);
    for k in 0..total {
        let m = k.min(BLOCK - 1);
        let mut known15 = vec![FILLER; BLOCK - 1 - m];
        known15.extend_from_slice(&recovered[k - m..k]);

        // Choose the shortest filler length that (a) puts byte `k` on a block's final byte and
        // (b) is long enough that the 15 bytes before it are known, so the window never reaches the
        // hidden prefix.
        let min_left = if k < BLOCK { BLOCK - 1 - k } else { 0 };
        let mut left = 0;
        while (prefix_len + left + k) % BLOCK != BLOCK - 1 {
            left += 1;
        }
        if left < min_left {
            left += BLOCK;
        }

        // Observe the real block: target byte `k` is the block's final byte, preceded by `known15`.
        let block = (prefix_len + left + k) / BLOCK;
        let observed = enc(&vec![FILLER; left]);
        let observed_block = &observed[block * BLOCK..block * BLOCK + BLOCK];

        // Probe: place `known15 || c` immediately on that same block and see which `c` reproduces
        // it. `known15 || c` spans `prefix_len + (left + k - 15) .. prefix_len + left + k`, a full
        // 16 bytes ending where byte `k` sits.
        let probe_left = left + k - (BLOCK - 1);
        let mut cand = vec![FILLER; probe_left];
        cand.extend_from_slice(&known15);
        cand.push(0);
        let last = cand.len() - 1;
        for c in 0..=u8::MAX {
            cand[last] = c;
            let probe = &enc(&cand)[block * BLOCK..block * BLOCK + BLOCK];
            if probe == observed_block {
                recovered.push(c);
                break;
            }
        }
    }
    recovered
}

/// The base64-decoded unknown string, used only to set up the oracle — the solver reads its length,
/// not its contents.
fn target_bytes() -> Vec<u8> {
    b64::b64_decode(TARGET).expect("the challenge constant is valid base64")
}

#[cfg(test)]
mod solve {
    use super::*;

    use proptest::prelude::*;

    /// A faithful L14 box with the prefix, secret, and key all injectable, so the property test can
    /// verify the attack against freshly generated values.
    ///
    /// ```ignore
    /// ecb(prefix || input || secret, key)
    /// ```
    fn encrypt_ecb_with_prefix(input: &[u8], prefix: &[u8], secret: &[u8], key: &[u8]) -> Vec<u8> {
        let mut plain = Vec::with_capacity(prefix.len() + input.len() + secret.len());
        plain.extend_from_slice(prefix);
        plain.extend_from_slice(input);
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
    fn the_oracle_prepends_an_unread_prefix() {
        // Because the box hides a prefix in front of the input, it emits strictly more ciphertext
        // than the L12-style box would for the same input and secret.
        let with_prefix = oracle(b"hi");
        let bare_secret = target_bytes();
        let mut plain = b"hi".to_vec();
        plain.extend_from_slice(&bare_secret);
        let bare_padded = pad::pkcs7_pad(&plain, BLOCK).unwrap();
        let bare = aes::ecb_encrypt(&bare_padded, &KEY).unwrap().len();
        assert!(with_prefix.len() > bare);
        assert_eq!(with_prefix.len() % BLOCK, 0);
    }

    #[test]
    fn the_prefix_len_matches_the_real_prefix() {
        assert_eq!(prefix_len(&target_bytes().len()), PREFIX.len());
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
    fn prefix_len_is_independent_of_the_input_residue() {
        // The minimum `len - filler` over any full set of residues gives the same total, no matter
        // which residue the filler happens to start from.
        let total = |shift| {
            (0..=BLOCK)
                .map(|x| oracle(&vec![FILLER; shift + x]).len() - (shift + x))
                .min()
                .unwrap()
                - 1
        };
        assert_eq!(total(0), total(7));
    }

    #[test]
    fn a_single_byte_secret_is_recovered() {
        let secret = [0x42];
        let prefix = [0x01, 0x02, 0x03, 0x04, 0x05];
        let key = [5u8; 16];
        let enc = |input: &[u8]| encrypt_ecb_with_prefix(input, &prefix, &secret, &key);
        assert_eq!(recover(1, prefix.len(), &enc), secret);
    }

    proptest! {
        #[test]
        fn the_attack_recovers_any_secret_behind_any_prefix(
            secret in prop::collection::vec(any::<u8>(), 1..=48),
            prefix in prop::collection::vec(any::<u8>(), 0..=40),
            key in prop::collection::vec(any::<u8>(), 16),
        ) {
            let enc = |input: &[u8]| encrypt_ecb_with_prefix(input, &prefix, &secret, &key);
            prop_assert_eq!(recover(secret.len(), prefix.len(), &enc), secret);
        }
    }
}
