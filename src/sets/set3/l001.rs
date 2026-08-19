//! Set 3, Challenge 17 — The CBC padding oracle.
//!
//! The best-known attack on real block-cipher deployments. The service here mirrors a server that
//! turns an encrypted session token into plaintext behind the scenes: one door mints a token, the
//! other consumes it and — crucially — *distinguishes* "the padding was valid" from "it was not".
//!
//! Minting a token picks one of ten known base64 strings, pads it to 16-byte blocks, and
//! AES-128-CBC-encrypts it under a fixed, hidden key, returning the ciphertext and the IV it was
//! encrypted under. The consuming door decrypts a ciphertext and reports a single bit: whether the
//! result ends in legal PKCS#7.
//!
//! That one bit is enough to read the whole plaintext off, without the key. CBC decodes block `i`
//! as `P_i = D(C_i) XOR C_{i-1}`; the attacker controls `C_{i-1}` by submitting the tampered pair
//! `[B_i, C_i]`, where `B_i` stands in for the predecessor block. For each position, from the
//! block's last byte back to its first, the attacker forces every byte *after* the target to a
//! known padding value `p = 16 - j`, then sweeps `B_i[j]` across all 256 values until the oracle
//! reports `p`. Because a shorter accidental padding (e.g. a lone `01`) is far less likely than the
//! forced `p`-long run, a "valid padding" is, in practice, the exact value being hunted — which is
//! exactly one candidate byte per position.
//!
//! The recovered per-block value is the raw `D(C_i)`; the real plaintext block `P_i` is then
//! `D(C_i) XOR (C_{i-1} or IV)`. Stripping the final padding block leaves the cookie's plaintext.

use crate::util::b64;
use crate::util::cbc;
use crate::util::err::CpalError;
use crate::util::pad;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// The AES block size in bytes.
const BLOCK: usize = 16;

/// The service's AES-128 key: generated once for a real deployment and never revealed. Held here as
/// a fixed, hidden constant so the challenge is reproducible; the attacker never reads it.
const KEY: [u8; 16] = [7, 3, 9, 5, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];

/// The IV the service encrypts and decrypts under. Given back to the caller with every token.
const IV: [u8; 16] = [0; 16];

/// The ten candidate token bodies the service chooses between — opaque base64 test vectors.
const CANDIDATES: [&str; 10] = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
];

/// Mint a token: pick one of [`CANDIDATES`], pad, and AES-128-CBC-encrypt it under the hidden key
/// and the fixed [`IV`]. Returns the ciphertext and the IV it was encrypted under.
///
/// A fixed `seed` makes the pick deterministic, which the tests and the doctest rely on.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set3::l001;
/// let (ct, iv) = l001::make_cookie(0);
/// assert_eq!(iv, [0u8; 16]); // the service's public, fixed IV
/// assert!(ct.len() % 16 == 0);
/// ```
pub fn make_cookie(seed: u64) -> (Vec<u8>, [u8; 16]) {
    let mut rng = StdRng::seed_from_u64(seed);
    let (ct, iv, _plain) = build_cookie(&mut rng);
    (ct, iv)
}

/// The minting step, keeping hold of the chosen plaintext so the tests can verify the attack against
/// it without the solver ever reading it.
fn build_cookie(rng: &mut StdRng) -> (Vec<u8>, [u8; 16], Vec<u8>) {
    let idx: usize = rng.gen_range(0..CANDIDATES.len());
    let plain = b64::b64_decode(CANDIDATES[idx]).expect("each candidate is valid base64");
    let padded = pad::pkcs7_pad(&plain, BLOCK).expect("16-byte block size");
    let ct = cbc::encrypt(&padded, &KEY, &IV).expect("padded + 16-byte key/iv");
    (ct, IV, plain)
}

/// The consuming door: AES-128-CBC-decrypt `ct` under the service's key and IV and report a single
/// bit — whether the plaintext ends in valid PKCS#7 padding. This is the side channel the attack
/// runs on.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set3::l001;
/// let (ct, _) = l001::make_cookie(0);
/// assert!(l001::padding_oracle(&ct));
/// ```
pub fn padding_oracle(ct: &[u8]) -> bool {
    let Ok(raw) = cbc::decrypt(ct, &KEY, &IV) else {
        return false;
    };
    pad::pkcs7_unpad(&raw, BLOCK).is_ok()
}

/// Decrypt the token `ct` using only the padding oracle and the (public) IV — no key, no peek into
/// a decryption. Returns the recovered plaintext with its padding stripped.
///
/// # Errors
///
/// - [`CpalError::CiphertextNotBlockAligned`] when `ct` is empty or not a multiple of 16.
/// - [`CpalError::BadPadding`] when the reconstructed plaintext does not end in valid padding.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set3::l001;
/// let (ct, iv) = l001::make_cookie(0);
/// let plain = l001::solve(&ct, iv, &l001::padding_oracle).unwrap();
/// assert!(!plain.is_empty());
/// ```
pub fn solve(
    ct: &[u8],
    iv: [u8; BLOCK],
    oracle: &dyn Fn(&[u8]) -> bool,
) -> Result<Vec<u8>, CpalError> {
    if ct.is_empty() || !ct.len().is_multiple_of(BLOCK) {
        return Err(CpalError::CiphertextNotBlockAligned(ct.len()));
    }

    let blocks: Vec<[u8; BLOCK]> = ct
        .chunks_exact(BLOCK)
        .map(|b| b.try_into().expect("chunk is exactly 16 bytes"))
        .collect();

    let mut out = Vec::with_capacity(ct.len());
    for (i, block) in blocks.iter().enumerate() {
        let raw = recover_raw(block, oracle); // = D(C_i), recovered via the oracle
        let prev: &[u8] = if i == 0 { &iv } else { &blocks[i - 1] };
        for k in 0..BLOCK {
            out.push(raw[k] ^ prev[k]); // P_i = D(C_i) XOR C_{i-1}
        }
    }

    pad::pkcs7_unpad(&out, BLOCK)
}

/// Recover the raw `D(C_i)` block — the value the oracle can read off of, before it is XORed with
/// the predecessor — using only `oracle`, by peeling the block byte-by-byte, last byte first.
fn recover_raw(target: &[u8], oracle: &dyn Fn(&[u8]) -> bool) -> [u8; BLOCK] {
    let mut raw = [0u8; BLOCK];
    for j in (0..BLOCK).rev() {
        let pad_value = (BLOCK - j) as u8;

        let mut b = [0u8; BLOCK];
        for i in (j + 1)..BLOCK {
            b[i] = raw[i] ^ pad_value; // force every later byte of the checked block to pad_value
        }

        for c in 0..=u8::MAX {
            b[j] = c ^ pad_value;
            let mut probe = [0u8; 2 * BLOCK];
            probe[..BLOCK].copy_from_slice(&b);
            probe[BLOCK..].copy_from_slice(target);
            if oracle(&probe) {
                raw[j] = c; // checked block j decrypts to pad_value only when raw[j] == c
                break;
            }
        }
    }
    raw
}

#[cfg(test)]
mod padding_oracle_attack {
    use super::*;

    use proptest::prelude::*;

    #[test]
    fn every_minted_cookie_its_own_oracle_accepts() {
        for seed in 0..10u64 {
            let (ct, _) = make_cookie(seed);
            assert!(padding_oracle(&ct), "seed {seed}");
        }
    }

    #[test]
    fn a_ragged_or_unpadded_ciphertext_is_rejected() {
        assert!(!padding_oracle(&[0u8; 15]));
    }

    #[test]
    fn solving_rejects_a_rag_ciphertext() {
        let (ct, _) = make_cookie(0);
        let ragged = &ct[..ct.len() - 1];
        let iv = IV;
        assert_eq!(
            solve(ragged, iv, &padding_oracle),
            Err(CpalError::CiphertextNotBlockAligned(ragged.len()))
        );
    }

    #[test]
    fn the_attack_recovers_the_cookie_byte_for_byte() {
        // Rebuild the exact plaintext the minting step chose, then confirm the oracle attack reads
        // it back without ever touching the key.
        let mut rng = StdRng::seed_from_u64(0);
        let (ct, iv, expected) = build_cookie(&mut rng);
        let recovered = solve(&ct, iv, &padding_oracle).expect("recovered the padding block");
        assert_eq!(recovered, expected);
    }

    #[test]
    fn the_recovered_cookie_matches_one_of_the_candidates() {
        for seed in 0..10u64 {
            let (ct, iv) = make_cookie(seed);
            let recovered = solve(&ct, iv, &padding_oracle).expect("recovered the cookie");
            let matched = CANDIDATES
                .iter()
                .any(|c| b64::b64_decode(c) == Ok(recovered.clone()));
            assert!(matched, "seed {seed}");
        }
    }

    #[test]
    fn solve_and_cbc_agree_directly() {
        let (ct, iv) = make_cookie(0);
        let oracle_recovered = solve(&ct, iv, &padding_oracle).expect("recovered via the oracle");
        let direct = cbc::decrypt(&ct, &KEY, &IV)
            .and_then(|raw| pad::pkcs7_unpad(&raw, BLOCK))
            .expect("padding is intact");
        assert_eq!(oracle_recovered, direct);
    }

    proptest! {
        #[test]
        fn the_attack_recovers_any_minted_cookie(
            seed in 0u64..10,
        ) {
            let mut rng = StdRng::seed_from_u64(seed);
            let (ct, iv, expected) = build_cookie(&mut rng);
            let got = solve(&ct, iv, &padding_oracle).expect("recovers");
            prop_assert_eq!(got, expected);
        }
    }
}
