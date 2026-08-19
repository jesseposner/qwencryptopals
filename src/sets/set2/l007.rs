//! Set 2, Challenge 15 — Byte at a time, CBC edition.
//!
//! L12 and L14 read a secret straight off ciphertext, because ECB (and a controlled ECB prefix)
//! let the attacker see how each 16-byte block encrypts. CBC breaks that: a plaintext block
//! decrypts to `D(C_i) XOR C_{i-1}`, so the byte you want sits behind a block you cannot peek at.
//! The one thing CBC does let you do that ECB never did is *control the block your target sits
//! against* — the previous ciphertext block `C_{i-1}` flows directly into the decryption of `C_i`.
//!
//! So the service here exposes a *decryption* black box that always appends a fixed, secret
//! ciphertext block to whatever ciphertext you feed it and then tells you one bit back: whether
//! the result ends in valid PKCS#7 padding. Concretely, if `B` is the 16 bytes you supply it:
//!
//! ```text
//! decrypt(B || SECRET_CT, IV) = [ D(B) XOR IV ; D(SECRET_CT) XOR B ]
//! ```
//!
//! and only the last of those two blocks is ever checked for padding. `SECRET_CT` is the AES
//! image of a fixed 16-byte secret, so the checked block is `D(SECRET_CT) XOR B = SECRET XOR B`:
//! a block that is a fixed unknown value XORed with 16 bytes *you* choose. Padding validity is a
//! statement about that block's last bytes, so by choosing `B` you can force every byte of
//! `SECRET XOR B` to a known value — except the one byte you are hunting. Sliding a running
//! padding value back across the block, byte at a time, each byte of the secret is peeled off.

use crate::util::aes;
use crate::util::cbc;
use crate::util::pad;

/// The AES block size in bytes.
const BLOCK: usize = 16;

/// The service's key: fixed once, used by every call, never revealed. Fixed only so the challenge
/// is reproducible — never exposed or read back.
const KEY: [u8; 16] = [7, 3, 9, 5, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];

/// The initialization vector the service always decrypts under. Fixed for reproducibility.
const IV: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// The fixed 16-byte secret the service hides inside [`SECRET_CT`]. Held in raw form only to build
/// the ciphertext; the solver recovers it, never reads this constant.
const SECRET: [u8; BLOCK] = [
    b'C', b'B', b'C', b' ', b'p', b'a', b'd', b'd', b'i', b'n', b'g', b' ', b'o', b'k', b',', b'!',
];

/// The ciphertext block the service appends to every request: the single-block AES image of
/// [`SECRET`]. The attacker is shown this block; it is the box to defeat.
fn secret_ct() -> [u8; BLOCK] {
    let ct = aes::ecb_encrypt(&SECRET, &KEY).expect("a 16-byte block with a 16-byte key");
    let mut out = [0u8; BLOCK];
    out.copy_from_slice(&ct);
    out
}

/// The service: take 16 attacker-chosen bytes, append the fixed [`secret_ct`] block, AES-128-CBC
/// decrypt the two blocks under the fixed [`IV`], and report whether the result ends in valid
/// PKCS#7 padding. That single bit is the only oracle the attacker gets.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set2::l007;
/// // Same input, same verdict — the service is deterministic.
/// let block = [10u8; 16];
/// assert_eq!(l007::padding_oracle(block), l007::padding_oracle(block));
/// ```
pub fn padding_oracle(block: [u8; BLOCK]) -> bool {
    padding_value(block).is_some()
}

/// The service's verdict, but keeping the pad value: `Some(n)` when the checked block decrypts to
/// exactly `n` bytes of `n` padding, `None` when it is not a legal full PKCS#7 block. The attack
/// keys off this value rather than the bare bit so a candidate is only accepted when the pad value
/// is *the exact value we forced*, not a longer accidental run the unrecovered bytes happen to form.
fn padding_value(block: [u8; BLOCK]) -> Option<u8> {
    let mut ct = [0u8; 2 * BLOCK];
    ct[..BLOCK].copy_from_slice(&block);
    ct[BLOCK..].copy_from_slice(&secret_ct());
    let plain = cbc::decrypt(&ct, &KEY, &IV).expect("two blocks align to 16-byte boundary");
    pad::pkcs7_unpad(&plain, BLOCK).ok().and_then(|_| {
        let n = *plain.last()? as usize;
        (1..=BLOCK).contains(&n).then_some(n as u8)
    })
}

/// Run the byte-at-a-time CBC attack against [`padding_oracle`] and return the recovered secret.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set2::l007;
/// assert_eq!(l007::solve(), b"CBC padding ok,!");
/// ```
pub fn solve() -> Vec<u8> {
    recover(BLOCK, &padding_value)
}

/// Peel a whole 16-byte block off, last byte first.
///
/// `oracle` is any callback reporting the pad value a CBC box reads off the checked block (here
/// [`padding_value`], where the checked block is `SECRET XOR block`), or none when it is not a legal
/// pad block. To read byte `j` we walk padding back across the block: for a running padding value
/// `p = BLOCK - j`, every byte *after* position `j` is forced to `p` (we already know those bytes,
/// being earlier in the run), then we sweep position `j` across all 256 values; exactly one makes
/// the oracle report pad value exactly `p`, and that one is `SECRET[j]`.
fn recover(total: usize, oracle: &dyn Fn([u8; BLOCK]) -> Option<u8>) -> Vec<u8> {
    let mut got = [0u8; BLOCK];
    for j in (0..total).rev() {
        let pad_value = (BLOCK - j) as u8;

        let mut block = [0u8; BLOCK];
        for i in (j + 1)..BLOCK {
            block[i] = got[i] ^ pad_value;
        }

        for c in 0..=u8::MAX {
            block[j] = c ^ pad_value;
            if oracle(block) == Some(pad_value) {
                got[j] = c;
                break;
            }
        }
    }
    got[..total].to_vec()
}

#[cfg(test)]
mod solve {
    use super::*;

    use proptest::prelude::*;

    /// A standalone value-oracle over a caller-chosen `secret`/`key`, mirroring [`padding_value`],
    /// so the property test can verify the attack against freshly generated secrets and keys.
    fn make_oracle(
        secret: [u8; BLOCK],
        key: [u8; 16],
    ) -> impl Fn([u8; BLOCK]) -> Option<u8> + 'static {
        let block0 = aes::ecb_encrypt(&secret, &key).expect("aligned");
        move |block| {
            let mut ct = [0u8; 2 * BLOCK];
            ct[..BLOCK].copy_from_slice(&block);
            ct[BLOCK..].copy_from_slice(&block0);
            let plain = cbc::decrypt(&ct, &key, &IV).expect("aligned");
            pad::pkcs7_unpad(&plain, BLOCK).ok().and_then(|_| {
                let n = *plain.last()? as usize;
                (1..=BLOCK).contains(&n).then_some(n as u8)
            })
        }
    }

    #[test]
    fn the_oracle_is_deterministic() {
        let block = [9u8; BLOCK];
        assert_eq!(padding_oracle(block), padding_oracle(block));
    }

    #[test]
    fn a_full_block_of_valid_padding_is_accepted() {
        // XOR the checked block to a whole block of 0x10 padding (a legal full-block pad value).
        let block = SECRET.map(|b| b ^ 0x10);
        assert!(padding_oracle(block));
    }

    #[test]
    fn a_zero_last_byte_is_rejected() {
        // Force the checked block's last byte to 0: no PKCS#7 block may end in 0x00.
        let mut block = [0u8; BLOCK];
        block[BLOCK - 1] = SECRET[BLOCK - 1]; // checked last byte: S ^ S = 0
        assert!(!padding_oracle(block));
    }

    #[test]
    fn an_all_zero_key_does_not_break_the_sweep() {
        // Regression: with a zero key and `secret[14]=2, secret[15]=26`, a bare bit-oracle used to
        // accept a too-long accidental pad and stop at the wrong byte. The value oracle does not.
        let mut secret = [0u8; BLOCK];
        secret[BLOCK - 2] = 2;
        secret[BLOCK - 1] = 26;
        let oracle = make_oracle(secret, [0u8; 16]);
        let got = recover(BLOCK, &oracle);
        assert_eq!(got.as_slice(), &secret[..]);
    }

    #[test]
    fn the_official_secret_is_recovered_byte_for_byte() {
        assert_eq!(solve(), SECRET.to_vec());
    }

    #[test]
    fn the_recovered_secret_has_the_expected_bytes() {
        let out = solve();
        assert_eq!(out.len(), BLOCK);
        assert_eq!(&out[..4], b"CBC ");
    }

    proptest! {
        #[test]
        fn the_attack_recovers_any_block_under_any_key(
            secret in prop::collection::vec(any::<u8>(), BLOCK),
            key in prop::collection::vec(any::<u8>(), BLOCK),
        ) {
            let secret: [u8; BLOCK] = secret.as_slice().try_into().expect("exactly 16 bytes");
            let key: [u8; BLOCK] = key.as_slice().try_into().expect("exactly 16 bytes");
            let oracle = make_oracle(secret, key);
            let got = recover(BLOCK, &oracle);
            prop_assert_eq!(got.as_slice(), &secret[..]);
        }
    }
}
