//! Set 2, Challenge 16 — CBC bit-flipping.
//!
//! A single flipped bit in a ciphertext block `C_{i-1}` fully scrambles that block's own plaintext
//! but flips the *corresponding* bit in the next plaintext block, because CBC decodes each block as
//! `P_i = D(C_i) XOR C_{i-1}`. Choosing which bits to flip and where, an attacker rewrites a whole
//! plaintext block to an arbitrary value without ever knowing the key.
//!
//! The service here keeps a fixed, hidden AES-128 key and a fixed, public IV. The encrypt door
//! wraps arbitrary input between two public delimiters
//! (`"comment1=cooking%20MCs;userdata="` … `";comment2=%20like%20a%20pound%20of%20bacon"`) after
//! escaping any `;` or `=`, so no input can produce the literal substring `";admin=true;"` through
//! the front door. The check door decrypts, strips the padding, and reports whether that substring
//! appears anywhere. The public delimiters line up so that, for a short input, one whole plaintext
//! block is fully known to the attacker — and that is the block they overwrite by editing the
//! ciphertext block in front of it.

use crate::util::cbc;
use crate::util::pad;

/// The AES block size in bytes.
const BLOCK: usize = 16;

/// The service's AES-128 key: fixed once, used by every call, never revealed. Kept hidden so the
/// challenge is reproducible; the attacker never reads it.
const KEY: [u8; 16] = [7, 3, 9, 5, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];

/// The IV the service always encrypts and decrypts under. Public to the attacker, fixed for
/// reproducibility.
const IV: [u8; 16] = [0; 16];

/// The two public delimiters the service sandwiches user input between.
const PREFIX: &str = "comment1=cooking%20MCs;userdata=";
const SUFFIX: &str = ";comment2=%20like%20a%20pound%20of%20bacon";

/// The substring the check door looks for.
const TARGET: &str = ";admin=true;";

/// The service's escaping rule: quote out `;` and `=` so caller text can never form a delimiter
/// itself.
fn sanitize(input: &str) -> String {
    input.replace(';', "\\;").replace('=', "\\=")
}

/// The exact, un-padded plaintext the service will build for a given input.
fn build_plain(input: &str) -> Vec<u8> {
    format!("{PREFIX}{}{SUFFIX}", sanitize(input)).into_bytes()
}

/// Encrypt door: build the delimited, sanitized, padded plaintext and AES-128-CBC-encrypt it under
/// the fixed key and IV.
pub fn encryption_oracle(input: &str) -> Vec<u8> {
    let padded = pad::pkcs7_pad(&build_plain(input), BLOCK).expect("pads to a block multiple");
    cbc::encrypt(&padded, &KEY, &IV).expect("padded + 16-byte key/iv")
}

/// Check door: AES-128-CBC-decrypt `ct`, strip the PKCS#7, and report whether the plaintext
/// contains `";admin=true;"`. Ragged or unpadded input simply fails the check.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set2::l008;
/// let honest = l008::encryption_oracle("AAAA");
/// assert!(!l008::is_admin(&honest));
/// ```
pub fn is_admin(ct: &[u8]) -> bool {
    let Ok(raw) = cbc::decrypt(ct, &KEY, &IV) else {
        return false;
    };
    let Ok(plain) = pad::pkcs7_unpad(&raw, BLOCK) else {
        return false;
    };
    plain.windows(TARGET.len()).any(|w| w == TARGET.as_bytes())
}

/// Rewrite the service's own ciphertext so it decrypts to a profile containing `";admin=true;"`.
///
/// With a four-byte input the second data block (plaintext offset 32..48) is fully known to the
/// attacker, because the public prefix (two blocks), the input, and the public suffix all line up.
/// Choosing the input to be four bytes makes that block's target value exactly
/// `input ++ ";admin=true;"`. To make the block decrypt to that, the attacker XORs a hand-picked
/// value into the predecessor ciphertext block `C_1`:
///
/// ```text
/// C_1[i] ^=  original_block2[i] ^ target_block2[i]
/// ```
///
/// leaving `C_2` (which carries the target block) untouched, so the rest of the profile is intact
/// and still un-pads cleanly.
pub fn forge() -> Vec<u8> {
    let input = "AAAA"; // 4 bytes: block 2 = input ++ first 12 suffix bytes
    let mut ct = encryption_oracle(input);

    let plain = build_plain(input);
    let original: [u8; BLOCK] = plain[32..48].try_into().expect("exactly 16 bytes");
    let mut target: [u8; BLOCK] = [0u8; BLOCK];
    target[..input.len()].copy_from_slice(input.as_bytes());
    target[input.len()..].copy_from_slice(TARGET.as_bytes());

    for i in 0..BLOCK {
        let delta = original[i] ^ target[i];
        ct[16 + i] ^= delta; // rewrite the block that XORs into block 2's decode
    }
    ct
}

/// Run the forge and report whether the check door accepts it.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set2::l008;
/// assert!(l008::solve());
/// ```
pub fn solve() -> bool {
    is_admin(&forge())
}

#[cfg(test)]
mod bitflip {
    use super::*;

    #[test]
    fn the_honest_ciphertext_is_rejected() {
        assert!(!is_admin(&encryption_oracle("AAAA")));
    }

    #[test]
    fn the_forged_ciphertext_passes_the_check() {
        assert!(solve());
    }

    #[test]
    fn the_forged_second_block_decrypts_to_admin_true() {
        let ct = forge();
        let raw = cbc::decrypt(&ct, &KEY, &IV).expect("block-aligned");
        let plain = pad::pkcs7_unpad(&raw, BLOCK).expect("the pad is untouched");
        // The rewritten block (offset 32..48) now decodes to the input plus the target substring;
        // the block in front of it is intentionally corrupted, so we check this block on its own.
        assert_eq!(&plain[32..48], b"AAAA;admin=true;");
    }

    #[test]
    fn user_input_cannot_inject_the_target_substring() {
        assert!(!is_admin(&encryption_oracle("admin=true")));
        assert!(!is_admin(&encryption_oracle(";admin=true;")));
    }

    #[test]
    fn a_ragged_ciphertext_is_rejected() {
        assert!(!is_admin(&[0u8; 15]));
    }

    #[test]
    fn the_forge_is_deterministic() {
        assert_eq!(forge(), forge());
    }
}
