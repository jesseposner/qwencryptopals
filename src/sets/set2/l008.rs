//! Set 2, Challenge 16 — Cut-and-paste, the CBC way.
//!
//! L13 forged a block by *reordering* ciphertext, because ECB encrypts each block of text on its
//! own and an identical block re-encodes identically. CBC has no such reorderable unit: every
//! plaintext block is bound to the ciphertext block that sits *before* it, because decrypting a
//! block is `D(C_i) XOR C_{i-1}`. The freedom CBC hands the attacker in return is to *overwrite a
//! decrypted block by editing the ciphertext block immediately in front of it* — `C_{i-1}` feeds
//! straight into the XOR that produces `P_i`. L13's "role=admin" cut-and-paste survives this
//! rewrite.
//!
//! The service here keeps a fixed key (held back, never revealed) and always decrypts under a
//! fixed, public IV. It offers the attacker two doors: an encrypt door, which AES-128-CBC-encrypts
//! any text the attacker chooses, and a check door, which AES-128-CBC-decrypts whatever
//! ciphertext the attacker hands back, strips the PKCS#7, and reports whether the result contains
//! `role=admin`. Somewhere in the service's own data there is a block whose plaintext is the
//! fixed suffix `role=user`; the attacker rewrites that block into `role=admin` by placing a
//! hand-picked ciphertext block in front of it.

use crate::util::cbc;
use crate::util::pad;

/// The AES block size in bytes.
const BLOCK: usize = 16;

/// The service's AES-128 key: fixed once, used by every call, never exposed.
const KEY: [u8; 16] = [7, 3, 9, 5, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];

/// The IV the service always encrypts and decrypts under. Public to the attacker, fixed here for
/// reproducibility.
const IV: [u8; 16] = [0; 16];

/// The fixed suffix the service keeps in its data; PKCS#7 to one block it reads `role=user` plus a
/// run of `0x07` pad bytes. Known to the attacker, because they know what the service pads.
const SUFFIX: [u8; 9] = *b"role=user";

/// The string the attacker wants to appear in a decryption.
const TARGET: [u8; 10] = *b"role=admin";

/// Encrypt door: AES-128-CBC-encrypt `plain` under the fixed key and IV after PKCS#7 padding. The
/// attacker may invoke this on any text they like.
pub fn encryption_oracle(plain: &[u8]) -> Vec<u8> {
    let padded = pad::pkcs7_pad(plain, BLOCK).expect("PKCS#7 pads to a block multiple");
    cbc::encrypt(&padded, &KEY, &IV).expect("padded input is block-aligned")
}

/// Check door: AES-128-CBC-decrypt `ct` under the fixed key and IV, strip the PKCS#7, and report
/// whether the plaintext contains `role=admin`. Ragged or unpadded input simply fails the check.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set2::l008;
/// let honest = l008::encryption_oracle(b"role=user");
/// assert!(!l008::decrypt_and_check(&honest));
/// ```
pub fn decrypt_and_check(ct: &[u8]) -> bool {
    let plain = match cbc::decrypt(ct, &KEY, &IV) {
        Ok(plain) => plain,
        Err(_) => return false,
    };
    let unpad = match pad::pkcs7_unpad(&plain, BLOCK) {
        Ok(unpad) => unpad,
        Err(_) => return false,
    };
    unpad.windows(TARGET.len()).any(|w| w == TARGET.as_ref())
}

/// Forge a ciphertext that decrypts to something containing `role=admin`.
///
/// The target block is the service's `role=user` block; the attacker only needs its ciphertext
/// `C_i` (from the encrypt door) and the fact that its plaintext is `role=user` plus seven `0x07`
/// pad bytes. A hand-picked predecessor block `C'` is chosen so that when the last block is
/// decrypted — `D(C_i) XOR C'` — it comes out as `role=admin` followed by six `0x06` pad bytes; the
/// leading `C'` then decrypts to some garbage block and the whole thing un-pads cleanly.
pub fn forged() -> Vec<u8> {
    let plain_orig = pad::pkcs7_pad(&SUFFIX, BLOCK).expect("nine bytes pad to one block");
    let ct_i = encryption_oracle(&SUFFIX); // the service's own ciphertext of `role=user`

    let desired: [u8; BLOCK] = {
        let mut d = [0x06u8; BLOCK];
        d[..TARGET.len()].copy_from_slice(&TARGET);
        d
    };

    let forged_prev: [u8; BLOCK] = std::array::from_fn(|i| plain_orig[i] ^ desired[i]);

    let mut ct = Vec::with_capacity(2 * BLOCK);
    ct.extend_from_slice(&forged_prev);
    ct.extend_from_slice(&ct_i);
    ct
}

/// Run the forge and report whether the service's check door accepts it.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set2::l008;
/// assert!(l008::solve());
/// ```
pub fn solve() -> bool {
    decrypt_and_check(&forged())
}

#[cfg(test)]
mod forge {
    use super::*;

    use proptest::prelude::*;

    #[test]
    fn the_honest_suffix_block_is_rejected() {
        let honest = encryption_oracle(&SUFFIX);
        assert!(!decrypt_and_check(&honest));
    }

    #[test]
    fn the_forged_ciphertext_passes_the_service_check() {
        assert!(resolve_forged_passes());
    }

    /// Same as [`solve`] but returns the forged ciphertext so the test can inspect it.
    fn resolve_forged_passes() -> bool {
        solve()
    }

    #[test]
    fn the_forged_last_block_decrypts_to_role_admin() {
        let ct = forged();
        let plain = cbc::decrypt(&ct, &KEY, &IV).expect("two blocks");
        // The service's `role=user` block was rewritten in place: the leading forged block is junk,
        // but the last block decrypts to `role\admin` plus a legal 0x06 run.
        let last = &plain[plain.len() - BLOCK..];
        assert_eq!(last, b"role=admin\x06\x06\x06\x06\x06\x06");
    }

    #[test]
    fn a_ragged_ciphertext_is_rejected() {
        assert!(!decrypt_and_check(&[0u8; 15]));
    }

    proptest! {
        #[test]
        fn the_forge_is_deterministic_across_runs(
            seed in any::<u8>(),
        ) {
            let a = solve();
            let b = solve();
            let _ = seed;
            prop_assert_eq!(a, b);
        }
    }
}
