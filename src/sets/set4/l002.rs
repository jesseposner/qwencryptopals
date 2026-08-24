//! Set 4, Challenge 26 - CTR bit-flipping: the CTR re-implementation of the CBC bit-flip.
//!
//! CTR *resists* the classic CBC bit-flip: there is no chaining, so a flipped bit in one
//! ciphertext byte cannot scramble the bytes that follow, the way
//! [L16](crate::sets::set2::l008) relies on. What CTR gives instead is a *random access
//! write*. With the key and counter fixed, the keystream is a fixed function of the two, so
//! one known `(plaintext, ciphertext)` pair recovers it byte-for-byte, `K[i] = P[i] ^ C[i]`,
//! and the attacker rewrites any range of the plaintext at will by rewriting the matching
//! range of the ciphertext: `C'[i] = K[i] ^ P'[i]`.
//!
//! The service here is the CTR twin of [L16](crate::sets::set2::l008): it keeps a fixed,
//! hidden AES-128 key and a fixed public counter ([`NONCE`]), and the encrypt door wraps
//! arbitrary input between two public delimiters after escaping any `;` or `=`, so no input
//! can produce the literal substring `";admin=true;"` through the front door. The check door
//! decrypts and reports whether that substring appears. The attacker knows the entire
//! plaintext (the public delimiters plus their own input), holds the ciphertext, and rewrites
//! the one fully-known 16-byte block so it decodes to `input ++ ";admin=true;"`.

use crate::util::ctr;

/// The AES block size in bytes: the width of the fully-known range the attack rewrites.
const BLOCK: usize = 16;

/// The service's AES-128 key: fixed once, used by every call, never revealed. Kept hidden so
/// the challenge is reproducible; the attacker never reads it.
const KEY: [u8; 16] = [7, 3, 9, 5, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];

/// The counter the service always encrypts and decrypts under: an 8-byte zero nonce plus an
/// 8-byte little-endian block index, the way [L18](crate::sets::set3::l002) lays it out.
/// Public to the attacker, fixed for reproducibility.
const NONCE: u64 = 0;

/// The two public delimiters the service sandwiches user input between.
const PREFIX: &str = "comment1=cooking%20MCs;userdata=";
const SUFFIX: &str = ";comment2=%20like%20a%20pound%20of%20bacon";

/// The substring the check door looks for.
const TARGET: &str = ";admin=true;";

/// The start of the fully-known 16-byte range the attack rewrites: right after the 32-byte
/// [`PREFIX`], so the range holds the four input bytes plus the first twelve bytes of the
/// public [`SUFFIX`].
const RANGE: usize = 32;

/// The service's escaping rule: quote out `;` and `=` so caller text can never form a
/// delimiter itself.
fn sanitize(input: &str) -> String {
    input.replace(';', "\\;").replace('=', "\\=")
}

/// The exact, un-padded plaintext the service builds for a given input: [`PREFIX`], the
/// sanitized input, and [`SUFFIX`]. CTR pads nothing, so this is the whole message.
fn build_plain(input: &str) -> Vec<u8> {
    format!("{PREFIX}{}{SUFFIX}", sanitize(input)).into_bytes()
}

/// Encrypt door: build the delimited, sanitized plaintext and AES-128-CTR-encrypt it under
/// the fixed key and counter. CTR is a stream, so the output is exactly as long as the input.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set4::l002;
/// // The key and counter are fixed, so the same input always yields the same ciphertext.
/// assert_eq!(l002::encryption_oracle("AAAA"), l002::encryption_oracle("AAAA"));
/// ```
pub fn encryption_oracle(input: &str) -> Vec<u8> {
    ctr::ctr(&build_plain(input), &KEY, NONCE).expect("a fixed 16-byte key")
}

/// Check door: AES-128-CTR-decrypt `ct` and report whether the plaintext contains
/// `";admin=true;"`. CTR pads nothing, so there is no padding to strip.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set4::l002;
/// let honest = l002::encryption_oracle("AAAA");
/// assert!(!l002::is_admin(&honest));
/// ```
pub fn is_admin(ct: &[u8]) -> bool {
    let Ok(plain) = ctr::ctr(ct, &KEY, NONCE) else {
        return false;
    };
    plain.windows(TARGET.len()).any(|w| w == TARGET.as_bytes())
}

/// Rewrite the service's own ciphertext so it decrypts to a profile containing
/// `";admin=true;"`.
///
/// CTR has no chaining to corrupt, so the bit-flip of [L16](crate::sets::set2::l008) does not
/// carry over; the CTR move is a random access write. With the key and counter fixed, the
/// keystream `K` is a fixed function, and the one known `(P, C)` pair recovers it byte-for-byte.
/// Over the one fully-known 16-byte range ([`RANGE`] to [`RANGE`]+[`BLOCK`]), which holds the
/// four input bytes and the first twelve bytes of the public [`SUFFIX`], the attacker writes
/// the target `input ++ TARGET` by setting `C'[i] = K[i] ^ target[i - RANGE]`. Every byte
/// outside the range is left untouched, so the rest of the profile decodes exactly as before
/// and the check door finds the injected token.
pub fn forge() -> Vec<u8> {
    let input = "AAAA"; // 4 bytes: the range = input ++ first 12 suffix bytes
    let mut ct = encryption_oracle(input);
    let plain = build_plain(input);

    let mut target: [u8; BLOCK] = [0u8; BLOCK];
    target[..input.len()].copy_from_slice(input.as_bytes());
    target[input.len()..].copy_from_slice(TARGET.as_bytes());

    for (j, _) in target.iter().enumerate() {
        let i = RANGE + j;
        let keystream = plain[i] ^ ct[i]; // K[i], from the one known pair
        ct[i] = keystream ^ target[j]; // C'[i] = K[i] ^ P'[i]
    }
    ct
}

/// Run the rewrite and report whether the check door accepts it.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set4::l002;
/// assert!(l002::solve());
/// ```
pub fn solve() -> bool {
    is_admin(&forge())
}

#[cfg(test)]
mod bitflip {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn the_honest_ciphertext_is_rejected() {
        assert!(!is_admin(&encryption_oracle("AAAA")));
    }

    #[test]
    fn the_forged_ciphertext_passes_the_check() {
        assert!(solve());
    }

    #[test]
    fn the_forged_range_decrypts_to_admin_true() {
        let raw = ctr::ctr(&forge(), &KEY, NONCE).expect("CTR is a stream");
        // The rewritten 16-byte range now decodes to the input plus the target token; the bytes
        // in front of it are untouched, so check the range on its own.
        assert_eq!(&raw[RANGE..RANGE + BLOCK], b"AAAA;admin=true;");
    }

    #[test]
    fn user_input_cannot_inject_the_target_substring() {
        assert!(!is_admin(&encryption_oracle("admin=true")));
        assert!(!is_admin(&encryption_oracle(";admin=true;")));
    }

    #[test]
    fn the_rewrite_touches_only_the_target_range() {
        let original = encryption_oracle("AAAA");
        let plain = build_plain("AAAA");
        let mut target: [u8; BLOCK] = [0u8; BLOCK];
        target[..4].copy_from_slice(b"AAAA");
        target[4..].copy_from_slice(TARGET.as_bytes());
        let forged = forge();
        assert_eq!(forged.len(), original.len());
        for i in 0..forged.len() {
            if (RANGE..RANGE + BLOCK).contains(&i) {
                // In range: the byte is exactly the keystream byte XORed with the target value.
                let k = plain[i] ^ original[i];
                assert_eq!(forged[i], k ^ target[i - RANGE]);
            } else {
                assert_eq!(forged[i], original[i], "out-of-range bytes are untouched");
            }
        }
    }

    #[test]
    fn the_forge_is_deterministic() {
        assert_eq!(forge(), forge());
    }

    proptest! {
        #[test]
        fn the_front_door_never_surfaces_the_target_token(input in "[^;=]{0,32}") {
            // Escaping `;` and `=` means the honest oracle can never surface the literal target
            // token, whatever the input.
            prop_assert!(!is_admin(&encryption_oracle(&input)));
        }
    }
}
