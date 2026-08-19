//! Set 2, Challenge 13 — ECB cut-and-paste.
//!
//! The system turns a user's email into a profile string,
//!
//! ```text
//! email=<email>&uid=10&role=user
//! ```
//!
//! PKCS#7-pads it, AES-128-ECB-encrypts it under a fixed session key, and hands the resulting
//! *cookie* back to the user for later use — which means the user can read, and even hand back,
//! their own ciphertext. That is the whole flaw, and it follows straight from the ECB lesson of
//! L8: ECB is per-block and deterministic, so a ciphertext is just a bag of interchangeable
//! 16-byte blocks that decrypt (and re-encrypt) identically no matter what order they sit in.
//!
//! The attack is to "cut" a block out of one honest cookie and "paste" it into another so the
//! reassembled plaintext parses with `role=admin`. To place `admin` where it must go, exploit
//! the padding: pick an email whose bytes, together with the fixed `&uid=10&role=user` tail,
//! line `admin` up in its own fresh 16-byte block followed by eleven `0x0B` bytes. When that
//! block is pasted last, those eleven bytes read as valid PKCS#7 padding and vanish on unpad,
//! leaving a clean `role=admin`. No key needed — only the oracle that encrypts an email and the
//! oracle that authenticates a cookie. [`encrypt_profile`] and [`auth`] are those two oracles;
//! [`solve`] carries out the splice.

use std::collections::BTreeMap;

use crate::util::aes;
use crate::util::err::CpalError;
use crate::util::pad;

/// The AES block size in bytes.
const BLOCK: usize = 16;

/// The oracle's AES key: fixed once, used by every call, never revealed to the caller.
/// Fixed only so the challenge is reproducible.
const KEY: [u8; 16] = [7, 3, 9, 5, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];

/// Filler byte for aligning the email into the first plaintext block.
const FILLER: u8 = b'A';

/// The attacker-chosen value to paste into the `role` slot.
const PRIVILEGE: &str = "admin";

/// The PKCS#7 padding byte value (= the number of pad bytes, `16 - len("admin") = 11`).
const PAD_BYTE: u8 = 0x0B;

/// Split a `k=v` profile string ("`foo=bar&baz=qux`") on `&` then `=` into a key/value map.
///
/// Pairs missing an `=` are skipped (there is no key/value separator to split on).
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set2::l005;
/// let m = l005::parse_kv("email=foo@bar.com&uid=10&role=user");
/// assert_eq!(m.get("role").map(String::as_str), Some("user"));
/// assert_eq!(m.get("uid").map(String::as_str), Some("10"));
/// ```
pub fn parse_kv(profiles: &str) -> BTreeMap<String, String> {
    profiles
        .split('&')
        .filter_map(|pair| {
            pair.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

/// Build the profile string for `email`, stripping any `&` and `=` so the caller cannot inject
/// new keys, and fixing `uid` and `role` on the server's side.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set2::l005;
/// assert_eq!(l005::profile_for("foo"), "email=foo&uid=10&role=user");
/// assert_eq!(l005::profile_for("a=b&c"), "email=abc&uid=10&role=user");
/// ```
pub fn profile_for(email: &str) -> String {
    let safe: String = email.chars().filter(|c| *c != '&' && *c != '=').collect();
    format!("email={safe}&uid=10&role=user")
}

/// The encrypting "profile" oracle: sanitize `email`, format it into a profile, PKCS#7-pad to
/// 16-byte blocks, and AES-128-ECB-encrypt under the fixed [`KEY`]. Hands back only the cookie.
///
/// Deterministic, so the same email always yields the same cookie.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set2::l005;
/// assert_eq!(l005::encrypt_profile("foo"), l005::encrypt_profile("foo"));
/// ```
pub fn encrypt_profile(email: &str) -> Vec<u8> {
    let padded =
        pad::pkcs7_pad(profile_for(email).as_bytes(), BLOCK).expect("block size 16 fits 1..=255");
    aes::ecb_encrypt(&padded, &KEY).expect("padded, 16-byte key")
}

/// The inverse of [`encrypt_profile`] as far as the wire is concerned: AES-128-ECB-decrypt,
/// unpad the PKCS#7, and hand back the raw profile bytes.
///
/// # Errors
///
/// - [`CpalError::InvalidKeyLength`] or [`CpalError::CiphertextNotBlockAligned`], or
/// - [`CpalError::BadPadding`] when the recovered padding is malformed (typical for a cookie
///   deliberately spliced out of alignment).
fn decrypt_unpad(cookie: &[u8]) -> Result<Vec<u8>, CpalError> {
    let plain = aes::ecb_decrypt(cookie, &KEY)?;
    pad::pkcs7_unpad(&plain, BLOCK)
}

/// Decrypt a profile cookie to the `k=v` profile map it parses as.
///
/// Non-UTF-8 bytes are coerced, since a cookie that cannot round-trip to text simply is not an
/// admin profile.
pub fn decrypt_profile(cookie: &[u8]) -> Result<BTreeMap<String, String>, CpalError> {
    let plain = decrypt_unpad(cookie)?;
    let text = String::from_utf8_lossy(&plain);
    Ok(parse_kv(text.as_ref()))
}

/// The "decrypt oracle" the challenge asks to defeat: decrypt and authenticate a cookie,
/// returning `Ok(())` only when the profile's `role` field is exactly `admin`.
///
/// # Errors
///
/// Propagates any decrypt/unpad error, else returns [`CpalError::AuthFailed`] when no `admin`
/// role was recovered (the honest outcome for every real user, and the expected outcome for a
/// spliced cookie that lost its padding).
pub fn auth(cookie: &[u8]) -> Result<(), CpalError> {
    match decrypt_profile(cookie)?.get("role").map(String::as_str) {
        Some("admin") => Ok(()),
        _ => Err(CpalError::AuthFailed),
    }
}

/// Run the ECB cut-and-paste attack: using only [`encrypt_profile`] (encrypt an attacker-chosen
/// email) and no knowledge of [`KEY`], forge a cookie that [`auth`] accepts as `role=admin`.
///
/// The crafted email is `10×'A'`, `admin`, eleven `0x0B`, and `3×'A'`. Under PKCS#7 it encrypts
/// to four blocks — `email=AAAAAAAAAA`, `admin<0x0B×11>`, `AAA&uid=10&role=`, `user<pad>` — and
/// the attack is to drop the first block of the honest cookie, keep block 2, and paste block 1
/// into the `role=` slot. Submitting that splice to [`auth`] must succeed.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set2::l005;
/// let forged = l005::solve();
/// assert!(l005::auth(&forged).is_ok());
/// ```
pub fn solve() -> Vec<u8> {
    let cookie = encrypt_profile(&crafted_email());
    debug_assert_eq!(
        cookie.len(),
        4 * BLOCK,
        "the crafted email must produce four blocks"
    );

    // Keep block 0, drop block 3 (the `user` tail), then paste block 2 (`&uid=10&role=`) after
    // block 0 and block 1 (`admin` + PKCS#7 padding) last, so the forged plaintext un-pads to
    // `email=<...>&uid=10&role=admin`.
    let mut forged = Vec::with_capacity(3 * BLOCK);
    forged.extend_from_slice(&cookie[0..BLOCK]);
    forged.extend_from_slice(&cookie[2 * BLOCK..3 * BLOCK]);
    forged.extend_from_slice(&cookie[BLOCK..2 * BLOCK]);

    auth(&forged).expect("the forged cookie authenticates as role=admin");
    forged
}

/// The 29-byte email that carries `admin` in its own PKCS#7-padded block.
///
/// `10×FILLER`, then `admin`, then eleven `0x0B` pad bytes (a legal PKCS#7 value, since it fills
/// the block), then `3×FILLER`. `&uid=10&role=user` then fills out the remaining two blocks.
fn crafted_email() -> String {
    let mut email: Vec<u8> = vec![FILLER; 10];
    email.extend_from_slice(PRIVILEGE.as_bytes());
    email.extend(std::iter::repeat_n(PAD_BYTE, BLOCK - PRIVILEGE.len()));
    email.extend_from_slice(&[FILLER; 3]);
    String::from_utf8(email).expect("ASCII filler and padding stay valid UTF-8")
}

#[cfg(test)]
mod cut_and_paste {
    use super::*;

    use proptest::prelude::*;

    #[test]
    fn parses_a_profile_into_key_value_pairs() {
        let m = parse_kv("email=foo@bar.com&uid=10&role=user");
        assert_eq!(m.get("email").map(String::as_str), Some("foo@bar.com"));
        assert_eq!(m.get("uid").map(String::as_str), Some("10"));
        assert_eq!(m.get("role").map(String::as_str), Some("user"));
    }

    #[test]
    fn strips_ampersand_and_equals_from_the_email() {
        assert_eq!(profile_for("foo"), "email=foo&uid=10&role=user");
        assert_eq!(profile_for("a=b&c"), "email=abc&uid=10&role=user");
    }

    #[test]
    fn encrypt_profile_is_deterministic_and_block_aligned() {
        let a = encrypt_profile("foo@bar.com");
        let b = encrypt_profile("foo@bar.com");
        assert_eq!(a, b);
        assert!(!a.is_empty());
        assert_eq!(a.len() % BLOCK, 0);
        assert!(encrypt_profile("a-much-longer-email.example.co.uk").len() > a.len());
    }

    #[test]
    fn a_honest_profile_roundtrips_through_the_oracles() {
        let cookie = encrypt_profile("foo@bar.com");
        let m = decrypt_profile(&cookie).expect("an honest cookie must decrypt");
        assert_eq!(m.get("email").map(String::as_str), Some("foo@bar.com"));
        assert_eq!(m.get("uid").map(String::as_str), Some("10"));
        assert_eq!(m.get("role").map(String::as_str), Some("user"));
    }

    #[test]
    fn a_honest_profile_is_rejected_as_not_admin() {
        let cookie = encrypt_profile("anyone@example.com");
        assert_eq!(auth(&cookie), Err(CpalError::AuthFailed));
    }

    #[test]
    fn the_spliced_cookie_authenticates_as_admin() {
        let forged = solve();
        assert!(auth(&forged).is_ok());
    }

    #[test]
    fn the_spliced_cookie_decodes_to_a_role_admin_profile() {
        let m = decrypt_profile(&solve()).expect("the forged cookie must decrypt");
        assert_eq!(m.get("role").map(String::as_str), Some("admin"));
        assert_eq!(m.get("email").map(String::as_str), Some("AAAAAAAAAAAAA"));
        assert_eq!(m.get("uid").map(String::as_str), Some("10"));
    }

    #[test]
    fn the_admin_block_is_a_verbatim_copy_of_an_oracle_block() {
        // The whole "cut and paste" property: block 1 of the forged cookie is block 1 of the
        // honest cookie for the same email, copied byte-for-byte. No key was used to forge it.
        let honest = encrypt_profile(&crafted_email());
        let forged = solve();
        assert_eq!(&forged[2 * BLOCK..3 * BLOCK], &honest[BLOCK..2 * BLOCK]);
    }

    #[test]
    fn the_admin_block_pads_with_a_legal_pkcs7_value() {
        // Block 1 of the crafted email must be `admin` + eleven `0x0B` bytes: five content, eleven pad.
        let padded = pad::pkcs7_pad(profile_for(&crafted_email()).as_bytes(), BLOCK).unwrap();
        assert_eq!(padded.len() % BLOCK, 0);
        let admin_block = &padded[BLOCK..2 * BLOCK];
        assert_eq!(&admin_block[..5], b"admin");
        assert!(admin_block[5..].iter().all(|&b| b == 0x0B));
        // Eleven pad bytes is a legal PKCS#7 value, so this block un-pads on its own as `admin`.
        assert_eq!(pad::pkcs7_unpad(admin_block, BLOCK).unwrap(), b"admin");
    }

    proptest! {
        #[test]
        fn any_email_roundtrips_into_its_profile(
            email in "[a-z0-9.@_+-]{1,40}",
        ) {
            let m = parse_kv(&profile_for(&email));
            prop_assert_eq!(m.get("email").map(String::as_str), Some(email.as_str()));
            prop_assert_eq!(m.get("role").map(String::as_str), Some("user"));
        }

        #[test]
        fn a_honest_cookie_is_never_admin_no_matter_the_email(
            email in "[a-z0-9.@_+-]{1,40}",
        ) {
            let cookie = encrypt_profile(&email);
            let m = decrypt_profile(&cookie).expect("an honest cookie must decrypt");
            prop_assert_eq!(m.get("role").map(String::as_str), Some("user"));
            prop_assert!(auth(&cookie).is_err());
        }
    }
}
