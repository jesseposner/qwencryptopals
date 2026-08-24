//! Set 1, Challenge 5 — Repeating-key XOR.
//!
//! The plaintext is XOR'd against a key that cycles from its start. The official vector is a
//! hex plaintext and a hex key; per the Cryptopals rule we work on raw bytes and treat hex
//! purely as transport.

use crate::util::err::CpalError;
use crate::util::hex;
use crate::util::xor;

/// Solve Challenge 5: hex-decode the plaintext and key, then return the repeating-key XOR
/// ciphertext.
///
/// # Errors
///
/// Propagates errors from [`crate::util::hex::from_hex`] and [`crate::util::xor::xore`]
/// (an empty key).
pub fn solve(plain_hex: &str, key_hex: &str) -> Result<Vec<u8>, CpalError> {
    let plain = hex::from_hex(plain_hex)?;
    let key = hex::from_hex(key_hex)?;
    xor::xore(&plain, &key)
}

#[cfg(test)]
mod solve {
    use super::*;

    const PLAIN_HEX: &str =
        "4275726e696e672027656d2c20696620796f752061696e277420717569636b20616e64206e696d626c650a4920676f206372617a79207768656e2049206865617220612063796d62616c";
    const KEY_HEX: &str = "494345";
    const EXPECTED_HEX: &str =
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

    #[test]
    fn produces_the_official_ciphertext() {
        let got = solve(PLAIN_HEX, KEY_HEX).expect("valid input must not error");
        let want = hex::from_hex(EXPECTED_HEX).expect("known-good output hex");
        assert_eq!(got, want);
    }

    #[test]
    fn an_empty_key_rejects() {
        assert_eq!(solve("42", ""), Err(CpalError::EmptyKey));
    }
}
