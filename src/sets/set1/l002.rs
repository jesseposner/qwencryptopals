//! Set 1 / Level 2 — Fixed XOR.
//!
//! Two equal-length buffers are XOR'd byte-wise; the official Cryptopals vectors are
//! hex-encoded. Per the Cryptopals rule we decode to raw bytes, XOR, and keep the result
//! as bytes (hex above is just transport).

use crate::util::err::CpalError;
use crate::util::hex;
use crate::util::xor;

/// Solve Level 2: hex-decode both buffers, XOR them byte-wise, and return the result.
///
/// # Errors
///
/// Propagates errors from [`crate::util::hex::from_hex`] and [`crate::util::xor::xor`].
pub fn solve(a_hex: &str, b_hex: &str) -> Result<Vec<u8>, CpalError> {
    let a = hex::from_hex(a_hex)?;
    let b = hex::from_hex(b_hex)?;
    xor::xor(&a, &b)
}

#[cfg(test)]
mod solve {
    use super::*;

    const INPUT_A_HEX: &str = "1c0111001f010100061a024b53535009181c";
    const INPUT_B_HEX: &str = "686974207468652062756c6c277320657965";
    const EXPECTED_HEX: &str = "746865206b696420646f6e277420706c6179";

    #[test]
    fn produces_the_official_xor_output() {
        let got = solve(INPUT_A_HEX, INPUT_B_HEX).expect("valid input must not error");
        let want = hex::from_hex(EXPECTED_HEX).expect("known-good output hex");
        assert_eq!(got, want);
    }
}
