//! Set 1 / Level 1 — Convert hex to base64.
//!
//! Official Cryptopals vector: the given hex blob must encode to the given base64 string.
//! Per the Cryptopals rule we operate on raw bytes; hex (in) and base64 (out) are just I/O.

use crate::util::b64;
use crate::util::err::CpalError;
use crate::util::hex;

/// Solve Level 1: decode the input hex, then re-encode those bytes as base64.
///
/// # Errors
///
/// Propagates the errors from [`crate::util::hex::from_hex`].
pub fn solve(input_hex: &str) -> Result<String, CpalError> {
    let bytes = hex::from_hex(input_hex)?;
    Ok(b64::b64_encode(&bytes))
}

#[cfg(test)]
mod solve {
    use super::*;

    const INPUT_HEX: &str =
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const EXPECTED_B64: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    #[test]
    fn produces_the_official_base64_for_the_level_one_vector() {
        let got = solve(INPUT_HEX).expect("valid input must not error");
        assert_eq!(got, EXPECTED_B64);
    }
}
