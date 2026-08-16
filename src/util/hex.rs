//! Hex decode — a transport/pretty-print layer over raw bytes.

use crate::util::err::CpalError;

/// Decode a hex-encoded string (pretty-print form) into raw bytes.
///
/// Hex, like base64, is only a transport/pretty-print layer; the actual
/// cryptography operates on the raw bytes returned here.
///
/// # Errors
///
/// Returns [`CpalError::OddLength`] when the input length is odd, or
/// [`CpalError::InvalidHexChar`] at the first non-hex digit.
///
/// # Examples
///
/// ```
/// assert_eq!(
///     cryptopals::util::hex::from_hex("49276d").unwrap(),
///     vec![0x49, 0x27, 0x6d]
/// );
/// ```
pub fn from_hex(s: &str) -> Result<Vec<u8>, CpalError> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(CpalError::OddLength);
    }

    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks(2) {
        out.push((hex_val(pair[0])? << 4) | hex_val(pair[1])?);
    }
    Ok(out)
}

/// Convert a single hex-digit byte to its 0-15 value.
fn hex_val(b: u8) -> Result<u8, CpalError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(CpalError::InvalidHexChar(b as char)),
    }
}

#[cfg(test)]
mod from_hex {
    use super::*;

    use proptest::prelude::*;

    #[test]
    fn decodes_a_single_high_nibble_byte() {
        assert_eq!(from_hex("ff").unwrap(), vec![0xff]);
    }

    #[test]
    fn decodes_the_zero_byte() {
        assert_eq!(from_hex("00").unwrap(), vec![0x00]);
    }

    #[test]
    fn decodes_multiple_bytes_regardless_of_case() {
        assert_eq!(from_hex("abcDEF").unwrap(), vec![0xab, 0xcd, 0xef]);
    }

    #[test]
    fn decodes_an_empty_string_to_an_empty_vec() {
        assert_eq!(from_hex("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn returns_odd_length_error_when_input_length_is_odd() {
        assert_eq!(from_hex("abc").unwrap_err(), CpalError::OddLength);
    }

    #[test]
    fn returns_invalid_char_error_on_a_non_hex_digit() {
        assert_eq!(from_hex("zz").unwrap_err(), CpalError::InvalidHexChar('z'));
    }

    // Byte -> hex via std formatting is an independent oracle, not from_hex's logic.
    proptest! {
        #[test]
        fn roundtrip_decodes_any_lowercase_hex_string(input in any::<Vec<u8>>()) {
            let hex: String = input.iter().map(|b| format!("{b:02x}")).collect();
            prop_assert_eq!(from_hex(&hex), Ok(input));
        }

        #[test]
        fn roundtrip_decodes_any_uppercase_hex_string(input in any::<Vec<u8>>()) {
            let hex: String = input.iter().map(|b| format!("{b:02X}")).collect();
            prop_assert_eq!(from_hex(&hex), Ok(input));
        }

        #[test]
        fn rejects_every_odd_length_string(n in 0usize..=128) {
            let s = "a".repeat(2 * n + 1);
            prop_assert_eq!(from_hex(&s), Err(CpalError::OddLength));
        }

        #[test]
        fn reports_the_first_invalid_digit(n in 0usize..=128) {
            let s = "ab".repeat(n) + "zz";
            prop_assert_eq!(from_hex(&s), Err(CpalError::InvalidHexChar('z')));
        }
    }
}
