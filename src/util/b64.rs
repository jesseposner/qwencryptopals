//! Base64 (RFC 4640) encode and decode — a transport/pretty-print layer over raw bytes.

use crate::util::err::CpalError;

/// Standard base64 alphabet, RFC 4640 §4: `A-Z a-z 0-9 + /`.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode raw bytes as base64 (RFC 4640, standard alphabet, `=` padding).
///
/// Base64 is only a transport/pretty-print layer; the cryptography operates on
/// the raw bytes passed in.
///
/// # Examples
///
/// ```
/// assert_eq!(cryptopals::util::b64::b64_encode(b"abc"), "YWJj");
/// ```
pub fn b64_encode(input: &[u8]) -> String {
    // Output is a multiple of 4 chars across ceil(input/3) groups.
    let mut out = String::with_capacity((input.len() / 3 + 1) * 4);

    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;

        let i0 = (n >> 18 & 0x3f) as usize;
        let i1 = (n >> 12 & 0x3f) as usize;
        let i2 = (n >> 6 & 0x3f) as usize;
        let i3 = (n & 0x3f) as usize;

        out.push(ALPHABET[i0] as char);
        out.push(ALPHABET[i1] as char);
        out.push(ALPHABET[i2] as char);
        out.push(ALPHABET[i3] as char);

        // 3 bytes -> full 4 symbols; 2 bytes -> pad one; 1 byte -> pad twice.
        if chunk.len() == 1 {
            out.pop();
            out.pop();
            out.push('=');
            out.push('=');
        } else if chunk.len() == 2 {
            out.pop();
            out.push('=');
        }
    }
    out
}

/// Decode a base64 string (RFC 4640, standard alphabet, `=` padding) to raw bytes.
///
/// A transport/pretty-print layer; the cryptography operates on the raw bytes returned.
/// Surrounding whitespace (including a trailing newline) is ignored.
///
/// # Errors
///
/// - [`CpalError::InvalidBase64Length`] if the length is not a multiple of four, or the
///   padding is not a trailing run of at most two `=` characters.
/// - [`CpalError::InvalidBase64Char`] if a character is not in the base64 alphabet.
///
/// # Examples
///
/// ```
/// assert_eq!(cryptopals::util::b64::b64_decode("YWJj"), Ok(b"abc".to_vec()));
/// ```
pub fn b64_decode(input: &str) -> Result<Vec<u8>, CpalError> {
    let input = input.trim();
    let len = input.len();
    if len == 0 {
        return Ok(Vec::new());
    }
    if !len.is_multiple_of(4) {
        return Err(CpalError::InvalidBase64Length(len));
    }

    let bytes = input.as_bytes();
    let pad = bytes.iter().rev().take_while(|c| **c == b'=').count();
    if pad > 2 || bytes[..len - pad].contains(&b'=') {
        return Err(CpalError::InvalidBase64Length(len));
    }

    // Padding sextets decode to zero; decode every group then truncate to the true length.
    let out_len = (len - pad) * 3 / 4;
    let mut out = Vec::with_capacity(out_len);
    for group in bytes.chunks(4) {
        let mut n: u32 = 0;
        for c in group {
            let v = match c {
                b'A'..=b'Z' => u32::from(*c - b'A'),
                b'a'..=b'z' => u32::from(*c - b'a') + 26,
                b'0'..=b'9' => u32::from(*c - b'0') + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => 0,
                _ => return Err(CpalError::InvalidBase64Char(*c as char)),
            };
            n = (n << 6) | v;
        }
        out.push(((n >> 16) & 0xff) as u8);
        out.push(((n >> 8) & 0xff) as u8);
        out.push((n & 0xff) as u8);
    }
    out.truncate(out_len);
    Ok(out)
}

#[cfg(test)]
mod b64_encode {
    use super::*;

    use proptest::prelude::*;

    #[test]
    fn encodes_an_empty_input_to_an_empty_string() {
        assert_eq!(b64_encode(&[]), "");
    }

    #[test]
    fn encodes_a_full_three_byte_block_with_no_padding() {
        assert_eq!(b64_encode("abc".as_bytes()), "YWJj");
    }

    #[test]
    fn pads_a_two_byte_input_with_one_eq_char() {
        assert_eq!(b64_encode("ab".as_bytes()), "YWI=");
    }

    #[test]
    fn pads_a_one_byte_input_with_two_eq_chars() {
        assert_eq!(b64_encode("a".as_bytes()), "YQ==");
    }

    proptest! {
        #[test]
        fn output_length_is_an_exact_multiple_of_four(input in any::<Vec<u8>>()) {
            let enc = b64_encode(&input);
            prop_assert_eq!(enc.len(), 4 * input.len().div_ceil(3));
            prop_assert!(enc.len().is_multiple_of(4));
        }

        #[test]
        fn output_only_uses_alphabet_and_padding(input in any::<Vec<u8>>()) {
            for c in b64_encode(&input).chars() {
                prop_assert!(ALPHABET.contains(&(c as u8)) || c == '=');
            }
        }

        #[test]
        fn padding_count_matches_input_length(input in any::<Vec<u8>>()) {
            let expected_pad: usize = match input.len() % 3 {
                0 => 0,
                1 => 2,
                _ => 1,
            };
            let enc = b64_encode(&input);
            prop_assert_eq!(enc.matches('=').count(), expected_pad);
            if expected_pad > 0 {
                let padding = "=".repeat(expected_pad);
                prop_assert!(enc.ends_with(padding.as_str()));
            }
        }
    }
}

#[cfg(test)]
mod b64_decode {
    use super::*;

    use proptest::prelude::*;

    #[test]
    fn decodes_a_full_three_byte_block() {
        assert_eq!(b64_decode("YWJj"), Ok(b"abc".to_vec()));
    }

    #[test]
    fn decodes_a_two_byte_input() {
        assert_eq!(b64_decode("YWI="), Ok(b"ab".to_vec()));
    }

    #[test]
    fn decodes_a_one_byte_input() {
        assert_eq!(b64_decode("YQ=="), Ok(b"a".to_vec()));
    }

    #[test]
    fn decodes_an_empty_string_to_an_empty_vec() {
        assert_eq!(b64_decode(""), Ok(Vec::new()));
    }

    #[test]
    fn ignores_surrounding_whitespace() {
        assert_eq!(b64_decode("  YWJj\n"), Ok(b"abc".to_vec()));
    }

    #[test]
    fn rejects_a_length_not_multiple_of_four() {
        assert_eq!(b64_decode("YWJjZ"), Err(CpalError::InvalidBase64Length(5)));
    }

    #[test]
    fn rejects_a_character_outside_the_alphabet() {
        assert_eq!(b64_decode("YWJ!"), Err(CpalError::InvalidBase64Char('!')));
    }

    #[test]
    fn rejects_padding_that_is_not_at_the_end() {
        assert_eq!(b64_decode("YW=Jjg"), Err(CpalError::InvalidBase64Length(6)));
    }

    #[test]
    fn rejects_more_than_two_trailing_pad_chars() {
        assert_eq!(b64_decode("Y==="), Err(CpalError::InvalidBase64Length(4)));
    }

    proptest! {
        #[test]
        fn decoding_an_encoding_recovers_the_input(input in any::<Vec<u8>>()) {
            let enc = b64_encode(&input);
            prop_assert_eq!(b64_decode(&enc), Ok(input));
        }
    }
}
