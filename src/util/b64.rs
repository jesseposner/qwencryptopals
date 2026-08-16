//! Base64 (RFC 4640) encode — a transport/pretty-print layer over raw bytes.

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
