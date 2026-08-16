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
}
