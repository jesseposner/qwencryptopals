/// Encode raw bytes as base64 (RFC 4640, standard alphabet, `=` padding).
///
/// base64 is only a transport/pretty-print layer; the cryptography operates on
/// the raw bytes passed in.
/// Standard base64 alphabet, RFC 4640 §4: A-Z a-z 0-9 + /
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(input: &[u8]) -> String {
    // Output length is always a multiple of 4, at most ceil(input/3) groups.
    let mut out = String::with_capacity((input.len() / 3 + 1) * 4);

    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;

        let i0 = (n >> 18 & 0x3f) as usize;
        let i1 = (n >> 12 & 0x3f) as usize;
        let i2 = (n >> 6 & 0x3f) as usize;
        let i3 = (n & 0x3f) as usize;

        out.push(ALPHABET[i0] as char);
        out.push(ALPHABET[i1] as char);
        out.push(ALPHABET[i2] as char);
        out.push(ALPHABET[i3] as char);

        // 3 bytes -> full 4 symbols; 2 bytes -> drop the last symbol, pad one;
        // 1 byte -> drop the last two symbols, pad twice.
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
mod tests {
    use super::*;

    #[test]
    fn empty() {
        assert_eq!(b64_encode(&[]), "");
    }

    #[test]
    fn no_padding_three_bytes() {
        assert_eq!(b64_encode("abc".as_bytes()), "YWJj");
    }

    #[test]
    fn single_pad_two_bytes() {
        assert_eq!(b64_encode("ab".as_bytes()), "YWI=");
    }

    #[test]
    fn double_pad_one_byte() {
        assert_eq!(b64_encode("a".as_bytes()), "YQ==");
    }
}
