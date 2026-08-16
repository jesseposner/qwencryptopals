use crate::util::err::CpalError;

/// Decode a hex-encoded string (pretty-print form) into raw bytes.
///
/// Cryptopals rule: hex, like base64, is only a transport/pretty-print layer.
/// All the actual cryptography operates on the raw bytes returned here.
pub fn from_hex(s: &str) -> Result<Vec<u8>, CpalError> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(CpalError::OddLength);
    }

    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        out.push((hex_val(bytes[i])? << 4) | hex_val(bytes[i + 1])?);
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8, CpalError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(CpalError::InvalidHexChar(b as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_a_byte() {
        assert_eq!(from_hex("ff").unwrap(), vec![0xff]);
        assert_eq!(from_hex("00").unwrap(), vec![0x00]);
    }

    #[test]
    fn decodes_multiple_bytes_and_mixed_case() {
        assert_eq!(from_hex("abcDEF").unwrap(), vec![0xab, 0xcd, 0xef]);
    }

    #[test]
    fn empty_is_empty() {
        assert_eq!(from_hex("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn odd_length_errors() {
        assert_eq!(from_hex("abc").unwrap_err(), CpalError::OddLength);
    }

    #[test]
    fn non_hex_char_errors() {
        assert_eq!(from_hex("zz").unwrap_err(), CpalError::InvalidHexChar('z'));
    }
}
