//! Set 3, Challenge 18 — Implement CTR, the stream cipher mode.
//!
//! CTR is the one block mode good code actually ships. Instead of encrypting the plaintext, a
//! running 16-byte counter is fed through the AES core to make a keystream, which is XORed over the
//! data. No chaining, no padding, and encryption is exactly decryption again, because regenerating
//! the same keystream and re-XORing recovers the input. The reusable keystream lives in
//! [`crate::util::ctr`]; this level just adds the transport — base64 in on the way in — and points
//! it at the challenge's fixed parameters: key `YELLOW SUBMARINE`, nonce `0`, with the counter laid
//! out as an 8-byte nonce then an 8-byte little-endian block count.

use crate::util::b64;
use crate::util::ctr;
use crate::util::err::CpalError;

/// The 16-byte AES-128 key the challenge fixes: `b"YELLOW SUBMARINE"`.
pub const KEY: [u8; 16] = *b"YELLOW SUBMARINE";

/// The 64-bit nonce the challenge fixes.
pub const NONCE: u64 = 0;

/// CTR-decrypt a base64-encoded byte stream under `key` with `nonce`, returning the plaintext.
/// CTR is unkeyed on length and needs no unpadding: the decoded ciphertext is XORed against the AES
/// keystream and the result is returned whole. Because CTR is involutive, feeding back CTR of the
/// result recovers the original ciphertext.
///
/// `key` must be 16 bytes. The base64 payload may be wrapped across lines.
///
/// # Errors
///
/// - a [`crate::util::b64::b64_decode`] error, or
/// - a [`crate::util::ctr::ctr`] error (a key that is not 16 bytes).
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set3::l002;
/// let blob = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
/// let plain = l002::solve(blob, &l002::KEY, l002::NONCE).unwrap();
/// assert_eq!(plain.len(), 52);
/// ```
pub fn solve(encrypted_b64: &str, key: &[u8], nonce: u64) -> Result<Vec<u8>, CpalError> {
    let ct = b64::b64_decode(encrypted_b64)?;
    ctr::ctr(&ct, key, nonce)
}

#[cfg(test)]
mod solve {
    use super::*;

    use crate::util::b64;
    use crate::util::ctr;

    use proptest::prelude::*;

    const OFFICIAL: &str =
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

    #[test]
    fn the_official_blob_decrypts_to_approximately_english() {
        let plain = solve(OFFICIAL, &KEY, NONCE).expect("the official blob is solvable");
        // The official blob decodes to 52 bytes (18 base64 groups, the last a single byte).
        assert_eq!(plain.len(), 52);
        // "Something approximating English": the large majority of the bytes are printable ASCII,
        // with a handful of newlines separating the lines.
        let printable: usize = plain
            .iter()
            .filter(|b| b.is_ascii_graphic() || **b == b' ' || **b == b'\n')
            .count();
        // Assert only on a trivial non-substantial prefix plus the ratio, so the test itself never
        // reproduces the recovered text.
        assert!(plain.starts_with(b"Yo, "));
        assert!(
            printable >= 47,
            "only {printable}/52 bytes are printable: {:?}",
            String::from_utf8_lossy(&plain)
        );
    }

    #[test]
    fn applying_ctr_twice_roundtrips_the_official_ciphertext() {
        // CTR is involutive: decrypting the blob gives the plaintext, and re-applying the very
        // same CTR operation (same key, nonce, counter) to that plaintext recovers the ciphertext.
        let plain = solve(OFFICIAL, &KEY, NONCE).expect("the official blob is solvable");
        let re_encrypted =
            solve(&b64::b64_encode(&plain), &KEY, NONCE).expect("re-applying CTR must succeed");
        assert_eq!(re_encrypted, b64::b64_decode(OFFICIAL).unwrap());
    }

    #[test]
    fn a_key_that_is_not_sixteen_bytes_is_rejected() {
        assert_eq!(
            solve(OFFICIAL, &[0u8; 8], NONCE),
            Err(CpalError::InvalidKeyLength(8))
        );
    }

    #[test]
    fn a_malformed_base64_ciphertext_is_rejected() {
        assert!(solve("!!!", &KEY, NONCE).is_err());
    }

    proptest! {
        #[test]
        fn solve_inverts_ctr_over_base64(
            key in prop::collection::vec(any::<u8>(), 16),
            nonce in any::<u64>(),
            stream in prop::collection::vec(any::<u8>(), 0..=300),
        ) {
            let ct = ctr::ctr(&stream, &key, nonce).unwrap();
            let got = solve(&b64::b64_encode(&ct), &key, nonce).expect("CTR must decode");
            prop_assert_eq!(got, stream);
        }
    }
}
