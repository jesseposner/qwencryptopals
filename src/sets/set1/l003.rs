//! Set 1, Challenge 3 — Single-byte XOR cipher.
//!
//! A message was XOR'd using a single byte repeated across the whole buffer. The official
//! ciphertext is hex-encoded; per the Cryptopals rule we decode it to raw bytes, then search
//! for the key by maximizing the decrypted-English frequency score from
//! [`crate::util::freq::best_single_byte_key`].

use crate::util::err::CpalError;
use crate::util::freq;
use crate::util::hex;

/// Solve Challenge 3: find the single-byte XOR key and return it alongside the decrypted
/// plaintext.
///
/// # Errors
///
/// Propagates [`crate::util::hex::from_hex`] errors for the hex ciphertext.
pub fn solve(cipher_hex: &str) -> Result<(u8, Vec<u8>), CpalError> {
    let ct = hex::from_hex(cipher_hex)?;
    let (key, plain) = freq::best_single_byte_key(&ct);
    Ok((key, plain))
}

#[cfg(test)]
mod solve {
    use super::*;

    use proptest::prelude::*;

    const CIPHER_HEX: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    const EXPECTED: &[u8] = b"Cooking MC's like a pound of bacon";

    const ENGLISH_SAMPLES: [&str; 4] = [
        "The quick brown fox jumps over the lazy dog.",
        "Pack my box with five dozen liquor jugs.",
        "How vexingly quick daft zebras jump!",
        "Sphinx of black quartz, judge my vow.",
    ];

    #[test]
    fn decrypts_the_official_single_byte_ciphertext() {
        let (key, plain) = solve(CIPHER_HEX).expect("official ciphertext must not error");
        assert_eq!(key, 0x58, "'X' is the expected single-byte key");
        assert_eq!(
            plain.as_slice(),
            EXPECTED,
            "decryption must match the expected plaintext"
        );
    }

    proptest! {
        #[test]
        fn recovers_key_and_plaintext(
            key in any::<u8>(),
            idx in 0..ENGLISH_SAMPLES.len(),
        ) {
            let plain: Vec<u8> = ENGLISH_SAMPLES[idx].as_bytes().to_vec();
            let ct: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
            let hex_str: String = ct.iter().map(|&b| format!("{:02x}", b)).collect();
            let (got_key, got_plain) = solve(&hex_str).expect("synthetic ciphertext must not error");
            prop_assert_eq!(got_key, key);
            prop_assert_eq!(got_plain, plain);
        }
    }
}
