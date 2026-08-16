//! Set 1 / Level 3 — Single-byte XOR cipher.
//!
//! A message was XOR'd using a single byte repeated across the whole buffer. The official
//! ciphertext is hex-encoded; per the Cryptopals rule we decode it to raw bytes, then — for
//! each of the 256 candidate key bytes — decrypt and score the result as English. The key
//! that yields the highest score is the answer.

use crate::util::err::CpalError;
use crate::util::hex;
use crate::util::xor;

/// Solve Level 3: find the single-byte XOR key and return it alongside the decrypted
/// plaintext.
///
/// # Errors
///
/// Propagates [`crate::util::hex::from_hex`] errors for the hex ciphertext.
pub fn solve(cipher_hex: &str) -> Result<(u8, Vec<u8>), CpalError> {
    let ct = hex::from_hex(cipher_hex)?;
    let (key, plain) = best_key(&ct);
    Ok((key, plain))
}

/// Decrypt the ciphertext with every candidate key byte and return the key byte and
/// plaintext that the [english_score] heuristic rates highest.
fn best_key(ct: &[u8]) -> (u8, Vec<u8>) {
    let mut key_buf = vec![0u8; ct.len()];
    let mut best_key = 0u8;
    let mut best_plain = xor::xor(ct, &key_buf).expect("key and ciphertext are the same length");
    let mut best_score = english_score(&best_plain);
    for key in 1..=u8::MAX {
        key_buf.fill(key);
        let plain = xor::xor(ct, &key_buf).expect("key and ciphertext are the same length");
        let score = english_score(&plain);
        if score > best_score {
            best_score = score;
            best_key = key;
            best_plain = plain;
        }
    }
    (best_key, best_plain)
}

/// Rough English-plaintext score: a weighted count of ASCII lowercase letters and space,
/// using relative English letter frequencies. Only the correct key byte turns the ciphertext
/// back into a letter-dense English string, so the key that maximizes this score wins.
fn english_score(data: &[u8]) -> u32 {
    // Relative single-letter frequencies for 'a'..'z'; space is treated as most frequent.
    const FREQ: [u32; 26] = [
        8, 1, 3, 5, 12, 2, 2, 5, 7, 1, 1, 4, 2, 7, 9, 2, 1, 6, 9, 10, 4, 1, 1, 2, 2, 1,
    ];
    let mut total = 0u32;
    for &b in data {
        match b {
            b'a'..=b'z' => total += FREQ[(b - b'a') as usize],
            b' ' => total += 15,
            _ => {}
        }
    }
    total
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
