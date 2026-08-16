//! Frequency analysis: an English-likeness score and the best single-byte XOR key search
//! built on it.

/// Rough English-plaintext score: a weighted count of ASCII lowercase letters and space,
/// using relative English letter frequencies. Real English text is letter-dense with the right
/// per-letter frequencies, so a true plaintext scores well above a random (or wrongly de-keyed)
/// buffer — the discriminator single-byte XOR breaks rely on.
pub fn english_score(data: &[u8]) -> u32 {
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

/// Decrypt `ciphertext` with every candidate key byte and return the `(key, plaintext)` pair
/// whose [`english_score`] is highest. Ties go to the lower key byte.
///
/// Assumes the input is a single-byte-XOR-encrypted English plaintext; on any other input it
/// still returns the 256-arg-maximum, not an error.
pub fn best_single_byte_key(ciphertext: &[u8]) -> (u8, Vec<u8>) {
    let mut best_key = 0u8;
    let mut best_plain = ciphertext.to_vec();
    let mut best_score = english_score(ciphertext);
    for key in 1..=u8::MAX {
        let plain: Vec<u8> = ciphertext.iter().map(|&b| b ^ key).collect();
        let score = english_score(&plain);
        if score > best_score {
            (best_key, best_plain, best_score) = (key, plain, score);
        }
    }
    (best_key, best_plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    const ENGLISH_SAMPLES: [&str; 4] = [
        "The quick brown fox jumps over the lazy dog.",
        "Pack my box with five dozen liquor jugs.",
        "How vexingly quick daft zebras jump!",
        "Sphinx of black quartz, judge my vow.",
    ];

    #[test]
    fn english_scores_a_real_sentence_above_random_bytes() {
        let english = ENGLISH_SAMPLES[0].as_bytes();
        let random = b"\x89\xE6\xA1\x03\x80\x4B\xC2\x09\xFE\xD0";
        assert!(english_score(english) > english_score(random));
    }

    #[test]
    fn a_nonsensical_buffer_scores_zero() {
        let random = b"\x89\xE6\xA1\x03\x80\x4B\xC2\x09\xFE\xD0";
        assert_eq!(english_score(random), 0);
    }

    proptest! {
        #[test]
        fn best_single_byte_key_recovers_key_and_plaintext(
            key in any::<u8>(),
            idx in 0..ENGLISH_SAMPLES.len(),
        ) {
            let plain: Vec<u8> = ENGLISH_SAMPLES[idx].as_bytes().to_vec();
            let ct: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
            let (got_key, got_plain) = best_single_byte_key(&ct);
            prop_assert_eq!(got_key, key);
            prop_assert_eq!(got_plain, plain);
        }
    }
}
