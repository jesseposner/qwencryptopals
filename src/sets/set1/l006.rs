//! Set 1, Challenge 6 — Breaking a repeating-key XOR cipher.
//!
//! The base64 blob is a repeating-key XOR ciphertext of English. `solve` finds the key length by
//! minimizing the mean normalized entropy of the ciphertext columns, recovers each key byte by
//! per-column [`freq::best_single_byte_key`], and returns `(key, plaintext)` whose
//! `key.len()` is the recovered fundamental key length.

use crate::util::b64;
use crate::util::entropy;
use crate::util::err::CpalError;
use crate::util::freq;
use crate::util::xor;

/// Inclusive upper bound on the repeating key length the estimator searches.
///
/// A key this long has no multiple inside the window, so the minimum-entropy column split
/// identifies the fundamental period unambiguously; and it comfortably exceeds this level's known
/// key length (29 bytes: `Terminator X: Bring the noise`).
const MAX_KEY_LEN: usize = 48;

/// Solve Challenge 6.
///
/// Base64-decodes `ciphertext`, estimates the repeating key length, recovers the key by
/// per-column frequency analysis, and pairs it with the decrypted plaintext. The returned
/// `key.len()` is the recovered key length and `plaintext == xor::xore(ciphertext, key)`.
///
/// # Errors
///
/// Propagates [`b64::b64_decode`] errors, or [`CpalError::CiphertextTooShort`] when the decoded
/// ciphertext holds fewer than two bytes.
pub fn solve(ciphertext: &str) -> Result<(Vec<u8>, Vec<u8>), CpalError> {
    let ct = b64::b64_decode(ciphertext)?;
    if ct.len() < 2 {
        return Err(CpalError::CiphertextTooShort(ct.len()));
    }

    let key_len = key_length(&ct);
    let key: Vec<u8> = (0..key_len)
        .map(|col| {
            let column = column_of(&ct, col, key_len);
            freq::best_single_byte_key(&column).0
        })
        .collect();
    let plaintext =
        xor::xore(&ct, &key).expect("key length is at least two, so the key is non-empty");
    Ok((key, plaintext))
}

/// The key length `l` in `[2, MAX_KEY_LEN]` that minimizes the mean entropy of its `l` columns.
/// Ties go to the smaller `l`.
fn key_length(ct: &[u8]) -> usize {
    let upper = MAX_KEY_LEN.min(ct.len());
    (2..=upper)
        .map(|l| (l, column_entropy(ct, l)))
        .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(l, _)| l)
        .unwrap_or(2)
}

/// Weighted mean of the normalized entropy of the `l` column slices of `ct`. Each column is `ct`
/// read at stride `l`; its weight is its share of the total byte count, so the result is a
/// length-independent "English-ness" measure comparable across candidate key lengths.
fn column_entropy(ct: &[u8], l: usize) -> f64 {
    let total = ct.len() as f64;
    (0..l)
        .map(|col| {
            let column = column_of(ct, col, l);
            (column.len() as f64 / total) * entropy::normalized_shannon_entropy(&column)
        })
        .sum()
}

/// The slice of `ct`'s bytes at positions `col, col + step, col + 2·step, …`.
fn column_of(ct: &[u8], col: usize, step: usize) -> Vec<u8> {
    ct.iter().skip(col).step_by(step).copied().collect()
}

#[cfg(test)]
mod solve {
    use super::*;

    use proptest::prelude::*;

    /// Repeats of English sentences: a column of a repeating-key XOR of this reads like English at
    /// the right key length, so both the key-length estimator and the per-column key search work.
    const CORPUS: &str =
        "The quick brown fox jumps over the lazy dog. Pack my box with five dozen \
                         liquor jugs. Now that the party is jumping over the fence.";

    #[test]
    fn recovers_the_official_key_and_plaintext() {
        let blob = include_str!("../../../data/challenge_06.txt");
        let (key, plain) = solve(blob).expect("the official blob is solvable");
        assert_eq!(key, "Terminator X: Bring the noise".as_bytes());
        assert!(plain.starts_with(b"I'm back and I'm ringin' the bell"));
    }

    #[test]
    fn a_single_byte_ciphertext_is_too_short() {
        assert_eq!(solve("YQ=="), Err(CpalError::CiphertextTooShort(1)));
    }

    #[test]
    fn an_invalid_base64_character_is_reported() {
        assert_eq!(solve("AA!B"), Err(CpalError::InvalidBase64Char('!')));
    }

    proptest! {
        #[test]
        fn recovers_the_fundamental_key_length(
            key in prop::collection::vec(any::<u8>(), 25..=48),
        ) {
            let corpus = CORPUS.as_bytes();
            let plain: Vec<u8> = corpus.iter().cycle().take(key.len() * 120).copied().collect();
            let ct = xor::xore(&plain, &key).expect("non-empty key");
            let (got_key, _) = solve(&b64::b64_encode(&ct)).expect("valid blob must not error");
            prop_assert_eq!(got_key.len(), key.len());
        }
    }
}
