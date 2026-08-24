//! Set 3, Challenge 19 — Break fixed-nonce CTR mode using substitutions.
//!
//! CTR with a **fixed nonce** (here `0`) and a counter that restarts for every message is a stream
//! cipher run with the same keystream prefix over and over. Every ciphertext is therefore XORed
//! against the leading bytes of one shared keystream, which leaks two things at once:
//!
//! - XORing any two ciphertexts cancels the keystream and leaves their plaintexts' XOR, and
//! - one fully-known `(ciphertext, plaintext)` pair pins that shared keystream, so the first
//!   *k* bytes of **every** other ciphertext read off as plaintext, where *k* is the pair's length.
//!
//! The reusable attack lives in [`crate::util::ctr`] (`shared_keystream`, `recover`). This level is
//! the concrete C19 setup: CTR-encrypt each of the 40 lines below under one fixed key and nonce,
//! then recover all of them end-to-end from a single known line. The plaintext is W. B. Yeats's
//! "Easter, 1916," public domain since the mid-20th century.

use crate::util::ctr;

/// The 16-byte AES-128 key the challenge says to "generate." Fixed here only so the 40 ciphertexts
/// are reproducible; it is never read back and is not the answer.
pub const KEY: [u8; 16] = *b"0123456789abcdef";

/// The fixed 64-bit nonce: `0`. This is the misconfiguration the whole level exploits.
pub const NONCE: u64 = 0;

/// The 40 plaintext lines C19 encrypts, in order (W. B. Yeats, "Easter, 1916," public domain).
/// The two lines that spell "thougt" and "louu" carry the spellings the official challenge data
/// provides, and are kept byte-for-byte so recovery reproduces exactly what was encrypted.
pub const LINES: &[&str] = &[
    "I have met them at close of day",
    "Coming with vivid faces",
    "From counter or desk among grey",
    "Eighteenth-century houses.",
    "I have passed with a nod of the head",
    "Or polite meaningless words,",
    "Or have lingered awhile and said",
    "Polite meaningless words,",
    "And thought before I had done",
    "Of a mocking tale or a gibe",
    "To please a companion",
    "Around the fire at the club,",
    "Being certain that they and I",
    "But lived where motley is worn:",
    "All changed, changed utterly:",
    "A terrible beauty is born.",
    "That woman's days were spent",
    "In ignorant good will,",
    "Her nights in argument",
    "Until her voice grew shrill.",
    "What voice more sweet than hers",
    "When young and beautiful,",
    "She rode to harriers?",
    "This man had kept a school",
    "And rode our winged horse.",
    "This other his helper and friend",
    "Was coming into his force;",
    "He might have won fame in the end,",
    "So sensitive his nature seemed,",
    "So daring and sweet his thougt.",
    "This other man I had dreamed",
    "A drunken, vain-glorious louu.",
    "He had done most bitter wrong",
    "To some who are near my heart,",
    "Yet I number him in the song;",
    "He, too, has resigned his part",
    "In the casual comedy;",
    "He, too, has been changed in his turn,",
    "Transformed utterly:",
    "A terrible beauty is born.",
];

/// CTR-encrypt each of [`LINES`] **independently** under the fixed [`KEY`]/[`NONCE`] — the nonce
/// stays `0` and the counter restarts from zero for every line, producing the 40 short ciphertexts
/// of the challenge. This is the vulnerable misconfiguration the attack runs against.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set3::l003;
/// let cts = l003::ciphers();
/// assert_eq!(cts.len(), l003::LINES.len());
/// // Every ciphertext is a different number of bytes than its plaintext only if CTR padded; it
/// // does not, so each ciphertext matches its plaintext byte-for-byte in length.
/// assert_eq!(cts[0].len(), l003::LINES[0].len());
/// ```
pub fn ciphers() -> Vec<Vec<u8>> {
    LINES
        .iter()
        .map(|line| ctr::ctr(line.as_bytes(), &KEY, NONCE).expect("KEY is a 16-byte constant"))
        .collect()
}

/// Recover the plaintext bytes of each of `ciphertexts` from one known
/// `(known_ct, known_pt)` pair, using the shared-keystream attack from
/// [`ctr::recover`]. A known line as long as the longest target recovers every target in full; a
/// shorter known line recovers only the shared prefix, and bytes past it are left as ciphertext.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set3::l003;
/// let cts = l003::ciphers();
/// // The longest line, once known, pins the keystream for the whole range.
/// let longest = (0..cts.len()).max_by_key(|&i| cts[i].len()).unwrap();
/// let out = l003::solve(&cts, &cts[longest], l003::LINES[longest].as_bytes());
/// assert_eq!(out[0], l003::LINES[0].as_bytes());
/// assert_eq!(out[out.len() - 1], l003::LINES[l003::LINES.len() - 1].as_bytes());
/// ```
pub fn solve(ciphertexts: &[Vec<u8>], known_ct: &[u8], known_pt: &[u8]) -> Vec<Vec<u8>> {
    ctr::recover(ciphertexts, known_ct, known_pt)
}

#[cfg(test)]
mod recovery {
    use super::*;

    use crate::util::ctr;

    use proptest::prelude::*;

    #[test]
    fn every_line_recovers_end_to_end_from_a_single_known_line() {
        let cts = ciphers();
        assert_eq!(cts.len(), LINES.len());

        // One known ciphertext/plaintext pair — the longest line, which spans the full keystream —
        // is enough to read every one of the 40 lines back, byte for byte.
        let known = (0..cts.len()).max_by_key(|&i| cts[i].len()).unwrap();
        let out = solve(&cts, &cts[known], LINES[known].as_bytes());

        for (i, line) in LINES.iter().enumerate() {
            assert_eq!(out[i], line.as_bytes(), "line {i} did not recover");
        }
    }

    #[test]
    fn two_ciphertexts_share_nothing_but_their_keystream() {
        // The fixed nonces mean c[0] ^ c[i] equals the plaintexts' XOR on the whole overlap: the
        // keystream cancels out. Assert this directly, with no known plaintext supplied.
        let cts = ciphers();
        for i in 1..cts.len() {
            let n = cts[0].len().min(cts[i].len());
            for (j, (a, b)) in cts[0].iter().zip(&cts[i]).take(n).enumerate() {
                assert_eq!(
                    a ^ b,
                    LINES[0].as_bytes()[j] ^ LINES[i].as_bytes()[j],
                    "line {i}, byte {j}"
                );
            }
        }
    }

    #[test]
    fn a_shorter_known_line_covers_only_its_shared_prefix() {
        let cts = ciphers();
        let (short, long) = (16usize, 37usize);
        assert!(
            cts[short].len() < cts[long].len(),
            "test invariant: a known line shorter than its target"
        );

        let out = solve(&cts, &cts[short], LINES[short].as_bytes());
        let shared = cts[short].len();

        // Over the shared prefix the target is real plaintext...
        assert_eq!(&out[long][0..shared], &LINES[long].as_bytes()[0..shared]);
        // ...and past it the byte is still the raw ciphertext, NOT the plaintext.
        assert_ne!(&out[long][shared..], &LINES[long].as_bytes()[shared..]);
        assert_eq!(&out[long][shared..], &cts[long][shared..]);
    }

    #[test]
    fn ciphers_are_reproducible_and_independent_per_line() {
        // Each ciphertext is exactly its own line run through CTR with a fresh counter at nonce 0,
        // and rerunning the fixed key gives the same ciphertexts — no cross-line chaining.
        let cts = ciphers();
        assert_eq!(cts, ciphers());
        for (i, line) in LINES.iter().enumerate() {
            let expected = ctr::ctr(line.as_bytes(), &KEY, NONCE).expect("KEY is 16 bytes");
            assert_eq!(cts[i], expected, "line {i}");
        }
    }

    #[test]
    fn the_line_count_matches_the_official_forty() {
        assert_eq!(LINES.len(), 40);
    }

    proptest! {
        #[test]
        fn solve_recovers_an_independent_ctr_set_given_its_longest_line(
            key in prop::collection::vec(any::<u8>(), 16),
            msgs in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..=200), 1..=12),
        ) {
            let cts: Vec<Vec<u8>> = msgs.iter().map(|m| ctr::ctr(m, &key, 0).unwrap()).collect();
            let known = cts
                .iter()
                .enumerate()
                .max_by(|x, y| x.1.len().cmp(&y.1.len()))
                .map(|(i, _)| i)
                .unwrap();
            let out = solve(&cts, &cts[known], &msgs[known]);
            for (i, m) in msgs.iter().enumerate() {
                prop_assert_eq!(&out[i], m);
            }
        }
    }
}
