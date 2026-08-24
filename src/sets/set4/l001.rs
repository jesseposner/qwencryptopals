//! Set 4, Challenge 25 - "random access read/write" AES CTR.
//!
//! The plaintext here is what [L12](crate::sets::set2::l004) recovered: the fixed secret the
//! byte-at-a-time ECB oracle appends, read off byte by byte. That plaintext is re-encrypted
//! under CTR, counter laid out the way [L18](crate::sets::set3::l002) lays it out (8-byte nonce,
//! 8-byte little-endian block count), under a 16-byte key the service drew once and holds.
//!
//! The service exposes one primitive, [`edit`]: seek to an offset, overwrite that region of the
//! *plaintext* with new text, re-encrypt the whole message, and hand back the new ciphertext.
//! CTR makes the seek trivial: the keystream is a pure function of the counter, so byte N of the
//! stream can be generated without walking from the start, and an edit is just a decrypt, a
//! splice, and an encrypt again.
//!
//! That convenience is the hole. The keystream is the same on every call, so one edit that
//! writes zeros across the whole document hands the caller the raw keystream, `0 ^ KS`. The
//! caller already has `C = P ^ KS`; XORing the two gives `P`, the entire original plaintext, in
//! a single oracle call, with the key never in sight. [`solve`] runs exactly that attack.

use crate::util::ctr;
use crate::util::err::CpalError;
use crate::util::xor;

/// The service's AES-128 key: drawn once, held by the service, and never shown to the
/// attacker. It is a fixed value only so the challenge is reproducible, the way
/// [L17](crate::sets::set3::l001) fixes its cookie key.
pub const KEY: [u8; 16] = [
    129, 85, 133, 47, 201, 63, 90, 14, 178, 55, 233, 7, 110, 196, 31, 88,
];

/// The nonce the service fixes for every call: with the counter space pinned, "seeking" means
/// only choosing where in it to start.
pub const NONCE: u64 = 0;

/// The service's edit: decrypt `ct` under CTR, splice `newtext` into the plaintext starting at
/// `offset`, re-encrypt the whole message, and return the new ciphertext.
///
/// The splice must fit inside the document: `offset` may sit at most at the end (where an empty
/// `newtext` is a no-op), and `offset + newtext.len()` may not run past it.
///
/// # Errors
///
/// - a [`ctr`] error (a key that is not 16 bytes), or
/// - a [`CpalError::CiphertextTooShort`] when the splice runs past the end of `ct`.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set4::l001;
/// let secret = cryptopals::sets::set2::l004::solve();
/// let ct = cryptopals::util::ctr::ctr(&secret, &l001::KEY, l001::NONCE).unwrap();
/// let edited = l001::edit(&ct, &l001::KEY, 0, b"hello").unwrap();
/// assert_eq!(edited.len(), ct.len());
/// ```
pub fn edit(ct: &[u8], key: &[u8], offset: usize, newtext: &[u8]) -> Result<Vec<u8>, CpalError> {
    let plain = ctr::ctr(ct, key, NONCE)?;

    if offset.checked_add(newtext.len()) > Some(ct.len()) {
        return Err(CpalError::CiphertextTooShort(offset));
    }

    let mut spliced = plain;
    spliced.splice(offset..offset + newtext.len(), newtext.iter().copied());
    ctr::ctr(&spliced, key, NONCE)
}

/// The attack: one edit call that writes zeros across the whole document returns the raw
/// keystream, and `P = C ^ KS` reads the original plaintext off in the same call.
///
/// `edit` is the attacker's view of the service: given an offset and new text, it returns the
/// re-encrypted document. The key and the plaintext never cross the wire.
///
/// # Errors
///
/// - whatever the oracle returns, or
/// - a [`CpalError::LengthMismatch`] if the oracle's answer does not line up with `ct`.
///
/// # Examples
///
/// ```
/// use cryptopals::sets::set4::l001;
/// let secret = cryptopals::sets::set2::l004::solve();
/// let ct = cryptopals::util::ctr::ctr(&secret, &l001::KEY, l001::NONCE).unwrap();
/// let recovered =
///     l001::solve(&ct, &|offset, newtext| l001::edit(&ct, &l001::KEY, offset, newtext)).unwrap();
/// assert_eq!(recovered, secret);
/// ```
#[allow(clippy::type_complexity)] // the oracle closure type is the API; an alias would pin newtext's lifetime to 'static
pub fn solve(
    ct: &[u8],
    edit: &dyn Fn(usize, &[u8]) -> Result<Vec<u8>, CpalError>,
) -> Result<Vec<u8>, CpalError> {
    let keystream = edit(0, &vec![0u8; ct.len()])?;
    if keystream.len() != ct.len() {
        return Err(CpalError::LengthMismatch {
            a: ct.len(),
            b: keystream.len(),
        });
    }
    xor::xor(ct, &keystream)
}

#[cfg(test)]
mod solve {
    use super::*;
    use crate::sets::set2::l004;
    use proptest::prelude::*;

    fn secret() -> Vec<u8> {
        l004::solve()
    }

    fn encrypt(secret: &[u8]) -> Vec<u8> {
        ctr::ctr(secret, &KEY, NONCE).expect("KEY is 16 bytes")
    }

    fn oracle(ct: &[u8], offset: usize, newtext: &[u8]) -> Result<Vec<u8>, CpalError> {
        edit(ct, &KEY, offset, newtext)
    }

    #[test]
    fn the_attack_recovers_the_ecb_exercise_secret() {
        let secret = secret();
        let ct = encrypt(&secret);
        let recovered = solve(&ct, &|offset, newtext| oracle(&ct, offset, newtext))
            .expect("one keystream leak");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn a_zeroed_full_length_edit_returns_the_raw_keystream() {
        let secret = secret();
        let ct = encrypt(&secret);
        let keystream = oracle(&ct, 0, &vec![0u8; ct.len()]).expect("the edit fits");
        assert_eq!(xor::xor(&ct, &keystream).expect("same length"), secret);
    }

    #[test]
    fn an_edit_touches_only_the_bytes_it_writes() {
        let secret = secret();
        let ct = encrypt(&secret);
        let at = 7;
        let newtext = b"qwerty";
        let edited = oracle(&ct, at, newtext).expect("the edit fits");
        for i in 0..ct.len() {
            if i < at || i >= at + newtext.len() {
                assert_eq!(edited[i], ct[i], "byte {i} is outside the edit");
            }
        }
        for (j, &b) in newtext.iter().enumerate() {
            let i = at + j;
            // The edited byte is re-encrypted: C'[i] = P'[i] ^ KS[i], and KS[i] = C[i] ^ P[i].
            assert_eq!(
                edited[i],
                b ^ ct[i] ^ secret[i],
                "byte {i} is re-encrypted, not copied"
            );
        }
    }

    #[test]
    fn an_edit_past_the_end_is_rejected() {
        let ct = encrypt(&secret());
        assert_eq!(
            edit(&ct, &KEY, ct.len(), b"x"),
            Err(CpalError::CiphertextTooShort(ct.len()))
        );
        assert_eq!(
            edit(&ct, &KEY, ct.len() + 3, b""),
            Err(CpalError::CiphertextTooShort(ct.len() + 3))
        );
    }

    #[test]
    fn a_key_that_is_not_sixteen_bytes_is_rejected() {
        let ct = encrypt(&secret());
        assert_eq!(
            edit(&ct, &KEY[..15], 0, b"x"),
            Err(CpalError::InvalidKeyLength(15))
        );
    }

    #[test]
    fn an_empty_document_cannot_host_a_nonempty_edit() {
        assert_eq!(
            edit(&[], &KEY, 0, b"x"),
            Err(CpalError::CiphertextTooShort(0))
        );
    }

    #[test]
    fn a_noop_edit_at_the_end_roundtrips_the_document() {
        let ct = encrypt(&secret());
        assert_eq!(
            edit(&ct, &KEY, ct.len(), &[]).expect("an empty edit fits at the end"),
            ct
        );
    }

    proptest! {
        #[test]
        fn the_attack_recovers_any_secret(secret in prop::collection::vec(any::<u8>(), 1..=256)) {
            let ct = ctr::ctr(&secret, &KEY, NONCE).expect("KEY is 16 bytes");
            let got = solve(&ct, &|offset, newtext| edit(&ct, &KEY, offset, newtext))
                .expect("keystream leak");
            prop_assert_eq!(got, secret);
        }

        #[test]
        fn an_edit_matches_splice_then_ctr(
            plain in prop::collection::vec(any::<u8>(), 1..=32),
            offset in 0usize..=32,
            newtext in prop::collection::vec(any::<u8>(), 0..=8),
        ) {
            prop_assume!(offset + newtext.len() <= plain.len());
            let ct = ctr::ctr(&plain, &KEY, NONCE).expect("KEY is 16 bytes");
            let edited = edit(&ct, &KEY, offset, &newtext).expect("the edit fits");
            let spliced: Vec<u8> = plain
                .iter()
                .enumerate()
                .map(|(i, &b)| {
                    if i >= offset && i < offset + newtext.len() {
                        newtext[i - offset]
                    } else {
                        b
                    }
                })
                .collect();
            prop_assert_eq!(
                edited,
                ctr::ctr(&spliced, &KEY, NONCE).expect("KEY is 16 bytes")
            );
        }
    }
}
