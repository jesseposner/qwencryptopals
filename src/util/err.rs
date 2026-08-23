//! Shared error type for the Cryptopals helpers.

use thiserror::Error;

/// Minimal error type for the Cryptopals helpers.
/// New variants are added just-in-time as a level needs them.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CpalError {
    /// A character that is not a valid hex digit (0-9, a-f, A-F).
    #[error("invalid hex character '{0}'")]
    InvalidHexChar(char),

    /// A hex string with an odd number of characters.
    #[error("hex string has an odd number of characters")]
    OddLength,

    /// The two inputs to a byte-wise operation have differing lengths.
    #[error("inputs have different lengths: {a} and {b}")]
    LengthMismatch {
        /// Length of the first input.
        a: usize,
        /// Length of the second input.
        b: usize,
    },

    /// A character that is not in the base64 alphabet (`A-Z a-z 0-9 + /`).
    #[error("invalid base64 character '{0}'")]
    InvalidBase64Char(char),

    /// A base64 string whose length or padding is structurally invalid.
    #[error("invalid base64 length {0}")]
    InvalidBase64Length(usize),

    /// No candidate lines were supplied to inspect.
    #[error("no lines to inspect")]
    NoLines,

    /// The key to a repeating-key operation has no bytes.
    #[error("key has no bytes")]
    EmptyKey,

    /// The base64-decoded ciphertext is too short to analyze.
    #[error("ciphertext too short to analyze: {0} bytes")]
    CiphertextTooShort(usize),

    /// An AES mode got a key that is not the 16 bytes AES-128 requires.
    #[error("AES-128 key must be 16 bytes, got {0}")]
    InvalidKeyLength(usize),

    /// An AES ciphertext whose byte length is not a whole number of 16-byte blocks.
    #[error("AES ciphertext has {0} bytes, not a multiple of 16")]
    CiphertextNotBlockAligned(usize),

    /// An initialization vector for a block-cipher mode that is not 16 bytes.
    #[error("initialization vector must be 16 bytes, got {0}")]
    InvalidIvLength(usize),

    /// A plaintext to encrypt under a block mode that is not a whole number of 16-byte blocks
    /// (i.e. the caller skipped the pad step).
    #[error("plain text has {0} bytes, not a multiple of 16")]
    PlaintextNotBlockAligned(usize),

    /// No ciphertext line revealed the repeated-block signature of ECB.
    #[error("no ciphertext line shows a repeated 16-byte block")]
    NoRepeatedBlock,

    /// A PKCS#7 block size outside `1..=255` was requested.
    #[error("block size must be 1..=255 bytes, got {0}")]
    InvalidBlockSize(usize),

    /// A buffer's PKCS#7 padding is malformed for its block size.
    #[error("malformed PKCS#7 padding in {0} bytes")]
    BadPadding(usize),

    /// A decrypted profile's `role` field is not `admin`.
    #[error("profile role is not admin")]
    AuthFailed,

    /// No seed in the searched window produced the observed RNG output.
    #[error("no seed in the window produced the observed output")]
    NoSeedFound,
}
