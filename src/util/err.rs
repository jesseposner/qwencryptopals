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
}
