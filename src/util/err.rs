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
}
