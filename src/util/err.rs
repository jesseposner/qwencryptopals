use std::error::Error;
use std::fmt;

/// Minimal hand-rolled error type for the Cryptopals helpers.
/// New variants are added just-in-time as a level needs them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpalError {
    /// A character that is not a valid hex digit (0-9, a-f, A-F).
    InvalidHexChar(char),
    /// A hex string with an odd number of characters.
    OddLength,
}

impl fmt::Display for CpalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CpalError::InvalidHexChar(c) => write!(f, "invalid hex character '{c}'"),
            CpalError::OddLength => write!(f, "hex string has an odd number of characters"),
        }
    }
}

impl Error for CpalError {}
