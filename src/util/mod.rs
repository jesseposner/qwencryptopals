//! Shared helpers, added just-in-time as a level needs them.
//!
//! Per the Cryptopals rule these are transport/pretty-print layers; the real
//! cryptography on raw bytes lives here as it becomes necessary.

pub mod b64;
pub mod entropy;
pub mod err;
pub mod freq;
pub mod hex;
pub mod pad;
pub mod xor;
