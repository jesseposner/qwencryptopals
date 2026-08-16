#![deny(missing_docs)]

//! Cryptopals: hand-rolled solutions, one level at a time.
//!
//! Shared helpers live in `util`; per-setting solutions live in `sets`.
//! Only the helpers a level actually needs are implemented — more are added
//! just-in-time. Hex and base64 are in for now.

pub mod sets;
pub mod util;
