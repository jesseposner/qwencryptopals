# qwencryptopals

Hand-rolled [Cryptopals](https://cryptopals.com/) solutions in Rust, one level at a time.
We hand-roll the cryptography; the only non-`std` runtime dependency is `thiserror`
(compile-time `Display`/`Error` derives for `CpalError`). Everything else, `std`.

Helpers are added **just-in-time** — only when a level actually needs one. No pre-stubbing.

## Building & testing

Run the checks the way they should be trusted:

```sh
cargo fmt
cargo test
cargo clippy --all-targets --all-features --locked -- -D warnings
```

`proptest` is a **dev-only** dependency used for property tests; it never ships in the crate.

## Conventions

- **TDD per level.** Tests first (red), then the implementation that flips them green,
  verified with the commands above before each commit.
- **Cryptopals rule.** Crypto happens on raw `&[u8]` / `Vec<u8>`; hex and base64 are
  transport/pretty-print layers only, never the operation.
- **`util` helpers just-in-time.** A helper (`xor`, `stream_cipher`, …) is introduced only
  when a level needs it.
- **One module per level** under `sets/<setN>/lNN.rs` with a public `solve`.
- **Errors** are a hand-grown, `thiserror`-derived `CpalError`; variants added just-in-time.
- **Docs enforced**: a crate-level `#![deny(missing_docs)]` means every public item is
  documented.
- **Properties over examples** where they're stronger:
  - decoders → roundtrip against an independent oracle (a `format!("{:02x}")` reference);
  - pure crypto ops (e.g. `xor`) → commutativity, identity, self-inverse, and inverse
    properties;
  - codecs → length/charset/padding invariants.
  All `proptest`-based.

## Layout

```
src/
  lib.rs            crate root; #![deny(missing_docs)]
  util/             just-in-time shared helpers
    err.rs          CpalError
     hex.rs          from_hex (decode)
     b64.rs          b64_encode
     xor.rs          xor (byte-wise)
  sets/
    set1/
      l001.rs       Set 1 / Level 1
      …
```
