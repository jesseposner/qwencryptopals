# cryptopals

Hand-rolled [Cryptopals](https://cryptopals.com/) solutions in Rust, one level at a time.
We hand-roll the cryptography: every Set 1 level is built from `std` plus `thiserror`
(compile-time `Display`/`Error` derives for `CpalError`). The one exception is
**Set 1 / Level 7** (AES-128 in ECB mode), which uses the
[`aes`](https://docs.rs/aes) crate for the AES block primitive itself — plus its
`generic-array` 16-byte wrapper. **Set 2 / Level 11** (the ECB/CBC detection oracle)
adds a single runtime dependency, [`rand`](https://docs.rs/rand), to draw the oracle's
random key, prefix/suffix and mode.

Helpers are added **just-in-time** — only when a level actually needs one. No pre-stubbing.

## Building & testing

Run the checks the way they should be trusted:

```sh
cargo fmt
cargo test
cargo clippy --all-targets --all-features --locked -- -D warnings
```

Or, if you have [just](https://github.com/casey/just), `just gate` runs the three
in sequence (it's the default recipe). Others: `just test`, `just test-fuzz`,
`just lvl set1 l003`, `just lint`, `just fmt`, `just doc` — or `just -l` for the
full list. The suite is **187 unit + 30 doc tests** and growing one level at a time.

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
  lib.rs               crate root; #![deny(missing_docs)]
  util/                just-in-time shared helpers
    err.rs             CpalError
    hex.rs             from_hex (decode)
    b64.rs             b64_encode / b64_decode
    aes.rs             aes::ecb_encrypt / aes::ecb_decrypt (AES-128-ECB, hand-rolled repeat)
    cbc.rs             cbc::decrypt / cbc::encrypt (AES-128-CBC, hand-rolled chain)
    ctr.rs             ctr::ctr (AES-128-CTR; involutive) + shared_keystream / recover (fixed-nonce reuse)
    pad.rs             pkcs7_pad / pkcs7_unpad
    xor.rs             xor (byte-wise) + xore (repeating-key)
    freq.rs            english_score + best_single_byte_key
    entropy.rs         normalized_shannon_entropy
  sets/
    set1/
      l001.rs … l008.rs    Set 1, Levels 1–8
    set2/
      l001.rs … l008.rs    Set 2, Levels 1–8 (PKCS#7, CBC, ECB/CBC oracle, byte-at-a-time ECB, cut-and-paste ECB, byte-at-a-time harder, PKCS#7 pad validation, CBC bit-flip)
    set3/
      l001.rs            Set 3, Level 1 (the CBC padding oracle)
      l002.rs            Set 3, Level 2 (AES-128-CTR stream cipher)
      l003.rs            Set 3, Level 3 (break fixed-nonce CTR via keystream reuse)
      l004.rs            Set 3, Level 4 (block cipher mode detection)
data/
  challenge_04.txt, challenge_06.txt, challenge_07.txt, challenge_08.txt,
  challenge_10.txt   official Cryptopals payloads read by their test modules
docs/
  index.html         self-contained HTML walkthrough of Sets 1–3, Levels L1–L20
```
