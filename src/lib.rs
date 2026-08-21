//! Cipherlock: a from scratch ChaCha20-Poly1305 AEAD toolkit.
//!
//! `chacha20` and `poly1305` implement the primitives from RFC 8439.
//! `aead` composes them into AEAD_CHACHA20_POLY1305. `kdf` turns a
//! passphrase into a key. `format` defines the on disk file layout used by
//! the CLI.

pub mod aead;
pub mod chacha20;
pub mod format;
pub mod kdf;
pub mod poly1305;
