//! A simple, honest, non-Argon2 passphrase KDF for v0.1.
//!
//! This repeatedly hashes the passphrase together with a random salt using
//! the ChaCha20 block function as a compression primitive. It is a fixed
//! round hash based stretch, not a memory hard KDF. See the README security
//! note: do not treat this as a replacement for Argon2 or scrypt in anything
//! that needs real brute force resistance.

use crate::chacha20;

pub const SALT_LEN: usize = 16;
const ROUNDS: u32 = 200_000;

/// Derive a 32-byte key from a passphrase and salt.
pub fn derive_key(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> [u8; 32] {
    // Seed the state from a hash-like mix of passphrase and salt, then
    // repeatedly run it through the ChaCha20 block function, feeding the
    // output back in as the next block's key material.
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];

    for (i, b) in passphrase.iter().enumerate() {
        key[i % 32] ^= *b;
        nonce[i % 12] ^= b.wrapping_add(salt[i % SALT_LEN]);
    }
    for (i, b) in salt.iter().enumerate() {
        key[(i + 7) % 32] ^= *b;
    }

    for round in 0..ROUNDS {
        let block = chacha20::block(&key, round, &nonce);
        for i in 0..32 {
            key[i] ^= block[i];
        }
        for i in 0..12 {
            nonce[i] ^= block[32 + i];
        }
    }

    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_inputs() {
        let salt = [1u8; SALT_LEN];
        let a = derive_key(b"correct horse battery staple", &salt);
        let b = derive_key(b"correct horse battery staple", &salt);
        assert_eq!(a, b);
    }

    #[test]
    fn different_passphrase_different_key() {
        let salt = [1u8; SALT_LEN];
        let a = derive_key(b"passphrase one", &salt);
        let b = derive_key(b"passphrase two", &salt);
        assert_ne!(a, b);
    }

    #[test]
    fn different_salt_different_key() {
        let a = derive_key(b"same passphrase", &[1u8; SALT_LEN]);
        let b = derive_key(b"same passphrase", &[2u8; SALT_LEN]);
        assert_ne!(a, b);
    }
}
