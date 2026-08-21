//! On disk file layout for the Cipherlock CLI.
//!
//! ```text
//! [ 16 bytes salt ] [ 12 bytes nonce ] [ ciphertext, same length as plaintext ] [ 16 bytes tag ]
//! ```
//!
//! The salt seeds the passphrase KDF, the nonce is fed to ChaCha20-Poly1305,
//! and the tag is verified before any plaintext is returned.

use crate::aead;
use crate::kdf::{self, SALT_LEN};

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

#[derive(Debug)]
pub enum DecryptError {
    /// The file is too short to even contain a header, nonce, and tag.
    Truncated,
    /// The tag did not verify. Wrong passphrase or the file was tampered with.
    AuthenticationFailed,
}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecryptError::Truncated => write!(f, "file is too short to be a valid cipherlock file"),
            DecryptError::AuthenticationFailed => {
                write!(f, "authentication failed: wrong passphrase or the file has been tampered with")
            }
        }
    }
}

impl std::error::Error for DecryptError {}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).expect("OS random number generator failed");
    buf
}

/// Encrypt `plaintext` under `passphrase`, returning the full file contents
/// (salt, nonce, ciphertext, tag) ready to be written to disk.
pub fn encrypt(passphrase: &str, plaintext: &[u8]) -> Vec<u8> {
    let salt: [u8; SALT_LEN] = random_bytes();
    let nonce: [u8; NONCE_LEN] = random_bytes();
    let key = kdf::derive_key(passphrase.as_bytes(), &salt);

    let (ciphertext, tag) = aead::seal(&key, &nonce, &[], plaintext);

    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len() + TAG_LEN);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    out
}

/// Decrypt file contents produced by [`encrypt`]. Fails loudly on a bad tag:
/// wrong passphrase or tampered ciphertext both come back as
/// `DecryptError::AuthenticationFailed`, and no plaintext is ever returned
/// in that case.
pub fn decrypt(passphrase: &str, file: &[u8]) -> Result<Vec<u8>, DecryptError> {
    if file.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
        return Err(DecryptError::Truncated);
    }

    let salt: [u8; SALT_LEN] = file[0..SALT_LEN].try_into().unwrap();
    let nonce: [u8; NONCE_LEN] =
        file[SALT_LEN..SALT_LEN + NONCE_LEN].try_into().unwrap();
    let ciphertext = &file[SALT_LEN + NONCE_LEN..file.len() - TAG_LEN];
    let tag: [u8; TAG_LEN] = file[file.len() - TAG_LEN..].try_into().unwrap();

    let key = kdf::derive_key(passphrase.as_bytes(), &salt);

    aead::open(&key, &nonce, &[], ciphertext, &tag).map_err(|_| DecryptError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let file = encrypt("hunter2", b"the plans are in the drawer");
        let plaintext = decrypt("hunter2", &file).unwrap();
        assert_eq!(plaintext, b"the plans are in the drawer");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let file = encrypt("hunter2", b"the plans are in the drawer");
        let err = decrypt("wrong password", &file).unwrap_err();
        assert!(matches!(err, DecryptError::AuthenticationFailed));
    }

    #[test]
    fn tampered_file_fails() {
        let mut file = encrypt("hunter2", b"the plans are in the drawer");
        let last = file.len() - 1;
        file[last] ^= 0xff;
        assert!(decrypt("hunter2", &file).is_err());
    }
}
