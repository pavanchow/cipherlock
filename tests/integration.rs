//! Integration tests exercising cipherlock through its public crate API, the
//! way a downstream consumer would. These complement the per-module unit tests
//! (which carry the RFC 8439 known-answer vectors) by covering the top-level
//! file format, cross-module properties, and error paths end to end.

use cipherlock::aead;
use cipherlock::chacha20;
use cipherlock::format::{self, DecryptError};
use cipherlock::kdf;
use cipherlock::poly1305;

const MIN_FILE_LEN: usize = kdf::SALT_LEN + format::NONCE_LEN + format::TAG_LEN;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn file_roundtrip() {
    let pass = "correct horse battery staple";
    let plaintext = b"the launch codes are in the second drawer";
    let file = format::encrypt(pass, plaintext);
    let recovered = format::decrypt(pass, &file).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn empty_plaintext_roundtrips_and_hits_min_length() {
    let file = format::encrypt("pw", b"");
    assert_eq!(file.len(), MIN_FILE_LEN, "empty payload is header + tag only");
    assert_eq!(format::decrypt("pw", &file).unwrap(), b"");
}

#[test]
fn large_multiblock_roundtrip() {
    // 10 KiB spans ~160 ChaCha20 blocks, so this fails if the block counter
    // does not advance correctly across block boundaries.
    let plaintext: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    let file = format::encrypt("pw", &plaintext);
    assert_eq!(format::decrypt("pw", &file).unwrap(), plaintext);
}

#[test]
fn truncated_file_is_rejected() {
    let short = vec![0u8; MIN_FILE_LEN - 1];
    assert!(matches!(
        format::decrypt("pw", &short),
        Err(DecryptError::Truncated)
    ));
    // A zero-length file is also truncated, not a panic.
    assert!(matches!(
        format::decrypt("pw", &[]),
        Err(DecryptError::Truncated)
    ));
}

#[test]
fn wrong_passphrase_is_rejected() {
    let file = format::encrypt("right", b"secret");
    assert!(matches!(
        format::decrypt("wrong", &file),
        Err(DecryptError::AuthenticationFailed)
    ));
}

#[test]
fn a_single_bitflip_in_any_region_is_rejected() {
    let pass = "pw";
    let base = format::encrypt(pass, b"tamper evident payload here");
    // salt, nonce, ciphertext, and tag regions each cover a distinct offset.
    for offset in [0usize, kdf::SALT_LEN, MIN_FILE_LEN, base.len() - 1] {
        let mut tampered = base.clone();
        tampered[offset] ^= 0x01;
        assert!(
            matches!(
                format::decrypt(pass, &tampered),
                Err(DecryptError::AuthenticationFailed)
            ),
            "flip at offset {offset} should fail authentication"
        );
    }
}

#[test]
fn aead_detects_aad_tampering() {
    let key = [0x24u8; 32];
    let nonce = [0x11u8; 12];
    let (ciphertext, tag) = aead::seal(&key, &nonce, b"header-v1", b"body");
    // Same key/nonce/ciphertext/tag but a different AAD must not verify.
    assert!(aead::open(&key, &nonce, b"header-v2", &ciphertext, &tag).is_err());
    // The original AAD still opens.
    assert_eq!(
        aead::open(&key, &nonce, b"header-v1", &ciphertext, &tag).unwrap(),
        b"body"
    );
}

#[test]
fn aead_public_pipeline_matches_rfc8439_vector() {
    // RFC 8439 section 2.8.2, checked through the public seal() entry point so
    // a broken re-export or visibility change is caught at the crate boundary.
    let key: [u8; 32] =
        hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .try_into()
            .unwrap();
    let nonce: [u8; 12] = hex("070000004041424344454647").try_into().unwrap();
    let aad = hex("50515253c0c1c2c3c4c5c6c7");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected_tag: [u8; 16] = hex("1ae10b594f09e26a7e902ecbd0600691")
        .try_into()
        .unwrap();

    let (_ciphertext, tag) = aead::seal(&key, &nonce, &aad, plaintext);
    assert_eq!(tag, expected_tag);
}

#[test]
fn chacha20_keystream_is_self_inverse() {
    let key = [0x42u8; 32];
    let nonce = [0x07u8; 12];
    let msg = b"applying the keystream twice returns the plaintext";
    let once = chacha20::apply_keystream(&key, 1, &nonce, msg);
    assert_ne!(&once[..], &msg[..], "ciphertext must differ from plaintext");
    let twice = chacha20::apply_keystream(&key, 1, &nonce, &once);
    assert_eq!(&twice[..], &msg[..]);
}

#[test]
fn poly1305_free_fn_matches_struct_api() {
    let key = [0x9au8; 32];
    let message = b"two public entry points, one result";
    let via_fn = poly1305::poly1305_mac(&key, message);
    let via_struct = poly1305::Poly1305::new(&key).tag(message);
    assert_eq!(via_fn, via_struct);
}

#[test]
fn kdf_key_is_deterministic_and_salt_sensitive() {
    let salt_a = [1u8; kdf::SALT_LEN];
    let salt_b = [2u8; kdf::SALT_LEN];
    let k1 = kdf::derive_key(b"passphrase", &salt_a);
    let k2 = kdf::derive_key(b"passphrase", &salt_a);
    let k3 = kdf::derive_key(b"passphrase", &salt_b);
    assert_eq!(k1, k2, "same passphrase and salt must derive the same key");
    assert_ne!(k1, k3, "a different salt must derive a different key");
}
