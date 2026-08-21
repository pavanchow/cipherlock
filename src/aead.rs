//! AEAD_CHACHA20_POLY1305, RFC 8439 section 2.8.

use crate::chacha20;
use crate::poly1305::Poly1305;

#[derive(Debug, PartialEq, Eq)]
pub struct TagMismatch;

fn pad16_len(len: usize) -> usize {
    (16 - (len % 16)) % 16
}

fn mac_data(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(
        aad.len() + pad16_len(aad.len()) + ciphertext.len() + pad16_len(ciphertext.len()) + 16,
    );
    data.extend_from_slice(aad);
    data.extend(std::iter::repeat_n(0u8, pad16_len(aad.len())));
    data.extend_from_slice(ciphertext);
    data.extend(std::iter::repeat_n(0u8, pad16_len(ciphertext.len())));
    data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    data
}

fn poly1305_key(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let block = chacha20::block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block[0..32]);
    otk
}

/// Encrypt `plaintext` with associated data `aad`, returning (ciphertext, tag).
/// Ciphertext is the same length as the plaintext.
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let otk = poly1305_key(key, nonce);
    let ciphertext = chacha20::apply_keystream(key, 1, nonce, plaintext);
    let data = mac_data(aad, &ciphertext);
    let tag = Poly1305::new(&otk).tag(&data);
    (ciphertext, tag)
}

/// Decrypt `ciphertext` and verify the tag. Fails loudly (Err) on any tag
/// mismatch: wrong passphrase, wrong nonce, or tampered ciphertext all land
/// here, and the caller must not use the plaintext if this returns Err.
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, TagMismatch> {
    let otk = poly1305_key(key, nonce);
    let data = mac_data(aad, ciphertext);
    let expected = Poly1305::new(&otk).tag(&data);

    if !constant_time_eq(&expected, tag) {
        return Err(TagMismatch);
    }

    Ok(chacha20::apply_keystream(key, 1, nonce, ciphertext))
}

fn constant_time_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc8439_aead_vector() {
        // RFC 8439 section 2.8.2
        let key: [u8; 32] =
            hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .try_into()
                .unwrap();
        let nonce: [u8; 12] = hex("070000004041424344454647").try_into().unwrap();
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let expected_ciphertext = hex(
            "d31a8d34648e60db7b86afbc53ef7ec2\
             a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b\
             1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58\
             fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b\
             6116",
        );
        let expected_tag: [u8; 16] = hex("1ae10b594f09e26a7e902ecbd0600691")
            .try_into()
            .unwrap();

        let (ciphertext, tag) = seal(&key, &nonce, &aad, plaintext);
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);

        let recovered = open(&key, &nonce, &aad, &ciphertext, &tag).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn tamper_detection() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let (mut ciphertext, tag) = seal(&key, &nonce, b"aad", b"secret message");
        ciphertext[0] ^= 0x01;
        assert!(open(&key, &nonce, b"aad", &ciphertext, &tag).is_err());
    }

    #[test]
    fn roundtrip() {
        let key = [3u8; 32];
        let nonce = [1u8; 12];
        let plaintext = b"round trip this please";
        let (ciphertext, tag) = seal(&key, &nonce, b"", plaintext);
        let recovered = open(&key, &nonce, b"", &ciphertext, &tag).unwrap();
        assert_eq!(recovered, plaintext);
    }
}
