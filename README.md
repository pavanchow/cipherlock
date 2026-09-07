<img src="docs/logo.svg" alt="Cipherlock logo" width="96">

**Cipherlock is a from scratch ChaCha20-Poly1305 authenticated encryption toolkit you can read and use.**

Most tools that do authenticated encryption either shell out to OpenSSL or wrap a crypto library as a black box. Cipherlock implements ChaCha20-Poly1305 (RFC 8439) directly in Rust with no crypto crates, so the same small binary that encrypts and decrypts your files is also the clearest place to read exactly how a modern AEAD works: the ChaCha20 stream cipher, the Poly1305 authenticator, and the construction that combines them into one authenticated encryption scheme.

## What it does

- Encrypts and decrypts files with a passphrase.
- Uses ChaCha20-Poly1305, the same authenticated encryption construction used in TLS 1.3 and WireGuard.
- Fails loudly on decryption if the passphrase is wrong or the ciphertext was tampered with. Authenticated encryption means a bad tag is a hard error, never a silently wrong plaintext.
- Ships as one binary, one crate, readable start to finish.

## Security note, read this before you use it for anything real

- ChaCha20, Poly1305, and the combined AEAD are implemented from scratch in `src/chacha20.rs`, `src/poly1305.rs`, and `src/aead.rs`. No crypto crates were used for the primitives.
- Correctness is checked against the official RFC 8439 known answer test vectors: the ChaCha20 block function vector, the ChaCha20 encryption vector, the Poly1305 vector, and the full AEAD vector. All four pass, see below.
- The passphrase to key derivation function in `src/kdf.rs` is a simple fixed round hash based stretch built on the ChaCha20 block function. It is honest but weak compared to Argon2 or scrypt. It has no memory hardness, which makes it more parallelizable to attack on GPUs than a proper password hashing function.
- This is a correct, teaching grade tool. Do not roll your own crypto in production. For anything that protects real secrets against a real attacker, use an audited library and a real password hashing function.

## Usage

Build it:

```
cargo build --release
```

Encrypt a file:

```
cipherlock encrypt secret.txt secret.txt.lock --pass "correct horse battery staple"
```

Decrypt it back:

```
cipherlock decrypt secret.txt.lock secret.txt --pass "correct horse battery staple"
```

A wrong passphrase, or a ciphertext that has been modified in any way, makes decryption fail with an authentication error. Nothing is written on failure.

## File format

```
[ 16 bytes salt ] [ 12 bytes nonce ] [ ciphertext ] [ 16 bytes tag ]
```

See `DESIGN.md` for how the pieces fit together.

## Testing

```
cargo test
```

This runs the RFC 8439 test vectors, an encrypt then decrypt roundtrip, and a tamper detection test that flips a ciphertext byte and checks that decryption fails.

## By Pavan Nallamothu.
