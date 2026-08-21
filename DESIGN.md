# Design

Cipherlock implements AEAD_CHACHA20_POLY1305 as described in RFC 8439. This document walks through the three layers, from the bottom up, and the on disk file layout the CLI uses on top of them.

## ChaCha20

ChaCha20 is a stream cipher. It expands a 256 bit key, a 96 bit nonce, and a 32 bit block counter into an arbitrary length keystream, which is then XORed with the plaintext.

The core is the block function in `src/chacha20.rs`. It builds a 4 by 4 matrix of 32 bit words from four fixed constants, the key, the block counter, and the nonce, then runs 20 rounds of a simple add rotate xor quarter round, alternating between column rounds and diagonal rounds. The result is added, word by word, to the original matrix and serialized in little endian order to produce a 64 byte keystream block.

Encryption and decryption are the same operation: split the data into 64 byte chunks, generate one keystream block per chunk with an increasing counter, and XOR. There is no key schedule beyond the block function itself, and no padding, since a stream cipher can produce exactly as much keystream as it needs.

## Poly1305

Poly1305 is a one time message authenticator. It takes a 256 bit one time key, split into two 128 bit halves called `r` and `s`, and a message, and produces a 128 bit tag.

The message is split into 16 byte blocks. Each block is read as a little endian number with a 1 bit appended just past its own length, added to a running accumulator, and the accumulator is multiplied by `r` modulo the prime `2^130 - 5`. After the last block, `s` is added to the accumulator and the low 128 bits are serialized as the tag.

`src/poly1305.rs` represents the accumulator and `r` as five 26 bit limbs so that every intermediate multiplication fits safely inside a 128 bit integer, which is the standard way to implement Poly1305 without a big integer library. `r` is clamped before use, per the RFC, by clearing specific bits so that the multiplication stays inside the field the algorithm needs.

Poly1305 is a one time authenticator. The key must never be reused across two different messages, which is why the AEAD construction below derives a fresh Poly1305 key from the ChaCha20 key and the message nonce for every single encryption.

## The AEAD construction

`src/aead.rs` combines the two primitives into AEAD_CHACHA20_POLY1305:

1. Generate a one time Poly1305 key by running the ChaCha20 block function with counter 0 and taking the first 32 bytes of the output as `r` and `s`.
2. Encrypt the plaintext with ChaCha20 starting at counter 1, since counter 0 was used for the Poly1305 key.
3. Build the authenticated data: associated data, padded to a multiple of 16 bytes with zeros, followed by the ciphertext, padded the same way, followed by the 8 byte little endian length of the associated data and the 8 byte little endian length of the ciphertext.
4. Compute the Poly1305 tag over that authenticated data using the one time key from step 1.

Decryption recomputes the same tag from the received ciphertext and associated data and compares it, in constant time, against the tag that came with the message, before ChaCha20 is ever run to recover the plaintext. If the tag does not match, nothing is decrypted and the caller gets a hard error. This is what makes the scheme authenticated: a tampered ciphertext, or a wrong key, is detected before any attacker controlled plaintext is ever produced.

## Passphrase key derivation

`src/kdf.rs` turns a passphrase and a random salt into the 256 bit key that feeds the AEAD. It mixes the passphrase and salt into an initial key and nonce, then repeatedly runs them through the ChaCha20 block function, folding the output back in each round. This is a fixed round hash based stretch. It is not memory hard and is not a substitute for Argon2 or scrypt, see the README for the full security note.

## Nonce and tag layout

Every encrypted file has this layout:

```
[ 16 bytes salt ] [ 12 bytes nonce ] [ ciphertext, same length as the plaintext ] [ 16 bytes tag ]
```

- The salt is generated fresh for every encryption and feeds the passphrase KDF.
- The nonce is generated fresh for every encryption and feeds ChaCha20-Poly1305. Reusing a nonce with the same key breaks the security of both ChaCha20 and Poly1305, so Cipherlock never reuses one: a new random salt and nonce are drawn from the OS random number generator on every encrypt call, which means a new key is derived every time as well.
- The tag sits at the end so the file can be streamed and verified as a single unit: read everything, split off the last 16 bytes, verify, then decrypt.
