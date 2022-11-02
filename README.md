# yCrypt

yCrypt is a simple encryption, decryption & signing package for go.

Expect breaking changes until v1.0.0.


## Contributing

Make sure to install the pre-push hooks.

    $ git config core.hooksPath .githooks

## Usage

 - Sign
   - This function signs a message by calculating an SHA256 hash of the message and signing it using RSA PKCS1v15.
 - Verify
   - This function verifies a message by calculating an SHA256 hash of the message and verifying it using RSA PKCS1v15.
 - EncryptAndSign
   1) Signing of the plaintext using the `Sign` function.
   2) Generation of a random symmetric key.
   3) Encryption of the plaintext using the symmetric key, using XChaCha20Poly1305.
   4) Encryption of the symmetric key using the public key, using RSA PKCS1v15.
 - DecryptAndVerify
   1) Decryption of the symmetric key using the private key, using RSA PKCS1v15.
   2) Decryption of the ciphertext using the symmetric key, using XChaCha20Poly1305.
   3) Verification of the plaintext using the `Verify` function.

## Notes

PKCS1v15 will be replaced with OAEP in the future.