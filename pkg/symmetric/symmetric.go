package symmetric

import (
	"crypto"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"github.com/awnumar/memguard"
	"github.com/united-manufacturing-hub/yCrypt/pkg"
	"github.com/united-manufacturing-hub/yCrypt/pkg/compress"
	"github.com/united-manufacturing-hub/yCrypt/pkg/errdef"
	"github.com/united-manufacturing-hub/yCrypt/pkg/signature"
	"github.com/united-manufacturing-hub/yCrypt/pkg/yubikey"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
)

type EncryptedData struct {
	Signer              rsa.PublicKey
	Ciphertext          []byte
	Signature           []byte
	Nonce               []byte
	EncryptedSessionKey []byte
}

// SignCompressEncrypt compresses the data using zstd,
// encrypts the data using XChaCha20-Poly1305 and signs the data using RSA.
func SignCompressEncrypt(
	sessionKeyEncryptionCertificate *x509.Certificate,
	plaintextSigner pkg.KeyOrCardInterface,
	plaintext []byte) (encryptedMessage EncryptedData, err error) {
	memguard.CatchInterrupt()

	// Sign data
	var sig []byte
	var signer rsa.PublicKey
	signer, sig, err = signature.Sign(plaintextSigner, &plaintext)
	if err != nil {
		return EncryptedData{}, err
	}

	sessionKey := memguard.NewEnclaveRandom(chacha20poly1305.KeySize)

	if sessionKey == nil {
		return EncryptedData{}, errdef.ErrorSessionKeyIsNil
	}

	var lockedBuffer *memguard.LockedBuffer
	lockedBuffer, err = sessionKey.Open()
	if err != nil {
		return EncryptedData{}, err
	}
	if lockedBuffer == nil {
		return EncryptedData{}, errdef.ErrorLockedBufferIsNil
	}
	defer lockedBuffer.Destroy()

	// Compress the data
	compressedData := compress.ZstdCompress(plaintext)

	// Fill plaintext with zeros
	for i := range plaintext {
		plaintext[i] = 0
	}

	// Encrypt data using XChaCha20-Poly1305
	var aead cipher.AEAD
	aead, err = chacha20poly1305.NewX(lockedBuffer.Data())
	if err != nil {
		return EncryptedData{}, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(compressedData)+aead.Overhead())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return EncryptedData{}, err
	}
	ciphertext := aead.Seal(nonce, nonce, compressedData, nil)

	// Encrypt session key
	var encryptedSessionKey []byte
	switch t := sessionKeyEncryptionCertificate.PublicKey.(type) {
	case *rsa.PublicKey:
		encryptedSessionKey, err = encryptSessionKeyUsingRSA(
			t,
			lockedBuffer.Data())
		if err != nil {
			return EncryptedData{}, err
		}

	default:
		return EncryptedData{}, errdef.ErrorUnknownPublicKeyAlgorithm
	}

	return EncryptedData{
		Ciphertext:          ciphertext,
		Signature:           sig,
		Nonce:               nonce,
		EncryptedSessionKey: encryptedSessionKey,
		Signer:              signer,
	}, nil
}

// encryptSessionKeyUsingRSA encrypts the session key using RSA.
func encryptSessionKeyUsingRSA(pubKey *rsa.PublicKey, sessionKey []byte) (
	encryptedSessionKey []byte,
	err error) {

	encryptedSessionKey, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, sessionKey)

	return encryptedSessionKey, err
}

// DecryptDecompressVerify decrypts the data using XChaCha20-Poly1305,
// decompresses the data using zstd and verifies the signature using RSA.
func DecryptDecompressVerify(
	ciphertext *EncryptedData,
	sessionKeyDecrypter pkg.KeyOrCardInterface,
	signatureValidator pkg.KeyOrCardInterface) (data []byte, err error) {
	// Decrypt session key
	var sessionKey []byte

	switch t := sessionKeyDecrypter.(type) {
	case *rsa.PrivateKey:
		sessionKey, err = decryptSessionKeyUsingRSA(
			ciphertext.EncryptedSessionKey, t)
		if err != nil {
			return nil, err
		}
	case pkg.SmartCardWithAdditionalData:

		var certificate *x509.Certificate
		certificate, err = t.SmartCard.GetCertificate(t.Slot)
		if err != nil {
			return nil, err
		}

		var yKey *yubikey.ThreadSafeYubikey
		yKey, err = t.SmartCard.GetYKHandle()
		if err != nil {
			return nil, err
		}
		var privateKey crypto.PrivateKey
		privateKey, err = yKey.PrivateKey(
			t.Slot,
			certificate.PublicKey,
			t.Auth)
		if err != nil {
			return nil, err
		}

		sessionKey, err = decryptSessionKeyUsingRSAYK(
			ciphertext.EncryptedSessionKey,
			privateKey.(crypto.Decrypter))

		if err != nil {
			return nil, err
		}
	}

	if len(sessionKey) != chacha20poly1305.KeySize {
		return nil, errdef.ErrorSessionKeySizeInvalid
	}

	// Decrypt data using XChaCha20-Poly1305
	var aead cipher.AEAD
	aead, err = chacha20poly1305.NewX(sessionKey)
	if err != nil {
		return nil, err
	}
	if len(ciphertext.Ciphertext) < aead.NonceSize() {
		return nil, errdef.ErrorCipherTextTooShort
	}
	nonce := ciphertext.Ciphertext[:aead.NonceSize()]
	plaintext, err := aead.Open(nil, nonce, ciphertext.Ciphertext[aead.NonceSize():], nil)
	if err != nil {
		return nil, err
	}

	// Decompress the data
	data, err = compress.ZstdDecompress(plaintext)
	if err != nil {
		return nil, err
	}

	// Verify signature
	err = signature.VerifySigned(signatureValidator, data, ciphertext.Signature)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// decryptSessionKeyUsingRSA decrypts the session key using an RSA private key.
func decryptSessionKeyUsingRSA(encryptedSessionKey []byte, decrypter *rsa.PrivateKey) (
	sessionKey []byte,
	err error) {
	sessionKey, err = rsa.DecryptPKCS1v15(rand.Reader, decrypter, encryptedSessionKey)

	return sessionKey, err
}

// decryptSessionKeyUsingRSAYK decrypts the session key using a yubikey crypto.Decrypter interface.
func decryptSessionKeyUsingRSAYK(encryptedSessionKey []byte, decrypter crypto.Decrypter) (
	sessionKey []byte,
	err error) {
	sessionKey, err = decrypter.Decrypt(
		nil,
		encryptedSessionKey,
		&rsa.PKCS1v15DecryptOptions{SessionKeyLen: chacha20poly1305.KeySize})

	return sessionKey, err
}
