package symmetric

import (
	"crypto"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/awnumar/memguard"
	"github.com/united-manufacturing-hub/yCrypt/pkg"
	"github.com/united-manufacturing-hub/yCrypt/pkg/signature"
	"github.com/united-manufacturing-hub/yCrypt/pkg/yubikey"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"math/big"
)

type EncryptedData struct {
	Ciphertext          []byte
	Signature           []byte
	Nonce               []byte
	EncryptedSessionKey []byte
	CertificateSerial   big.Int
}

func EncryptAndSign(
	sessionKeyEncryptionCertificate *x509.Certificate,
	plaintextSigner pkg.KeyOrCardInterface,
	plaintext []byte) (encryptedMessage EncryptedData, err error) {
	memguard.CatchInterrupt()

	// Sign data
	var sig []byte
	sig, err = signature.Sign(plaintextSigner, &plaintext)
	if err != nil {
		return EncryptedData{}, err
	}

	sessionKey := memguard.NewEnclaveRandom(chacha20poly1305.KeySize)

	if sessionKey == nil {
		return EncryptedData{}, errors.New("sessionKey is nil")
	}

	var lockedBuffer *memguard.LockedBuffer
	lockedBuffer, err = sessionKey.Open()
	if err != nil {
		return EncryptedData{}, err
	}
	if lockedBuffer == nil {
		return EncryptedData{}, errors.New("lockedBuffer is nil")
	}
	defer lockedBuffer.Destroy()

	// Encrypt data using XChaCha20-Poly1305
	var aead cipher.AEAD
	aead, err = chacha20poly1305.NewX(lockedBuffer.Data())
	if err != nil {
		return EncryptedData{}, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return EncryptedData{}, err
	}
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)

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
		return EncryptedData{}, errors.New("unknown public key type")
	}

	return EncryptedData{
		Ciphertext:          ciphertext,
		Signature:           sig,
		Nonce:               nonce,
		EncryptedSessionKey: encryptedSessionKey,
		CertificateSerial:   *sessionKeyEncryptionCertificate.SerialNumber,
	}, nil
}

func encryptSessionKeyUsingRSA(pubKey *rsa.PublicKey, sessionKey []byte) (
	encryptedSessionKey []byte,
	err error) {
	//TODO: use OAEP

	encryptedSessionKey, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, sessionKey)

	return encryptedSessionKey, err
}

func DecryptAndVerifySig(
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
	fmt.Printf("sessionKey: %x, len: %d\n", sessionKey, len(sessionKey))

	if len(sessionKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("session key has wrong size: %d", len(sessionKey))
	}

	// Decrypt data using XChaCha20-Poly1305
	var aead cipher.AEAD
	aead, err = chacha20poly1305.NewX(sessionKey)
	if err != nil {
		return nil, err
	}
	if len(ciphertext.Ciphertext) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext.Ciphertext[:aead.NonceSize()]
	plaintext, err := aead.Open(nil, nonce, ciphertext.Ciphertext[aead.NonceSize():], nil)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Decrypted data: %s\n", plaintext)
	// Verify signature
	err = signature.VerifySigned(signatureValidator, plaintext, ciphertext.Signature)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func decryptSessionKeyUsingRSA(encryptedSessionKey []byte, decrypter *rsa.PrivateKey) (
	sessionKey []byte,
	err error) {
	//TODO: use OAEP
	sessionKey, err = rsa.DecryptPKCS1v15(rand.Reader, decrypter, encryptedSessionKey)

	return sessionKey, err
}

func decryptSessionKeyUsingRSAYK(encryptedSessionKey []byte, decrypter crypto.Decrypter) (
	sessionKey []byte,
	err error) {
	//TODO: use OAEP
	sessionKey, err = decrypter.Decrypt(
		nil,
		encryptedSessionKey,
		&rsa.PKCS1v15DecryptOptions{SessionKeyLen: chacha20poly1305.KeySize})

	return sessionKey, err
}
