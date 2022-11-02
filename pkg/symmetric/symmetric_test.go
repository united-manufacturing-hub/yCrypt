package symmetric

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"github.com/go-piv/piv-go/piv"
	"github.com/united-manufacturing-hub/yCrypt/pkg"
	"github.com/united-manufacturing-hub/yCrypt/pkg/yubikey"
	"sync"
	"testing"
)

func TestEncryptDecryptUsingRSA(t *testing.T) {

	var waitGroup sync.WaitGroup
	var keysizes = []int{1024, 2048, 4096, 8196}
	waitGroup.Add(len(keysizes))
	for _, keysize := range keysizes {
		go testEncryptDecryptUsingRSA(t, keysize, &waitGroup)
	}
	waitGroup.Wait()
}

func testEncryptDecryptUsingRSA(t *testing.T, keySize int, s *sync.WaitGroup) {
	defer s.Done()
	t.Logf("Testing key size: %d", keySize)

	sessionKey32Bytes := make([]byte, 32)
	var err error
	_, err = rand.Read(sessionKey32Bytes)

	if err != nil {
		t.Logf("failed to generate random bytes: %v", err)
		panic(err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		t.Logf("failed to generate private key: %v", err)
		panic(err)
	}
	publicKey := privateKey.PublicKey

	var encryptedSessionKey []byte
	encryptedSessionKey, err = encryptSessionKeyUsingRSA(&publicKey, sessionKey32Bytes)
	if err != nil {
		t.Logf("EncryptUsingRSA() failed: %v", err)
		panic(err)
	}
	decryptedSessionKey, err := decryptSessionKeyUsingRSA(encryptedSessionKey, privateKey)
	if err != nil {
		t.Logf("DecryptUsingRSA() failed: %v", err)
		panic(err)
	}
	if !bytes.Equal(decryptedSessionKey, sessionKey32Bytes) {
		t.Logf("SessionKey: %s", string(sessionKey32Bytes))
		t.Logf("DecryptedSessionKey: %s", string(decryptedSessionKey))
		panic("Decrypted session key is not the same as the original")
	}
}

func TestEncryptDecryptYKUsingRSA(t *testing.T) {
	smartCard := yubikey.GetValidSmartCards(nil)[0]
	var publicKey any
	var err error
	publicKey, err = smartCard.GetPublicKey(piv.SlotSignature)
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}

	sessionKey32Bytes := make([]byte, 32)
	_, err = rand.Read(sessionKey32Bytes)
	if err != nil {
		t.Fatalf("failed to generate random bytes: %v", err)
	}

	var yKey *yubikey.ThreadSafeYubikey
	yKey, err = smartCard.GetYKHandle()
	if err != nil {
		t.Fatalf("failed to open smart card: %v", err)
	}

	var encryptedSessionKey []byte
	encryptedSessionKey, err = encryptSessionKeyUsingRSA(publicKey.(*rsa.PublicKey), sessionKey32Bytes)
	if err != nil {
		t.Fatalf("EncryptUsingRSA() failed: %v", err)
	}

	privateKey, err := yKey.PrivateKey(piv.SlotSignature, publicKey, piv.KeyAuth{PIN: piv.DefaultPIN})
	if err != nil {
		t.Fatalf("failed to get private key: %v", err)
	}

	decryptedSessionKey, err := decryptSessionKeyUsingRSAYK(encryptedSessionKey, privateKey.(crypto.Decrypter))

	if err != nil {
		t.Fatalf("DecryptUsingRSA() failed: %v", err)
	}
	if !bytes.Equal(decryptedSessionKey, sessionKey32Bytes) {
		t.Logf("SessionKey: %s", string(sessionKey32Bytes))
		t.Logf("DecryptedSessionKey: %s", string(decryptedSessionKey))
		t.Fatalf("Decrypted session key is not the same as the original")
	}
}

func TestEncryptDataYK(t *testing.T) {
	smartCard := yubikey.GetValidSmartCards(nil)[0]

	var cardWithAdditionalData = pkg.SmartCardWithAdditionalData{
		SmartCard: &smartCard,
		Slot:      piv.SlotSignature,
		Auth:      piv.KeyAuth{PIN: piv.DefaultPIN},
	}

	certificate, err := smartCard.GetCertificate(cardWithAdditionalData.Slot)
	if err != nil {
		t.Fatalf("failed to get certificate: %v", err)
	}

	var encryptedData EncryptedData
	encryptedData, err = EncryptAndSign(certificate, cardWithAdditionalData, []byte("test"))
	if err != nil {
		t.Fatalf("EncryptAndSign() failed: %v", err)
	}
	t.Logf("Encrypted data: %#v", encryptedData)

	var decryptedData []byte
	decryptedData, err = DecryptAndVerifySig(&encryptedData, cardWithAdditionalData, cardWithAdditionalData)
	if err != nil {
		t.Fatalf("DecryptAndVerify() failed: %v", err)
	}
	t.Logf("Decrypted data: %s", string(decryptedData))

}

func TestZZZZZZZZZZZZZZZZZZZZZZZZZ(t *testing.T) {
	yubikey.CloseAllPIVHandles()
}
