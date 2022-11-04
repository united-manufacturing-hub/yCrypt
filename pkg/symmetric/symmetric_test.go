package symmetric

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"github.com/go-piv/piv-go/piv"
	"github.com/united-manufacturing-hub/yCrypt/pkg"
	"github.com/united-manufacturing-hub/yCrypt/pkg/rsagen"
	"github.com/united-manufacturing-hub/yCrypt/pkg/yubikey"
	mrand "math/rand"
	"sync"
	"testing"
)

func TestEncryptDecryptUsingRSA(t *testing.T) {

	var waitGroup sync.WaitGroup
	var keysizes = []int{1024, 2048, 4096, 8196}
	for i := 0; i < 5; i++ {
		// Add random key sizes to the list
		keysizes = append(keysizes, mrand.Intn(8196))
	}
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
	smartCards := yubikey.GetValidSmartCards(nil)
	if len(smartCards) == 0 {
		t.Skip("No smart card found")
	}
	smartCard := smartCards[0]
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
	smartCards := yubikey.GetValidSmartCards(nil)
	if len(smartCards) == 0 {
		t.Skip("No smart card found")
	}
	smartCard := smartCards[0]

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
	encryptedData, err = SignCompressEncrypt(certificate, cardWithAdditionalData, []byte("test"))
	if err != nil {
		t.Fatalf("SignCompressEncrypt() failed: %v", err)
	}
	t.Logf("Encrypted data: %#v", encryptedData)

	var decryptedData []byte
	decryptedData, err = DecryptDecompressVerify(&encryptedData, cardWithAdditionalData, cardWithAdditionalData)
	if err != nil {
		t.Fatalf("DecryptAndVerify() failed: %v", err)
	}
	t.Logf("Decrypted data: %s", string(decryptedData))

}

func TestEncryptData(t *testing.T) {
	_, _, bundle, err := rsagen.GenerateFakeCAAndCertificates(2)
	if err != nil {
		t.Fatalf("Failed to generate certificate & private key: %s", err)
	}

	var plainData = []byte("test")
	// Need to copy, since plainData will be wiped
	var plainDataCopy = make([]byte, len(plainData))
	copy(plainDataCopy, plainData)
	var encryptedData EncryptedData

	encryptedData, err = SignCompressEncrypt(bundle[0].Certificate, bundle[1].PrivateKey, plainData)
	if err != nil {
		t.Fatalf("SignCompressEncrypt() failed: %v", err)
	}
	t.Logf("Encrypted data:")
	t.Logf("\tSessionKey: %v", encryptedData.EncryptedSessionKey)
	t.Logf("\tSigner Public key: %v", encryptedData.Signer)
	t.Logf("\tNonce: %v", encryptedData.Nonce)
	t.Logf("\tCiphertext: %v", encryptedData.Ciphertext)
	t.Logf("\tSignature: %v", encryptedData.Signature)

	var decryptedData []byte
	decryptedData, err = DecryptDecompressVerify(&encryptedData, bundle[0].PrivateKey, bundle[1].Certificate)
	if err != nil {
		t.Fatalf("DecryptAndVerify() failed: %v", err)
	}
	t.Logf("Decrypted data: %s", string(decryptedData))
	if !bytes.Equal(plainDataCopy, decryptedData) {
		t.Fatalf("Decrypted data is not the same as the original: (%v) vs (%v)", plainDataCopy, decryptedData)
	}
}

func FuzzEncryptDecrypt(f *testing.F) {
	caCert, caPrivKey, bundle, err := rsagen.GenerateFakeCAAndCertificates(1)
	if err != nil {
		f.Fatalf("Failed to generate certificate & private key: %s", err)
	}

	f.Add([]byte("test"))
	f.Add([]byte("abcdef"))
	f.Add(
		[]byte(`{
	"compiler": "gc",
	"arch": "amd64",
	"os": "windows"
}`))
	f.Fuzz(
		func(t *testing.T, testData []byte) {
			var testDataCopy []byte
			testDataCopy = make([]byte, len(testData))
			copy(testDataCopy, testData)
			var encryptedData EncryptedData
			encryptedData, err = SignCompressEncrypt(bundle[0].Certificate, caPrivKey, testData)
			if err != nil {
				t.Fatalf("SignCompressEncrypt() failed: %v", err)
			}
			t.Logf("Encrypted data: %#v", encryptedData)

			var decryptedData []byte
			decryptedData, err = DecryptDecompressVerify(&encryptedData, bundle[0].PrivateKey, caCert)
			if err != nil {
				t.Fatalf("DecryptAndVerify() failed: %v", err)
			}
			if !bytes.Equal(decryptedData, testDataCopy) {
				t.Fatalf("testData & decryptedData data are not the same ! (%v) vs (%v)", testDataCopy, decryptedData)
			}

		})
}

func TestZZZZZZZZZZZZZZZZZZZZZZZZZ(t *testing.T) {
	yubikey.CloseAllPIVHandles()
}
