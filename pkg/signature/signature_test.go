package signature

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/go-piv/piv-go/piv"
	"github.com/united-manufacturing-hub/yCrypt/pkg"
	"github.com/united-manufacturing-hub/yCrypt/pkg/yubikey"
	"sync"
	"testing"
)

func TestSignWithYubikey(t *testing.T) {
	smartCard := yubikey.GetValidSmartCards(nil)[0]

	var randomDataToSign = make([]byte, 512)
	_, err := rand.Read(randomDataToSign)
	if err != nil {
		t.Fatalf("failed to generate random bytes: %v", err)
	}

	cardWithData := pkg.SmartCardWithAdditionalData{
		SmartCard: &smartCard,
		Slot:      piv.SlotSignature,
		Auth: piv.KeyAuth{
			PIN: piv.DefaultPIN,
		},
	}

	t.Logf("Signing with Yubikey: %v", cardWithData)

	var signature []byte
	signature, err = Sign(
		cardWithData,
		&randomDataToSign)
	if err != nil {
		t.Fatalf("Error signing with Yubikey: %v", err)
	}

	t.Logf("Signature: %v", signature)
}

func TestSignWithPrivateKey(t *testing.T) {
	var keysizes = []int{1024, 2048, 4096, 8196}
	var waitGroup sync.WaitGroup
	waitGroup.Add(len(keysizes))
	for _, keysize := range keysizes {
		go testSignWithPrivateKey(t, keysize, &waitGroup)
	}
	waitGroup.Wait()
}

func testSignWithPrivateKey(t *testing.T, keySize int, s *sync.WaitGroup) {
	defer s.Done()
	t.Logf("Testing key size: %d", keySize)
	// Generate rsa key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		t.Logf("failed to generate private key: %v", err)
		panic(err)
	}
	var randomDataToSign = make([]byte, 512)
	_, err = rand.Read(randomDataToSign)
	if err != nil {
		t.Logf("failed to generate random bytes: %v", err)
		panic(err)
	}

	var signature []byte
	signature, err = Sign(privateKey, &randomDataToSign)
	if err != nil {
		t.Logf("Error signing with privatekey: %v", err)
		panic(err)
	}

	t.Logf("Signature: %v", signature)

}

func TestZZZZZZZZZZZZZZZZZZZZZZZZZ(t *testing.T) {
	yubikey.CloseAllPIVHandles()
}
