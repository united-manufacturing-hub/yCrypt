package symmetric

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/go-piv/piv-go/piv"
	"github.com/united-manufacturing-hub/yCrypt/pkg"
	"github.com/united-manufacturing-hub/yCrypt/pkg/yubikey"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
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
	caCert, caPrivKey, userCert, userPrivKey, err := getCertAndPKs()
	if err != nil {
		t.Fatalf("Failed to generate certificate & private key: %s", err)
	}

	var plainData = []byte("test")
	// Need to copy, since plainData will be wiped
	var plainDataCopy = make([]byte, len(plainData))
	copy(plainDataCopy, plainData)
	var encryptedData EncryptedData
	encryptedData, err = SignCompressEncrypt(userCert, caPrivKey, plainData)
	if err != nil {
		t.Fatalf("SignCompressEncrypt() failed: %v", err)
	}
	t.Logf("Encrypted data:")
	t.Logf("\tSessionKey: %v", encryptedData.EncryptedSessionKey)
	t.Logf("\tCertificateSerial: %v", encryptedData.CertificateSerial)
	t.Logf("\tNonce: %v", encryptedData.Nonce)
	t.Logf("\tCiphertext: %v", encryptedData.Ciphertext)
	t.Logf("\tSignature: %v", encryptedData.Signature)

	var decryptedData []byte
	decryptedData, err = DecryptDecompressVerify(&encryptedData, userPrivKey, caCert)
	if err != nil {
		t.Fatalf("DecryptAndVerify() failed: %v", err)
	}
	t.Logf("Decrypted data: %s", string(decryptedData))
	if !bytes.Equal(plainDataCopy, decryptedData) {
		t.Fatalf("Decrypted data is not the same as the original: (%v) vs (%v)", plainDataCopy, decryptedData)
	}
}

func getCertAndPKs() (
	caCert *x509.Certificate,
	caPrivKey *rsa.PrivateKey,
	userCert *x509.Certificate,
	userPrivKey *rsa.PrivateKey,
	err error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"UMH Systems GmbH"},
			Country:       []string{"DE"},
			Province:      []string{""},
			Locality:      []string{"Aachen"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	caPEM := new(bytes.Buffer)
	err = pem.Encode(
		caPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caBytes,
		})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	derCert, _ := pem.Decode(caPEM.Bytes())

	caCertificates, err := x509.ParseCertificates(derCert.Bytes)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	caCert = caCertificates[0]

	// Begin user cert creation
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"UMH Systems GmbH"},
			Country:       []string{"DE"},
			Province:      []string{""},
			Locality:      []string{"Aachen"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	userPrivKey, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	userCertBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &userPrivKey.PublicKey, userPrivKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	userCertPEM := new(bytes.Buffer)
	err = pem.Encode(
		userCertPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: userCertBytes,
		})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	derCertUser, _ := pem.Decode(userCertPEM.Bytes())

	userCertificates, err := x509.ParseCertificates(derCertUser.Bytes)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	userCert = userCertificates[0]

	return
}

func FuzzEncryptDecrypt(f *testing.F) {
	caCert, caPrivKey, userCert, userPrivKey, err := getCertAndPKs()
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
			encryptedData, err = SignCompressEncrypt(userCert, caPrivKey, testData)
			if err != nil {
				t.Fatalf("SignCompressEncrypt() failed: %v", err)
			}
			t.Logf("Encrypted data: %#v", encryptedData)

			var decryptedData []byte
			decryptedData, err = DecryptDecompressVerify(&encryptedData, userPrivKey, caCert)
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
