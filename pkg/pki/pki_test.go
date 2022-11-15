package pki

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	certificates "github.com/united-manufacturing-hub/oid/pkg/oid/100_managementConsole/100_certificates"
	"github.com/united-manufacturing-hub/yCrypt/pkg/encoding"
	"github.com/united-manufacturing-hub/yCrypt/pkg/rsagen"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyPKI(t *testing.T) {
	caCert, caPrivKey, certBundle, err := rsagen.GenerateFakeCAAndCertificates(2)
	if err != nil {
		return
	}

	err = os.MkdirAll("testdata", os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}

	caPEM, err := encoding.EncodeCertificateToPEM(caCert.Raw)
	if err != nil {
		t.Errorf("Error encoding CA certificate to PEM: %v", err)
	}
	// dump to disk
	err = os.WriteFile(fmt.Sprintf("testdata/%s.crt", caCert.SerialNumber.String()), caPEM, 0o600)
	if err != nil {
		t.Errorf("Error writing CA certificate to disk: %v", err)
	}

	pkcs8PrivateKey, err := x509.MarshalPKCS8PrivateKey(caPrivKey)
	if err != nil {
		return
	}

	caPrivKeyPEM, err := encoding.EncodePrivateKeyToPEM(pkcs8PrivateKey)
	if err != nil {
		t.Errorf("Error encoding CA private key to PEM: %v", err)
	}
	// dump to disk
	err = os.WriteFile(fmt.Sprintf("testdata/%s.key", caCert.SerialNumber.String()), caPrivKeyPEM, 0o600)
	if err != nil {
		t.Errorf("Error writing CA private key to disk: %v", err)
	}

	path := filepath.Join("testdata", caCert.SerialNumber.String())

	err = os.MkdirAll(path, os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}

	for _, cert := range certBundle {

		userCertificate := cert.Certificate
		userPrivateKey := cert.PrivateKey
		var chain []*x509.Certificate

		var ok bool
		ok, err = VerifyPKI(
			caCert, userCertificate, chain, []asn1.ObjectIdentifier{
				certificates.GetDeviceCertificateAsn10id(),
				certificates.GetCaCertificateAsn10id(),
				certificates.GetTechCertificateAsn10id(),
			})
		if err != nil {
			t.Errorf("Error verifying PKI: %v", err)
		}
		if !ok {
			t.Errorf("PKI verification failed")
		}

		var userCertPEM []byte
		userCertPEM, err = encoding.EncodeCertificateToPEM(userCertificate.Raw)
		if err != nil {
			t.Errorf("Error encoding user certificate to PEM: %v", err)
		}

		certName := userCertificate.SerialNumber.String()

		// dump to disk
		err = os.WriteFile(filepath.Join(path, fmt.Sprintf("%s.crt", certName)), userCertPEM, 0o600)
		if err != nil {
			t.Errorf("Error writing user certificate to disk: %v", err)
		}

		// dump private key to disk

		var pkcs8UserPrivateKey []byte
		pkcs8UserPrivateKey, err = x509.MarshalPKCS8PrivateKey(userPrivateKey)
		if err != nil {
			return
		}

		var userPrivateKeyPEM []byte
		userPrivateKeyPEM, err = encoding.EncodePrivateKeyToPEM(pkcs8UserPrivateKey)
		if err != nil {
			t.Errorf("Error encoding user private: %v", err)
		}

		err = os.WriteFile(filepath.Join(path, fmt.Sprintf("%s.key", certName)), userPrivateKeyPEM, 0o600)
		if err != nil {
			t.Errorf("Error writing user private key to disk: %v", err)
		}
	}
}
