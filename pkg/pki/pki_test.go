package pki

import (
	"crypto/x509"
	"github.com/united-manufacturing-hub/yCrypt/pkg/encoding"
	"github.com/united-manufacturing-hub/yCrypt/pkg/rsagen"
	"os"
	"testing"
)

func TestVerifyPKI(t *testing.T) {
	caCert, _, certBundle, err := rsagen.GenerateFakeCAAndCertificates(3)
	if err != nil {
		return
	}

	rootCaCertificate := caCert

	for _, cert := range certBundle {

		userCertificate := cert.Certificate
		var chain []*x509.Certificate

		caPEM, err := encoding.EncodeCertificateToPEM(rootCaCertificate.Raw)
		if err != nil {
			t.Errorf("Error encoding CA certificate to PEM: %v", err)
		}
		// dump to disk
		err = os.WriteFile("ca.pem", caPEM, 0644)
		if err != nil {
			t.Errorf("Error writing CA certificate to disk: %v", err)
		}

		userCertPEM, err := encoding.EncodeCertificateToPEM(userCertificate.Raw)
		if err != nil {
			t.Errorf("Error encoding user certificate to PEM: %v", err)
		}
		// dump to disk
		err = os.WriteFile("user.pem", userCertPEM, 0644)
		if err != nil {
			t.Errorf("Error writing user certificate to disk: %v", err)
		}

		var ok bool
		ok, err = VerifyPKI(rootCaCertificate, userCertificate, chain)
		if err != nil {
			t.Errorf("Error verifying PKI: %v", err)
		}
		if !ok {
			t.Errorf("PKI verification failed")
		}
	}
}
