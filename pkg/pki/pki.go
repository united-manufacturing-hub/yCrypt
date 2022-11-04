package pki

import (
	"crypto/x509"
	"fmt"
	"time"
)

func VerifyPKI(
	rootCaCertificate *x509.Certificate,
	userCertificate *x509.Certificate,
	chain []*x509.Certificate) (bool, error) {

	/*
		Verify attempts to verify c by building one or more chains from c to a certificate in opts.Roots,
		using certificates in opts.Intermediates if needed.
		If successful, it returns one or more chains where the first element of the chain is c and
		the last element is from opts.Roots.
	*/

	roots := x509.NewCertPool()
	roots.AddCert(rootCaCertificate)

	intermediates := x509.NewCertPool()
	for _, cert := range chain {
		intermediates.AddCert(cert)
	}

	verify, err := userCertificate.Verify(
		x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			CurrentTime:   time.Now(),
		})

	if err != nil {
		return false, err
	}

	for _, validatorChain := range verify {
		fmt.Printf("Chain:\n")
		for _, cert := range validatorChain {
			fmt.Printf("\tCertificate: %s [%s]\n", cert.Subject, cert.SerialNumber)
		}
	}

	return len(verify) > 0, nil
}
