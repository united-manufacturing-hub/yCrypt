package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"
)

// VerifyPKI verifies the PKI certificate chain.
func VerifyPKI(
	rootCaCertificate *x509.Certificate,
	userCertificate *x509.Certificate,
	chain []*x509.Certificate,
	additionalExtensions []asn1.ObjectIdentifier,
) (bool, error) {

	/*
		Verify attempts to verify c by building one or more chains from c to a certificate in opts.Roots,
		using certificates in opts.Intermediates if needed.
		If successful, it returns one or more chains where the first element of the chain is c and
		the last element is from opts.Roots.
	*/

	removeAllowedCriticalExtensions(rootCaCertificate, additionalExtensions)
	removeAllowedCriticalExtensions(userCertificate, additionalExtensions)

	newChain := make([]*x509.Certificate, 0, len(chain))
	for _, cert := range chain {
		removeAllowedCriticalExtensions(cert, additionalExtensions)
		newChain = append(newChain, cert)
	}
	chain = newChain

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

	return len(verify) > 0, nil
}

func removeAllowedCriticalExtensions(
	cert *x509.Certificate,
	allowedExtensions []asn1.ObjectIdentifier) {

	var unhandledExtensions []pkix.Extension

	for _, extension := range cert.Extensions {
		if !extension.Critical {
			unhandledExtensions = append(unhandledExtensions, extension)
			continue
		}
		var found bool
		for _, additionalExtension := range allowedExtensions {
			if extension.Id.Equal(additionalExtension) {
				found = true
				break
			}
		}
		if !found {
			unhandledExtensions = append(unhandledExtensions, extension)
		}
	}
	cert.Extensions = unhandledExtensions

	// Cleanup the unhandled critical extensions

	var unhandledCriticalExtensions []asn1.ObjectIdentifier
	for _, unhandledCriticalExtension := range cert.UnhandledCriticalExtensions {
		var found bool
		for _, additionalExtension := range allowedExtensions {
			if unhandledCriticalExtension.Equal(additionalExtension) {
				found = true
				break
			}
		}
		if !found {
			unhandledCriticalExtensions = append(unhandledCriticalExtensions, unhandledCriticalExtension)
		}
	}
	cert.UnhandledCriticalExtensions = unhandledCriticalExtensions

}
