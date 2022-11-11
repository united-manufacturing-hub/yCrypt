package encoding

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// EncodeCertificateToPEM encodes a certificate to PEM format.
func EncodeCertificateToPEM(certBytes []byte) ([]byte, error) {
	caPEM := new(bytes.Buffer)
	err := pem.Encode(
		caPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		})
	return caPEM.Bytes(), err
}

// EncodePrivateKeyToPEM encodes a private key to PEM format.
func EncodePrivateKeyToPEM(certBytes []byte) ([]byte, error) {
	caPEM := new(bytes.Buffer)
	err := pem.Encode(
		caPEM, &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: certBytes,
		})
	return caPEM.Bytes(), err
}

// CertBytesToX509Certificate converts a byte array to an X509 certificate, using PEM formatting.
func CertBytesToX509Certificate(certBytes []byte) (cert []*x509.Certificate, err error) {
	certificateToPEM, err := EncodeCertificateToPEM(certBytes)
	if err != nil {
		return nil, err
	}
	var derCert *pem.Block
	var rest []byte
	derCert, rest = pem.Decode(certificateToPEM)
	if len(rest) > 0 {
		return nil, errors.New("rest not empty")
	}
	if derCert == nil {
		return nil, errors.New("derCert is nil")
	}
	cert, err = x509.ParseCertificates(derCert.Bytes)
	return cert, err
}
