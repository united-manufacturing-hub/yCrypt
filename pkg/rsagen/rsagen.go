package rsagen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"github.com/united-manufacturing-hub/yCrypt/pkg/encoding"
	"math/big"
	"time"
)

type CertKeyBundle struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

var subjectCA = pkix.Name{
	Country:            []string{"DE"},
	Organization:       []string{"UMH Systems GmbH"},
	OrganizationalUnit: []string{"IT"},
	Locality:           []string{"Aachen"},
	Province:           []string{"NRW"},
	StreetAddress:      []string{"Vaalser Straße 460"},
	PostalCode:         []string{"52074"},
	CommonName:         "UMH-TEST-CERTIFICATE-DO-NOT-USE",
}

var keyUsageCA = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
	x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement |
	x509.KeyUsageCertSign | x509.KeyUsageCRLSign
var extKeyUsageCA = []x509.ExtKeyUsage{
	x509.ExtKeyUsageServerAuth,
	x509.ExtKeyUsageClientAuth,
	x509.ExtKeyUsageTimeStamping,
	x509.ExtKeyUsageOCSPSigning,
}

// GenerateFakeCAAndCertificates generates a fake CA certificate and nCerts certificates signed by the CA
func GenerateFakeCAAndCertificates(nCerts uint) (
	caCert *x509.Certificate,
	caPrivKey *rsa.PrivateKey,
	certKeyBundle []CertKeyBundle,
	err error) {

	caCert, caPrivKey, err = GenerateSelfSignedCertificate(big.NewInt(2019), subjectCA, keyUsageCA, extKeyUsageCA)
	if err != nil {
		return nil, nil, nil, err
	}

	certKeyBundle = make([]CertKeyBundle, 0, nCerts)

	for i := uint(0); i < nCerts; i++ {
		var userPrivKey *rsa.PrivateKey
		var userCert *x509.Certificate
		userCert, userPrivKey, err = GenerateFakeUserCertificate(caCert, caPrivKey)
		if err != nil {
			return nil, nil, nil, err
		}
		certKeyBundle = append(certKeyBundle, CertKeyBundle{Certificate: userCert, PrivateKey: userPrivKey})
	}

	return caCert, caPrivKey, certKeyBundle, nil
}

// GenerateFakeUserCertificate generates a fake user certificate signed by the CA
func GenerateFakeUserCertificate(ca *x509.Certificate, caPrivKey *rsa.PrivateKey) (
	*x509.Certificate,
	*rsa.PrivateKey,
	error) {
	var err error
	var userPrivKey *rsa.PrivateKey
	userPrivKey, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	var certificateRequest *x509.CertificateRequest

	certificateRequest, err = GenerateCSR(
		userPrivKey, pkix.Name{
			Country:            []string{"DE"},
			Organization:       []string{"UMH Systems GmbH"},
			OrganizationalUnit: []string{"IT"},
			Locality:           []string{"Aachen"},
			Province:           []string{"NRW"},
			StreetAddress:      []string{"Vaalser Straße 460"},
			PostalCode:         []string{"52074"},
			CommonName:         "UMH-TEST-TECHNICIAN-CERTIFICATE-DO-NOT-USE",
		})
	if err != nil {
		return nil, nil, err
	}
	randomBigInt, err := rand.Int(rand.Reader, big.NewInt(1000000000000000000))
	if err != nil {
		return nil, nil, err
	}

	var certificate *x509.Certificate
	certificate, err = SignCSR(ca, caPrivKey, userPrivKey.PublicKey, certificateRequest, randomBigInt, false)
	if err != nil {
		return nil, nil, err
	}

	return certificate, userPrivKey, nil

}

// GenerateSelfSignedCertificate generates a self-signed certificate, with CA flag set to true
func GenerateSelfSignedCertificate(
	serialNUmber *big.Int,
	subject pkix.Name,
	keyUsage x509.KeyUsage,
	extKeyUsage []x509.ExtKeyUsage) (cert *x509.Certificate, key *rsa.PrivateKey, err error) {
	caCertificate := &x509.Certificate{
		SerialNumber:          serialNUmber,
		Subject:               subject,
		Issuer:                subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           extKeyUsage,
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
	}

	key, err = rsa.GenerateKey(rand.Reader, 8192)
	if err != nil {
		return cert, key, err
	}
	var caCertBytes []byte
	caCertBytes, err = x509.CreateCertificate(
		rand.Reader,
		caCertificate,
		caCertificate,
		&key.PublicKey,
		key)

	var caCertificates []*x509.Certificate
	caCertificates, err = encoding.CertBytesToX509Certificate(caCertBytes)
	if err != nil {
		return cert, key, err
	}
	if len(caCertificates) != 1 {
		return cert, key, errors.New("len(caCertificates) != 1")
	}

	cert = caCertificates[0]

	return cert, key, nil
}

// GenerateCSR generates a certificate signing request
func GenerateCSR(privateKey *rsa.PrivateKey, subject pkix.Name) (csr *x509.CertificateRequest, err error) {
	template := x509.CertificateRequest{
		Subject: subject,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return csr, err
	}

	csr, err = x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return csr, err
	}
	err = csr.CheckSignature()
	return csr, err
}

// SignCSR signs a certificate signing request
func SignCSR(
	caCert *x509.Certificate,
	caPrivKey *rsa.PrivateKey,
	userPublicKey rsa.PublicKey,
	csr *x509.CertificateRequest,
	serialNumber *big.Int, isIntermediateCA bool) (cert *x509.Certificate, err error) {

	certificate := &x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKey:          csr.PublicKey,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,

		SerialNumber: serialNumber,
		Subject:      csr.Subject,

		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 1, 0),

		SubjectKeyId: serialNumber.Bytes(),
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageKeyAgreement |
			x509.KeyUsageDataEncipherment |
			x509.KeyUsageContentCommitment,
		IsCA:                  isIntermediateCA,
		BasicConstraintsValid: true,
		AuthorityKeyId:        caCert.SubjectKeyId,
	}
	if isIntermediateCA {
		certificate.KeyUsage |= x509.KeyUsageCertSign
		certificate.KeyUsage |= x509.KeyUsageCRLSign
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certificate, caCert, &userPublicKey, caPrivKey)

	if err != nil {
		return cert, err
	}

	var certificates []*x509.Certificate
	certificates, err = encoding.CertBytesToX509Certificate(certBytes)
	if err != nil {
		return cert, err
	}
	if len(certificates) != 1 {
		return cert, errors.New("len(certificates) != 1")
	}

	cert = certificates[0]
	return cert, nil
}
