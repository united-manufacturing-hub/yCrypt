package rsagen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/united-manufacturing-hub/yCrypt/pkg/encoding"
	"math/big"
	"net"
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

var keyUsageUser = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
	x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement |
	x509.KeyUsageCertSign | x509.KeyUsageCRLSign

var extKeyUsageUser = []x509.ExtKeyUsage{
	x509.ExtKeyUsageClientAuth,
	x509.ExtKeyUsageServerAuth,
	x509.ExtKeyUsageTimeStamping,
	x509.ExtKeyUsageOCSPSigning,
}

func GenerateFakeCAAndCertificates(nCerts uint) (
	caCert *x509.Certificate,
	caPrivKey *rsa.PrivateKey,
	certKeyBundle []CertKeyBundle,
	err error) {
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               subjectCA,
		Issuer:                subjectCA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           extKeyUsageCA,
		KeyUsage:              keyUsageCA,
		BasicConstraintsValid: true,
	}

	caPrivKey, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, nil, err
	}
	var caPEM []byte
	caPEM, err = encoding.EncodeCertificateToPEM(caBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	derCert, _ := pem.Decode(caPEM)

	caCertificates, err := x509.ParseCertificates(derCert.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	caCert = caCertificates[0]

	certKeyBundle = make([]CertKeyBundle, 0, nCerts)

	for i := uint(0); i < nCerts; i++ {
		var userPrivKey *rsa.PrivateKey
		var userCert *x509.Certificate
		userCert, userPrivKey, err = GenerateFakeUserCertificate(ca, caPrivKey)
		if err != nil {
			return nil, nil, nil, err
		}
		certKeyBundle = append(certKeyBundle, CertKeyBundle{Certificate: userCert, PrivateKey: userPrivKey})
	}

	return caCert, caPrivKey, certKeyBundle, nil
}

func GenerateFakeUserCertificate(ca *x509.Certificate, caPrivKey *rsa.PrivateKey) (
	*x509.Certificate,
	*rsa.PrivateKey,
	error) {
	var err error
	var userPrivKey1 *rsa.PrivateKey
	userPrivKey1, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{"DE"},
			Organization:       []string{"UMH Systems GmbH"},
			OrganizationalUnit: []string{"IT"},
			Locality:           []string{"Aachen"},
			Province:           []string{"NRW"},
			StreetAddress:      []string{"Vaalser Straße 460"},
			PostalCode:         []string{"52074"},
			CommonName:         "UMH-TEST-TECHNICIAN-CERTIFICATE-DO-NOT-USE",
		},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, userPrivKey1)
	if err != nil {
		return nil, nil, err
	}

	certificateRequest, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, nil, err
	}
	err = certificateRequest.CheckSignature()
	if err != nil {
		return nil, nil, err
	}

	randomBigInt, err := rand.Int(rand.Reader, big.NewInt(1000000000000000000))
	if err != nil {
		return nil, nil, err
	}

	// Begin user cert creation

	cert := &x509.Certificate{
		Signature:          certificateRequest.Signature,
		SignatureAlgorithm: certificateRequest.SignatureAlgorithm,

		PublicKeyAlgorithm: certificateRequest.PublicKeyAlgorithm,
		PublicKey:          certificateRequest.PublicKey,

		SerialNumber: randomBigInt,
		Subject:      certificateRequest.Subject,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: randomBigInt.Bytes(),
		ExtKeyUsage:  extKeyUsageUser,
		KeyUsage:     keyUsageUser,
		Issuer:       ca.Subject,
	}

	certificate, err := x509.CreateCertificate(rand.Reader, cert, ca, &userPrivKey1.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	var userPEM []byte
	userPEM, err = encoding.EncodeCertificateToPEM(certificate)
	if err != nil {
		return nil, nil, nil
	}

	var derCert *pem.Block
	derCert, _ = pem.Decode(userPEM)

	userCertificates, err := x509.ParseCertificates(derCert.Bytes)
	if err != nil {
		return nil, nil, err
	}
	var userCert1 = userCertificates[0]
	return userCert1, userPrivKey1, nil

}
