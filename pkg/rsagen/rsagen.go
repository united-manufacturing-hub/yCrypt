package rsagen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"github.com/united-manufacturing-hub/oid/pkg/oid"
	certificates "github.com/united-manufacturing-hub/oid/pkg/oid/100_managementConsole/100_certificates"
	"github.com/united-manufacturing-hub/yCrypt/pkg/encoding"
	"math/big"
	"sync"
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

	caCert, caPrivKey, err = GenerateSelfSignedCertificate(
		big.NewInt(2019),
		&subjectCA,
		keyUsageCA,
		extKeyUsageCA,
		[]pkix.Extension{oid.ToPkixExtension(certificates.GetCaCertificateAsn10id(), true, []byte{0x01})})
	if err != nil {
		return nil, nil, nil, err
	}

	certKeyBundle = make([]CertKeyBundle, 0, nCerts)

	var wg sync.WaitGroup
	wg.Add(int(nCerts))

	for i := uint(0); i < nCerts; i++ {
		go func(waitGroup *sync.WaitGroup) {
			var userPrivKey *rsa.PrivateKey
			var userCert *x509.Certificate
			// random bool
			var randData [1]byte
			_, err = rand.Read(randData[:])
			if err != nil {
				return
			}
			userCert, userPrivKey, err = GenerateFakeUserOrDeviceCertificate(caCert, caPrivKey, randData[0]%2 == 0)
			if err != nil {
				return
			}
			certKeyBundle = append(certKeyBundle, CertKeyBundle{Certificate: userCert, PrivateKey: userPrivKey})
			waitGroup.Done()
		}(&wg)
	}
	wg.Wait()

	return caCert, caPrivKey, certKeyBundle, nil
}

// GenerateFakeUserOrDeviceCertificate generates a fake user certificate signed by the CA
func GenerateFakeUserOrDeviceCertificate(ca *x509.Certificate, caPrivKey *rsa.PrivateKey, isDeviceCertificate bool) (
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

	var cn string
	if isDeviceCertificate {
		cn = "UMH-TEST-DEVICE-DO-NOT-USE"
	} else {
		cn = "UMH-TEST-USER-DO-NOT-USE"
	}

	var csrExtensions []pkix.Extension
	if isDeviceCertificate {
		csrExtensions = []pkix.Extension{
			oid.ToPkixExtension(
				certificates.GetDeviceCertificateAsn10id(),
				true,
				[]byte{0x01})}

	} else {
		csrExtensions = []pkix.Extension{
			oid.ToPkixExtension(
				certificates.GetTechCertificateAsn10id(),
				true,
				[]byte{0x01})}
	}

	certificateRequest, err = GenerateCSR(
		userPrivKey, &pkix.Name{
			Country:            []string{"DE"},
			Organization:       []string{"UMH Systems GmbH"},
			OrganizationalUnit: []string{"IT"},
			Locality:           []string{"Aachen"},
			Province:           []string{"NRW"},
			StreetAddress:      []string{"Vaalser Straße 460"},
			PostalCode:         []string{"52074"},
			CommonName:         cn,
		}, csrExtensions)

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
	subject *pkix.Name,
	keyUsage x509.KeyUsage,
	extKeyUsage []x509.ExtKeyUsage,
	extensions []pkix.Extension,
) (cert *x509.Certificate, key *rsa.PrivateKey, err error) {
	caCertificate := &x509.Certificate{
		SerialNumber:          serialNUmber,
		Subject:               *subject,
		Issuer:                *subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           extKeyUsage,
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
	}
	caCertificate.ExtraExtensions = extensions

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
	if err != nil {
		return cert, key, err

	}

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
func GenerateCSR(
	privateKey *rsa.PrivateKey,
	subject *pkix.Name,
	extension []pkix.Extension) (csr *x509.CertificateRequest, err error) {
	template := x509.CertificateRequest{
		Subject:         *subject,
		ExtraExtensions: extension,
	}

	fmt.Println("template", template)

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return csr, err
	}

	csr, err = x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return csr, err
	}

	fmt.Println("csr", csr.Extensions)

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
		ExtraExtensions:       csr.Extensions,
	}
	if isIntermediateCA {
		certificate.KeyUsage |= x509.KeyUsageCertSign
		certificate.KeyUsage |= x509.KeyUsageCRLSign
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certificate, caCert, &userPublicKey, caPrivKey)

	if err != nil {
		return cert, err
	}

	var certs []*x509.Certificate
	certs, err = encoding.CertBytesToX509Certificate(certBytes)
	if err != nil {
		return cert, err
	}
	if len(certs) != 1 {
		return cert, errors.New("len(certs) != 1")
	}

	cert = certs[0]
	return cert, nil
}
