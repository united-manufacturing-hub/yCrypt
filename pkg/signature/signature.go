package signature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/go-piv/piv-go/piv"
	"github.com/united-manufacturing-hub/yCrypt/pkg"
	"github.com/united-manufacturing-hub/yCrypt/pkg/yubikey"
	_ "golang.org/x/crypto/sha3"
)

const SignerHash = crypto.SHA256

func Sign(signer pkg.KeyOrCardInterface, data *[]byte) ([]byte, error) {
	switch t := signer.(type) {
	case pkg.SmartCardWithAdditionalData:
		return signWithYubikey(
			t.SmartCard,
			t.Slot,
			data,
			t.Auth)
	case *rsa.PrivateKey:
		return signWithPrivateKey(t, data)
	case *rsa.PublicKey:
		return nil, fmt.Errorf("public key is not a signer")
	default:
		return nil, fmt.Errorf("unknown signer type: %T", signer)
	}
}

func signWithYubikey(smartCard *yubikey.SmartCard, slot piv.Slot, data *[]byte, auth piv.KeyAuth) (
	signature []byte,
	err error) {
	var publicKey any
	publicKey, err = smartCard.GetPublicKey(slot)
	if err != nil {
		return nil, err
	}

	var yKey *yubikey.ThreadSafeYubikey
	yKey, err = smartCard.GetYKHandle()
	if err != nil {
		return nil, err
	}

	var priv crypto.PrivateKey
	priv, err = yKey.PrivateKey(slot, publicKey, auth)
	if err != nil {
		return nil, err
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key is not a signer")
	}

	switch signer.Public().(type) {
	case *rsa.PublicKey:
		if len(*data) == 0 {
			return nil, fmt.Errorf("data is empty")
		}

		hashB := SignerHash.New()
		hashB.Write(*data)
		hashSumB := hashB.Sum(nil)

		var rsaPubKey *rsa.PublicKey
		rsaPubKey, ok = signer.Public().(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is not RSA")
		}
		signature, err = signer.Sign(rand.Reader, hashSumB, SignerHash)
		if err != nil {
			return nil, err
		}
		err = rsa.VerifyPKCS1v15(rsaPubKey, SignerHash, hashSumB, signature)
		if err != nil {
			return nil, err
		}
		if len(signature) == 0 {
			return nil, fmt.Errorf("signature is empty")
		}
		return signature, nil
	default:
		return nil, fmt.Errorf("unknown key type")
	}
}

func signWithPrivateKey(privKey *rsa.PrivateKey, data *[]byte) (
	signature []byte,
	err error) {

	hashB := SignerHash.New()
	hashB.Write(*data)
	hashSumB := hashB.Sum(nil)

	signature, err = rsa.SignPKCS1v15(rand.Reader, privKey, SignerHash, hashSumB)
	if err != nil {
		return nil, err
	}
	err = rsa.VerifyPKCS1v15(privKey.Public().(*rsa.PublicKey), SignerHash, hashSumB, signature)
	if err != nil {
		return nil, err
	}
	if len(signature) == 0 {
		return nil, fmt.Errorf("signature is empty")
	}
	return signature, nil
}

func VerifySigned(validator pkg.KeyOrCardInterface, data, signature []byte) error {
	switch t := validator.(type) {
	case pkg.SmartCardWithAdditionalData:
		return verifySignedWithYubiKey(t.SmartCard, t.Slot, data, signature)
	case *x509.Certificate:
		return verifySignedWithCertificate(t, data, signature)
	}
	return fmt.Errorf("unknown validator type: %T", validator)
}

func verifySignedWithYubiKey(card *yubikey.SmartCard, slot piv.Slot, data, signature []byte) error {
	fmt.Printf("Retrieving certificate from slot %v\n", slot)
	certificate, err := card.GetCertificate(slot)
	if err != nil {
		return err
	}
	fmt.Printf("Verifying certificate for %v\n", signature)
	err = verifySignedWithCertificate(certificate, data, signature)
	if err != nil {
		return err
	}
	return nil
}

func verifySignedWithCertificate(certificate *x509.Certificate, data, signature []byte) (err error) {
	hash := SignerHash.New()
	hash.Write(data)
	hashSum := hash.Sum(nil)

	switch v := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(v, SignerHash, hashSum, signature)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown key type")
	}
	return nil
}

func VerifyPKI(signerCertificate, caCert *x509.Certificate) (chain [][]*x509.Certificate, err error) {
	opts := x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	opts.Roots.AddCert(caCert)

	return signerCertificate.Verify(opts)
}
