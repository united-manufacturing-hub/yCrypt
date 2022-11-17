package signature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"github.com/go-piv/piv-go/piv"
	"github.com/united-manufacturing-hub/yCrypt/pkg"
	"github.com/united-manufacturing-hub/yCrypt/pkg/errdef"
	"github.com/united-manufacturing-hub/yCrypt/pkg/yubikey"
	_ "golang.org/x/crypto/sha3"
)

const SignerHash = crypto.SHA256

// Sign signs the data with the given key or card.
func Sign(signer pkg.KeyOrCardInterface, data *[]byte) (rsa.PublicKey, []byte, error) {
	switch t := signer.(type) {
	case pkg.SmartCardWithAdditionalData:
		sig, err := signWithYubikey(
			t.SmartCard,
			t.Slot,
			data,
			t.Auth)
		if err != nil {
			return rsa.PublicKey{}, nil, err
		}
		publicKey, err := t.SmartCard.GetPublicKey(t.Slot)
		if err != nil {
			return rsa.PublicKey{}, nil, err
		}
		return publicKey.(rsa.PublicKey), sig, nil
	case *rsa.PrivateKey:
		sig, err := signWithPrivateKey(t, data)
		if err != nil {
			return rsa.PublicKey{}, nil, err
		}
		return t.PublicKey, sig, nil
	case *rsa.PublicKey:
		return rsa.PublicKey{}, nil, errdef.ErrorPublicKeyIsNotASigner
	default:
		return rsa.PublicKey{}, nil, errdef.ErrorUnknownPrivateKeyAlgorithm
	}
}

// signWithYubikey signs the data with a yubikey.
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
		return nil, errdef.ErrorPrivateKeyIsNotASigner
	}

	switch signer.Public().(type) {
	case *rsa.PublicKey:
		if len(*data) == 0 {
			return nil, errdef.ErrorDataIsEmpty
		}

		hashB := SignerHash.New()
		hashB.Write(*data)
		hashSumB := hashB.Sum(nil)

		var rsaPubKey *rsa.PublicKey
		rsaPubKey, ok = signer.Public().(*rsa.PublicKey)
		if !ok {
			return nil, errdef.ErrorPublicKeyIsNotRSA
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
			return nil, errdef.ErrorSignatureIsEmpty
		}
		return signature, nil
	default:
		return nil, errdef.ErrorUnknownPublicKeyAlgorithm
	}
}

// signWithPrivateKey signs the data with a private key.
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
		return nil, errdef.ErrorSignatureIsEmpty
	}
	return signature, nil
}

// VerifySigned verifies the signature of the data with the given key or card.
func VerifySigned(validator pkg.KeyOrCardInterface, data, signature []byte) error {
	switch t := validator.(type) {
	case pkg.SmartCardWithAdditionalData:
		return verifySignedWithYubiKey(t.SmartCard, t.Slot, data, signature)
	case *x509.Certificate:
		return verifySignedWithCertificate(t, data, signature)
	}
	return errdef.ErrorUnknownValidatorAlgorithm
}

// verifySignedWithYubiKey verifies the signature of the data with a yubikey.
func verifySignedWithYubiKey(card *yubikey.SmartCard, slot piv.Slot, data, signature []byte) error {
	certificate, err := card.GetCertificate(slot)
	if err != nil {
		return err
	}
	err = verifySignedWithCertificate(certificate, data, signature)
	if err != nil {
		return err
	}
	return nil
}

// verifySignedWithCertificate verifies the signature of the data with a certificate.
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
		return errdef.ErrorUnknownPublicKeyAlgorithm
	}
	return nil
}
