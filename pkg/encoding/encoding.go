package encoding

import (
	"bytes"
	"encoding/pem"
)

func EncodeCertificateToPEM(certBytes []byte) ([]byte, error) {
	caPEM := new(bytes.Buffer)
	err := pem.Encode(
		caPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		})
	return caPEM.Bytes(), err
}
func EncodePrivateKeyToPEM(certBytes []byte) ([]byte, error) {
	caPEM := new(bytes.Buffer)
	err := pem.Encode(
		caPEM, &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: certBytes,
		})
	return caPEM.Bytes(), err
}
