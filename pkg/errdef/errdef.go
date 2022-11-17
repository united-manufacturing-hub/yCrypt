package errdef

import errwrap "github.com/united-manufacturing-hub/errWrap/pkg"

const (
	// ErrorYubikeyNotOpen is thrown when the yubikey was not opened before use.
	ErrorYubikeyNotOpen = errwrap.ConstError("yubikey not open")
	// ErrorNoCertificateInSlot is thrown when the slot does not contain a certificate.
	ErrorNoCertificateInSlot = errwrap.ConstError("no certificate in slot")
	// ErrorIncorrectFormFactorBytes is thrown when the form factory could not be decoded (expects a byte length of 1).
	ErrorIncorrectFormFactorBytes = errwrap.ConstError("incorrect form factor bytes")
	// ErrorUnrecognizedTouchPolicy is thrown when the touch policy could not be decoded.
	ErrorUnrecognizedTouchPolicy = errwrap.ConstError("unrecognized touch policy")
	// ErrUnrecognizedPinPolicy is thrown when the pin policy could not be decoded.
	ErrUnrecognizedPinPolicy = errwrap.ConstError("unrecognized pin policy")
	// ErrUnexpectedKeyPolicyByteLen is thrown when the key policy could not be decoded (expects a byte length of 2).
	ErrUnexpectedKeyPolicyByteLen = errwrap.ConstError("unexpected key policy byte length")
	// ErrorSerialNumberNegative is thrown when the serial number is negative.
	ErrorSerialNumberNegative = errwrap.ConstError("serial number negative")
	// ErrorSerialNumberIsNotAsn1 is thrown when the serial number is not ASN.1.
	ErrorSerialNumberIsNotAsn1 = errwrap.ConstError("failed to parse serial number (not ASN.1)")
	// ErrorUnexpectedFWVersionBytes is thrown when the firmware version could not be decoded (expects a byte length of 3).
	ErrorUnexpectedFWVersionBytes = errwrap.ConstError("unexpected firmware version bytes")
	// ErrorCipherTextTooShort is thrown when the cipher text is too short (Smaller than the Nonce size).
	ErrorCipherTextTooShort = errwrap.ConstError("ciphertext too short")
	// ErrorSessionKeySizeInvalid is thrown when the session key size is not matching the expected size of the encryption algorithm (Ex: ChaCha20Poly1305: 32 byte).
	ErrorSessionKeySizeInvalid = errwrap.ConstError("session key size invalid")
	// ErrorUnknownPublicKeyAlgorithm is thrown when the public key algorithm is not supported (E.g. not RSA).
	ErrorUnknownPublicKeyAlgorithm = errwrap.ConstError("unknown public key algorithm")
	// ErrorLockedBufferIsNil is thrown when the enclave object failed to be decrypted.
	ErrorLockedBufferIsNil = errwrap.ConstError("locked buffer is nil")
	// ErrorSessionKeyIsNil is thrown when the session key is nil (This can happen, if there is not enough randomness).
	ErrorSessionKeyIsNil = errwrap.ConstError("session key is nil")
	// ErrorUnknownValidatorAlgorithm is thrown when the validator algorithm is not supported.
	ErrorUnknownValidatorAlgorithm = errwrap.ConstError("unknown validation algorithm")
	// ErrorSignatureIsEmpty is thrown when the signature is empty.
	ErrorSignatureIsEmpty = errwrap.ConstError("signature is nil")
	// ErrorPublicKeyIsNotRSA is thrown when the public key is not RSA.
	ErrorPublicKeyIsNotRSA = errwrap.ConstError("public key is not RSA")
	// ErrorDataIsEmpty is thrown when the data to decrypt/encrypt/sign is empty.
	ErrorDataIsEmpty = errwrap.ConstError("data is empty")
	// ErrorPrivateKeyIsNotASigner is thrown when the private key is not a signer (This shouldn't happen with RSA keys).
	ErrorPrivateKeyIsNotASigner = errwrap.ConstError("private key is not a signer")
	// ErrorPublicKeyIsNotASigner is thrown when the private key is not a signer (This shouldn't happen with RSA keys).
	ErrorPublicKeyIsNotASigner = errwrap.ConstError("public key is not a signer")
	// ErrorUnknownPrivateKeyAlgorithm is thrown when the private key algorithm is not supported (E.g. not RSA).
	ErrorUnknownPrivateKeyAlgorithm = errwrap.ConstError("unknown private key algorithm")
	// ErrorPEMContainedNotExactlyOneKey is thrown when the PEM file contains more than one key or none.
	ErrorPEMContainedNotExactlyOneKey = errwrap.ConstError("PEM contained not exactly one key")
	// ErrorDERIsEmpty when the decoded PEM -> DER resulted in an empty byte array.
	ErrorDERIsEmpty = errwrap.ConstError("DER is empty")
	// ErrorRestIsNotEmpty is thrown when the rest of the PEM decoding byte array is not empty.
	ErrorRestIsNotEmpty = errwrap.ConstError("rest is not zero")
)
