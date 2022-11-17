package yubikey

import (
	"crypto"
	"crypto/x509"
	"github.com/go-piv/piv-go/piv"
	"github.com/united-manufacturing-hub/yCrypt/pkg/errdef"
	"sync"
)

// ThreadSafeYubikey is a thread safe wrapper for the yubikey
// It contains information about the yubikey and a lock to prevent concurrent access
// It also contains a boolean to check if the yubikey is open
type ThreadSafeYubikey struct {
	yubikey *piv.YubiKey
	serial  uint32
	lock    sync.Mutex
	open    bool
}

// Close closes the yubikey, once all other locks are released
func (y *ThreadSafeYubikey) Close() error {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return nil
	}
	y.open = false
	return y.yubikey.Close()
}

// AttestationCertificate returns the attestation certificate of the yubikey, once all other locks are released
func (y *ThreadSafeYubikey) AttestationCertificate() (*x509.Certificate, error) {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return nil, errdef.ErrorYubikeyNotOpen
	}
	return y.yubikey.AttestationCertificate()
}

// Attest generates an attestation of the yubikey, once all other locks are released
func (y *ThreadSafeYubikey) Attest(slot piv.Slot) (*x509.Certificate, error) {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return nil, errdef.ErrorYubikeyNotOpen
	}
	return y.yubikey.Attest(slot)
}

// Certificate returns the certificate of a slot in the yubikey, once all other locks are released
func (y *ThreadSafeYubikey) Certificate(slot piv.Slot) (*x509.Certificate, error) {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return nil, errdef.ErrorYubikeyNotOpen
	}
	return y.yubikey.Certificate(slot)
}

// SetCertificate sets the certificate of a slot in the yubikey, once all other locks are released
func (y *ThreadSafeYubikey) SetCertificate(key [24]byte, slot piv.Slot, cert *x509.Certificate) error {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return errdef.ErrorYubikeyNotOpen
	}
	return y.yubikey.SetCertificate(key, slot, cert)
}

// GenerateKey generates a key in the yubikey, once all other locks are released
func (y *ThreadSafeYubikey) GenerateKey(key [24]byte, slot piv.Slot, opts piv.Key) (crypto.PublicKey, error) {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return nil, errdef.ErrorYubikeyNotOpen
	}
	return y.yubikey.GenerateKey(key, slot, opts)
}

// PrivateKey returns the private key of a slot in the yubikey, once all other locks are released
// Note: The private key never really leaves the yubikey, this will only return an interface to the key
func (y *ThreadSafeYubikey) PrivateKey(slot piv.Slot, public crypto.PublicKey, auth piv.KeyAuth) (
	crypto.PrivateKey,
	error) {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return nil, errdef.ErrorYubikeyNotOpen
	}
	return y.yubikey.PrivateKey(slot, public, auth)
}

// SetPrivateKeyInsecure sets the private key of a slot in the yubikey, once all other locks are released
func (y *ThreadSafeYubikey) SetPrivateKeyInsecure(
	key [24]byte,
	slot piv.Slot,
	private crypto.PrivateKey,
	policy piv.Key) error {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return errdef.ErrorYubikeyNotOpen
	}
	return y.yubikey.SetPrivateKeyInsecure(key, slot, private, policy)
}

// Version returns the version of the yubikey, once all other locks are released
func (y *ThreadSafeYubikey) Version() piv.Version {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return piv.Version{
			Major: 0,
			Minor: 0,
			Patch: 0,
		}
	}
	return y.yubikey.Version()
}

// Serial returns the serial number of the yubikey, once all other locks are released
func (y *ThreadSafeYubikey) Serial() (uint32, error) {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return 0, errdef.ErrorYubikeyNotOpen
	}
	return y.yubikey.Serial()
}

// Retries returns the number of retries left to unlock the yubikey, once all other locks are released
func (y *ThreadSafeYubikey) Retries() (int, error) {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return 0, errdef.ErrorYubikeyNotOpen
	}
	return y.yubikey.Retries()
}

// Reset resets the yubikey, once all other locks are released
func (y *ThreadSafeYubikey) Reset() error {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return errdef.ErrorYubikeyNotOpen
	}
	return y.yubikey.Reset()
}

// SetManagementKey sets the management key of the yubikey, once all other locks are released
func (y *ThreadSafeYubikey) SetManagementKey(oldKey, newKey [24]byte) error {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return errdef.ErrorYubikeyNotOpen
	}
	return y.yubikey.SetManagementKey(oldKey, newKey)
}

// SetPIN sets the PIN of the yubikey, once all other locks are released
func (y *ThreadSafeYubikey) SetPIN(oldPIN, newPIN string) error {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return errdef.ErrorYubikeyNotOpen
	}
	return y.yubikey.SetPIN(oldPIN, newPIN)
}

// Unblock sets a new PIN using the PUK, once all other locks are released
func (y *ThreadSafeYubikey) Unblock(puk, newPIN string) error {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return errdef.ErrorYubikeyNotOpen
	}
	return y.yubikey.Unblock(puk, newPIN)
}

// SetPUK sets the PUK of the yubikey, once all other locks are released
func (y *ThreadSafeYubikey) SetPUK(oldPUK, newPUK string) error {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return errdef.ErrorYubikeyNotOpen
	}
	return y.yubikey.SetPUK(oldPUK, newPUK)
}

// Metadata returns the metadata of the yubikey, once all other locks are released
func (y *ThreadSafeYubikey) Metadata(pin string) (*piv.Metadata, error) {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return nil, errdef.ErrorYubikeyNotOpen
	}
	return y.yubikey.Metadata(pin)
}

// SetMetadata sets the metadata of the yubikey, once all other locks are released
func (y *ThreadSafeYubikey) SetMetadata(key [24]byte, m *piv.Metadata) error {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return errdef.ErrorYubikeyNotOpen
	}
	return y.yubikey.SetMetadata(key, m)
}
