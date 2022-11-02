package yubikey

import (
	"crypto"
	"crypto/x509"
	"errors"
	"github.com/go-piv/piv-go/piv"
	"sync"
)

type ThreadSafeYubikey struct {
	yubikey *piv.YubiKey
	serial  uint32
	lock    sync.Mutex
	open    bool
}

func (y *ThreadSafeYubikey) Close() error {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return nil
	}
	y.open = false
	return y.yubikey.Close()
}

func (y *ThreadSafeYubikey) AttestationCertificate() (*x509.Certificate, error) {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return nil, errors.New("yubikey not open")
	}
	return y.yubikey.AttestationCertificate()
}
func (y *ThreadSafeYubikey) Attest(slot piv.Slot) (*x509.Certificate, error) {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return nil, errors.New("yubikey not open")
	}
	return y.yubikey.Attest(slot)
}
func (y *ThreadSafeYubikey) Certificate(slot piv.Slot) (*x509.Certificate, error) {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return nil, errors.New("yubikey not open")
	}
	return y.yubikey.Certificate(slot)
}
func (y *ThreadSafeYubikey) SetCertificate(key [24]byte, slot piv.Slot, cert *x509.Certificate) error {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return errors.New("yubikey not open")
	}
	return y.yubikey.SetCertificate(key, slot, cert)
}
func (y *ThreadSafeYubikey) GenerateKey(key [24]byte, slot piv.Slot, opts piv.Key) (crypto.PublicKey, error) {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return nil, errors.New("yubikey not open")
	}
	return y.yubikey.GenerateKey(key, slot, opts)
}
func (y *ThreadSafeYubikey) PrivateKey(slot piv.Slot, public crypto.PublicKey, auth piv.KeyAuth) (
	crypto.PrivateKey,
	error) {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return nil, errors.New("yubikey not open")
	}
	return y.yubikey.PrivateKey(slot, public, auth)
}
func (y *ThreadSafeYubikey) SetPrivateKeyInsecure(
	key [24]byte,
	slot piv.Slot,
	private crypto.PrivateKey,
	policy piv.Key) error {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return errors.New("yubikey not open")
	}
	return y.yubikey.SetPrivateKeyInsecure(key, slot, private, policy)
}
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
func (y *ThreadSafeYubikey) Serial() (uint32, error) {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return 0, errors.New("yubikey not open")
	}
	return y.yubikey.Serial()
}
func (y *ThreadSafeYubikey) Retries() (int, error) {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return 0, errors.New("yubikey not open")
	}
	return y.yubikey.Retries()
}
func (y *ThreadSafeYubikey) Reset() error {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return errors.New("yubikey not open")
	}
	return y.yubikey.Reset()
}
func (y *ThreadSafeYubikey) SetManagementKey(oldKey, newKey [24]byte) error {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return errors.New("yubikey not open")
	}
	return y.yubikey.SetManagementKey(oldKey, newKey)
}
func (y *ThreadSafeYubikey) SetPIN(oldPIN, newPIN string) error {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return errors.New("yubikey not open")
	}
	return y.yubikey.SetPIN(oldPIN, newPIN)
}
func (y *ThreadSafeYubikey) Unblock(puk, newPIN string) error {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return errors.New("yubikey not open")
	}
	return y.yubikey.Unblock(puk, newPIN)
}
func (y *ThreadSafeYubikey) SetPUK(oldPUK, newPUK string) error {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return errors.New("yubikey not open")
	}
	return y.yubikey.SetPUK(oldPUK, newPUK)
}
func (y *ThreadSafeYubikey) Metadata(pin string) (*piv.Metadata, error) {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return nil, errors.New("yubikey not open")
	}
	return y.yubikey.Metadata(pin)
}
func (y *ThreadSafeYubikey) SetMetadata(key [24]byte, m *piv.Metadata) error {
	y.lock.Lock()
	defer y.lock.Unlock()
	if !y.open {
		return errors.New("yubikey not open")
	}
	return y.yubikey.SetMetadata(key, m)
}
