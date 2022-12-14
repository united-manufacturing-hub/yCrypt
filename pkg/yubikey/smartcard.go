package yubikey

import (
	"crypto/x509"
	"encoding/asn1"
	"github.com/go-piv/piv-go/piv"
	"github.com/united-manufacturing-hub/yCrypt/pkg/errdef"
	"go.uber.org/zap"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

var ykHandleMap = make(map[uint32]*ThreadSafeYubikey)
var ykHandleMapMutex = &sync.RWMutex{}

// getOrOpenPIVBySerial returns a ThreadSafeYubikey pointer for the given serial number
// If the Yubikey was not opened before, it will be opened and added to the global map
func getOrOpenPIVBySerial(serial uint32, name string) (*ThreadSafeYubikey, error) {
	ykHandleMapMutex.Lock()
	defer ykHandleMapMutex.Unlock()
	yubiKey, ok := ykHandleMap[serial]
	if !ok {
		var err error
		var yK *piv.YubiKey
		yK, err = piv.Open(name)
		if err != nil {
			return nil, err
		}

		ykHandleMap[serial] = &ThreadSafeYubikey{yubikey: yK, serial: serial, lock: sync.Mutex{}, open: true}
		return ykHandleMap[serial], nil
	}
	return yubiKey, nil
}

// CloseAllPIVHandles must be called at the end of the program
func CloseAllPIVHandles() {
	ykHandleMapMutex.Lock()
	defer ykHandleMapMutex.Unlock()
	for _, yk := range ykHandleMap {
		err := yk.Close()
		if err != nil {
			zap.S().Error("Error closing PIV handle", zap.Error(err))
		}
	}
}

// SmartCard contains information to uniquely identify a SmartCard
type SmartCard struct {
	yubikey       *ThreadSafeYubikey
	Name          string
	Pin           string
	Puk           string
	Version       piv.Version
	Serial        uint32
	ManagementKey [24]byte
}

var smartCardList []SmartCard
var smartCardListRWLock = &sync.RWMutex{}
var smartCardListRunOnce = &onceReset{}

// onceReset is a resettable once
type onceReset struct {
	done uint32
	m    sync.Mutex
}

// do checks if the once was executed and if not, calls doSlow with the once function
func (o *onceReset) do(f func()) {
	if atomic.LoadUint32(&o.done) == 0 {
		o.doSlow(f)
	}
}

// doSlow sets once to done and calls the once function
func (o *onceReset) doSlow(f func()) {
	o.m.Lock()
	defer o.m.Unlock()
	if o.done == 0 {
		defer atomic.StoreUint32(&o.done, 1)
		f()
	}
}

// reset resets the once
func (o *onceReset) reset() {
	o.m.Lock()
	defer o.m.Unlock()
	atomic.StoreUint32(&o.done, 0)
}

// RefreshSmartCards resets the smart card list
func RefreshSmartCards() {
	smartCardListRunOnce.reset()
	GetValidSmartCards(nil)
}

// GetValidSmartCards returns a list of valid smart cards, optionally filtered by the given serial number
func GetValidSmartCards(serialFilter *uint32) []SmartCard {
	smartCardListRunOnce.do(
		func() {
			smartCardListRWLock.Lock()
			defer smartCardListRWLock.Unlock()
			CloseAllPIVHandles()

			cards, err := piv.Cards()
			if err != nil {
				panic(err)
			}
			smartcards := make([]SmartCard, 0)
			for _, card := range cards {
				if strings.Contains(card, "Windows Hello") {
					continue
				}
				var smartcard *piv.YubiKey
				smartcard, err = piv.Open(card)
				if err != nil || smartcard == nil {
					continue
				}
				scard := SmartCard{
					Name:          card,
					Version:       smartcard.Version(),
					ManagementKey: piv.DefaultManagementKey,
					Pin:           piv.DefaultPIN,
					Puk:           piv.DefaultPUK,
				}
				var serial uint32
				serial, err = smartcard.Serial()
				if err != nil {
					continue
				}
				scard.Serial = serial
				err = smartcard.Close()
				if err != nil {
					continue
				}

				smartcards = append(smartcards, scard)
			}

			sort.SliceStable(
				smartcards, func(i, j int) bool {
					a := smartcards[i]
					b := smartcards[j]
					return a.Serial < b.Serial
				})

			smartCardList = smartcards
		})
	smartCardListRWLock.RLock()
	defer smartCardListRWLock.RUnlock()

	if serialFilter == nil {
		return smartCardList
	}
	for _, card := range smartCardList {
		if card.Serial == *serialFilter {
			return []SmartCard{card}
		}
	}
	return []SmartCard{}
}

func (c *SmartCard) GetYKHandle() (*ThreadSafeYubikey, error) {
	if c.yubikey != nil {
		return c.yubikey, nil
	}
	// Lookup in global map
	var err error
	c.yubikey, err = getOrOpenPIVBySerial(c.Serial, c.Name)

	return c.yubikey, err
}

// GenerateKey generates a new key on the YubiKey
func (c *SmartCard) GenerateKey(slot piv.Slot, key piv.Key) (err error) {
	yKey, err := c.GetYKHandle()
	if err != nil {
		return err
	}

	_, err = yKey.GenerateKey(c.ManagementKey, slot, key)

	if err != nil {
		return err
	}

	return nil
}

// GetPublicKey returns the public key of a slot on the YubiKey
func (c *SmartCard) GetPublicKey(slot piv.Slot) (publicKey any, err error) {
	yKey, err := c.GetYKHandle()
	if err != nil {
		return nil, err
	}

	certificate, err := yKey.Certificate(slot)
	if err != nil {
		return nil, err
	}
	if certificate == nil {
		return nil, errdef.ErrorNoCertificateInSlot
	}

	return certificate.PublicKey, nil
}

// GetAttestationCertificate returns the attestation certificate of the YubiKey
func (c *SmartCard) GetAttestationCertificate() (cert *x509.Certificate, err error) {
	yKey, err := c.GetYKHandle()
	if err != nil {
		return nil, err
	}
	cert, err = yKey.AttestationCertificate()

	return cert, err
}

// Attest attests the certificate on the YubiKey
func (c *SmartCard) Attest(slot piv.Slot) (cert *x509.Certificate, err error) {
	yKey, err := c.GetYKHandle()
	if err != nil {
		return
	}
	cert, err = yKey.Attest(slot)

	return cert, err
}

// GetCertificate returns the certificate of a slot on the YubiKey
func (c *SmartCard) GetCertificate(slot piv.Slot) (cert *x509.Certificate, err error) {
	yKey, err := c.GetYKHandle()
	if err != nil {
		return nil, err
	}
	cert, err = yKey.Certificate(slot)

	return cert, err
}

// ResetYubikey resets the YubiKey
func (c *SmartCard) ResetYubikey() error {
	yKey, err := c.GetYKHandle()
	if err != nil {
		return err
	}
	err = yKey.Reset()
	return err
}

// ImportCertificate imports a certificate on the YubiKey
func (c *SmartCard) ImportCertificate(slot piv.Slot, cert *x509.Certificate) error {
	yKey, err := c.GetYKHandle()
	if err != nil {
		return err
	}
	err = yKey.SetCertificate(c.ManagementKey, slot, cert)
	return err
}

// GetAttestation returns the attestation certificate of the YubiKey
func (c *SmartCard) GetAttestation(toVerify piv.Slot) (attestation *piv.Attestation, err error) {
	yKey, err := c.GetYKHandle()
	if err != nil {
		return attestation, err
	}
	var attestCert *x509.Certificate
	attestCert, err = yKey.Attest(toVerify)
	if err != nil {
		return attestation, err
	}

	attestation = &piv.Attestation{}

	for _, e := range attestCert.Extensions {

		switch e.Id.String() {
		case extIDFirmwareVersion.String():
			if len(e.Value) != 3 {
				return nil, errdef.ErrorUnexpectedFWVersionBytes
			}
			attestation.Version = piv.Version{
				Major: int(e.Value[0]),
				Minor: int(e.Value[1]),
				Patch: int(e.Value[2]),
			}
		case extIDSerialNumber.String():
			var serial int64
			if _, err = asn1.Unmarshal(e.Value, &serial); err != nil {
				return nil, errdef.ErrorSerialNumberIsNotAsn1
			}
			if serial < 0 {
				return nil, errdef.ErrorSerialNumberNegative
			}
			attestation.Serial = uint32(serial)
		case extIDKeyPolicy.String():
			if len(e.Value) != 2 {
				return nil, errdef.ErrUnexpectedKeyPolicyByteLen
			}
			switch e.Value[0] {
			case 0x01:
				attestation.PINPolicy = piv.PINPolicyNever
			case 0x02:
				attestation.PINPolicy = piv.PINPolicyOnce
			case 0x03:
				attestation.PINPolicy = piv.PINPolicyAlways
			default:
				return nil, errdef.ErrUnrecognizedPinPolicy
			}
			switch e.Value[1] {
			case 0x01:
				attestation.TouchPolicy = piv.TouchPolicyNever
			case 0x02:
				attestation.TouchPolicy = piv.TouchPolicyAlways
			case 0x03:
				attestation.TouchPolicy = piv.TouchPolicyCached
			default:
				return nil, errdef.ErrorUnrecognizedTouchPolicy
			}
		case extIDFormFactor.String():

			if len(e.Value) != 1 {
				return nil, errdef.ErrorIncorrectFormFactorBytes
			}
			attestation.Formfactor = piv.Formfactor(e.Value[0])
		}

	}

	return attestation, err
}

var (
	extIDFirmwareVersion = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 3, 3})
	extIDSerialNumber    = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 3, 7})
	extIDKeyPolicy       = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 3, 8})
	extIDFormFactor      = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 3, 9})
)
