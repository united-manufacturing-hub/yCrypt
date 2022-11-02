package yubikey

import (
	"github.com/go-piv/piv-go/piv"
	"testing"
)

func TestGetValidSmartCards(t *testing.T) {
	smartcards := GetValidSmartCards(nil)
	for _, smartcard := range smartcards {
		t.Logf("%+v\n", smartcard)
	}
}

func TestVerify(t *testing.T) {
	for _, smartcard := range GetValidSmartCards(nil) {
		attestation, err := smartcard.GetAttestation(piv.SlotCardAuthentication)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%+v\n", attestation)
	}

}

func TestZZZZZZZZZZZZZZZZZZZZZZZZZ(t *testing.T) {
	CloseAllPIVHandles()
}
