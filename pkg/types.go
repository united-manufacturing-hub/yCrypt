package pkg

import (
	"github.com/go-piv/piv-go/piv"
	"github.com/united-manufacturing-hub/yCrypt/pkg/yubikey"
)

type SmartCardWithAdditionalData struct {
	SmartCard *yubikey.SmartCard
	Auth      piv.KeyAuth
	Slot      piv.Slot
}

// KeyOrCardInterface should either be SmartCardWithAdditionalData or *rsa.PrivateKey
type KeyOrCardInterface interface{}
