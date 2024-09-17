package validator

import (
	"sync"
	"zhanghefan123/security/protocol"
)

func NewValidatorSet(logger protocol.Logger, validators []string) *ValidatorSet {
	return &ValidatorSet{
		Mutex:      sync.Mutex{},
		Logger:     logger,
		Validators: validators,
	}
}
