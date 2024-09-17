package validator

import (
	"sync"
	"zhanghefan123/security/protocol"
)

type ValidatorSet struct {
	sync.Mutex
	Logger     protocol.Logger
	Validators []string
}

// Size 返回 validatorSet 的大小
func (vs *ValidatorSet) Size() int {
	vs.Lock()
	defer vs.Unlock()
	return len(vs.Validators)
}
