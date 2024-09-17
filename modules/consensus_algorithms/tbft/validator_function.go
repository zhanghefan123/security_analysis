package tbft

import (
	"errors"
	"fmt"
	"sort"
	"zhanghefan123/security/protocol"
)

var (
	// ErrInvalidIndex implements the error for invalid index of validators
	ErrInvalidIndex = errors.New("invalid index")
)

// NewValidatorSet 创建一个新的 ValidatorSet
func NewValidatorSet(logger protocol.Logger, validators []string, blocksPerProposer uint64) *ValidatorSet {
	// 按照字符大小排序
	sort.SliceStable(validators, func(i, j int) bool { return validators[i] < validators[j] })
	// 创建 validatorset
	validatorSet := &ValidatorSet{
		logger:                  logger,
		Validators:              validators,
		ValidatorsHeight:        make(map[string]uint64),
		ValidatorsHeartBeatTime: make(map[string]int64),
		BlocksPerProposer:       blocksPerProposer,
	}
	validatorSet.logger.Info("new validator set: %v", validators)
	return validatorSet
}

// isNilOrEmpty 是否是 nil 还是空
func (valSet *ValidatorSet) isNilOrEmpty() bool {
	if valSet == nil {
		return true
	}
	valSet.Lock()
	defer valSet.Unlock()
	return len(valSet.Validators) == 0
}

// String 打印所有的 validators
func (valSet *ValidatorSet) String() string {
	if valSet == nil {
		return ""
	}
	valSet.Lock()
	defer valSet.Unlock()

	return fmt.Sprintf("%v", valSet.Validators)
}

// Size 返回 validators 的长度
func (valSet *ValidatorSet) Size() int32 {
	if valSet == nil {
		return 0
	}
	valSet.Lock()
	defer valSet.Unlock()
	return int32(len(valSet.Validators))
}

// HasValidator holds the lock and return whether validator is in
// the validatorSet
func (valSet *ValidatorSet) HasValidator(validator string) bool {
	if valSet == nil {
		return false
	}

	valSet.Lock()
	defer valSet.Unlock()

	return valSet.hasValidator(validator)
}

// hasValidator 遍历所有的 valSet 之中存储的 validators 判断是否存在
func (valSet *ValidatorSet) hasValidator(validator string) bool {
	for _, val := range valSet.Validators {
		if val == validator {
			return true
		}
	}
	return false
}

// 在 v2.3.0 版本之前进行 proposer 的获取
func (valSet *ValidatorSet) GetProposerV230(height uint64, round int32) (validator string, err error) {
	if valSet.isNilOrEmpty() {
		return "", ErrInvalidIndex
	}
	// 计算一下现在高度的偏移量
	heightOffset := int32((height + 1) / valSet.BlocksPerProposer)
	// 计算下现在 round 的偏移量
	roundOffset := round % valSet.Size()
	// 计算下真实的 index
	proposerIndex := (heightOffset + roundOffset) % valSet.Size()
	// 返回 validator
	return valSet.getByIndex(proposerIndex)
}

// 在 v.2.3.0 版本之后进行 proposer 的获取
func (valSet *ValidatorSet) GetProposer(blockVersion uint32, preProposer string,
	height uint64, round int32) (validator string, err error) {
	if blockVersion < blockVersion231 {
		return valSet.GetProposerV230(height, round)
	}
	if valSet.isNilOrEmpty() {
		return "", ErrInvalidIndex
	}

	proposerOffset := valSet.getIndexByString(preProposer)
	if (height % valSet.blocksPerProposer) == 0 {
		proposerOffset++
	}
	roundOffset := round % valSet.Size()
	proposerIndex := (roundOffset + proposerOffset) % valSet.Size()

	return valSet.getByIndex(proposerIndex)
}

//
// getByIndex
// @Description: Get proposer by index
// @receiver valSet
// @param index
// @return validator
// @return err
//
func (valSet *ValidatorSet) getByIndex(index int32) (validator string, err error) {
	if index < 0 || index >= valSet.Size() {
		return "", ErrInvalidIndex
	}

	valSet.Lock()
	defer valSet.Unlock()

	val := valSet.Validators[index]
	return val, nil
}
