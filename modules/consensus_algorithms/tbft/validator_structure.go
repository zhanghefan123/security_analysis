package tbft

import (
	"sync"
	"zhanghefan123/security/protocol"
)

//
// ValidatorSet
// @Description: validator set
//
type ValidatorSet struct {
	sync.Mutex
	logger     protocol.Logger
	Validators []string
	// Validator's current block height
	ValidatorsHeight map[string]uint64
	// Validator's beat Time
	ValidatorsHeartBeatTime map[string]int64
	// The number of consecutive proposals by the proposer
	BlocksPerProposer uint64
}
