package register

import (
	consensus_utils "zhanghefan123/security/consensus-utils"
	"zhanghefan123/security/modules/consensus_algorithms"
	"zhanghefan123/security/modules/consensus_algorithms/pbft"
	"zhanghefan123/security/modules/consensus_provider"
	"zhanghefan123/security/protocol"
)

// RegisterAllComponents 注册所有组件的构造函数
func RegisterAllComponents() {
	RegisterConsensus()
}

// RegisterConsensus 注册所有共识实例的构造函数
func RegisterConsensus() {
	// 注册 pbft 共识协议
	pbftFunction := func(config *consensus_utils.ConsensusImplConfig) (protocol.ConsensusEngine, error) {
		return pbft.New(config)
	}
	consensus_provider.RegisterConsensusProvider(consensus_algorithms.ConsensusType_PBFT, pbftFunction)
}
