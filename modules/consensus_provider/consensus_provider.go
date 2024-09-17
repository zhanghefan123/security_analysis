package consensus_provider

import (
	consensus_utils "zhanghefan123/security/consensus-utils"
	"zhanghefan123/security/modules/consensus_algorithms"
	"zhanghefan123/security/protocol"
)

// Provider 定义了共识实例构造函数
type Provider func(config *consensus_utils.ConsensusImplConfig) (protocol.ConsensusEngine, error)

// consensusProviders 定义了从共识类型到相应构造函数的映射
var consensusProviders = make(map[consensus_algorithms.ConsensusProtocolType]Provider)

// RegisterConsensusProvider 向 consensusProviders 进行注册
func RegisterConsensusProvider(t consensus_algorithms.ConsensusProtocolType, f Provider) {
	consensusProviders[t] = f
}

// GetConsensusProvider 向 consensusProviders 进行注册
func GetConsensusProvider(t consensus_algorithms.ConsensusProtocolType) Provider {
	provider, ok := consensusProviders[t]
	if !ok {
		return nil
	}
	return provider
}
