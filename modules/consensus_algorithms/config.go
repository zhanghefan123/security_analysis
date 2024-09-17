package consensus_algorithms

import "zhanghefan123/security/common/msgbus"

type ConsensusProtocolType int32

const (
	ConsensusType_PBFT ConsensusProtocolType = 11
)

var PbftMsgBusTopics = []msgbus.Topic{msgbus.RecvConsensusMsg}
