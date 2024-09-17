package vars

import "zhanghefan123/security/modules/consensus_algorithms"

const (
	FlagNameOfNodeNumber          = "node-number"
	FlagNameShortHandOfNodeNumber = "n"

	FlagNameOfStartP2PPort          = "start-p2p-port"
	FlagNameShortHandOfStartP2PPort = "p"

	FlagNameOfStartRPCPort          = "start-rpc-port"
	FlagNameShortHandOfStartRPCPort = "r"

	FlagNameOfChooseConsensusType          = "choose-consensus-type"
	FlagNameShortHandOfChooseConsensusType = "c"

	FlagNameOfGeneratedDestination          = "generated-destination"
	FlagNameShortHandOfGeneratedDestination = "d"
)

type ConfigParams struct {
	NodeNumber           int
	StartP2PPort         int
	StartRPCPort         int
	StartRpcPort         int
	ConsensusType        int
	GeneratedDestination string
}

var ConfigParamsInstance = &ConfigParams{
	NodeNumber:           4,
	StartP2PPort:         11301,
	StartRPCPort:         12301,
	ConsensusType:        consensus_algorithms.ConsensusType_PBFT,
	GeneratedDestination: "../../simulation",
}
