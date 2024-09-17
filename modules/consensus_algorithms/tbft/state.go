package tbft

import (
	tbftpb "zhanghefan123/security/protobuf/pb-go/consensus/tbft"
	"zhanghefan123/security/protocol"
)

// ConsensusState represents the consensus state of the node
type ConsensusState struct {
	logger protocol.Logger
	// node id
	Id string
	// current height
	Height uint64
	// current round
	Round int32
	// current step
	Step tbftpb.Step

	// proposal
	Proposal *TBFTProposal
	// verifing proposal
	VerifingProposal *TBFTProposal
	LockedRound      int32
	// locked proposal
	LockedProposal *tbftpb.Proposal
	ValidRound     int32
	// valid proposal
	ValidProposal      *tbftpb.Proposal
	heightRoundVoteSet *heightRoundVoteSet
}
