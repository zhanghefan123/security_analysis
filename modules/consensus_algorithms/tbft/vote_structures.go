package tbft

import (
	"errors"
	tbftpb "zhanghefan123/security/protobuf/pb-go/consensus/tbft"
	"zhanghefan123/security/protocol"
)

var (
	// ErrVoteNil implements the error of nil vote
	ErrVoteNil = errors.New("nil vote")
	// ErrUnexceptedStep implements the error of unexpected step in tbft
	ErrUnexceptedStep = errors.New("unexpected step")
	// ErrInvalidValidator implements the error of nil invalid validator
	ErrInvalidValidator = errors.New("invalid validator")
	// ErrVoteForDifferentHash implements the error of invalid hash
	ErrVoteForDifferentHash = errors.New("vote for different hash")
)

// BlockVotes 每个区块的投票
type BlockVotes struct {
	Votes map[string]*tbftpb.Vote
	Sum   uint64
}

// VoteSet 投票的集合
type VoteSet struct {
	Logger protocol.Logger
	Type   tbftpb.VoteType
	// -------------- 区块链相关的字段 -----------
	Height       uint64
	Round        int32
	Sum          uint64
	Maj23        []byte                  // 一致的投票是否超过了组内的 2/3
	Votes        map[string]*tbftpb.Vote // 每个投票人 --> 投票
	VotesByBlock map[string]*BlockVotes  // 每个区块的投票
	invalidTx    map[string]int32        // 无效的交易
	needToDelTxs []string
	validators   *ValidatorSet
	// -------------- 区块链相关的字段 -----------
}

// roundVoteSet 当前轮的投票集合
type roundVoteSet struct {
	Height     uint64
	Round      int32
	Prevotes   *VoteSet
	Precommits *VoteSet
}

// heightRoundVoteSet 高度伦次投票集合
type heightRoundVoteSet struct {
	Logger        protocol.Logger
	Height        uint64
	Round         int32
	RoundVoteSets map[int32]*roundVoteSet
	validators    *ValidatorSet
}

// ConsensusMsg implements transformation of structure and pb
type ConsensusMsg struct {
	Type tbftpb.TBFTMsgType
	Msg  interface{}
}
