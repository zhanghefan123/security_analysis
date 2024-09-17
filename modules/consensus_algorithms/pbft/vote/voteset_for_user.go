package vote

import (
	pbftPb "zhanghefan123/security/modules/consensus_algorithms/consensus-pb/pbft"
	"zhanghefan123/security/modules/consensus_algorithms/pbft"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/validator"
	"zhanghefan123/security/protocol"
)

// UserVoteSet 用户投票集合, 每个用户投票集合包含三个子投票集合
type UserVoteSet struct {
	PrepareVoteSet *PrepareCommitVoteset // prepare 阶段 voteset
	CommitVoteSet  *PrepareCommitVoteset // commit 阶段 voteset
	ReplyVoteSet   *ReplyVoteSet         // reply 阶段 voteset
}

// AddVote 在 VoteSetAll 之中，根据类型选择插入哪个 voteSet 之中
func (vsa *UserVoteSet) AddVote(pbftImpl *pbft.ConsensusPbftImpl, vote *pbftPb.Vote) {
	switch vote.Type {
	case pbftPb.VoteType_VOTE_PREPARE:
		vsa.PrepareVoteSet.AddPrepareVote(pbftImpl, vote)
	case pbftPb.VoteType_VOTE_COMMIT:
		vsa.CommitVoteSet.AddCommitVote(pbftImpl, vote)
	case pbftPb.VoteType_VOTE_REPLY:
		vsa.ReplyVoteSet.AddVote(vote)
	default:
	}
}

// NewUserVoteSet 创建用户投票集合
func NewUserVoteSet(logger protocol.Logger, validatorSet *validator.ValidatorSet) *UserVoteSet {
	return &UserVoteSet{
		PrepareVoteSet: NewVoteSet(logger, pbftPb.VoteType_VOTE_PREPARE, validatorSet),
		CommitVoteSet:  NewVoteSet(logger, pbftPb.VoteType_VOTE_COMMIT, validatorSet),
		ReplyVoteSet:   NewReplyVoteSet(logger, pbftPb.VoteType_VOTE_REPLY, validatorSet),
	}
}
