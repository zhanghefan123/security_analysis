package message

import (
	pbftPb "zhanghefan123/security/modules/consensus_algorithms/consensus-pb/pbft"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/state"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/variables"
)

// NewVote 创建新的投票
func NewVote(typ pbftPb.VoteType, voter string, userId, accessId string, judge bool) *pbftPb.Vote {
	return &pbftPb.Vote{
		Type:     typ,
		Voter:    voter,
		UserId:   userId,
		AccessId: accessId,
		Judge:    judge,
	}
}

// AddVoteForUser 添加投票给用户
func AddVoteForUser(consensusState *state.GlobalState, vote *pbftPb.Vote) error {
	if _, ok := consensusState.UserVoteSets[vote.UserId]; !ok {
		return variables.ErrUserDontExist
	}
	err := consensusState.UserVoteSets[vote.UserId].AddVote(vote)
	if err != nil {
		return err
	}
	return nil
}
