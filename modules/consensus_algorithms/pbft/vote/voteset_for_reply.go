package vote

import (
	pbftPb "zhanghefan123/security/modules/consensus_algorithms/consensus-pb/pbft"
	"zhanghefan123/security/modules/consensus_algorithms/pbft"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/state"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/validator"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/variables"
	"zhanghefan123/security/protocol"
)

// ReplyVoteSet 只要超过 1/3 即可
type ReplyVoteSet struct {
	Logger              protocol.Logger
	Type                pbftPb.VoteType
	LegalUserVotesSum   int32
	IllegalUserVotesSum int32
	LegalUserVotes      map[string]*pbftPb.Vote
	IllegalUserVotes    map[string]*pbftPb.Vote
	Maj13               bool
	Judgement           bool
	ValidatorSet        *validator.ValidatorSet
}

// AddVote 添加投票
func (rvs *ReplyVoteSet) AddVote(vote *pbftPb.Vote) error {
	if rvs == nil {
		rvs.Logger.Errorf("AddVote on nil VoteSet")
		return variables.ErrAddVoteOnNilVoteset
	}
	if vote == nil {
		rvs.Logger.Errorf("AddVote on nil Vote")
		return variables.ErrAddNilVote
	}
	if _, ok := rvs.LegalUserVotes[vote.Voter]; ok {
		return nil
	}
	if _, ok := rvs.IllegalUserVotes[vote.Voter]; ok {
		return nil
	}
	// 判断用户的选择
	if vote.Judge {
		rvs.LegalUserVotes[vote.Voter] = vote
		rvs.LegalUserVotesSum++
	} else {
		rvs.IllegalUserVotes[vote.Voter] = vote
		rvs.IllegalUserVotesSum++
	}
	// 达到 1/3 所需要的人数
	quorum := rvs.ValidatorSet.Size()*1/3 + 1
	// 还没有达到  1/3
	if !rvs.Maj13 {
		if int32(quorum) <= (rvs.LegalUserVotesSum) {
			rvs.Maj13 = true
			rvs.Judgement = false
		} else if int32(quorum) <= rvs.IllegalUserVotesSum {
			rvs.Maj13 = true
			rvs.Judgement = false
		}
	}
	return nil
}

// AddReplyVote 添加响应投票
func (rvs *ReplyVoteSet) AddReplyVote(pbftImpl *pbft.ConsensusPbftImpl, replyVote *pbftPb.Vote) {
	userId := replyVote.UserId
	if userState, ok := pbftImpl.ConsensusState.UserStates[userId]; ok {
		if userState.Step != pbftPb.Step_REPLY {
			pbftImpl.Logger.Errorf("[%s] add prepareVote at incorrect step", pbftImpl.LocalPeerId)
		}
	} else {
		pbftImpl.Logger.Errorf("cannot retrieve user state")
		return
	}

	err := rvs.AddVote(replyVote)
	if err != nil {
		return
	}

	if rvs.Maj13 {
		pbftImpl.Logger.Infof("[%s] up to 1/3 consistent reply message", replyVote.UserId)
		state.EnterCompleteStage(pbftImpl, replyVote)

	}
}

// NewReplyVoteSet 创建新的投票集给 reply
func NewReplyVoteSet(logger protocol.Logger, typ pbftPb.VoteType, validatorSet *validator.ValidatorSet) *ReplyVoteSet {
	return &ReplyVoteSet{
		Logger:              logger,
		Type:                typ,
		LegalUserVotesSum:   0,
		IllegalUserVotesSum: 0,
		LegalUserVotes:      make(map[string]*pbftPb.Vote),
		IllegalUserVotes:    make(map[string]*pbftPb.Vote),
		Maj13:               false,
		Judgement:           false,
		ValidatorSet:        validatorSet,
	}
}
