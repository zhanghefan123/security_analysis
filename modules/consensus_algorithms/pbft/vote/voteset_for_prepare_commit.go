package vote

import (
	pbftPb "zhanghefan123/security/modules/consensus_algorithms/consensus-pb/pbft"
	"zhanghefan123/security/modules/consensus_algorithms/pbft"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/state"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/validator"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/variables"
	"zhanghefan123/security/protocol"
)

// PrepareCommitVoteset VoteSet 在 addVoteToVoteSetAll 的时候创建
type PrepareCommitVoteset struct {
	Logger              protocol.Logger
	Type                pbftPb.VoteType
	LegalUserVotesSum   int32
	IllegalUserVotesSum int32
	LegalUserVotes      map[string]*pbftPb.Vote
	IllegalUserVotes    map[string]*pbftPb.Vote
	Maj23               bool // 是否超过 2/3
	Judgement           bool // 用户在这个阶段所给出的判断
	ValidatorSet        *validator.ValidatorSet
}

// AddVote 在普通 VoteSet 之中添加投票
func (vs *PrepareCommitVoteset) AddVote(vote *pbftPb.Vote) error {
	if vs == nil {
		vs.Logger.Errorf("AddVote on nil VoteSet")
		return variables.ErrAddVoteOnNilVoteset
	}
	if vote == nil {
		vs.Logger.Errorf("AddVote on nil Vote")
		return variables.ErrAddNilVote
	}
	if _, ok := vs.LegalUserVotes[vote.Voter]; ok {
		return nil
	}
	if _, ok := vs.IllegalUserVotes[vote.Voter]; ok {
		return nil
	}
	// 判断用户的选择
	if vote.Judge {
		vs.LegalUserVotes[vote.Voter] = vote
		vs.LegalUserVotesSum++
	} else {
		vs.IllegalUserVotes[vote.Voter] = vote
		vs.IllegalUserVotesSum++
	}
	// 达到 2/3 所需要的人数
	quorum := vs.ValidatorSet.Size()*2/3 + 1
	// 还没有达到  2/3
	if !vs.Maj23 {
		if int32(quorum) <= (vs.LegalUserVotesSum) {
			vs.Maj23 = true
			vs.Judgement = false
		} else if int32(quorum) <= vs.IllegalUserVotesSum {
			vs.Maj23 = true
			vs.Judgement = false
		}
	}
	return nil
}

// NewVoteSet 创建新的投票集给 prepare 和 commit
func NewVoteSet(logger protocol.Logger, typ pbftPb.VoteType, validatorSet *validator.ValidatorSet) *PrepareCommitVoteset {
	return &PrepareCommitVoteset{
		Logger:              logger,
		Type:                typ,
		LegalUserVotesSum:   0,
		IllegalUserVotesSum: 0,
		LegalUserVotes:      make(map[string]*pbftPb.Vote),
		IllegalUserVotes:    make(map[string]*pbftPb.Vote),
		Maj23:               false,
		Judgement:           false,
		ValidatorSet:        validatorSet,
	}
}

// AddPrepareVote 添加准备投票
func (vs *PrepareCommitVoteset) AddPrepareVote(pbftImpl *pbft.ConsensusPbftImpl, prepareVote *pbftPb.Vote) {
	userId := prepareVote.UserId
	if userState, ok := pbftImpl.ConsensusState.UserStates[userId]; ok {
		if userState.Step != pbftPb.Step_PREPARE {
			pbftImpl.Logger.Errorf("[%s] add prepareVote at incorrect step", pbftImpl.LocalPeerId)
		}
	} else {
		pbftImpl.Logger.Errorf("cannot retrieve user state")
		return
	}

	err := vs.AddVote(prepareVote)
	if err != nil {
		return
	}

	if vs.Maj23 {
		pbftImpl.Logger.Infof("[%s] up to 2/3 consistent prepare message", prepareVote.UserId)
		state.EnterCommitStage(pbftImpl, prepareVote)
	}
}

// AddCommitVote 添加提交投票
func (vs *PrepareCommitVoteset) AddCommitVote(pbftImpl *pbft.ConsensusPbftImpl, commitVote *pbftPb.Vote) {
	userId := commitVote.UserId
	if userState, ok := pbftImpl.ConsensusState.UserStates[userId]; ok {
		if userState.Step != pbftPb.Step_COMMIT {
			pbftImpl.Logger.Errorf("[%s] add commit vote at incorrect step", pbftImpl.LocalPeerId)
		}
	} else {
		pbftImpl.Logger.Errorf("cannot retrieve user state")
		return
	}
	err := vs.AddVote(commitVote)
	if err != nil {
		return
	}
	if vs.Maj23 {
		pbftImpl.Logger.Infof("[%s] up to 2/3 consistent commit message", commitVote.UserId)
		state.EnterReplyStage(pbftImpl, commitVote)
	}
}
