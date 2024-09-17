package state

import (
	pbftPb "zhanghefan123/security/modules/consensus_algorithms/consensus-pb/pbft"
	"zhanghefan123/security/modules/consensus_algorithms/pbft"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/api"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/message"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/variables"
)

// EnterPrepareStage [PrePrepare -> Prepare] 进入准备阶段
func EnterPrepareStage(pbftImpl *pbft.ConsensusPbftImpl, prePrepare *pbftPb.PrePrepare) {
	// 日志输出
	pbftImpl.Logger.Infof("[%s/%s] consensus enter prepare", pbftImpl.LocalPeerId, prePrepare.UserId)

	// 用户合法性检查 --> 给出了一次自己的判断
	legal := api.UserLegalityCheck(pbftImpl.LegalUsers, prePrepare.UserId)

	// 创建相应的 PrepareVote
	prepareVote := message.NewVote(pbftPb.VoteType_VOTE_PREPARE, pbftImpl.LocalPeerId,
		prePrepare.UserId, prePrepare.AccessId, legal)

	// 将 vote 封装成为 ConsensusMsg
	prepareVoteConsensusMsg := message.CreatePrepareConsensusMessage(prepareVote)

	// 进行状态的转换
	if userState, ok := pbftImpl.ConsensusState.UserStates[prePrepare.UserId]; ok {
		err := userState.EnterPrepareStage()
		if err != nil {
			pbftImpl.Logger.Errorf("state error: %v", err)
		}
	} else {
		pbftImpl.Logger.Errorf("state error: user state: %v", variables.ErrUserDontExist)
	}

	// 将 自己产生的 Vote 放到内部消息 channel 之中
	pbftImpl.InternalMsgChan <- prepareVoteConsensusMsg

	// 日志输出
	pbftImpl.Logger.Infof("[%s] generated [%s] prepare message", pbftImpl.LocalPeerId, prepareVote.UserId)
}

// EnterCommitStage 当收到了超过 [2/3] 个 Prepare 消息的时候, 进入 Commit 阶段
func EnterCommitStage(pbftImpl *pbft.ConsensusPbftImpl, prepare *pbftPb.Vote) {
	// 日志输出
	pbftImpl.Logger.Infof("[%s/%s] consensus enter commit", pbftImpl.LocalPeerId, prepare.UserId)

	// 用户合法性检查
	legal := api.UserLegalityCheck(pbftImpl.LegalUsers, prepare.UserId)

	// 创建相应的 commitVote
	commitVote := message.NewVote(pbftPb.VoteType_VOTE_COMMIT, pbftImpl.LocalPeerId,
		prepare.UserId, prepare.AccessId, legal)

	// 将 vote 封装成为 ConsensusMsg
	commitVoteConsensusMsg := message.CreateCommitConsensusMessage(commitVote)

	// 进行状态的转换
	if userState, ok := pbftImpl.ConsensusState.UserStates[prepare.UserId]; ok {
		err := userState.EnterCommitStage()
		if err != nil {
			pbftImpl.Logger.Errorf("state error: %v", err)
		}
	} else {
		pbftImpl.Logger.Errorf("state error: user state: %v", variables.ErrUserDontExist)
	}

	// 将自己产生的 Vote 放到内部消息 channel 之中
	pbftImpl.InternalMsgChan <- commitVoteConsensusMsg

	// 日志输出
	pbftImpl.Logger.Infof("[%s] generated [%s] commit message", pbftImpl.LocalPeerId, prepare.UserId)
}

// EnterReplyStage 进入响应阶段, legal 是超过了 2/3 的人给出的判断, 这个时候不应该给出自己的判断
func EnterReplyStage(pbftImpl *pbft.ConsensusPbftImpl, commit *pbftPb.Vote) {
	// 日志输出
	pbftImpl.Logger.Infof("[%s/%s] consensus enter reply", pbftImpl.LocalPeerId, commit.UserId)

	// 创建相应的 replyVote
	replyVote := message.NewVote(pbftPb.VoteType_VOTE_REPLY, pbftImpl.LocalPeerId,
		commit.UserId, commit.AccessId, legal)

	// 将 replyVote 封装成为 ConsensusMsg
	replyVoteConsensusMsg := message.CreateReplyConsensusMessage(replyVote)

	// 进行状态的转换
	if userState, ok := pbftImpl.ConsensusState.UserStates[commit.UserId]; ok {
		err := userState.EnterReplyStage()
		if err != nil {
			pbftImpl.Logger.Errorf("state error: %v", err)
		}
	} else {
		pbftImpl.Logger.Errorf("state error: user state: %v", variables.ErrUserDontExist)
	}

	// 将自己产生的 Vote 放到内部消息 channel 之中
	pbftImpl.InternalMsgChan <- replyVoteConsensusMsg

	// 日志输出
	pbftImpl.Logger.Infof("[%s] generated [%s] reply message", pbftImpl.LocalPeerId, commit.UserId)
}

// EnterCompleteStage 进入
func EnterCompleteStage(pbftImpl *pbft.ConsensusPbftImpl, reply *pbftPb.Vote) {
	// 日志输出
	pbftImpl.Logger.Infof("[%s/%s] consensus enter complte", pbftImpl.LocalPeerId, reply.UserId)

	// 进行状态的转换
	if userState, ok := pbftImpl.ConsensusState.UserStates[reply.UserId]; ok {
		err := userState.EnterCompleteStage()
		if err != nil {
			pbftImpl.Logger.Errorf("state error: %v", err)
		}
	} else {
		pbftImpl.Logger.Errorf("state error: user state: %v", variables.ErrUserDontExist)
	}

	// 日志输出
	pbftImpl.Logger.Infof("[%s] generated [%s] reply message", pbftImpl.LocalPeerId, reply.UserId)
}
