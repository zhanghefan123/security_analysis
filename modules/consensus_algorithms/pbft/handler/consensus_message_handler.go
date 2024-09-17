package handler

import (
	pbftPb "zhanghefan123/security/modules/consensus_algorithms/consensus-pb/pbft"
	"zhanghefan123/security/modules/consensus_algorithms/pbft"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/message"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/state"
)

// HandleConsensusMsg 处理消息
func HandleConsensusMsg(pbftImpl *pbft.ConsensusPbftImpl, msg *message.ConsensusMessage) {
	switch msg.Type {
	case pbftPb.PBFTMsgType_MSG_PRE_PREPARE:
		prePrepareMsg := msg.Msg.(*pbftPb.PrePrepare)
		HandlePrePrepareMessage(pbftImpl, prePrepareMsg)
	case pbftPb.PBFTMsgType_MSG_PREPARE:
		prepareMsg := msg.Msg.(*pbftPb.Vote)
		HandlePrepareMessage(pbftImpl, prepareMsg)
	case pbftPb.PBFTMsgType_MSG_COMMIT:
		commitMsg := msg.Msg.(*pbftPb.Vote)
		HandlePrepareMessage(pbftImpl, commitMsg)
	case pbftPb.PBFTMsgType_MSG_REPLY:
		replyMsg := msg.Msg.(*pbftPb.Vote)
		HandleReplyMessage(pbftImpl, replyMsg)
	}
}

// HandlePrePrepareMessage 处理预准备消息
func HandlePrePrepareMessage(pbftImpl *pbft.ConsensusPbftImpl, prePrepareMsg *pbftPb.PrePrepare) {
	pbftImpl.Logger.Infof("handle internal preprepare message")
	state.EnterPrepareStage(pbftImpl, prePrepareMsg)
}

// HandlePrepareMessage 处理准备消息
func HandlePrepareMessage(pbftImpl *pbft.ConsensusPbftImpl, prepareVote *pbftPb.Vote) {
	pbftImpl.Logger.Infof("handle internal prepare message")
	userId := prepareVote.UserId
	if userVoteSet, ok := pbftImpl.ConsensusState.UserVoteSets[userId]; !ok {
		userVoteSet.AddVote(pbftImpl, prepareVote)
	}
}

// HandleCommitMessage 处理提交消息
func HandleCommitMessage(pbftImpl *pbft.ConsensusPbftImpl, commitVote *pbftPb.Vote) {
	pbftImpl.Logger.Infof("handle internal commit message")
	userId := commitVote.UserId
	if userVoteSet, ok := pbftImpl.ConsensusState.UserVoteSets[userId]; !ok {
		userVoteSet.AddVote(pbftImpl, commitVote)
	}
}

// HandleReplyMessage 处理响应消息, 响应消息可以是本地提交的发送给其他节点的, 也可能是其他节点发来的
func HandleReplyMessage(pbftImpl *pbft.ConsensusPbftImpl, replyVote *pbftPb.Vote) {
	pbftImpl.Logger.Infof("handle internal reply message")
	userId := replyVote.UserId
	if pbftImpl.LocalPeerId == replyVote.AccessId {
		if userVoteSet, ok := pbftImpl.ConsensusState.UserVoteSets[userId]; !ok {
			userVoteSet.AddVote(pbftImpl, replyVote)
		}
	} else {
		message.SendConsensusVoteMessage(pbftImpl, replyVote) // 将消息发送到指定的 accessId 的位置处
	}
}
