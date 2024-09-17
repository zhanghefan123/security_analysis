package message

import (
	pbftPb "zhanghefan123/security/modules/consensus_algorithms/consensus-pb/pbft"
)

type ConsensusMessage struct {
	Type pbftPb.PBFTMsgType
	Msg  interface{}
}

// CreatePrePrepareConsensusMessage 创建预准备消息
func CreatePrePrepareConsensusMessage(prePrepare *pbftPb.PrePrepare) *ConsensusMessage {
	return &ConsensusMessage{
		Type: pbftPb.PBFTMsgType_MSG_PRE_PREPARE,
		Msg: &pbftPb.PrePrepare{
			AccessId: prePrepare.AccessId,
			UserId:   prePrepare.UserId,
		}, // 这里不是直接使用, 而进行拷贝, 是避免副作用
	}
}

// CreatePrepareConsensusMessage 创建准备消息
func CreatePrepareConsensusMessage(prepareVote *pbftPb.Vote) *ConsensusMessage {
	return &ConsensusMessage{
		Type: pbftPb.PBFTMsgType_MSG_PREPARE,
		Msg: &pbftPb.Vote{
			Type:     prepareVote.Type,
			Voter:    prepareVote.Voter,
			UserId:   prepareVote.UserId,
			AccessId: prepareVote.AccessId,
			Judge:    prepareVote.Judge,
		}, // 这里不是直接使用, 而进行拷贝, 是避免副作用
	}
}

// CreateCommitConsensusMessage 创建提交消息
func CreateCommitConsensusMessage(commit *pbftPb.Vote) *ConsensusMessage {
	return &ConsensusMessage{
		Type: pbftPb.PBFTMsgType_MSG_COMMIT,
		Msg: &pbftPb.Vote{
			Type:     commit.Type,
			Voter:    commit.Voter,
			UserId:   commit.UserId,
			AccessId: commit.AccessId,
			Judge:    commit.Judge,
		},
	}
}

// CreateReplyConsensusMessage 创建响应消息
func CreateReplyConsensusMessage(reply *pbftPb.Vote) *ConsensusMessage {
	return &ConsensusMessage{
		Type: pbftPb.PBFTMsgType_MSG_REPLY,
		Msg: &pbftPb.Vote{
			Type:     reply.Type,
			Voter:    reply.Voter,
			UserId:   reply.UserId,
			AccessId: reply.AccessId,
			Judge:    reply.Judge,
		},
	}
}
