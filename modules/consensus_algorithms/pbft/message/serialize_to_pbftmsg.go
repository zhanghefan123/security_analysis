package message

import (
	"zhanghefan123/security/modules/consensus_algorithms/consensus-pb/pbft"
	"zhanghefan123/security/modules/utils"
)

// SerializePrePrepareConsensusMessage 转换 prepare 消息
func SerializePrePrepareConsensusMessage(prePrepare *pbft.PrePrepare) *pbft.PBFTMsg {
	return &pbft.PBFTMsg{
		Type: pbft.PBFTMsgType_MSG_PRE_PREPARE,
		Msg:  utils.MustMarshal(prePrepare),
	}
}

// SerializePrepareConsensusMessage 转换 prepare 消息
func SerializePrepareConsensusMessage(prepare *pbft.Vote) *pbft.PBFTMsg {
	return &pbft.PBFTMsg{
		Type: pbft.PBFTMsgType_MSG_PRE_PREPARE,
		Msg:  utils.MustMarshal(prepare),
	}
}

// SerializeCommitConsensusMessage 转换 commit 消息
func SerializeCommitConsensusMessage(commit *pbft.Vote) *pbft.PBFTMsg {
	return &pbft.PBFTMsg{
		Type: pbft.PBFTMsgType_MSG_COMMIT,
		Msg:  utils.MustMarshal(commit),
	}
}

// SerializeReplyConsensusMessage 转换 reply 消息
func SerializeReplyConsensusMessage(reply *pbft.Vote) *pbft.PBFTMsg {
	return &pbft.PBFTMsg{
		Type: pbft.PBFTMsgType_MSG_REPLY,
		Msg:  utils.MustMarshal(reply),
	}
}
