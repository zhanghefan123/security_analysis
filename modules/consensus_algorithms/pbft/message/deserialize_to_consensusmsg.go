package message

import (
	pbftPb "zhanghefan123/security/modules/consensus_algorithms/consensus-pb/pbft"
	"zhanghefan123/security/modules/utils"
)

// CreateConsensusMsgFromBytes 从 bytes unmarshal 成为 consensus_msg
func CreateConsensusMsgFromBytes(bytes []byte) *ConsensusMessage {
	pbftMsg := new(pbftPb.PBFTMsg)      // net message 包含的 payload 就是 pbft.PBFTMsg, 其的产生定义在 consensus_message.go 之中
	utils.MustUnmarshal(bytes, pbftMsg) // 将 bytes 变为 pbftMsg
	switch pbftMsg.Type {
	case pbftPb.PBFTMsgType_MSG_PRE_PREPARE:
		prePrepare := new(pbftPb.PrePrepare)
		utils.MustUnmarshal(pbftMsg.Msg, prePrepare) // 根据类型将 pbftMsg 之中的 Msg unMarshal 成对应的 proto
		return &ConsensusMessage{
			Type: pbftPb.PBFTMsgType_MSG_PRE_PREPARE,
			Msg:  prePrepare,
		}
	case pbftPb.PBFTMsgType_MSG_PREPARE:
		prepare := new(pbftPb.Vote)
		utils.MustUnmarshal(pbftMsg.Msg, prepare)
		return &ConsensusMessage{
			Type: pbftPb.PBFTMsgType_MSG_PREPARE,
			Msg:  prepare,
		}
	case pbftPb.PBFTMsgType_MSG_COMMIT:
		commit := new(pbftPb.Vote)
		utils.MustUnmarshal(pbftMsg.Msg, commit)
		return &ConsensusMessage{
			Type: pbftPb.PBFTMsgType_MSG_COMMIT,
			Msg:  commit,
		}
	case pbftPb.PBFTMsgType_MSG_REPLY:
		reply := new(pbftPb.Vote)
		utils.MustUnmarshal(pbftMsg.Msg, reply)
		return &ConsensusMessage{
			Type: pbftPb.PBFTMsgType_MSG_REPLY,
			Msg:  reply,
		}
	default:
		panic("unhandled default case")
	}
}
