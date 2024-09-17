package message

import (
	"github.com/gogo/protobuf/proto"
	"zhanghefan123/security/common/msgbus"
	pbftPb "zhanghefan123/security/modules/consensus_algorithms/consensus-pb/pbft"
	"zhanghefan123/security/modules/consensus_algorithms/pbft"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/variables"
)

// SendPrePrepareMessage 发送预准备消息
func SendPrePrepareMessage(pbftImpl *pbft.ConsensusPbftImpl, prePrepareMessage *pbftPb.PrePrepare) {
	// 序列化为 pbft.PBFTMsg
	msg := SerializePrePrepareConsensusMessage(prePrepareMessage)

	// 广播这条消息
	SendMessageCore(pbftImpl, msg, variables.AllConsensusNodes)
}

// SendConsensusVoteMessage 发送共识投票消息
func SendConsensusVoteMessage(pbftImpl *pbft.ConsensusPbftImpl, vote *pbftPb.Vote) {
	var msg *pbftPb.PBFTMsg
	switch vote.Type {
	case pbftPb.VoteType_VOTE_PREPARE:
		// 如果是 prepare 消息的话就进行广播的操作
		msg = SerializePrepareConsensusMessage(vote)
		SendMessageCore(pbftImpl, msg, variables.AllConsensusNodes)
	case pbftPb.VoteType_VOTE_COMMIT:
		// 如果是 commit 消息的话就进行广播的操作
		msg = SerializeCommitConsensusMessage(vote)
		SendMessageCore(pbftImpl, msg, variables.AllConsensusNodes)
	case pbftPb.VoteType_VOTE_REPLY:
		// 如果是 reply 消息的话就返回到 accessNode
		msg = SerializeReplyConsensusMessage(vote)
		SendMessageCore(pbftImpl, msg, vote.AccessId)
	}
}

// SendMessageCore 消息发送的核心
func SendMessageCore(pbftImpl *pbft.ConsensusPbftImpl, msg proto.Message, destination string) {
	if destination == variables.AllConsensusNodes {
		for _, validator := range pbftImpl.ValidatorSet.Validators {
			if validator != pbftImpl.LocalPeerId {
				go func(validator string) {
					netMsg := GenerateNetMsgFromProto(msg, validator)
					pbftImpl.Logger.Infof("%s send consensus message to %s succeed", pbftImpl.LocalPeerId, validator)
					pbftImpl.MsgBus.Publish(msgbus.SendConsensusMsg, netMsg)
				}(validator)
			}
		}
	} else {
		go func(validator string) {
			netMsg := GenerateNetMsgFromProto(msg, validator)
			pbftImpl.Logger.Infof("%s send consensus message to %s succeed", pbftImpl.LocalPeerId, validator)
			pbftImpl.MsgBus.Publish(msgbus.SendConsensusMsg, netMsg)
		}(destination)
	}
}
