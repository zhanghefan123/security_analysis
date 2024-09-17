package message

import (
	"github.com/gogo/protobuf/proto"
	"zhanghefan123/security/modules/utils"
	pbNet "zhanghefan123/security/protobuf/pb-go/net"
)

// GenerateNetMsgFromProto 从 proto 生成 NetMsg
func GenerateNetMsgFromProto(msg proto.Message, destination string) *pbNet.NetMsg {
	return &pbNet.NetMsg{
		Payload: utils.MustMarshal(msg),
		Type:    pbNet.NetMsg_CONSENSUS_MSG,
		To:      destination,
	}
}
