package handler

import (
	"zhanghefan123/security/modules/consensus_algorithms/pbft"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/api"
	"zhanghefan123/security/modules/request_pool"
	pb "zhanghefan123/security/modules/rpc/protobuf/pb-go"
)

// HandleUserRequest 处理用户消息
func HandleUserRequest(pbftImpl *pbft.ConsensusPbftImpl, request *request_pool.Request) {
	// 拿到实际的消息类型
	switch request.Message.Type {
	case pb.RpcMessageType_AuthRequest:
		api.HandleAuthenticationRequest(pbftImpl, request)
	}
}
