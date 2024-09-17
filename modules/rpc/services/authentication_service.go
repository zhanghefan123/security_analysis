package services

import (
	"context"
	"zhanghefan123/security/modules/blockchain"
	"zhanghefan123/security/modules/request_pool"
	pb "zhanghefan123/security/modules/rpc/protobuf/pb-go"
	"zhanghefan123/security/modules/utils"
)

// AuthenticationService 继承了 pb.UnimplementedAuthenticationServiceServer 然后需要进行相应的实现
type AuthenticationService struct {
	pb.UnimplementedAuthenticationServiceServer
	Blockchain *blockchain.Blockchain
}

// ReplyToAuthenticationRequest 进行了对请求的回复, 每次请求都会开启一个新的协程, 所以不用在里面再进行开启
func (auth *AuthenticationService) ReplyToAuthenticationRequest(ctx context.Context, in *pb.AuthenticationRequest) (*pb.AuthenticationReply, error) {
	// 将用户的请求存放到一个请求池之中，等待进行执行
	finishChannel := make(chan *pb.RpcMessage)

	// 创建相应的 pb.RpcMessage
	message := &pb.RpcMessage{
		Type:    pb.RpcMessageType_AuthRequest,
		Content: utils.MustMarshal(in),
	}

	// 创建并添加新的请求
	newRequest := request_pool.NewRequest(message, finishChannel)
	AddRequest(auth.Blockchain.RequestPool, newRequest)

	// 结果从 finishChannel 之中进行返回
	result := <-finishChannel
	replyMessage := &pb.AuthenticationReply{}
	utils.MustUnmarshal(result.Content, replyMessage)

	// 返回认证结果
	return replyMessage, nil
}

// AddRequest 添加请求
func AddRequest(requestPool *request_pool.RequestPool, request *request_pool.Request) {
	requestPool.RequestChan <- request
}
