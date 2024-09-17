package api

import (
	"time"
	"zhanghefan123/security/modules/consensus_algorithms/pbft"
	"zhanghefan123/security/modules/consensus_algorithms/pbft/message"
	"zhanghefan123/security/modules/request_pool"
	pb "zhanghefan123/security/modules/rpc/protobuf/pb-go"
	"zhanghefan123/security/modules/utils"
)

// UserLegalityCheck 检测用户的合法性
func UserLegalityCheck(validUsers *map[string]interface{}, user string) bool {
	if _, ok := (*validUsers)[user]; !ok {
		return false
	}
	return true
}

// PendingRequest 添加待处理用户认证请求
func PendingRequest(pbftImpl *pbft.ConsensusPbftImpl, userId string, channel chan pb.AuthenticationResult) error {
	// 1. 首先需要添加用户到 GlobalState 之中
	err := pbftImpl.ConsensusState.AddUserForAuthentication(userId, channel)
	if err != nil {
		return err
	}

	// 2. 生成相应的 prePrepareMessage, 并启动相应的共识流程
	prePrepareMessage := message.NewPrePrepare(userId, pbftImpl.LocalPeerId)
	prePrepareConsensusMessage := message.CreatePrePrepareConsensusMessage(prePrepareMessage)
	pbftImpl.InternalMsgChan <- prePrepareConsensusMessage
	return nil
}

// HandleAuthenticationRequest 处理认证请求
func HandleAuthenticationRequest(pbftImpl *pbft.ConsensusPbftImpl, request *request_pool.Request) {
	// 计时器处理
	t := time.NewTimer(time.Second * 30)
	defer t.Stop()

	// 获取 responseChan -> 用于向用户进行结果返回
	responseChan := request.ResponseChan

	// 获取结果
	resultChannel := make(chan pb.AuthenticationResult)

	// 创建 authRequest 空对象
	authRequest := &pb.AuthenticationRequest{}

	// 进行反序列化
	utils.MustUnmarshal(request.Message.Content, authRequest)

	// 拿到 userId
	userId := authRequest.UserId

	// 创建新的请求添加到队列之中
	err := PendingRequest(pbftImpl, userId, resultChannel)
	if err != nil {
		pbftImpl.Logger.Errorf("already existed user")
	}

	select {
	// 当从 resultChannel 之中返回结果的时候
	case result := <-resultChannel:
		// 日志输出
		pbftImpl.Logger.Infof("HandleUserRequest received message")

		// 创建 authenticationReply消息
		authReply := &pb.AuthenticationReply{
			UserId: userId,
			Result: result,
		}

		// 创建 rpc 消息 将响应结果返回
		rpcMessage := &pb.RpcMessage{
			Type:    pb.RpcMessageType_AuthRequest,
			Content: utils.MustMarshal(authReply),
		}

		responseChan <- rpcMessage

	// 当计时器超时的时候
	case <-t.C:
		// 日志输出
		pbftImpl.Logger.Errorf("handle user request time out")

		// 创建 authenticationReply消息
		authReply := &pb.AuthenticationReply{
			UserId: userId,
			Result: pb.AuthenticationResult_ConsensusTimeout,
		}

		// 创建 rpc 消息, 将响应结果返回
		rpcMessage := &pb.RpcMessage{
			Type:    pb.RpcMessageType_AuthReply,
			Content: utils.MustMarshal(authReply),
		}

		responseChan <- rpcMessage
	}
}
