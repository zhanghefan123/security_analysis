package handler

import "zhanghefan123/security/modules/consensus_algorithms/pbft"

// Handle 各种类型消息
func Handle(pbftImpl *pbft.ConsensusPbftImpl) {
	for {
		select {
		// 接受到用户发送来的请求
		case userRequest := <-pbftImpl.RequestPool.RequestChan:
			HandleUserRequest(pbftImpl, userRequest)
		// 接受内部网络之中的 ConsensusMsg
		case internalMsg := <-pbftImpl.InternalMsgChan:
			HandleConsensusMsg(pbftImpl, internalMsg)
		// 接受外部网络中的 ConsensusMsg
		case externalMsg := <-pbftImpl.ExternalMsgChan:
			HandleConsensusMsg(pbftImpl, externalMsg)
		}
	}
}
