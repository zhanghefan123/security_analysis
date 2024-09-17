package request_pool

import pb "zhanghefan123/security/modules/rpc/protobuf/pb-go"

// RequestPool 交易池
type RequestPool struct {
	// MaxSize 缓存大小
	MaxSize int

	// RequestChan 缓存
	RequestChan chan *Request
}

// Request 请求
type Request struct {
	// 请求的内容
	Message *pb.RpcMessage

	// 结果的返回的 channel
	ResponseChan chan *pb.RpcMessage
}

// NewRequestPool 新的请求处理池
func NewRequestPool(channelSize int) *RequestPool {
	return &RequestPool{
		MaxSize:     channelSize,
		RequestChan: make(chan *Request, channelSize),
	}
}

// NewRequest 创建新的结果
func NewRequest(message *pb.RpcMessage, resultChan chan *pb.RpcMessage) *Request {
	return &Request{
		Message:      message,
		ResponseChan: resultChan,
	}
}
