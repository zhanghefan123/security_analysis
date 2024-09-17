package rpc

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
	"net"
)

const (
	//UNKNOWN unknown string
	UNKNOWN = "unknown"
)

// GetClientAddr 进行客户端的地址的获取
func GetClientAddr(ctx context.Context) string {
	pr, ok := peer.FromContext(ctx)
	if !ok {
		log.Errorf("getClientAddr FromContext failed")
		return UNKNOWN
	}

	if pr.Addr == net.Addr(nil) {
		log.Errorf("getClientAddr failed, peer.Addr is nil")
		return UNKNOWN
	}

	return pr.Addr.String()
}

// LoggingInterceptor 日志拦截器
func LoggingInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	addr := GetClientAddr(ctx)

	log.Debugf("[%s] call gRPC method: %s", addr, info.FullMethod)
	log.DebugDynamic(func() string {
		str := fmt.Sprintf("req detail: %+v", req)
		if len(str) > 1024 {
			str = str[:1024] + " ......"
		}
		return str
	})
	resp, err := handler(ctx, req)
	log.Debugf("[%s] call gRPC method: %s, resp detail: %+v", addr, info.FullMethod, resp)
	return resp, err
}
