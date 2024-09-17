package rpc

import (
	"context"
	"fmt"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
	"net"
	"zhanghefan123/security/localconf"
	"zhanghefan123/security/logger"
	pb "zhanghefan123/security/modules/rpc/protobuf/pb-go"
	"zhanghefan123/security/modules/rpc/services"
)

// 获取 RPC_SERVER 的日志记录器
var log = logger.GetLogger(logger.MODULE_RPC_SERVER)

type RPCServer struct {
	grpcServer     *grpc.Server       // grpcServer google 官方
	log            *logger.CMLogger   // log 日志记录器
	ctx            context.Context    // context 上下文
	cancelFunction context.CancelFunc // cancelContext 对应的取消函数
	isShutDown     bool               // isShutDown 是否已经关闭
}

func NewRPCServer() (*RPCServer, error) {
	// 1. grpcServer 是内部实际提供服务的
	grpcServer, err := newGrpc()
	if err != nil {
		fmt.Printf("create grpc server failed, err:%v\n", err)
		return nil, err
	} else {
		return &RPCServer{
			grpcServer: grpcServer,
			log:        logger.GetLogger(logger.MODULE_RPC),
		}, nil
	}
}

// 创建一个新的 RPCServer 内部实现
func newGrpc() (*grpc.Server, error) {
	// 仅仅简单的添加了一个日志拦截器
	opts := []grpc.ServerOption{
		grpc_middleware.WithUnaryServerChain(
			LoggingInterceptor,
		),
	}
	server := grpc.NewServer(opts...)
	return server, nil
}

func (s *RPCServer) Start() error {
	var err error
	s.ctx, s.cancelFunction = context.WithCancel(context.Background())
	s.isShutDown = false

	// 1. 注册 grpc handler
	err = s.RegisterHandler()

	// 2. 在指定端口上进行监听
	host := localconf.ChainMakerConfig.RpcConfig.Host
	port := localconf.ChainMakerConfig.RpcConfig.Port
	endPoint := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Listen("tcp", endPoint)
	if err != nil {
		fmt.Printf("create rpc server listener failed, err:%v\n", err)
	}

	// 3. 开始提供服务
	err = s.grpcServer.Serve(conn)
	if err != nil {
		fmt.Printf("create rpc server listener failed, err:%v\n", err)
	}
	return err
}

// RegisterHandler 注册处理器
func (s *RPCServer) RegisterHandler() error {
	pb.RegisterAuthenticationServiceServer(s.grpcServer, &services.AuthenticationService{})
	return nil
}

// Stop 停止 RPCServer
func (s *RPCServer) Stop() {
	s.isShutDown = true
	s.cancelFunction()
	s.grpcServer.GracefulStop()
	s.log.Info("rpc server stop")
}
