package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"zhanghefan123/security/localconf"
	"zhanghefan123/security/logger"
	"zhanghefan123/security/modules/manager"
	rpcserver "zhanghefan123/security/modules/rpc"
	"zhanghefan123/security/starter/register"
)

// log 启动客户端的 logger
var log = logger.GetLogger(logger.MODULE_CLI)

// CreateStartCmd 创建启动命令
func CreateStartCmd() *cobra.Command {
	var startCmd = &cobra.Command{
		Use:   "start",
		Short: "Startup Chainmaker Node",
		Long:  "Startup Chainmaker Node",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("start the chain")
			register.RegisterAllComponents()
			InitLocalConfig(cmd)
			MainStart()
		},
	}
	AttachFlags(startCmd, []string{flagNameOfConfigFilePath})
	return startCmd
}

// InitLocalConfig 处理 InitLocalConfig 所可能会出现错误
func InitLocalConfig(cmd *cobra.Command) {
	if err := localconf.InitLocalConfig(cmd); err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
}

// MainStart 程序启动逻辑
func MainStart() {
	// error 信道
	errorChan := make(chan error)

	// 1. 创建新的 ChainManager
	// -------------------------------------------------------------------
	chainManager := manager.NewChainManager()
	// -------------------------------------------------------------------

	// 2. 初始化链服务
	// -------------------------------------------------------------------
	err := chainManager.Init()
	if err != nil {
		// 打印出错的原因
		log.Errorf("chainmaker server init failed, %s", err.Error())
		return
	}
	// -------------------------------------------------------------------

	// 3. 创建 rpcServer 并定义日志拦截器
	// -------------------------------------------------------------------
	rpcServer, err := rpcserver.NewRPCServer()
	if err != nil {
		log.Errorf("chainmaker server init failed, %s", err.Error())
		return
	}
	// -------------------------------------------------------------------

	// 4. 启动链服务
	// -------------------------------------------------------------------
	if err := chainManager.Start(); err != nil {
		log.Errorf("chain manager startup failed, %s", err.Error())
		errorChan <- err
	}
	// -------------------------------------------------------------------

	// 5. 启动 rpcServer 并监听指定的端口
	// -------------------------------------------------------------------
	err = rpcServer.Start()
	if err != nil {
		log.Errorf("rpc server startup failed, %s", err.Error())
		errorChan <- err
	}
	// -------------------------------------------------------------------

	// 当没有错误的时候阻塞在这里, 如果出现错误执行清理程序
	// -------------------------------------------------------------------
	err = <-errorChan
	if err != nil {
		log.Errorf("chainmaker server startup failed, %s", err.Error())
	}
	log.Infof("stop the rpc server")
	rpcServer.Stop()
	log.Infof("stop the chain manager")
	chainManager.Stop()
	// -------------------------------------------------------------------
}
