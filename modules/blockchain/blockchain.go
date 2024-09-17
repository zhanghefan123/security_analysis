package blockchain

import (
	"zhanghefan123/security/common/msgbus"
	"zhanghefan123/security/logger"
	"zhanghefan123/security/modules/request_pool"
	"zhanghefan123/security/protocol"
)

// Blockchain 区块链的结构体
type Blockchain struct {
	// logger of blockchain
	log *logger.CMLogger
	// genesis block 是创世块的json字符串
	genesis string
	// chain id 是区块链的id
	chainId string
	// message bus 是消息总线
	msgBus msgbus.MessageBus
	// net, shared with other blockchains 和其他区块链共享的网络
	net protocol.Net
	// requestPool 用于接受请求的池子
	RequestPool *request_pool.RequestPool
	// netService 链提供的网络服务
	netService protocol.NetService
	// consensus 共识模块
	consensus protocol.ConsensusEngine
	// initModules is the modules that have been initialized.
	initModules map[string]struct{}
	// startModules is the modules that have been started.
	startModules map[string]struct{}
}

// NewBlockChain 新的区块链
func NewBlockChain(chainId string, genesis string, msgBus msgbus.MessageBus, net protocol.Net) *Blockchain {
	return &Blockchain{ // 返回一个区块链的结构体实例
		log:          logger.GetLoggerByChain(logger.MODULE_BLOCKCHAIN, chainId), // 日志记录器的获取
		genesis:      genesis,                                                    // 创世区块bcx.xml的全路径
		chainId:      chainId,                                                    // 区块链的id
		msgBus:       msgBus,                                                     // 消息总线，每创建一个区块链，都会创建一个消息总线
		net:          net,                                                        // server 之中保存的 net
		initModules:  make(map[string]struct{}),                                  // 已经初始化的模块
		startModules: make(map[string]struct{}),                                  // 已经启动的模块
	}
}
