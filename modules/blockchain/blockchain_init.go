package blockchain

import (
	consensus_utils "zhanghefan123/security/consensus-utils"
	"zhanghefan123/security/localconf"
	"zhanghefan123/security/logger"
	"zhanghefan123/security/modules/consensus_provider"
	"zhanghefan123/security/modules/net"
	"zhanghefan123/security/modules/request_pool"
)

type InitFunction func() error

// 初始化模块的名称
const (
	ModuleNameNetService  = "NetService"
	ModuleNameConsensus   = "ConsensusService"
	ModuleNameRequestPool = "RequestPool"
)

// Init 初始化区块链
func (bc *Blockchain) Init() (err error) {
	// 一个元素类型为 map[string]InitFunction 的数组, 使用数组的原因是可以保证顺序
	baseModules := []map[string]InitFunction{
		// 初始化订阅器
		{ModuleNameRequestPool: bc.InitRequestPool},    // 初始化请求池
		{ModuleNameNetService: bc.InitNetService},      // 网络模块
		{ModuleNameConsensus: bc.InitConsensusService}, // 共识模块服务
	}
	err = bc.InitBaseModules(baseModules)
	return err
}

// InitBaseModules 初始化基础模块
func (bc *Blockchain) InitBaseModules(baseModules []map[string]InitFunction) (err error) {
	moduleNum := len(baseModules)
	for idx, baseModule := range baseModules {
		for name, initFunc := range baseModule {
			if err := initFunc(); err != nil {
				bc.log.Errorf("init base module[%s] failed, %s", name, err)
				return err
			}
			bc.log.Infof("BASE INIT STEP (%d/%d) => init base[%s] success :)", idx+1, moduleNum, name)
		}
	}
	return
}

// InitRequestPool 初始化请求池
func (bc *Blockchain) InitRequestPool() (err error) {
	_, ok := bc.initModules[ModuleNameRequestPool]
	if ok {
		bc.log.Errorf("init request pool already exists")
		return
	}
	requestChannelSize := localconf.ChainMakerConfig.RpcConfig.RequestChannelSize
	bc.RequestPool = request_pool.NewRequestPool(requestChannelSize)
	bc.initModules[ModuleNameRequestPool] = struct{}{}
	return nil
}

// InitNetService 初始化网络服务
func (bc *Blockchain) InitNetService() (err error) {
	_, ok := bc.initModules[ModuleNameNetService]
	if ok {
		bc.log.Infof("net service module existed, ignore.")
		return
	}
	var netServiceFactory net.NetServiceFactory
	if bc.netService, err = netServiceFactory.NewNetService(bc.net, bc.chainId, net.WithMsgBus(bc.msgBus)); err != nil {
		bc.log.Errorf("new net service failed, %s", err)
		return
	}
	bc.initModules[ModuleNameNetService] = struct{}{}
	return
}

// InitConsensusService 初始化共识服务
func (bc *Blockchain) InitConsensusService() (err error) {
	// 获取本地节点 id
	localPeerId := localconf.ChainMakerConfig.NodeConfig.NodeId

	// 判断是否初始化了共识模块
	_, ok := bc.initModules[ModuleNameConsensus]
	if ok {
		bc.log.Infof("consensus module existed, ignore.")
		return
	}

	config := &consensus_utils.ConsensusImplConfig{
		ChainId:     bc.chainId,                                                   // (区块链的id)
		NodeId:      localPeerId,                                                  // (本地节点的 id)
		MsgBus:      bc.msgBus,                                                    // (消息总线)
		NetService:  bc.netService,                                                // (网络服务)
		Logger:      logger.GetLoggerByChain(logger.MODULE_CONSENSUS, bc.chainId), // 日志
		RequestPool: bc.RequestPool,                                               // (请求池)
	}
	// 获取相应的创建者
	provider := consensus_provider.GetConsensusProvider(localconf.ChainMakerConfig.ConsensusConfig.ConsensusType)

	// 调用创建者创建相应的共识实例
	bc.consensus, err = provider(config)
	if err != nil {
		bc.log.Errorf("new consensus engine failed, %s", err)
		return err
	}

	// 创建初始化模块
	bc.initModules[ModuleNameConsensus] = struct{}{}
	return
}

// isModuleInit 判断 module 是否启动了
func (bc *Blockchain) isModuleInit(moduleName string) bool {
	_, ok := bc.initModules[moduleName]
	if ok {
		return true
	} else {
		return false
	}
}
