package manager

import (
	"zhanghefan123/security/common/crypto/engine"
	"zhanghefan123/security/localconf"
	"zhanghefan123/security/modules/blockchain"
)

// Start 启动链管理器
func (manager *ChainManager) Start() error {
	// 1. 进行网络的启动
	if err := manager.net.Start(); err != nil {
		log.Errorf("failed to start manager: %v", err)
		return err
	}
	log.Infof("chain manager started")

	// 2. 进行加密引擎的启动
	tls := false
	engine.InitCryptoEngine(localconf.ChainMakerConfig.CryptoEngine, tls)

	// 3. 进行区块链的启动
	// sync.Map 的 range 方法之中传入的函数，如果返回 false 则停止继续
	go startBlockChain(manager.blockchain)

	// 4. 关闭 readyC 代表启动好了
	close(manager.readyC)
	return nil
}

// startBlockChain 启动区块链
func startBlockChain(chain *blockchain.Blockchain) {
}
