package manager

// Stop 进行 chain_manager 的停止
func (manager *ChainManager) Stop() {
	// 停止 manager 所管理的 blockchain
	manager.blockchain.Stop()

	// 停止所依赖的网络模块
	if err := manager.net.Stop(); err != nil {
		log.Errorf("chain manager net stop err:%v", err)
	}

	// 打印停止
	log.Infof("chain manager net stop success")
}
