package blockchain

import "fmt"

type StopFunction func() error

// Stop 停止区块链
func (bc *Blockchain) Stop() {
	// 停止模块
	var stopModules = make([]map[string]StopFunction, 0)

	// 添加停止网络模块的函数
	if bc.isModuleStartUp(ModuleNameNetService) {
		stopModules = append(stopModules, map[string]StopFunction{ModuleNameConsensus: bc.StopNetService})
	}

	// 添加停止共识模块的函数
	if bc.isModuleStartUp(ModuleNameConsensus) {
		stopModules = append(stopModules, map[string]StopFunction{ModuleNameConsensus: bc.StopNetService})
	}

	if err := bc.StopModules(stopModules); err != nil {
		fmt.Printf("Error stopping modules: %v\n", err)
	}
}

// StopModules 进行所有模块的停止
func (bc *Blockchain) StopModules(stopModules []map[string]StopFunction) error {
	moduleNum := len(stopModules)
	for idx, baseModule := range stopModules {
		for name, stopFunc := range baseModule {
			if err := stopFunc(); err != nil {
				bc.log.Errorf("stop module[%s] failed, %s", name, err)
				continue
			}
			bc.log.Infof("STOP STEP (%d/%d) => stop module[%s] success :)", idx+1, moduleNum, name)
		}
	}
	return nil
}

// StopNetService 停止网络服务
func (bc *Blockchain) StopNetService() error {
	// stop net service
	if err := bc.netService.Stop(); err != nil {
		bc.log.Errorf("stop net service failed, %v", err)
		return err
	}
	delete(bc.startModules, ModuleNameNetService)
	return nil
}

// StopConsensus 停止共识
func (bc *Blockchain) StopConsensus() error {
	// stop the consensus
	if err := bc.consensus.Stop(); err != nil {
		bc.log.Errorf("stop consensus failed, %v", err)
	}
	delete(bc.startModules, ModuleNameConsensus)
	return nil
}
