package blockchain

import (
	"go.uber.org/zap"
)

type StartFunction func() error

// Start 启动区块链之中所有模块
func (bc *Blockchain) Start() error {
	var startModules = make([]map[string]StartFunction, 0)

	// 添加启动网络模块的函数
	if bc.isModuleInit(ModuleNameNetService) && !bc.isModuleStartUp(ModuleNameNetService) {
		startModules = append(startModules, map[string]StartFunction{ModuleNameNetService: bc.startNetService})
	}

	// 添加启动共识模块的函数
	if bc.isModuleInit(ModuleNameConsensus) && !bc.isModuleStartUp(ModuleNameConsensus) {
		startModules = append(startModules, map[string]StartFunction{ModuleNameConsensus: bc.startConsensusService})
	}

	// 调用 bc.StartModules 启动
	err := bc.StartModules(startModules)
	if err != nil {
		return err
	}
	return nil
}

// StartModules 进行模块的启动
func (bc *Blockchain) StartModules(startModules []map[string]StartFunction) error {
	moduleNum := len(startModules)
	for idx, baseModule := range startModules {
		for name, initFunc := range baseModule {
			if err := initFunc(); err != nil {
				bc.log.Errorf("start base module[%s] failed, %s", name, err)
				return err
			}
			bc.log.Infof("START STEP (%d/%d) => init base[%s] success :)", idx+1, moduleNum, name)
		}
	}
	return nil
}

// startNetService 启动网络服务
func (bc *Blockchain) startNetService() error {
	// start net service
	if err := bc.netService.Start(); err != nil {
		bc.log.Error("start net service error", zap.Error(err))
		return err
	}
	bc.startModules[ModuleNameNetService] = struct{}{}
	return nil
}

// startConsensus 启动共识服务
func (bc *Blockchain) startConsensusService() error {
	// start consensus service
	if err := bc.consensus.Start(); err != nil {
		bc.log.Error("start consensus service error", zap.Error(err))
		return err
	}
	bc.startModules[ModuleNameConsensus] = struct{}{}
	return nil
}

// isModuleStartUp 判断模块是否已经启动
func (bc *Blockchain) isModuleStartUp(name string) bool {
	_, ok := bc.startModules[name]
	if ok {
		return true
	} else {
		return false
	}
}
