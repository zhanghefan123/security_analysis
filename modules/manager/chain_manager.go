package manager

import (
	"zhanghefan123/security/modules/blockchain"
	"zhanghefan123/security/protocol"
)

// ChainManager 区块链的管理器

type ChainManager struct {
	// net 网络服务
	net protocol.Net

	// blockchain 区块链
	blockchain *blockchain.Blockchain

	// readyC 有事件出现
	readyC chan struct{}
}

func NewChainManager() *ChainManager {
	return &ChainManager{}
}
