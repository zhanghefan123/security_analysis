package manager

import (
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"zhanghefan123/security/common/crypto/asym"
	"zhanghefan123/security/common/helper"
	"zhanghefan123/security/common/msgbus"
	"zhanghefan123/security/localconf"
	"zhanghefan123/security/logger"
	blockchain2 "zhanghefan123/security/modules/blockchain"
	"zhanghefan123/security/modules/net"
	"zhanghefan123/security/protocol"
)

var (
	log                                = logger.GetLogger(logger.MODULE_BLOCKCHAIN)
	ErrNotSupportedMultipleBlockchains = errors.New("not supported multiple blockchains")
)

// Init 用来进行网络的初始化
func (manager *ChainManager) Init() error {
	log.Infof("begin to init the chain manager server")

	// 1. 初始化管道
	manager.readyC = make(chan struct{})

	// 2. 初始化网络
	err := manager.initNet()
	if err != nil {
		// 返回错误原因，让调用者进行处理
		return err
	}

	// 3. 初始化区块链
	err = manager.initBlockChain()
	if err != nil {
		// 返回错误原因，让调用者进行处理
		return err
	}
	return nil
}

// initNet 私有方法, 同个包之中可以使用, 不同包之中不可以使用
func (manager *ChainManager) initNet() error {
	var netType protocol.NetType // 网络类型
	var err error                // 错误类型

	// ------------------------ 网络实现 ------------------------
	netProvider := localconf.ChainMakerConfig.NetConfig.Provider
	switch strings.ToLower(netProvider) {
	case "libp2p":
		netType = protocol.Libp2p
	case "liquid":
		// not supported
		return errors.New("not supported liquid")
	default:
		return errors.New("not supported net provider")
	}
	// ------------------------ 网络实现 ------------------------

	// ---------------------- 加载密钥路径 ----------------------
	keyPath := localconf.ChainMakerConfig.NetConfig.TLSConfig.PrivKeyFile
	if !filepath.IsAbs(keyPath) {
		keyPath, err = filepath.Abs(keyPath)
		if err != nil {
			return err
		}
	}
	log.Infof("load net tls key file path: %s", keyPath)
	// ---------------------- 加载密钥路径 ----------------------

	// --------------- netFactory create newNet ---------------
	var netFactory net.NetFactory
	manager.net, err = netFactory.NewNet(
		netType,
		net.WithReadySignalC(manager.readyC),
		net.WithListenAddr(localconf.ChainMakerConfig.NetConfig.ListenAddr),
		net.WithPublicKeyModeCrypto(keyPath),
		net.WithPeerStreamPoolSize(localconf.ChainMakerConfig.NetConfig.PeerStreamPoolSize),
		net.WithMaxPeerCountAllowed(localconf.ChainMakerConfig.NetConfig.MaxPeerCountAllow),
		net.WithPeerEliminationStrategy(localconf.ChainMakerConfig.NetConfig.PeerEliminationStrategy),
		net.WithSeeds(localconf.ChainMakerConfig.NetConfig.Seeds...),
		net.WithBlackAddresses(localconf.ChainMakerConfig.NetConfig.BlackList.Addresses...),
		net.WithBlackNodeIds(localconf.ChainMakerConfig.NetConfig.BlackList.NodeIds...),
		net.WithMsgCompression(localconf.ChainMakerConfig.DebugConfig.UseNetMsgCompression),
		net.WithInsecurity(localconf.ChainMakerConfig.DebugConfig.IsNetInsecurity),
	)
	if err != nil {
		errMsg := fmt.Sprintf("new net failed, %s", err.Error())
		log.Error(errMsg)
		return errors.New(errMsg)
	}
	// --------------- netFactory create newNet ---------------

	// ------------------ 读取私钥文件->生成peerid ------------------
	// 读取字符串 PEM 格式的密钥
	file, err := ioutil.ReadFile(keyPath)
	if err != nil {
		errMsg := fmt.Sprintf("read PEM format secret key failed, %s", err.Error())
		log.Error(errMsg)
		return err
	}
	// 从 PEM 格式字符串的密钥还原出 crypto.PrivateKey 的密钥
	privateKey, err := asym.PrivateKeyFromPEM(file, nil)
	if err != nil {
		errMsg := fmt.Sprintf("convert PEM format secret key to crypto.PrivateKey failed, %s", err.Error())
		log.Error(errMsg)
		return err
	}
	// 通过私钥生成 peerId
	localPeerId, err := helper.CreateLibp2pPeerIdWithPrivateKey(privateKey)
	if err != nil {
		errMsg := fmt.Sprintf("generate local peerid failed, %s", err.Error())
		log.Error(errMsg)
		return err
	}
	localconf.ChainMakerConfig.SetNodeId(localPeerId)
	// ------------------ 读取私钥文件->生成peerid ------------------
	return nil
}

// initBlockChain 进行区块链的初始化
func (manager *ChainManager) initBlockChain() error {
	blockchains := localconf.ChainMakerConfig.GetBlockChains()
	if len(blockchains) != 1 {
		return ErrNotSupportedMultipleBlockchains
	}
	genesis := blockchains[0].Genesis
	chainId := blockchains[0].ChainId
	if !filepath.IsAbs(genesis) { // 判断创世区块是否是绝对路径，如果不是绝对路径，那么就将相对路径转换为绝对路径
		var err error
		genesis, err = filepath.Abs(genesis)
		if err != nil {
			return err
		}
	}
	log.Infof("load genesis file path of chain[%s]: %s", chainId, genesis)                         // 进行日至的打印，说明正在进行创世区块的加载
	blockchain := blockchain2.NewBlockChain(chainId, genesis, msgbus.NewMessageBus(), manager.net) // 进行新的区块链的创建

	if err := blockchain.Init(); err != nil {
		errMsg := fmt.Sprintf("init blockchain[%s] failed, %s", chainId, err.Error())
		return errors.New(errMsg)
	}
	manager.blockchain = blockchain
	log.Infof("init blockchain[%s] success!", chainId)
	return nil
}
