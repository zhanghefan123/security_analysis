/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package net

import (
	"errors"
	"io/ioutil"

	libp2p "zhanghefan123/security/network/net-libp2p/libp2pnet"
	"zhanghefan123/security/protocol"
)

var ErrorNetType = errors.New("error net type")

// NetFactory 网络创建工厂
type NetFactory struct {
	netType protocol.NetType

	n protocol.Net
}

// NetOption 是一个附加配置项到 net 实例的一个函数
type NetOption func(cfg *NetFactory) error

// WithReadySignalC 是用来进行 ReadyC 的设置的
func WithReadySignalC(signalC chan struct{}) NetOption {
	return func(nf *NetFactory) error {
		switch nf.netType {
		case protocol.Libp2p:
			n, _ := nf.n.(*libp2p.LibP2pNet)
			n.Prepare().SetReadySignalC(signalC)
		case protocol.Liquid:
			return errors.New("not support liquid")
		}
		return nil
	}
}

// WithListenAddr 设置网络监听的地址
func WithListenAddr(addr string) NetOption {
	return func(nf *NetFactory) error {
		switch nf.netType {
		case protocol.Libp2p:
			n, _ := nf.n.(*libp2p.LibP2pNet)
			n.Prepare().SetListenAddr(addr)
		case protocol.Liquid:
			return errors.New("not support liquid")
		}
		return nil
	}
}

// WithCrypto set private key file and tls cert file for the net to create connection.
func WithCrypto(pkMode bool, keyFile, certFile string, encKeyFile, encCertFile string) NetOption {
	return func(nf *NetFactory) error {
		var (
			err                       error
			keyBytes, certBytes       []byte
			encKeyBytes, encCertBytes []byte
		)
		//try to read
		encKeyBytes, _ = ioutil.ReadFile(encKeyFile)
		encCertBytes, _ = ioutil.ReadFile(encCertFile)

		keyBytes, err = ioutil.ReadFile(keyFile)
		if err != nil {
			return err
		}
		if !pkMode {
			certBytes, err = ioutil.ReadFile(certFile)
			if err != nil {
				return err
			}
		}
		switch nf.netType {
		case protocol.Libp2p:
			n, _ := nf.n.(*libp2p.LibP2pNet)
			n.Prepare().SetPubKeyModeEnable(pkMode)
			n.Prepare().SetKey(keyBytes)
			if !pkMode {
				n.Prepare().SetCert(certBytes)
				n.Prepare().SetEncKey(encKeyBytes)
				n.Prepare().SetEncCert(encCertBytes)
			}
		case protocol.Liquid:
			return errors.New("not support liquid")
		}
		return nil
	}
}

// WithPublicKeyModeCrypto 只进行私钥的存储和公钥模式的设置
func WithPublicKeyModeCrypto(secretKeyPath string) NetOption {
	return func(nf *NetFactory) error {
		var (
			err             error
			privateKeyBytes []byte
		)
		privateKeyBytes, err = ioutil.ReadFile(secretKeyPath)
		if err != nil {
			return err
		}
		n, _ := nf.n.(*libp2p.LibP2pNet)
		n.Prepare().SetPubKeyModeEnable(true)
		n.Prepare().SetKey(privateKeyBytes)
		return nil
	}
}

// WithPeerStreamPoolSize 设置最大的连接数量
func WithPeerStreamPoolSize(size int) NetOption {
	return func(nf *NetFactory) error {
		switch nf.netType {
		case protocol.Libp2p:
			n, _ := nf.n.(*libp2p.LibP2pNet)
			n.Prepare().SetPeerStreamPoolSize(size)
		case protocol.Liquid:
			return errors.New("not support liquid")
		}
		return nil
	}
}

// WithSeeds 设置初始的连接的 peer 节点
func WithSeeds(seeds ...string) NetOption {
	return func(nf *NetFactory) error {
		if seeds == nil {
			return nil
		}
		switch nf.netType {
		case protocol.Libp2p:
			n, _ := nf.n.(*libp2p.LibP2pNet)
			for _, seed := range seeds {
				n.Prepare().AddBootstrapsPeer(seed)
			}
		case protocol.Liquid:
			return errors.New("not support liquid")
		}
		return nil
	}
}

// WithMaxPeerCountAllowed 设置能够连接的最大数量
func WithMaxPeerCountAllowed(max int) NetOption {
	return func(nf *NetFactory) error {
		switch nf.netType {
		case protocol.Libp2p:
			n, _ := nf.n.(*libp2p.LibP2pNet)
			n.Prepare().SetMaxPeerCountAllow(max)
		case protocol.Liquid:
			return errors.New("not support liquid")
		}
		return nil
	}
}

// WithPeerEliminationStrategy 设置 peer 删除策略
func WithPeerEliminationStrategy(strategy int) NetOption {
	return func(nf *NetFactory) error {
		switch nf.netType {
		case protocol.Libp2p:
			n, _ := nf.n.(*libp2p.LibP2pNet)
			n.Prepare().SetPeerEliminationStrategy(strategy)
		case protocol.Liquid:
			return errors.New("not support liquid")
		}
		return nil
	}
}

// WithBlackAddresses 通过地址设置黑名单
func WithBlackAddresses(blackAddresses ...string) NetOption {
	return func(nf *NetFactory) error {
		if blackAddresses == nil {
			return nil
		}
		switch nf.netType {
		case protocol.Libp2p:
			n, _ := nf.n.(*libp2p.LibP2pNet)
			for _, ba := range blackAddresses {
				n.Prepare().AddBlackAddress(ba)
			}
		case protocol.Liquid:
			return errors.New("not support liquid")
		}
		return nil
	}
}

// WithBlackNodeIds 通过 peerId 设置黑名单
func WithBlackNodeIds(blackNodeIds ...string) NetOption {
	return func(nf *NetFactory) error {
		if blackNodeIds == nil {
			return nil
		}
		switch nf.netType {
		case protocol.Libp2p:
			n, _ := nf.n.(*libp2p.LibP2pNet)
			for _, bn := range blackNodeIds {
				n.Prepare().AddBlackPeerId(bn)
			}
		case protocol.Liquid:
			return errors.New("not support liquid")
		}
		return nil
	}
}

// WithMsgCompression 设置信息压缩
func WithMsgCompression(enable bool) NetOption {
	return func(nf *NetFactory) error {
		switch nf.netType {
		case protocol.Libp2p:
			n, _ := nf.n.(*libp2p.LibP2pNet)
			n.SetCompressMsgBytes(enable)
		case protocol.Liquid:
			//n, _ := nf.n.(*liquid.LiquidNet)
			//n.HostConfig().MsgCompress = enable
			return errors.New("not supported liquid")
		}
		return nil
	}
}

// WithInsecurity 表示是否禁用网络加密和认证措施
func WithInsecurity(isInsecurity bool) NetOption {
	return func(nf *NetFactory) error {
		switch nf.netType {
		case protocol.Libp2p:
			n, _ := nf.n.(*libp2p.LibP2pNet)
			n.Prepare().SetIsInsecurity(isInsecurity)
		case protocol.Liquid:
			// not supported
			return errors.New("not supported liquid")
		}
		return nil
	}
}

// NewNet create a new net instance.
func (nf *NetFactory) NewNet(netType protocol.NetType, opts ...NetOption) (protocol.Net, error) {
	nf.netType = netType
	switch nf.netType {
	case protocol.Libp2p:
		localNet, err := libp2p.NewLibP2pNet(GlobalNetLogger)
		if err != nil {
			return nil, err
		}
		nf.n = localNet
	case protocol.Liquid:
		return nil, errors.New("not supported liquid")
	default:
		return nil, ErrorNetType
	}
	if err := nf.Apply(opts...); err != nil {
		return nil, err
	}
	return nf.n, nil
}

// Apply 应用上面所提到的一系列的 NetOptions
func (nf *NetFactory) Apply(opts ...NetOption) error {
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(nf); err != nil {
			return err
		}
	}
	return nil
}

// WithStunClient read stun client cfg
// clientListenAddr: listen bind addr
// stunServerAddr: stun server addr
// networkType: udp,tcp,quic
func WithStunClient(clientListenAddr, stunServerAddr, networkType string, enable bool) NetOption {
	return func(nf *NetFactory) error {
		switch nf.netType {
		case protocol.Libp2p:
			return errors.New("not supported libp2p")
		case protocol.Liquid:
			return errors.New("not supported liquid")
		}
		return nil
	}
}

// WithStunServer read stun server cfg
// enable: set stun server if enable
// twoPublicAddr: one device have two PublicAddr
// addr1, addr2 must set
func WithStunServer(enable, twoPublicAddr bool, other string, notifyAddr, localNotify,
	addr1, addr2, addr3, addr4, networkType string) NetOption {
	return func(nf *NetFactory) error {
		switch nf.netType {
		case protocol.Libp2p:
			return errors.New("not supported libp2p")
		case protocol.Liquid:
			return errors.New("not supported liquid")
		}
		return nil
	}
}

// WithHolePunch read hole-punch cfg
// enable: set hole-punch function if enable
func WithHolePunch(enable bool) NetOption {
	return func(nf *NetFactory) error {
		switch nf.netType {
		case protocol.Libp2p:
			return errors.New("not supported liquid")
		case protocol.Liquid:
			return errors.New("not supported liquid")
		}
		return nil
	}
}
