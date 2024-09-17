/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package net

import (
	"zhanghefan123/security/modules/utils"
	"zhanghefan123/security/protocol"
)

// NetServiceFactory is a net service instance factory.
type NetServiceFactory struct {
}

// NewNetService create a new net service instance.
func (nsf *NetServiceFactory) NewNetService(net protocol.Net, chainId string, opts ...NetServiceOption) (protocol.NetService, error) {
	//初始化工厂实例
	ns := NewNetService(chainId, net)

	// 应用选项
	if err := ns.Apply(opts...); err != nil {
		return nil, err
	}

	// 设置共识节点的 id
	ns.consensusNodeIds = utils.GetValidatorsMapFromLocalConfig()

	// 进行结果的返回
	return ns, nil
}

func (nsf *NetServiceFactory) setAllConsensusNodeIds(ns *NetService, chainConf protocol.ChainConf) error {
	consensusNodeUidList := make([]string, 0)
	// add all the seeds
	for _, node := range chainConf.ChainConfig().Consensus.Nodes {
		consensusNodeUidList = append(consensusNodeUidList, node.NodeId...)
	}
	// set all consensus node id for net service
	err := ns.Apply(WithConsensusNodeUid(consensusNodeUidList...))
	if err != nil {
		return err
	}
	ns.logger.Infof("[NetServiceFactory] set consensus node uid list ok(chain-id:%s)", ns.chainId)
	return nil
}
