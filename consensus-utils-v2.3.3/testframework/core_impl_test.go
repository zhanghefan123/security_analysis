/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testframework

import (
	"testing"

	commonPb "zhanghefan123/security/protobuf/pb-go/common"

	"zhanghefan123/security/logger"

	"github.com/stretchr/testify/require"

	"github.com/golang/mock/gomock"

	configPb "zhanghefan123/security/protobuf/pb-go/config"
)

func TestCoreImpl(t *testing.T) {
	ctrl := gomock.NewController(t)
	testNodeConfigs, err := CreateTestNodeConfig(ctrl, blockchainId, consensusType, 1,
		ListenAddrs, Seeds, func(cfg *configPb.ChainConfig) []byte { return nil })
	require.Nil(t, err)
	cmLogger := logger.GetLogger(blockchainId)
	coreEngine := NewCoreEngineForTest(testNodeConfigs[0], cmLogger)
	coreEngine.GetBlockCommitter()
	coreEngine.GetBlockVerifier()
	coreEngine.GetMaxbftHelper()
	coreEngine.GetHotStuffHelper()
	block := &commonPb.Block{
		Header: &commonPb.BlockHeader{
			ChainId:      "chain1",
			BlockHeight:  100,
			PreBlockHash: nil,
		},
		Txs: fetchTxBatch(txNum),
	}
	coreEngine.commitBlock(block)
	coreEngine.Start()
	defer coreEngine.Stop()

}
