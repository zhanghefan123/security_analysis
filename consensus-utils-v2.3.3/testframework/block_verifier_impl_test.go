/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testframework

import (
	"testing"

	commonPb "zhanghefan123/security/protobuf/pb-go/common"

	"github.com/golang/mock/gomock"

	"github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/require"

	"zhanghefan123/security/utils"
)

//TestBlockVerifier
func TestBlockVerifier(t *testing.T) {
	ctrl := gomock.NewController(t)
	chainconfig := InitChainConfig("chain1", consensusType, 1)
	chainConfigBytes, err := proto.Marshal(chainconfig)
	require.NotNil(t, t, err)

	var maxbftConsensusVal []byte
	blockchainStore := newMockStore(ctrl, maxbftConsensusVal, chainConfigBytes)
	chainConfigForTest := newChainConfImplForTest(blockchainStore, chainconfig)
	// create genesis block
	genesisBlock, _, err := utils.CreateGenesis(chainconfig)
	require.NotNil(t, t, err)
	// create ledgerCache
	ledgerCache := NewCache("chain1")
	//SetLastCommittedBlock
	ledgerCache.SetLastCommittedBlock(genesisBlock)
	//NewProposalCache
	proposalCache := NewProposalCache(chainConfigForTest, ledgerCache)
	//newBlockVerifierForTest
	blockVerifyForTest := newBlockVerifierForTest(proposalCache, ledgerCache)
	block := &commonPb.Block{
		Header: &commonPb.BlockHeader{
			ChainId:      "chain1",
			BlockHeight:  100,
			PreBlockHash: nil,
		},
		Txs: fetchTxBatch(txNum),
	}

	//VerifyBlock
	_ = blockVerifyForTest.VerifyBlock(block, 0)
}
