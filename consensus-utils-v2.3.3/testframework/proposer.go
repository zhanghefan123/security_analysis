/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testframework

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"zhanghefan123/security/protobuf/pb-go/consensus/maxbft"

	"zhanghefan123/security/common/msgbus"
	commonPb "zhanghefan123/security/protobuf/pb-go/common"
	consensusPb "zhanghefan123/security/protobuf/pb-go/consensus"
	"zhanghefan123/security/utils"
)

//startProposingLoop
func (ce *CoreEngineForTest) startProposingLoop() {
	go func() {
		for {
			select {
			case <-ce.isProposer:
				if ce.consensusType == consensusPb.ConsensusType_RAFT {
					ce.proposeBlockRaft()
				} else if ce.consensusType == consensusPb.ConsensusType_TBFT ||
					ce.consensusType == consensusPb.ConsensusType_DPOS {
					ce.proposeBlockTBFT()
				} else {
					ce.log.Warnf("Unrecognized consensus types: %s", ce.consensusType)
				}
			case <-ce.quit:
				return
			}
		}
	}()
}

//proposeBlockRaft
func (ce *CoreEngineForTest) proposeBlockRaft() {
	go func() {
		lastBlock := ce.ledgerCache.GetLastCommittedBlock()
		proposingHeight := lastBlock.Header.BlockHeight + 1

		ce.Lock()
		defer ce.Unlock()
		lastProposalHeight := ce.proposedBlockHeight

		// raft 正常不换主，且存在多次发送自己是主节点的问题，所以不需要重复发送同一高度的块
		if lastProposalHeight >= proposingHeight {
			if ce.consensusType == consensusPb.ConsensusType_RAFT {
				ce.log.Warnf("[nodeId:%d,%s] has proposal block begin, height:%d",
					map_nodeId_num[ce.nodeId], ce.nodeId, lastProposalHeight)
				return
			}
		}
		ce.proposedBlockHeight = proposingHeight

		block := &commonPb.Block{
			Header: &commonPb.BlockHeader{
				ChainId:      ce.chainId,
				BlockHeight:  proposingHeight,
				PreBlockHash: lastBlock.Hash(),
			},
			Txs: fetchTxBatch(txNum),
		}
		ce.msgBus.Publish(msgbus.ProposedBlock, &consensusPb.ProposalBlock{Block: block})
		ce.times[proposingHeight] = &consensusTime{start: utils.CurrentTimeMillisSeconds()}
		ce.log.Infof("[nodeId:%d,%s] proposal block height:%d", map_nodeId_num[ce.nodeId], ce.nodeId, proposingHeight)
	}()
}

//proposeBlockTBFT
func (ce *CoreEngineForTest) proposeBlockTBFT() {
	go func() {
		lastBlock := ce.ledgerCache.GetLastCommittedBlock()
		proposingHeight := lastBlock.Header.BlockHeight + 1

		block := &commonPb.Block{
			Header: &commonPb.BlockHeader{
				ChainId:      ce.chainId,
				BlockHeight:  proposingHeight,
				PreBlockHash: lastBlock.Hash(),
			},
			Txs: fetchTxBatch(txNum),
		}
		ce.msgBus.Publish(msgbus.ProposedBlock, &consensusPb.ProposalBlock{Block: block})
		ce.times[proposingHeight] = &consensusTime{start: utils.CurrentTimeMillisSeconds()}
		ce.log.Infof("[nodeId:%d,%s] proposal block height:%d", map_nodeId_num[ce.nodeId], ce.nodeId, proposingHeight)
	}()
}

//proposeBlockMaxbft
func (ce *CoreEngineForTest) proposeBlockMaxbft(proposal *maxbft.BuildProposal) {
	go func() {
		proposingHeight := proposal.Height
		preHash := proposal.PreHash

		if !ce.shouldProposeByChainedBFT(proposingHeight, preHash) {
			ce.log.Infof("not a legal proposal request [%d](%x)", proposingHeight, preHash)
			return
		}

		block := &commonPb.Block{
			Header: &commonPb.BlockHeader{
				ChainId:      ce.chainId,
				BlockHeight:  proposingHeight,
				PreBlockHash: preHash,
				Signature:    []byte("123"),
			},
			Txs: fetchTxBatch(txNum),
		}
		ce.msgBus.Publish(msgbus.ProposedBlock, &consensusPb.ProposalBlock{Block: block})
		ce.times[proposingHeight] = &consensusTime{start: utils.CurrentTimeMillisSeconds()}
		ce.log.Infof("[nodeId:%d,%s] proposal block height:%d", map_nodeId_num[ce.nodeId], ce.nodeId, proposingHeight)
	}()
}

// 生成指定数量的交易：txNum
func fetchTxBatch(txNum int) []*commonPb.Transaction {
	payload := make([]byte, txSize)
	if _, err := rand.Read(payload); err != nil {
		panic(err)
	}

	batch := make([]*commonPb.Transaction, txNum)
	for i := 0; i < txNum; i++ {
		batch[i] = &commonPb.Transaction{
			Payload: &commonPb.Payload{
				Parameters: []*commonPb.KeyValuePair{
					{
						Key:   fmt.Sprintf("%d", i),
						Value: payload,
					},
				},
			},
		}
	}
	return batch
}

/*
 * shouldProposeByChainedBFT, check if node should propose new block
 * Only for chained bft consensus
 */
func (ce *CoreEngineForTest) shouldProposeByChainedBFT(height uint64, preHash []byte) bool {
	committedBlock := ce.ledgerCache.GetLastCommittedBlock()
	if committedBlock == nil {
		ce.log.Errorf("no committed block found")
		return false
	}
	currentHeight := committedBlock.Header.BlockHeight
	// proposing height must higher than current height
	if currentHeight >= height {
		ce.log.Errorf("current commit block height: %d, propose height: %d", currentHeight, height)
		return false
	}
	if height == currentHeight+1 {
		// height follows the last committed block
		if bytes.Equal(committedBlock.Header.BlockHash, preHash) {
			return true
		}
		ce.log.Errorf("block pre hash error, expect %x, got %x, can not propose",
			committedBlock.Header.BlockHash, preHash)
		return false

	}
	// if height not follows the last committed block, then check last proposed block
	b, _ := ce.proposalCache.GetProposedBlockByHashAndHeight(preHash, height-1)
	if b == nil {
		ce.log.Errorf("not find preBlock: [%d:%x]", height-1, preHash)
	}
	return b != nil
}
