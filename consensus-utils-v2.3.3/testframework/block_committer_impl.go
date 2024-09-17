/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testframework

import (
	"zhanghefan123/security/common/msgbus"
	commonPb "zhanghefan123/security/protobuf/pb-go/common"
	"zhanghefan123/security/protocol"
)

// ####################################################################################################################
//                                       impls BlockCommitter for RAFT and HotStuff
// ####################################################################################################################
type blockCommitterForTest struct {
	msgBus      msgbus.MessageBus
	ledgerCache protocol.LedgerCache
}

//newBlockCommitterForTest
func newBlockCommitterForTest(msgBus msgbus.MessageBus,
	ledgerCache protocol.LedgerCache) *blockCommitterForTest {
	return &blockCommitterForTest{msgBus: msgBus, ledgerCache: ledgerCache}
}

// AddBlock raft invoke the interface
func (b *blockCommitterForTest) AddBlock(blk *commonPb.Block) error {
	b.msgBus.Publish(msgbus.BlockInfo, blk)
	b.ledgerCache.SetLastCommittedBlock(blk)
	return nil
}
