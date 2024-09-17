/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import (
	commonPb "zhanghefan123/security/protobuf/pb-go/common"
)

// NewBlockEvent - define new block event object
type NewBlockEvent struct {
	BlockInfo *commonPb.BlockInfo
}

type NewContractEvent struct {
	ContractEventInfoList *commonPb.ContractEventInfoList
}
