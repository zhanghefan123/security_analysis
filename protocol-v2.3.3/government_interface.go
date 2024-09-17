/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protocol

import (
	"zhanghefan123/security/protobuf/pb-go/config"
	consensuspb "zhanghefan123/security/protobuf/pb-go/consensus"
)

//Government 治理接口
type Government interface {
	//Verify used to verify consensus data
	Verify(consensusType consensuspb.ConsensusType, chainConfig *config.ChainConfig) error
	// GetGovernanceContract get GovernanceContract
	GetGovernanceContract() (*consensuspb.GovernanceContract, error)
}
