/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package consensus_utils is consensus utils
package consensus_utils

import (
	"fmt"
	"path"
	"strconv"
	"zhanghefan123/security/modules/request_pool"

	"zhanghefan123/security/common/msgbus"
	"zhanghefan123/security/consensus-utils/wal_service"
	"zhanghefan123/security/localconf"
	"zhanghefan123/security/protobuf/pb-go/config"
	"zhanghefan123/security/protocol"
)

// MaxBFT signature algorithm
const (
	KeySigAlgo           = "MaxbftSigAlgo"
	KeyCheckVoteInSingle = "MaxbftCheckVoteInSingle"
)

// Threshold algorithm
const (
	ECDSAAlgo                = "ecdsa"
	ThresholdAlgo            = "threshold"
	DefaultCheckVoteInSingle = true
)

// ConsensusImplConfig is consensus config to init consensus engine
type ConsensusImplConfig struct {
	ChainId           string
	NodeId            string
	Ac                protocol.AccessControlProvider
	Core              protocol.CoreEngine
	Store             protocol.BlockchainStore
	Sync              protocol.SyncService
	MsgBus            msgbus.MessageBus
	Signer            protocol.SigningMember
	ChainConf         protocol.ChainConf
	NetService        protocol.NetService
	LedgerCache       protocol.LedgerCache
	ProposalCache     protocol.ProposalCache
	Logger            protocol.Logger
	Manager           protocol.SnapshotManager
	SigAlgoInVote     string
	CheckVoteInSingle bool
	RequestPool       *request_pool.RequestPool // zhf add code
}

// ValidatorListFunc load validator list by chain config and blockchain store
type ValidatorListFunc func(chainConfig *config.ChainConfig,
	store protocol.BlockchainStore) (validators []string, err error)

// InitWalService init wal service
func InitWalService(config *config.ConsensusConfig, chainID, nodeID string) (wal_service.WalService, error) {
	return InitWalServiceByMarshalFunc(config, chainID, nodeID, nil)
}

// InitWalServiceByMarshalFunc init wal service use marshal functions
func InitWalServiceByMarshalFunc(config *config.ConsensusConfig, chainID, nodeID string,
	marshalFunc wal_service.MarshalFunc) (wal_service.WalService, error) {
	// load the wal write mode from config
	var (
		walWriteMode = wal_service.SyncWalWrite // default is sync
		walService   wal_service.WalService
		err          error
	)
	for _, v := range config.ExtConfig {
		if v.Key == wal_service.WALWriteModeKey {
			val, err1 := strconv.Atoi(v.Value)
			if err1 != nil {
				return nil, err
			}
			walWriteMode = wal_service.WalWriteMode(val)
		}
	}

	if walWriteMode == wal_service.NonWalWrite {
		walService, err = wal_service.NewWalService(marshalFunc, wal_service.WithWriteMode(walWriteMode))
	} else {
		waldir := path.Join(localconf.ChainMakerConfig.GetStorePath(),
			chainID, fmt.Sprintf("%s_%s", wal_service.WalDir, nodeID))
		walService, err = wal_service.NewWalService(marshalFunc,
			wal_service.WithWriteMode(walWriteMode), wal_service.WithWritePath(waldir))
	}
	if err != nil {
		return nil, err
	}
	return walService, nil
}
