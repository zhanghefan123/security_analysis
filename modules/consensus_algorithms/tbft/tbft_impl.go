package tbft

import (
	"chainmaker.org/chainmaker/lws"
	"context"
	"github.com/gogo/protobuf/proto"
	"sync"
	"time"
	"zhanghefan123/security/common/msgbus"
	"zhanghefan123/security/consensus-utils/consistent_service"
	"zhanghefan123/security/consensus-utils/wal_service"
	consensuspb "zhanghefan123/security/protobuf/pb-go/consensus"
	"zhanghefan123/security/protocol"
)

var (
	defaultChanCap                  = 1000
	nilHash                         = []byte("NilHash")
	defaultConsensusStateCacheSize  = uint64(10)
	defaultConsensusFutureCacheSize = uint64(10)
	// TBFTAddtionalDataKey implements the block key for store tbft infos
	TBFTAddtionalDataKey = "TBFTAddtionalDataKey"
	// TBFT_propose_timeout_key implements the config key for chainconf
	TBFT_propose_timeout_key = "TBFT_propose_timeout"
	// TBFT_propose_delta_timeout_key implements the config key for chainconf
	TBFT_propose_delta_timeout_key = "TBFT_propose_delta_timeout"
	// TBFT_blocks_per_proposer implements the config key for chainconf
	TBFT_blocks_per_proposer = "TBFT_blocks_per_proposer"
	// TBFT_propose_timeout_optimal_key implements the config key for chainconf
	TBFT_propose_timeout_optimal_key = "TBFT_propose_timeout_optimal"
	// TBFT_propose_optimal_key implements the config key for chainconf
	TBFT_propose_optimal_key = "TBFT_propose_optimal"
	// blockVersion231 the blockchain v2.3.1 version
	blockVersion231 = uint32(2030100)
)

const (
	// 定义的一些计时器
	// DefaultTimeoutPropose Timeout of waitting for a proposal before prevoting nil
	DefaultTimeoutPropose = 30 * time.Second
	// DefaultTimeoutProposeDelta Increased time delta of TimeoutPropose between rounds
	DefaultTimeoutProposeDelta = 1 * time.Second
	// DefaultBlocksPerProposer The number of blocks each proposer can propose
	DefaultBlocksPerProposer = uint64(1)
	// DefaultTimeoutProposeOptimal optimal timeout of waitting for a proposal before prevoting nil
	DefaultTimeoutProposeOptimal = 2 * time.Second
	// TimeoutPrevote Timeout of waiting for >2/3 prevote
	TimeoutPrevote = 30 * time.Second
	// TimeoutPrevoteDelta Increased time delta of TimeoutPrevote between round
	TimeoutPrevoteDelta = 1 * time.Second
	// TimeoutPrecommit Timeout of waiting for >2/3 precommit
	TimeoutPrecommit = 30 * time.Second
	// TimeoutPrecommitDelta Increased time delta of TimeoutPrecommit between round
	TimeoutPrecommitDelta = 1 * time.Second
	// TimeoutCommit Timeout to wait for precommite
	TimeoutCommit = 30 * time.Second
	// TimeDisconnet the duration of node disconnectio(3000ms)
	TimeDisconnet = 3000
)

// 需要订阅的消息的主题
var msgBusTopics = []msgbus.Topic{msgbus.ProposedBlock, msgbus.VerifyResult,
	msgbus.RecvConsensusMsg, msgbus.RecvConsistentMsg, msgbus.BlockInfo}

// mustMarshal
func mustMarshal(msg proto.Message) (data []byte) {
	var err error
	defer func() {
		// while first marshal failed, retry marshal again
		if recover() != nil {
			data, err = proto.Marshal(msg)
			if err != nil {
				panic(err)
			}
		}
	}()

	data, err = proto.Marshal(msg)
	if err != nil {
		panic(err)
	}
	return
}

// mustUnmarshal unmarshals from byte slice to protobuf message or panic
func mustUnmarshal(b []byte, msg proto.Message) {
	if err := proto.Unmarshal(b, msg); err != nil {
		panic(err)
	}
}

// ConsensusTBFTImpl is the implementation of TBFT algorithm
// and it implements the ConsensusEngine interface.
type ConsensusTBFTImpl struct {
	sync.RWMutex
	ctx    context.Context
	logger protocol.Logger
	// chain id
	chainID string
	// node id
	Id string
	// Currently nil, not used
	extendHandler protocol.ConsensusExtendHandler
	// signer（node）
	signer protocol.SigningMember
	// sync service
	syncService protocol.SyncService
	// Access Control
	ac protocol.AccessControlProvider
	// Cache the latest block in ledger(wal)
	ledgerCache protocol.LedgerCache
	// The Proposer of the last block commit height
	lastHeightProposer string
	// block version
	blockVersion uint32
	// chain conf
	chainConf protocol.ChainConf
	// net service （Need to use network module method GetNodeUidByCertId）
	netService protocol.NetService
	// send/receive a message using msgbus
	msgbus msgbus.MessageBus
	// stop tbft
	closeC chan struct{}
	// wal is used to record the consensus state and prevent forks
	wal *lws.Lws
	// write wal sync: 0
	walWriteMode wal_service.WalWriteMode
	// validator Set
	validatorSet *ValidatorSet
	// Current Consensus State
	*ConsensusState
	// History Consensus State（Save 10）
	// When adding n, delete the cache before n-10
	consensusStateCache *consensusStateCache
	// Cache future consensus msg
	// When update height of consensus, delete the cache before height (triggered every 10 heights)
	consensusFutureMsgCache *ConsensusFutureMsgCache
	// timeScheduler is used by consensus for shecdule timeout events.
	// Outdated timeouts will be ignored in processing.
	timeScheduler *timeScheduler

	// channel for processing a block
	proposedBlockC chan *proposedProposal
	// channel used to verify the results
	verifyResultC chan *consensuspb.VerifyResult
	// channel used to enter new height
	blockHeightC chan uint64
	// channel used to externalMsg（msgbus）
	externalMsgC chan *ConsensusMsg
	// Use in handleConsensusMsg method
	internalMsgC chan *ConsensusMsg

	invalidTxs []string

	// Timeout = TimeoutPropose + TimeoutProposeDelta * round
	TimeoutPropose        time.Duration
	TimeoutProposeDelta   time.Duration
	TimeoutProposeOptimal time.Duration
	ProposeOptimal        bool
	ProposeOptimalTimer   *time.Timer

	// The specific time points of each stage of each round in each altitude
	// for printing logs
	metrics *heightMetrics
	// Tbft Consistent Engine
	// will only work if the node is abnormal
	// prevent message loss
	consistentEngine consistent_service.ConsistentEngine
	// use block verifier from core module
	blockVerifier protocol.BlockVerifier
}
